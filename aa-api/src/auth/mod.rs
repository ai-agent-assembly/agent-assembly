//! Authentication and authorization for the API server.
//!
//! Auth is handled via Axum `FromRequestParts` extractors, not middleware
//! layers. The [`AuthenticatedCaller`] extractor validates API keys or JWTs
//! and enforces per-key rate limits. [`RequireScope`] checks scope levels.

pub mod api_key;
pub mod config;
pub mod gate;
pub mod jwt;
pub mod policy_auth;
pub mod rate_limit;
pub mod scope;

use std::sync::Arc;

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

use self::api_key::{ApiKeyStore, KeyNotValid};
use self::config::{AuthConfig, AuthMode};
use self::jwt::JwtVerifier;
use self::rate_limit::RateLimiter;
use self::scope::Scope;
use crate::error::ProblemDetail;

/// Authentication / authorization errors returned by extractors.
#[derive(Debug)]
pub enum AuthError {
    /// No `Authorization` header was present.
    MissingHeader,
    /// The token could not be validated (bad format, wrong signature, etc.).
    InvalidToken(String),
    /// The token signature was valid but the token has expired.
    ExpiredToken,
    /// The caller has exceeded the per-key rate limit.
    RateLimited {
        /// Seconds until the next request may be accepted.
        retry_after_secs: u64,
    },
    /// The caller's scopes do not satisfy the required scope.
    InsufficientScope {
        /// The scope level that was required.
        required: Scope,
    },
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        match self {
            AuthError::MissingHeader => ProblemDetail::from_status(StatusCode::UNAUTHORIZED)
                .with_detail("Missing Authorization header")
                .into_response(),

            AuthError::InvalidToken(reason) => ProblemDetail::from_status(StatusCode::UNAUTHORIZED)
                .with_detail(format!("Invalid token: {reason}"))
                .into_response(),

            AuthError::ExpiredToken => ProblemDetail::from_status(StatusCode::UNAUTHORIZED)
                .with_detail("Token has expired")
                .into_response(),

            AuthError::RateLimited { retry_after_secs } => {
                let problem = ProblemDetail::from_status(StatusCode::TOO_MANY_REQUESTS)
                    .with_detail(format!("Rate limit exceeded. Retry after {retry_after_secs} seconds"));
                let mut response = problem.into_response();
                response.headers_mut().insert(
                    "retry-after",
                    retry_after_secs
                        .to_string()
                        .parse()
                        .expect("integer is valid header value"),
                );
                response
            }

            AuthError::InsufficientScope { required } => ProblemDetail::from_status(StatusCode::FORBIDDEN)
                .with_detail(format!("Insufficient scope: requires '{required}'"))
                .into_response(),
        }
    }
}

/// The authenticated identity of a request caller.
///
/// The tenant a caller is scoped to (AAASM-3139).
///
/// A caller with a `team_id` (or `org_id`) is confined to that tenant for
/// per-tenant data endpoints. An empty `Tenant` (both `None`) means "no tenant
/// scope" — such a caller can only see cross-tenant data if it also holds
/// `Scope::Admin`. The synthetic bypass-mode caller and admin callers are not
/// confined by tenant.
#[derive(Debug, Clone, Default)]
pub struct Tenant {
    /// The team this caller is scoped to, if any.
    pub team_id: Option<String>,
    /// The org this caller is scoped to, if any.
    pub org_id: Option<String>,
}

/// Populated by the `FromRequestParts` implementation, which validates
/// either an API key (`aa_…`) or a JWT bearer token.
#[derive(Debug, Clone)]
pub struct AuthenticatedCaller {
    /// The API key ID or JWT subject that identifies this caller.
    pub key_id: String,
    /// Scopes granted to this caller.
    pub scopes: Vec<Scope>,
    /// The tenant this caller is confined to for per-tenant data (AAASM-3139).
    pub tenant: Tenant,
}

impl AuthenticatedCaller {
    /// Whether this caller may see data for `team` without a separate admin gate.
    ///
    /// AAASM-3139: an admin sees every tenant; a tenant-scoped caller sees only
    /// its own team. A caller with no team scope (and no admin) sees no
    /// per-tenant data.
    pub fn can_access_team(&self, team: &str) -> bool {
        if self.scopes.contains(&Scope::Admin) {
            return true;
        }
        self.tenant.team_id.as_deref() == Some(team)
    }

    /// Whether this caller may see data for `org` without a separate admin gate.
    ///
    /// AAASM-3483: the org-tier analogue of [`Self::can_access_team`], used by
    /// the topology and audit-log surfaces. An admin sees every org; a
    /// tenant-scoped caller sees only its own org. A caller with no org scope
    /// (and no admin) sees no per-org data.
    pub fn can_access_org(&self, org: &str) -> bool {
        if self.scopes.contains(&Scope::Admin) {
            return true;
        }
        self.tenant.org_id.as_deref() == Some(org)
    }
}

/// Prefix used by API keys (`aa_`).
const API_KEY_PREFIX: &str = "aa_";

impl<S> FromRequestParts<S> for AuthenticatedCaller
where
    S: Send + Sync,
{
    type Rejection = AuthError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        // 1. Read auth config from extensions.
        let auth_config = parts
            .extensions
            .get::<Arc<AuthConfig>>()
            .expect("AuthConfig extension missing — did you forget to add it in build_app?");

        // Bypass mode: return synthetic admin caller.
        if auth_config.mode == AuthMode::Off {
            return Ok(AuthenticatedCaller {
                key_id: "__bypass__".to_string(),
                scopes: vec![Scope::Read, Scope::Write, Scope::Admin],
                // Bypass mode is admin — not confined to any tenant.
                tenant: Tenant::default(),
            });
        }

        // 2. Parse `Authorization: Bearer <token>` header.
        let header_value = parts
            .headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .ok_or(AuthError::MissingHeader)?;

        let token = header_value
            .strip_prefix("Bearer ")
            .ok_or_else(|| AuthError::InvalidToken("expected 'Bearer <token>' format".into()))?;

        // 3. Determine credential type and validate.
        let caller = if token.starts_with(API_KEY_PREFIX) {
            // API key path.
            let key_store = parts
                .extensions
                .get::<Arc<ApiKeyStore>>()
                .expect("ApiKeyStore extension missing");

            let entry = match key_store.validate_detailed(token) {
                Ok(e) => e,
                Err(KeyNotValid::Revoked) => {
                    return Err(AuthError::InvalidToken("revoked API key".into()));
                }
                Err(KeyNotValid::NotFound) => {
                    return Err(AuthError::InvalidToken("invalid API key".into()));
                }
            };

            AuthenticatedCaller {
                key_id: entry.id.clone(),
                scopes: entry.scopes.clone(),
                tenant: Tenant {
                    team_id: entry.team_id.clone(),
                    org_id: entry.org_id.clone(),
                },
            }
        } else {
            // JWT path.
            let jwt_verifier = parts
                .extensions
                .get::<Arc<JwtVerifier>>()
                .expect("JwtVerifier extension missing");

            let claims = jwt_verifier.verify(token).map_err(|e| {
                let msg = e.to_string();
                if msg.contains("ExpiredSignature") {
                    AuthError::ExpiredToken
                } else {
                    AuthError::InvalidToken(msg)
                }
            })?;

            AuthenticatedCaller {
                key_id: claims.sub,
                scopes: claims.scope,
                tenant: Tenant {
                    team_id: claims.team_id,
                    org_id: claims.org_id,
                },
            }
        };

        // 4. Check rate limit.
        let rate_limiter = parts
            .extensions
            .get::<Arc<RateLimiter>>()
            .expect("RateLimiter extension missing");

        rate_limiter
            .check(&caller.key_id)
            .map_err(|retry_after_secs| AuthError::RateLimited { retry_after_secs })?;

        Ok(caller)
    }
}
