//! Shared HTTP authentication and authorization framework for Agent Assembly.
//!
//! This leaf crate holds the transport-agnostic auth primitives that the API
//! presentation layer (`aa-api`) — and, in a follow-up, the gateway — build on:
//! API-key and JWT credential validation, scope levels, per-key rate limiting,
//! and the deny-by-default authentication gate. It depends only on `axum`,
//! `http`, `serde`, and the credential primitives, never on `aa-core`,
//! `aa-gateway`, `aa-runtime`, or `aa-api`, so it stays a true leaf.
//!
//! Auth is handled via Axum `FromRequestParts` extractors, not middleware
//! layers. The [`AuthenticatedCaller`] extractor validates API keys or JWTs
//! and enforces per-key rate limits. [`scope::RequireScope`] checks scope levels.

pub mod api_key;
pub mod config;
pub mod gate;
pub mod jwt;
pub mod rate_limit;
pub mod scope;

mod error;
pub use error::ProblemDetail;

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

    /// The verified tenant org that scopes this caller's storage access, if any.
    ///
    /// AAASM-3596: this is the single, honest source for the `app.tenant_id` GUC
    /// the storage layer's Row-Level Security filters on (AAASM-3595). It is
    /// taken *only* from [`Self::tenant`] — the verified JWT `org_id` claim or
    /// the authenticated API-key entry — and never from a request `Query`,
    /// header, or body. A client cannot redirect it by sending a different
    /// `?org_id` / `X-Org-Id`, because nothing here reads request input.
    ///
    /// Returns `None` for a caller with no tenant scope (an admin / cross-tenant
    /// caller). Such a caller must run the storage connection with NO
    /// `app.tenant_id` GUC — i.e. via a dedicated RLS-bypass admin DB role — and
    /// must *never* synthesize a tenant from a client-chosen value. Feeding a
    /// `None` here into the GUC seam yields a fail-closed (zero-row) connection,
    /// not a full-table read.
    pub fn storage_tenant_org(&self) -> Option<&str> {
        self.tenant.org_id.as_deref()
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
        // AAASM-4829: reuse a caller already resolved earlier in this request's
        // lifecycle (e.g. by the `require_authentication` route-layer gate, which
        // inserts it into extensions). Re-running the full resolution here would
        // repeat the argon2 API-key/JWT validation AND a second
        // `RateLimiter::check`, double-charging the per-key rate limit for every
        // gated request. A cached caller short-circuits both.
        if let Some(cached) = parts.extensions.get::<AuthenticatedCaller>() {
            return Ok(cached.clone());
        }

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

#[cfg(test)]
mod tenant_guard_tests {
    use super::*;

    fn caller_with_org(org: Option<&str>, scopes: Vec<Scope>) -> AuthenticatedCaller {
        AuthenticatedCaller {
            key_id: "key-1".to_string(),
            scopes,
            tenant: Tenant {
                team_id: None,
                org_id: org.map(str::to_string),
            },
        }
    }

    /// AAASM-3596: the value feeding the storage `app.tenant_id` GUC is the
    /// caller's verified org and nothing else.
    #[test]
    fn storage_tenant_org_is_the_verified_org() {
        let caller = caller_with_org(Some("org-verified"), vec![Scope::Read]);
        assert_eq!(caller.storage_tenant_org(), Some("org-verified"));
    }

    /// AAASM-3596 (the spoof case): a request might carry any `?org_id` /
    /// `X-Org-Id`, but `storage_tenant_org` reads none of that — it only ever
    /// returns the verified tenant, so a client-supplied org cannot redirect or
    /// widen a caller's storage scope.
    #[test]
    fn client_supplied_org_cannot_redirect_storage_scope() {
        // The caller is verified as org-A. A spoofed request body/header asking
        // for "org-victim" is irrelevant: the seam never consults request input.
        let caller = caller_with_org(Some("org-A"), vec![Scope::Read]);
        let spoofed_client_org = "org-victim";
        assert_ne!(
            caller.storage_tenant_org(),
            Some(spoofed_client_org),
            "a client-chosen org must not become the storage tenant"
        );
        assert_eq!(
            caller.storage_tenant_org(),
            Some("org-A"),
            "the storage tenant is provably the verified org only"
        );
    }

    /// A caller with no verified tenant scope yields None — which the storage
    /// GUC seam maps to a fail-closed (zero-row) connection, never a synthesized
    /// client-chosen tenant.
    #[test]
    fn no_tenant_scope_yields_none_not_a_client_value() {
        let caller = caller_with_org(None, vec![Scope::Read, Scope::Admin]);
        assert_eq!(caller.storage_tenant_org(), None);
    }

    /// AAASM-4829: a caller cached in request extensions (by the
    /// `require_authentication` gate) is reused verbatim — the extractor never
    /// re-runs credential validation or the rate-limit check. Two things prove
    /// it: (1) the future resolves synchronously (`Poll::Ready` on first poll,
    /// no await), and (2) neither the `AuthConfig` nor `RateLimiter` extension is
    /// present — the resolution path would panic on the missing `AuthConfig`
    /// rather than return the cached caller.
    #[test]
    fn cached_caller_in_extensions_is_reused_without_revalidation() {
        use std::future::Future;
        use std::pin::pin;
        use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

        fn noop_waker() -> Waker {
            const VTABLE: RawWakerVTable = RawWakerVTable::new(|_| RAW, |_| {}, |_| {}, |_| {});
            const RAW: RawWaker = RawWaker::new(std::ptr::null(), &VTABLE);
            // SAFETY: the vtable's clone/wake/drop are all no-ops over a null
            // pointer, so the waker is inert and never dereferences the data.
            unsafe { Waker::from_raw(RAW) }
        }

        let cached = caller_with_org(Some("org-A"), vec![Scope::Read, Scope::Write]);
        let (mut parts, _body) = axum::http::Request::new(()).into_parts();
        parts.extensions.insert(cached.clone());

        let mut fut = pin!(AuthenticatedCaller::from_request_parts(&mut parts, &()));
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let resolved = match fut.as_mut().poll(&mut cx) {
            Poll::Ready(r) => r.expect("cached caller is reused"),
            Poll::Pending => panic!("cached-caller path must complete synchronously"),
        };
        assert_eq!(resolved.key_id, cached.key_id);
        assert_eq!(resolved.scopes, cached.scopes);
        assert_eq!(resolved.tenant.org_id.as_deref(), Some("org-A"));
    }
}
