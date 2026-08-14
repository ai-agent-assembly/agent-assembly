//! Authentication routes: JWT token issuance.

use std::sync::Arc;

use axum::Extension;
use axum::Json;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::auth::jwt::JwtSigner;
use crate::auth::scope::Scope;
use crate::auth::AuthenticatedCaller;
use crate::error::ProblemDetail;
use crate::ws::ticket::{WsTicketPurpose, WsTicketStore};

/// JWT token lifetime in seconds (must match [`crate::auth::jwt::TOKEN_EXPIRY_SECS`]).
const TOKEN_EXPIRY_SECS: u64 = 24 * 60 * 60;

/// Request body for `POST /auth/token`.
#[derive(Debug, Deserialize, ToSchema)]
pub struct TokenRequest {
    /// Requested scopes for the issued JWT.
    /// If omitted, the caller's full scopes are used.
    #[serde(default)]
    pub scopes: Option<Vec<Scope>>,
}

/// Response body for `POST /auth/token`.
#[derive(Debug, Serialize, ToSchema)]
pub struct TokenResponse {
    /// The issued JWT token string.
    pub token: String,
    /// Unix timestamp when the token expires.
    pub expires_at: u64,
    /// Scopes granted in the token.
    pub scopes: Vec<Scope>,
}

/// Issue a short-lived JWT token from an authenticated API key.
///
/// The caller must already be authenticated (via API key or existing JWT).
/// If `scopes` is provided in the request body, it must be a subset of
/// the caller's granted scopes.
#[utoipa::path(
    post,
    path = "/api/v1/auth/token",
    request_body = TokenRequest,
    responses(
        (status = 200, description = "JWT issued successfully", body = TokenResponse),
        (status = 401, description = "Missing or invalid credentials", body = ProblemDetail),
        (status = 403, description = "Requested scope exceeds caller grants", body = ProblemDetail),
    ),
    security(("bearer_auth" = [])),
    tag = "auth"
)]
pub async fn issue_token(
    caller: AuthenticatedCaller,
    Extension(jwt_signer): Extension<Arc<JwtSigner>>,
    Json(body): Json<TokenRequest>,
) -> Result<Json<TokenResponse>, ProblemDetail> {
    let token_scopes = match body.scopes {
        Some(requested) => {
            // Validate that each requested scope is satisfied by the caller's scopes.
            for scope in &requested {
                if !scope.is_satisfied_by(&caller.scopes) {
                    return Err(ProblemDetail::from_status(axum::http::StatusCode::FORBIDDEN)
                        .with_detail(format!("Requested scope '{scope}' exceeds caller's granted scopes")));
                }
            }
            requested
        }
        None => caller.scopes.clone(),
    };

    // AAASM-3894: carry the caller's tenant into the issued JWT. `sign` drops
    // team_id/org_id, so a tenant-confined key's token would lose its tenant
    // scope and fall back to admin-only cross-tenant gating on the per-tenant
    // data endpoints. Propagate the tenant so the issued token stays confined.
    let token = jwt_signer
        .sign_with_tenant(
            &caller.key_id,
            &token_scopes,
            caller.tenant.team_id.clone(),
            caller.tenant.org_id.clone(),
        )
        .map_err(|e| {
            ProblemDetail::from_status(axum::http::StatusCode::INTERNAL_SERVER_ERROR)
                .with_detail(format!("Failed to sign token: {e}"))
        })?;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before Unix epoch")
        .as_secs();

    Ok(Json(TokenResponse {
        token,
        expires_at: now + TOKEN_EXPIRY_SECS,
        scopes: token_scopes,
    }))
}

/// Request body for `POST /auth/ws-ticket` (AAASM-4861).
#[derive(Debug, Deserialize, ToSchema)]
pub struct WsTicketRequest {
    /// Which WebSocket stream the ticket will open. A ticket minted for one
    /// purpose is rejected by any other WS endpoint.
    pub purpose: WsTicketPurpose,
}

/// Response body for `POST /auth/ws-ticket` (AAASM-4861).
#[derive(Debug, Serialize, ToSchema)]
pub struct WsTicketResponse {
    /// The opaque, single-use ticket to present as `?ticket=` on the WS upgrade.
    pub ticket: String,
    /// Unix timestamp when the ticket expires. It is also invalidated the moment
    /// it is used; whichever comes first.
    pub expires_at: u64,
    /// The stream this ticket may open (echoes the request).
    pub purpose: WsTicketPurpose,
}

/// Mint a short-lived, single-use WebSocket ticket for the authenticated caller.
///
/// A browser cannot set an `Authorization` header on a WebSocket handshake, so
/// the dashboard mints a ticket here (over an authenticated REST call) and
/// presents it once as `?ticket=` on the upgrade, instead of putting a
/// long-lived credential in the URL where infrastructure logs would capture it
/// (AAASM-4861; see ADR 0012). The ticket is bound to this caller's identity,
/// scopes, and tenant, is valid only for the requested stream, is atomically
/// consumed on first use (replay-safe), is not accepted by any REST route, and
/// is not refreshable — a reconnect mints a fresh one.
#[utoipa::path(
    post,
    path = "/api/v1/auth/ws-ticket",
    request_body = WsTicketRequest,
    responses(
        (status = 200, description = "Ticket issued successfully", body = WsTicketResponse),
        (status = 401, description = "Missing or invalid credentials", body = ProblemDetail),
    ),
    security(("bearer_auth" = [])),
    tag = "auth"
)]
pub async fn issue_ws_ticket(
    caller: AuthenticatedCaller,
    Extension(ticket_store): Extension<WsTicketStore>,
    Json(body): Json<WsTicketRequest>,
) -> Json<WsTicketResponse> {
    let ticket = ticket_store.mint(&caller, body.purpose).await;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before Unix epoch")
        .as_secs();

    Json(WsTicketResponse {
        ticket,
        expires_at: now + ticket_store.ttl().as_secs(),
        purpose: body.purpose,
    })
}
