//! WebSocket auth resolution: ticket-first, header-fallback (AAASM-4861).
//!
//! A browser cannot set an `Authorization` header on a WebSocket handshake, so
//! the dashboard authenticates a WS upgrade with a short-lived, single-use
//! `?ticket=` minted over REST ([`crate::ws::ticket`]). Non-browser clients
//! (the CLI, integration tests) *can* send a Bearer header and continue to do
//! so unchanged. This module resolves whichever was presented into the same
//! [`AuthenticatedCaller`] the rest of the WS handler already gates on.

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::response::{IntoResponse, Response};

use crate::auth::{AuthError, AuthenticatedCaller};
use crate::ws::ticket::{WsTicketPurpose, WsTicketStore};

/// The header-derived caller for a WS upgrade, if the client sent an
/// `Authorization` header.
///
/// Browsers can't set that header on a WS handshake, so this is `None` for the
/// dashboard (which authenticates via a `?ticket=`) and `Some` only for
/// non-browser clients that can. A malformed / expired / rate-limited header
/// still rejects — only a *missing* header maps to `None`, so the ticket path
/// can take over rather than a bad credential silently becoming anonymous.
pub struct WsHeaderCaller(pub Option<AuthenticatedCaller>);

impl<S> FromRequestParts<S> for WsHeaderCaller
where
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        match AuthenticatedCaller::from_request_parts(parts, state).await {
            Ok(caller) => Ok(Self(Some(caller))),
            Err(AuthError::MissingHeader) => Ok(Self(None)),
            Err(other) => Err(other.into_response()),
        }
    }
}

/// Resolve the caller a WS upgrade authenticates as, for `purpose`.
///
/// A `?ticket=` — the browser path — is consumed single-use from `store` and
/// must have been minted for `purpose`. With no ticket, the header-derived
/// caller (CLI / non-browser) is used. Either way a failure is a `401` response,
/// never a silent downgrade to an unauthenticated stream.
pub async fn resolve_ws_caller(
    store: &WsTicketStore,
    ticket: Option<&str>,
    purpose: WsTicketPurpose,
    header_caller: Option<AuthenticatedCaller>,
) -> Result<AuthenticatedCaller, Response> {
    if let Some(ticket) = ticket {
        return store.consume(ticket, purpose).await.ok_or_else(|| {
            AuthError::InvalidToken("invalid, expired, or already-used WebSocket ticket".into()).into_response()
        });
    }
    header_caller.ok_or_else(|| AuthError::MissingHeader.into_response())
}
