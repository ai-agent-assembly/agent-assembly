//! Router-level authentication gate (AAASM-3125).
//!
//! Historically every protected handler had to opt in to authentication by
//! declaring an `AuthenticatedCaller` / `RequireScope` extractor. Handlers
//! that forgot to do so (e.g. the alert-rule CRUD endpoints, AAASM-3129)
//! silently shipped unauthenticated. This module provides a single
//! deny-by-default [`require_authentication`] middleware that is applied as a
//! `route_layer` over the protected sub-router in the consuming service's
//! router, so a new route is authenticated unless it is explicitly mounted on
//! the public router.
//!
//! The gate reuses the existing [`AuthenticatedCaller`] extractor, so it
//! honours `AuthMode::Off` (bypass) and the API-key / JWT validation and
//! per-key rate-limit logic exactly as the per-handler extractors do.

use axum::extract::{FromRequestParts, Request};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use http::request::Parts;

use crate::AuthenticatedCaller;

/// Deny-by-default authentication middleware.
///
/// Resolves [`AuthenticatedCaller`] from the request parts. On success the
/// request proceeds to the inner service; on failure the [`AuthError`] is
/// rendered (401 / 403 / 429) and the inner handler is never reached.
///
/// [`AuthError`]: crate::AuthError
pub async fn require_authentication(request: Request, next: Next) -> Response {
    let (mut parts, body): (Parts, _) = request.into_parts();

    // `()` is a valid `S: Send + Sync` state for the extractor — all auth
    // inputs come from request extensions, not router state.
    match AuthenticatedCaller::from_request_parts(&mut parts, &()).await {
        Ok(caller) => {
            // AAASM-4829: cache the resolved caller in request extensions so a
            // downstream extractor (`AuthenticatedCaller` / `RequireRead` / …)
            // reuses it instead of re-running argon2 validation and a SECOND
            // `RateLimiter::check` — the double rate-check halved each key's
            // effective limit for every gated request.
            parts.extensions.insert(caller);
            let request = Request::from_parts(parts, body);
            next.run(request).await
        }
        Err(rejection) => rejection.into_response(),
    }
}
