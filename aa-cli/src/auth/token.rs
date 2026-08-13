//! API-key → scoped-JWT exchange against `POST /api/v1/auth/token` (AAASM-5507/5508).
//!
//! This is the one network primitive the auth workflow adds. `aasm login` calls
//! it to mint the initial session; the client layer calls it again to silently
//! refresh an expired JWT from the stored source key (the server issues no
//! refresh token, so re-exchange *is* the refresh — see [`crate::auth::session`]).
//!
//! The endpoint authenticates the caller by the bearer key itself and returns
//! `{ token, expires_at, scopes }`. A requested scope subset that exceeds the
//! caller's grants is rejected `403`; a bad/absent key is `401`. Both surface as
//! the typed [`CliError`] variants so callers can render actionable guidance
//! rather than a raw HTTP status.

use serde::{Deserialize, Serialize};

use crate::auth::session::{now_unix, Session};
use crate::client::build_client;
use crate::error::CliError;

/// Path of the token-exchange endpoint (public router; full `/api/v1` prefix
/// per the CLI's path convention).
const TOKEN_PATH: &str = "/api/v1/auth/token";

/// Request body for `/auth/token`. `scopes: None` asks for the caller's full
/// grants; `Some(subset)` mints a narrowed session (server validates ⊆ grants).
#[derive(Debug, Serialize)]
struct TokenRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    scopes: Option<Vec<String>>,
}

/// Response body from `/auth/token`.
#[derive(Debug, Deserialize)]
struct TokenResponse {
    token: String,
    expires_at: u64,
    scopes: Vec<String>,
}

/// Exchange `api_key` at `api_url` for a scoped JWT, returning a ready-to-store
/// [`Session`].
///
/// `requested_scopes` is `None` for the caller's full scopes, or `Some` for a
/// narrowed subset. On success the returned session carries the JWT, its expiry,
/// the granted scopes, and the source key (retained for later refresh).
///
/// Errors map the server's response to actionable variants: `401` →
/// [`CliError::AuthRequired`], `403` → [`CliError::ScopeDenied`] (carrying the
/// server's problem-detail message when present).
pub async fn exchange(
    api_url: &str,
    api_key: &str,
    requested_scopes: Option<Vec<String>>,
) -> Result<Session, CliError> {
    let url = format!("{api_url}{TOKEN_PATH}");
    let resp = build_client()
        .post(&url)
        .bearer_auth(api_key)
        .json(&TokenRequest {
            scopes: requested_scopes,
        })
        .send()
        .await?;

    match resp.status() {
        reqwest::StatusCode::OK => {
            let body: TokenResponse = resp.json().await?;
            Ok(Session {
                token: body.token,
                expires_at: body.expires_at,
                scopes: body.scopes,
                source_key: api_key.to_string(),
                api_url: api_url.to_string(),
            })
        }
        reqwest::StatusCode::UNAUTHORIZED => Err(CliError::AuthRequired),
        reqwest::StatusCode::FORBIDDEN => Err(CliError::ScopeDenied(problem_detail(resp).await)),
        other => Err(CliError::AuthExchange(format!(
            "unexpected status {other} from {TOKEN_PATH}"
        ))),
    }
}

/// Re-mint a session from its stored source key. Convenience over [`exchange`]
/// that preserves the currently-granted scopes, used by the client layer when a
/// JWT has expired.
pub async fn refresh(session: &Session) -> Result<Session, CliError> {
    exchange(&session.api_url, &session.source_key, Some(session.scopes.clone())).await
}

/// If `session` is expired, refresh it and return the new session; otherwise
/// return it unchanged. The `bool` reports whether a refresh happened, so the
/// caller can decide to persist the updated credential.
pub async fn ensure_fresh(session: Session) -> Result<(Session, bool), CliError> {
    if session.is_expired(now_unix()) {
        let refreshed = refresh(&session).await?;
        Ok((refreshed, true))
    } else {
        Ok((session, false))
    }
}

/// Extract a human-readable message from an RFC-7807 problem-detail body,
/// falling back to a generic phrase when the body isn't shaped as expected.
async fn problem_detail(resp: reqwest::Response) -> String {
    match resp.json::<serde_json::Value>().await {
        Ok(v) => v
            .get("detail")
            .or_else(|| v.get("title"))
            .and_then(|d| d.as_str())
            .map(|s| s.to_string())
            .unwrap_or_else(|| "insufficient scope for this operation".to_string()),
        Err(_) => "insufficient scope for this operation".to_string(),
    }
}
