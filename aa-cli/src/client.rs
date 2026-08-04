//! Shared HTTP client for communicating with the Agent Assembly gateway.
//!
//! Every async request helper here runs through one shared bearer-resolution +
//! send path ([`send_with_auth`]) so auth behaves identically across `get`,
//! `post`, and `delete`. The layer's contract (AAASM-5508 / AAASM-5513):
//!
//! 1. **Bearer resolution order** (backwards-compatible): a stored session's
//!    JWT is preferred; otherwise fall back to the context's raw `api_key`;
//!    otherwise send no `Authorization` header at all. The CLI deliberately
//!    does **not** fail-fast on a missing credential — the gateway is the sole
//!    authorization authority (a bypass-default gateway serves unauthenticated
//!    requests fine), so the client sends what it has and lets the server rule.
//! 2. **Silent refresh:** the server issues no refresh token, so an expired JWT
//!    is re-minted from the retained source key (see [`crate::auth::token`])
//!    before the request goes out, and the fresh session is persisted.
//! 3. **Single 401-retry:** an expiry that slips through the pre-send check
//!    (clock skew, a token revoked mid-flight then re-granted) surfaces as a
//!    server `401`. When we used a stored session we re-mint once and resend —
//!    exactly once, because a second consecutive 401 means the source key is
//!    genuinely rejected, and retrying further would just loop.
//! 4. **Typed status translation:** `401` → [`CliError::AuthRequired`], `403` →
//!    [`CliError::ScopeDenied`] (with the server's problem-detail message when
//!    present) instead of the opaque [`CliError::Api`] that `error_for_status`
//!    collapses every 4xx/5xx into.

use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::auth::session::{load_session, now_unix, save_session, session_key, Session};
use crate::auth::token;
use crate::config::ResolvedContext;
use crate::error::CliError;

/// Build a [`reqwest::Client`] with default settings.
pub fn build_client() -> reqwest::Client {
    reqwest::Client::new()
}

/// Build a blocking GET request to `url`, attaching the operator bearer token
/// from the resolved context when one is present.
///
/// This is the blocking analog of the auth-header injection in [`get_json`]:
/// the default gateway requires API-key auth, so every synchronous (`reqwest::blocking`)
/// call site that hits the REST surface must send `Authorization: Bearer <key>`
/// or the request comes back `401`. Routing those call sites through this helper
/// keeps auth attachment in one place instead of each command re-deriving it
/// (the audit/logs group regressed by skipping it — AAASM-4659).
pub fn blocking_get(ctx: &ResolvedContext, url: &str) -> reqwest::blocking::RequestBuilder {
    let mut req = reqwest::blocking::Client::new().get(url);
    if let Some(ref key) = ctx.api_key {
        req = req.bearer_auth(key);
    }
    req
}

/// Which credential [`resolve_bearer`] picked, so [`send_with_auth`] knows
/// whether a `401` is retryable: only a stored-session JWT can be re-minted.
enum Bearer {
    /// A stored-session JWT was resolved (possibly just refreshed). Carries the
    /// session so a mid-flight `401` can trigger one re-mint + resend.
    Session(Session),
    /// The context's raw `api_key` (legacy path). Not refreshable.
    ApiKey(String),
    /// No credential at all — send unauthenticated and let the server decide.
    None,
}

impl Bearer {
    /// The bearer token to attach, if any.
    fn token(&self) -> Option<&str> {
        match self {
            Bearer::Session(s) => Some(&s.token),
            Bearer::ApiKey(k) => Some(k),
            Bearer::None => None,
        }
    }
}

/// Resolve the credential for `ctx` per the module's resolution order,
/// refreshing and persisting an expired session's JWT before it is used.
///
/// A refresh failure caused by the source key being revoked
/// ([`CliError::AuthRequired`] / [`CliError::AuthExchange`]) is propagated so
/// the caller surfaces a clear auth error rather than sending a stale token.
async fn resolve_bearer(ctx: &ResolvedContext) -> Result<Bearer, CliError> {
    if let Some(session) = load_session(&session_key(ctx)) {
        let session = refresh_if_expired(ctx, session).await?;
        return Ok(Bearer::Session(session));
    }
    match &ctx.api_key {
        Some(key) => Ok(Bearer::ApiKey(key.clone())),
        None => Ok(Bearer::None),
    }
}

/// Re-mint `session` from its source key if the JWT is expired, persisting the
/// fresh credential; otherwise return it unchanged.
async fn refresh_if_expired(ctx: &ResolvedContext, session: Session) -> Result<Session, CliError> {
    if session.is_expired(now_unix()) {
        let refreshed = token::refresh(&session).await?;
        save_session(&session_key(ctx), &refreshed)?;
        Ok(refreshed)
    } else {
        Ok(session)
    }
}

/// Apply the resolved bearer to a freshly-built request, send it, retry once on
/// a `401` if we used a refreshable session, and translate the final status.
///
/// `make_req` rebuilds the request each attempt because a `reqwest::Response`
/// consumes its `RequestBuilder`; on the 401-retry path a second builder is
/// needed for the resend.
async fn send_with_auth(
    ctx: &ResolvedContext,
    make_req: impl Fn(&reqwest::Client) -> reqwest::RequestBuilder,
) -> Result<reqwest::Response, CliError> {
    let client = build_client();
    let mut bearer = resolve_bearer(ctx).await?;

    let resp = send_once(&client, &make_req, &bearer).await?;

    // A `401` after using a stored session means the pre-send freshness check
    // missed (clock skew / mid-flight revocation). Re-mint once from the source
    // key and resend a single time; a second `401` is a genuine rejection.
    if resp.status() == reqwest::StatusCode::UNAUTHORIZED {
        if let Bearer::Session(session) = &bearer {
            let refreshed = token::refresh(session).await?;
            save_session(&session_key(ctx), &refreshed)?;
            bearer = Bearer::Session(refreshed);
            let retry = send_once(&client, &make_req, &bearer).await?;
            return translate_status(retry).await;
        }
    }

    translate_status(resp).await
}

/// Build one request via `make_req`, attach the bearer, and send it.
async fn send_once(
    client: &reqwest::Client,
    make_req: &impl Fn(&reqwest::Client) -> reqwest::RequestBuilder,
    bearer: &Bearer,
) -> Result<reqwest::Response, CliError> {
    let mut req = make_req(client);
    if let Some(token) = bearer.token() {
        req = req.bearer_auth(token);
    }
    Ok(req.send().await?)
}

/// Map a final response status to a typed [`CliError`], or pass a 2xx response
/// through unchanged.
///
/// The body is read only on the `403` branch (for the problem-detail message);
/// every other branch leaves the response intact so success callers can still
/// `.json()` it — a `reqwest::Response` body can be consumed only once.
async fn translate_status(resp: reqwest::Response) -> Result<reqwest::Response, CliError> {
    match resp.status() {
        reqwest::StatusCode::UNAUTHORIZED => Err(CliError::AuthRequired),
        reqwest::StatusCode::FORBIDDEN => Err(CliError::ScopeDenied(problem_detail(resp).await)),
        // Non-auth non-success (404, 5xx, …) keeps the prior behavior: surface
        // it as the opaque `CliError::Api` via `error_for_status`.
        _ => Ok(resp.error_for_status()?),
    }
}

/// Extract a human-readable message from an RFC-7807 problem-detail `403` body,
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

/// Perform a GET request to the gateway and deserialize the JSON response.
pub async fn get_json<T: DeserializeOwned>(ctx: &ResolvedContext, path: &str) -> Result<T, CliError> {
    let url = format!("{}{path}", ctx.api_url);
    let resp = send_with_auth(ctx, |client| client.get(&url)).await?;
    let body = resp.json::<T>().await?;
    Ok(body)
}

/// Perform a POST request to the gateway with a JSON body and deserialize the response.
pub async fn post_json<B: Serialize, T: DeserializeOwned>(
    ctx: &ResolvedContext,
    path: &str,
    body: &B,
) -> Result<T, CliError> {
    let url = format!("{}{path}", ctx.api_url);
    let resp = send_with_auth(ctx, |client| client.post(&url).json(body)).await?;
    let result = resp.json::<T>().await?;
    Ok(result)
}

/// Perform a POST request to the gateway with an empty body and deserialize the response.
pub async fn post_empty<T: DeserializeOwned>(ctx: &ResolvedContext, path: &str) -> Result<T, CliError> {
    let url = format!("{}{path}", ctx.api_url);
    let resp = send_with_auth(ctx, |client| client.post(&url)).await?;
    let result = resp.json::<T>().await?;
    Ok(result)
}

/// Perform a POST request to the gateway with an optional JSON body and deserialize the response.
pub async fn post_opt_json<B: Serialize, T: DeserializeOwned>(
    ctx: &ResolvedContext,
    path: &str,
    body: Option<&B>,
) -> Result<T, CliError> {
    let url = format!("{}{path}", ctx.api_url);
    let resp = send_with_auth(ctx, |client| match body {
        Some(b) => client.post(&url).json(b),
        None => client.post(&url),
    })
    .await?;
    let result = resp.json::<T>().await?;
    Ok(result)
}

/// Perform a DELETE request to the gateway.
pub async fn delete(ctx: &ResolvedContext, path: &str) -> Result<(), CliError> {
    let url = format!("{}{path}", ctx.api_url);
    send_with_auth(ctx, |client| client.delete(&url)).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::header::AUTHORIZATION;
    use wiremock::matchers::{header, method, path as path_matcher};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn ctx(api_key: Option<&str>) -> ResolvedContext {
        ResolvedContext {
            name: None,
            api_url: "http://127.0.0.1:7391".to_string(),
            api_key: api_key.map(String::from),
        }
    }

    /// A `ResolvedContext` pointed at `url`, keyed to a name so a stored session
    /// (which we save under the same name) is what `resolve_bearer` picks up.
    fn named_ctx(name: &str, url: &str, api_key: Option<&str>) -> ResolvedContext {
        ResolvedContext {
            name: Some(name.to_string()),
            api_url: url.to_string(),
            api_key: api_key.map(String::from),
        }
    }

    /// Run `body` with `HOME` pointed at a fresh tempdir so `load_session` /
    /// `save_session` see an isolated (initially empty) credential store, then
    /// restore the previous `HOME`. Mirrors the pattern in `config.rs` tests.
    ///
    /// Returns the closure's value; the tempdir is kept alive for its duration.
    ///
    /// The env lock is deliberately held across the `.await`: it guards the
    /// process-global `HOME` (mutated by the surrounding sync `set_var` calls),
    /// so it must stay held for the whole body — including the awaited request —
    /// to keep the credential store isolated from concurrent tests. An
    /// async-aware mutex wouldn't change that, so the lint is suppressed here.
    #[allow(clippy::await_holding_lock)]
    async fn with_isolated_home<F, Fut, T>(body: F) -> T
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = T>,
    {
        let _guard = crate::test_support::env_guard();
        let tmp = tempfile::TempDir::new().unwrap();
        let prev_home = std::env::var_os("HOME");
        std::env::set_var("HOME", tmp.path());

        let result = body().await;

        match prev_home {
            Some(v) => std::env::set_var("HOME", v),
            None => std::env::remove_var("HOME"),
        }
        result
    }

    /// Regression test for AAASM-4659: the audit/logs commands GET
    /// `/api/v1/logs` through `blocking_get`, which must carry the operator
    /// bearer token, or the default (auth-required) gateway answers 401.
    #[test]
    fn blocking_get_attaches_bearer_for_logs_endpoint() {
        let req = blocking_get(
            &ctx(Some("secret-token")),
            "http://127.0.0.1:7391/api/v1/logs?per_page=50&page=1",
        )
        .build()
        .unwrap();
        let auth = req
            .headers()
            .get(AUTHORIZATION)
            .expect("audit/logs request must carry an Authorization header");
        assert_eq!(auth, "Bearer secret-token");
    }

    #[test]
    fn blocking_get_omits_auth_when_no_api_key() {
        let req = blocking_get(&ctx(None), "http://127.0.0.1:7391/api/v1/logs")
            .build()
            .unwrap();
        assert!(req.headers().get(AUTHORIZATION).is_none());
    }

    /// A non-expired stored session must send `Authorization: Bearer <jwt>` and
    /// succeed on a 200. The mock only matches when the header carries the JWT,
    /// so a successful decode proves the session token was attached.
    #[tokio::test]
    async fn valid_session_sends_bearer_jwt_and_succeeds() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path_matcher("/api/v1/ping"))
            .and(header("authorization", "Bearer jwt.abc.123"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({ "ok": true })))
            .mount(&server)
            .await;

        let uri = server.uri();
        let body: serde_json::Value = with_isolated_home(|| async {
            let context = named_ctx("prod", &uri, None);
            let session = Session {
                token: "jwt.abc.123".to_string(),
                // Far-future expiry so no refresh is attempted.
                expires_at: now_unix() + 3_600,
                scopes: vec!["read".to_string()],
                source_key: "aa_source".to_string(),
                api_url: uri.clone(),
            };
            save_session(&session_key(&context), &session).unwrap();
            get_json(&context, "/api/v1/ping").await.expect("200 decodes")
        })
        .await;

        assert_eq!(body["ok"], serde_json::json!(true));
    }

    /// A `403` must map to the typed `CliError::ScopeDenied` (carrying the
    /// server's problem-detail `detail`), NOT the opaque `CliError::Api`.
    #[tokio::test]
    async fn forbidden_maps_to_scope_denied() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path_matcher("/api/v1/agents"))
            .respond_with(
                ResponseTemplate::new(403).set_body_json(serde_json::json!({ "detail": "requires admin scope" })),
            )
            .mount(&server)
            .await;

        let uri = server.uri();
        let err = with_isolated_home(|| async {
            let context = ctx(Some("aa_key"));
            let context = ResolvedContext {
                api_url: uri.clone(),
                ..context
            };
            get_json::<serde_json::Value>(&context, "/api/v1/agents")
                .await
                .expect_err("403 must be an error")
        })
        .await;

        match err {
            CliError::ScopeDenied(msg) => assert_eq!(msg, "requires admin scope"),
            other => panic!("expected ScopeDenied, got {other:?}"),
        }
    }

    /// A `401` with no local session and no key maps to `CliError::AuthRequired`
    /// (not a retry, since there is no refreshable session).
    #[tokio::test]
    async fn unauthorized_without_credential_maps_to_auth_required() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path_matcher("/api/v1/agents"))
            .respond_with(ResponseTemplate::new(401))
            .mount(&server)
            .await;

        let uri = server.uri();
        let err = with_isolated_home(|| async {
            let context = ResolvedContext {
                name: None,
                api_url: uri.clone(),
                api_key: None,
            };
            get_json::<serde_json::Value>(&context, "/api/v1/agents")
                .await
                .expect_err("401 must be an error")
        })
        .await;

        assert!(
            matches!(err, CliError::AuthRequired),
            "expected AuthRequired, got {err:?}"
        );
    }

    /// Backwards-compat: with only `ctx.api_key` set (no stored session) the raw
    /// key is attached as the bearer. The mock only matches on that header.
    #[tokio::test]
    async fn api_key_fallback_attaches_key_as_bearer() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path_matcher("/api/v1/ping"))
            .and(header("authorization", "Bearer aa_raw_key"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({ "ok": true })))
            .mount(&server)
            .await;

        let uri = server.uri();
        let body: serde_json::Value = with_isolated_home(|| async {
            let context = ResolvedContext {
                name: None,
                api_url: uri.clone(),
                api_key: Some("aa_raw_key".to_string()),
            };
            get_json(&context, "/api/v1/ping")
                .await
                .expect("200 decodes with key fallback")
        })
        .await;

        assert_eq!(body["ok"], serde_json::json!(true));
    }
}
