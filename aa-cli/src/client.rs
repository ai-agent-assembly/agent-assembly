//! Shared HTTP client for communicating with the Agent Assembly gateway.

use serde::de::DeserializeOwned;
use serde::Serialize;

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

/// Perform a GET request to the gateway and deserialize the JSON response.
pub async fn get_json<T: DeserializeOwned>(ctx: &ResolvedContext, path: &str) -> Result<T, CliError> {
    let url = format!("{}{path}", ctx.api_url);
    let client = build_client();

    let mut req = client.get(&url);
    if let Some(ref key) = ctx.api_key {
        req = req.bearer_auth(key);
    }

    let resp = req.send().await?.error_for_status()?;
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
    let client = build_client();

    let mut req = client.post(&url).json(body);
    if let Some(ref key) = ctx.api_key {
        req = req.bearer_auth(key);
    }

    let resp = req.send().await?.error_for_status()?;
    let result = resp.json::<T>().await?;
    Ok(result)
}

/// Perform a POST request to the gateway with an empty body and deserialize the response.
pub async fn post_empty<T: DeserializeOwned>(ctx: &ResolvedContext, path: &str) -> Result<T, CliError> {
    let url = format!("{}{path}", ctx.api_url);
    let client = build_client();

    let mut req = client.post(&url);
    if let Some(ref key) = ctx.api_key {
        req = req.bearer_auth(key);
    }

    let resp = req.send().await?.error_for_status()?;
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
    let client = build_client();

    let mut req = match body {
        Some(b) => client.post(&url).json(b),
        None => client.post(&url),
    };
    if let Some(ref key) = ctx.api_key {
        req = req.bearer_auth(key);
    }

    let resp = req.send().await?.error_for_status()?;
    let result = resp.json::<T>().await?;
    Ok(result)
}

/// Perform a DELETE request to the gateway.
pub async fn delete(ctx: &ResolvedContext, path: &str) -> Result<(), CliError> {
    let url = format!("{}{path}", ctx.api_url);
    let client = build_client();

    let mut req = client.delete(&url);
    if let Some(ref key) = ctx.api_key {
        req = req.bearer_auth(key);
    }

    req.send().await?.error_for_status()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::header::AUTHORIZATION;

    fn ctx(api_key: Option<&str>) -> ResolvedContext {
        ResolvedContext {
            name: None,
            api_url: "http://127.0.0.1:7391".to_string(),
            api_key: api_key.map(String::from),
        }
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
}
