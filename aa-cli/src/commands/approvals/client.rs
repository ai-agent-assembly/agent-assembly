//! HTTP client functions for the `aasm approvals` subcommand.

use url::Url;

use crate::config::ResolvedContext;
use crate::error::CliError;

use super::models::{ApprovalResponse, PaginatedResponse};

/// Build the base URL for the approvals API endpoint.
///
/// Strips trailing slashes from the base URL and appends
/// `/api/v1/approvals`.
pub fn build_approvals_url(base: &str) -> String {
    let base = base.trim_end_matches('/');
    format!("{base}/api/v1/approvals")
}

/// Fetch all pending approval requests from the API.
pub async fn list_approvals(ctx: &ResolvedContext) -> Result<PaginatedResponse<ApprovalResponse>, CliError> {
    let url = build_approvals_url(&ctx.api_url);
    let client = reqwest::Client::new();
    let mut req = client.get(&url);
    if let Some(ref key) = ctx.api_key {
        req = req.bearer_auth(key);
    }
    let resp = req.send().await?.error_for_status()?;
    let body = resp.json::<PaginatedResponse<ApprovalResponse>>().await?;
    Ok(body)
}

/// Fetch a single pending approval request by ID.
pub async fn get_approval(ctx: &ResolvedContext, id: &str) -> Result<ApprovalResponse, CliError> {
    let url = format!("{}/{id}", build_approvals_url(&ctx.api_url));
    let client = reqwest::Client::new();
    let mut req = client.get(&url);
    if let Some(ref key) = ctx.api_key {
        req = req.bearer_auth(key);
    }
    let resp = req.send().await?.error_for_status()?;
    let body = resp.json::<ApprovalResponse>().await?;
    Ok(body)
}

/// Approve a pending approval request by ID.
pub async fn approve_action(
    ctx: &ResolvedContext,
    id: &str,
    reason: Option<&str>,
) -> Result<ApprovalResponse, CliError> {
    let url = format!("{}/{id}/approve", build_approvals_url(&ctx.api_url));
    let client = reqwest::Client::new();
    let body = serde_json::json!({
        "by": "cli",
        "reason": reason,
    });
    let mut req = client.post(&url).json(&body);
    if let Some(ref key) = ctx.api_key {
        req = req.bearer_auth(key);
    }
    let resp = req.send().await?.error_for_status()?;
    let result = resp.json::<ApprovalResponse>().await?;
    Ok(result)
}

/// Reject a pending approval request by ID.
pub async fn reject_action(ctx: &ResolvedContext, id: &str, reason: &str) -> Result<ApprovalResponse, CliError> {
    let url = format!("{}/{id}/reject", build_approvals_url(&ctx.api_url));
    let client = reqwest::Client::new();
    let body = serde_json::json!({
        "by": "cli",
        "reason": reason,
    });
    let mut req = client.post(&url).json(&body);
    if let Some(ref key) = ctx.api_key {
        req = req.bearer_auth(key);
    }
    let resp = req.send().await?.error_for_status()?;
    let result = resp.json::<ApprovalResponse>().await?;
    Ok(result)
}

/// Convert an HTTP(S) base URL to a WebSocket URL for the events endpoint.
///
/// `http://` becomes `ws://`, `https://` becomes `wss://`.
/// Appends `/api/v1/ws/events?types={types}` — matches the route mounted by
/// `aa-api` (see `aa-api::routes::mod::v1_router` and `aa-api::ws::handler::ws_events_handler`).
pub fn build_ws_url(base: &str, types: &str) -> Result<String, CliError> {
    let mut parsed =
        Url::parse(base).map_err(|e| CliError::Io(std::io::Error::new(std::io::ErrorKind::InvalidInput, e)))?;
    let new_scheme = match parsed.scheme() {
        "https" => "wss",
        _ => "ws",
    };
    parsed.set_scheme(new_scheme).map_err(|()| {
        CliError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "failed to set scheme",
        ))
    })?;
    let base_str = parsed.as_str().trim_end_matches('/');
    Ok(format!("{base_str}/api/v1/ws/events?types={types}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_approvals_url_without_trailing_slash() {
        assert_eq!(
            build_approvals_url("http://localhost:8080"),
            "http://localhost:8080/api/v1/approvals"
        );
    }

    #[test]
    fn build_approvals_url_with_trailing_slash() {
        assert_eq!(
            build_approvals_url("http://localhost:8080/"),
            "http://localhost:8080/api/v1/approvals"
        );
    }

    #[test]
    fn build_ws_url_http_to_ws() {
        let url = build_ws_url("http://localhost:8080", "approval").unwrap();
        assert_eq!(url, "ws://localhost:8080/api/v1/ws/events?types=approval");
    }

    #[test]
    fn build_ws_url_https_to_wss() {
        let url = build_ws_url("https://api.example.com", "approval").unwrap();
        assert_eq!(url, "wss://api.example.com/api/v1/ws/events?types=approval");
    }

    #[tokio::test]
    async fn list_approvals_returns_paginated_items_from_mock() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;
        let body = serde_json::json!({
            "items": [{
                "id": "abc-123",
                "agent_id": "support-agent",
                "action": "process_refund",
                "reason": "amount > $100",
                "status": "pending",
                "created_at": "2026-04-30T10:00:00Z"
            }],
            "page": 1, "per_page": 20, "total": 1
        });
        Mock::given(method("GET"))
            .and(path("/api/v1/approvals"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&body))
            .mount(&mock_server)
            .await;

        let ctx = ResolvedContext {
            name: None,
            api_url: mock_server.uri(),
            api_key: None,
        };
        let result = list_approvals(&ctx).await.unwrap();
        assert_eq!(result.items.len(), 1);
        assert_eq!(result.items[0].id, "abc-123");
        assert_eq!(result.total, 1);
    }

    #[tokio::test]
    async fn approve_action_sends_post_and_returns_approved() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;
        let body = serde_json::json!({
            "id": "abc-123",
            "agent_id": "support-agent",
            "action": "process_refund",
            "reason": "",
            "status": "approved",
            "created_at": "2026-04-30T10:00:00Z"
        });
        Mock::given(method("POST"))
            .and(path("/api/v1/approvals/abc-123/approve"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&body))
            .mount(&mock_server)
            .await;

        let ctx = ResolvedContext {
            name: None,
            api_url: mock_server.uri(),
            api_key: None,
        };
        let result = approve_action(&ctx, "abc-123", Some("looks good")).await.unwrap();
        assert_eq!(result.status, "approved");
    }

    #[tokio::test]
    async fn reject_action_sends_post_and_returns_rejected() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;
        let body = serde_json::json!({
            "id": "abc-123",
            "agent_id": "support-agent",
            "action": "process_refund",
            "reason": "not authorized",
            "status": "rejected",
            "created_at": "2026-04-30T10:00:00Z"
        });
        Mock::given(method("POST"))
            .and(path("/api/v1/approvals/abc-123/reject"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&body))
            .mount(&mock_server)
            .await;

        let ctx = ResolvedContext {
            name: None,
            api_url: mock_server.uri(),
            api_key: None,
        };
        let result = reject_action(&ctx, "abc-123", "not authorized").await.unwrap();
        assert_eq!(result.status, "rejected");
    }
}
