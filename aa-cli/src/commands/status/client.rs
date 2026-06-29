//! HTTP client for fetching status data from the governance gateway.

use reqwest::Client;

use super::models::{
    AdminStatusResponse, AgentResponse, ApprovalResponse, CostResponse, HealthResponse, HealthzResponse,
    PaginatedResponse,
};
use crate::error::CliError;

/// Client for making status-related API requests.
pub struct StatusClient {
    base_url: String,
    http: Client,
    /// Optional bearer credential sent on the admin-gated `/api/v1/admin/status`
    /// call (AAASM-3910). `None` for an unauthenticated client — which still
    /// works against a bypass-default gateway (AAASM-1591).
    api_key: Option<String>,
}

impl StatusClient {
    /// Create a new `StatusClient` targeting the given gateway base URL with no
    /// credential. Use [`with_api_key`](Self::with_api_key) to attach one.
    pub fn new(base_url: &str) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            http: Client::new(),
            api_key: None,
        }
    }

    /// Attach an optional bearer credential, sent on admin-gated requests.
    pub fn with_api_key(mut self, api_key: Option<String>) -> Self {
        self.api_key = api_key;
        self
    }

    /// Build a full URL for the given API path.
    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }

    /// Return the base URL (for error messages).
    #[allow(dead_code)]
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Check gateway health via `GET /api/v1/health`.
    pub async fn check_health(&self) -> Result<HealthResponse, CliError> {
        let resp = self.http.get(self.url("/api/v1/health")).send().await?;
        let body = resp.json::<HealthResponse>().await?;
        Ok(body)
    }

    /// Fetch the storage-aware admin status block via
    /// `GET /api/v1/admin/status` (AAASM-1591 / Epic 18 S-J).
    ///
    /// Returns an error when the gateway is unreachable or returns a
    /// body the CLI cannot decode; in particular, an older gateway that
    /// does not yet expose this route will respond with a `404` whose
    /// non-JSON body fails decoding. Callers map both failures to a
    /// missing storage section in `aasm status` rather than surfacing
    /// the error directly.
    pub async fn fetch_admin_status(&self) -> Result<AdminStatusResponse, CliError> {
        // AAASM-3910: `/api/v1/admin/status` is admin-gated (AAASM-3895). Send
        // the configured bearer credential when present; the public `/healthz`
        // and `/api/v1/health` probes stay unauthenticated.
        let mut req = self.http.get(self.url("/api/v1/admin/status"));
        if let Some(ref key) = self.api_key {
            req = req.bearer_auth(key);
        }
        let resp = req.send().await?;
        let body = resp.json::<AdminStatusResponse>().await?;
        Ok(body)
    }

    /// Fetch the lightweight gateway liveness probe via `GET /healthz`.
    ///
    /// Backs the deployment-overview section of `aasm status` — surfaces the
    /// `mode`, `version`, `storage`, and `uptime_secs` fields published by
    /// `aa-gateway::routes::healthz::healthz` regardless of deployment mode.
    /// Returns an error when the gateway is unreachable or returns a body the
    /// client cannot decode; callers map that to `health = "unreachable"`.
    pub async fn check_healthz(&self) -> Result<HealthzResponse, CliError> {
        let resp = self.http.get(self.url("/healthz")).send().await?;
        let body = resp.json::<HealthzResponse>().await?;
        Ok(body)
    }

    /// List all agents via `GET /api/v1/agents`.
    pub async fn list_agents(&self) -> Result<Vec<AgentResponse>, CliError> {
        let resp = self
            .http
            .get(self.url("/api/v1/agents"))
            .query(&[("per_page", "100")])
            .send()
            .await?;
        let body = resp.json::<PaginatedResponse<AgentResponse>>().await?;
        Ok(body.items)
    }

    /// List all approvals via `GET /api/v1/approvals`.
    pub async fn list_approvals(&self) -> Result<Vec<ApprovalResponse>, CliError> {
        let resp = self
            .http
            .get(self.url("/api/v1/approvals"))
            .query(&[("per_page", "100")])
            .send()
            .await?;
        let body = resp.json::<PaginatedResponse<ApprovalResponse>>().await?;
        Ok(body.items)
    }

    /// Fetch cost summary via `GET /api/v1/costs`.
    pub async fn get_costs(&self) -> Result<CostResponse, CliError> {
        let resp = self.http.get(self.url("/api/v1/costs")).send().await?;
        let body = resp.json::<CostResponse>().await?;
        Ok(body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// Minimal valid `/api/v1/admin/status` body the CLI can decode.
    fn admin_status_body() -> serde_json::Value {
        serde_json::json!({
            "mode": "remote",
            "version": "0.0.1",
            "uptime_secs": 1,
            "storage": {
                "backend": "sqlite",
                "health": "ok",
                "latency_ms": 1,
                "row_counts": { "audit_events_hot": 0, "agents": 0, "policy_versions": 0 }
            }
        })
    }

    /// AAASM-3910: with a configured key, the admin-status fetch must carry the
    /// bearer credential. The mock only matches when the header is present, so a
    /// 200 proves it was sent.
    #[tokio::test]
    async fn fetch_admin_status_sends_bearer_when_key_set() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/admin/status"))
            .and(header("authorization", "Bearer aa_test_key"))
            .respond_with(ResponseTemplate::new(200).set_body_json(admin_status_body()))
            .mount(&server)
            .await;

        let client = StatusClient::new(&server.uri()).with_api_key(Some("aa_test_key".to_string()));
        let resp = client.fetch_admin_status().await.expect("admin status decodes");
        assert_eq!(resp.mode, "remote");
    }

    /// With no key configured the fetch still works (bypass-default gateway):
    /// no `Authorization` header is required by the mock.
    #[tokio::test]
    async fn fetch_admin_status_works_without_key() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/admin/status"))
            .respond_with(ResponseTemplate::new(200).set_body_json(admin_status_body()))
            .mount(&server)
            .await;

        let client = StatusClient::new(&server.uri());
        let resp = client.fetch_admin_status().await.expect("admin status decodes");
        assert_eq!(resp.mode, "remote");
    }
}
