//! HTTP client for fetching status data from the governance gateway.

use reqwest::Client;

use super::models::{
    AgentResponse, ApprovalResponse, CostResponse, HealthResponse, HealthzResponse, PaginatedResponse,
};
use crate::error::CliError;

/// Client for making status-related API requests.
pub struct StatusClient {
    base_url: String,
    http: Client,
}

impl StatusClient {
    /// Create a new `StatusClient` targeting the given gateway base URL.
    pub fn new(base_url: &str) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            http: Client::new(),
        }
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
