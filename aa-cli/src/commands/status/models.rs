//! Data models for the `aasm status` command.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// API response from `GET /api/v1/health`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct HealthResponse {
    /// Liveness status string, always `"ok"` when the service is running.
    pub status: String,
    /// Server uptime in seconds since startup.
    #[serde(default)]
    pub uptime_secs: u64,
    /// Number of currently active WebSocket/SSE connections.
    #[serde(default)]
    pub active_connections: i64,
    /// Pipeline processing lag in milliseconds.
    #[serde(default)]
    pub pipeline_lag_ms: u64,
}

/// Computed runtime health for display.
#[derive(Debug, Clone, Serialize)]
pub struct RuntimeHealth {
    /// Whether the API gateway is reachable.
    pub reachable: bool,
    /// Status string from the health endpoint (e.g. `"ok"`).
    pub status: String,
    /// Server uptime in seconds since startup.
    pub uptime_secs: u64,
    /// Number of currently active WebSocket/SSE connections.
    pub active_connections: i64,
    /// Pipeline processing lag in milliseconds.
    pub pipeline_lag_ms: u64,
}

/// API response item from `GET /api/v1/agents`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AgentResponse {
    pub id: String,
    pub name: String,
    pub framework: String,
    pub version: String,
    pub status: String,
    pub tool_names: Vec<String>,
    pub metadata: BTreeMap<String, String>,
    /// Number of sessions handled by this agent.
    #[serde(default)]
    pub session_count: u32,
    /// Number of policy violations recorded for this agent.
    #[serde(default)]
    pub policy_violations_count: u32,
    /// Governance layer this agent is assigned to.
    #[serde(default)]
    pub layer: Option<String>,
    /// ISO 8601 timestamp of the most recent event.
    #[serde(default)]
    pub last_event: Option<String>,
    /// Most recent events emitted by this agent.
    #[serde(default)]
    pub recent_events: Vec<RecentEventResponse>,
}

/// Summary of a recent event from the API response.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RecentEventResponse {
    /// Event type classification (e.g. "violation", "tool_call").
    pub event_type: String,
    /// Short human-readable summary.
    pub summary: String,
    /// ISO 8601 timestamp when the event occurred.
    pub timestamp: String,
}

/// Flattened agent row for tabular display.
#[derive(Debug, Clone, Serialize)]
pub struct AgentRow {
    pub id: String,
    pub name: String,
    pub framework: String,
    pub status: String,
    pub sessions: u32,
    pub violations_today: u32,
    pub last_event: String,
    pub layer: String,
}

/// API response item from `GET /api/v1/approvals`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ApprovalResponse {
    pub id: String,
    pub agent_id: String,
    pub action: String,
    pub reason: String,
    pub status: String,
    pub created_at: String,
    /// Team this request was routed to (empty when agent has no team).
    #[serde(default)]
    pub team_id: String,
    /// Human-readable routing status, e.g. `"routed:team-x"` or `"no_team_id"`.
    #[serde(default)]
    pub routing_status: String,
}

/// Computed approvals summary for display.
#[derive(Debug, Clone, Serialize)]
pub struct ApprovalsSummary {
    /// Number of approvals currently in `"pending"` status.
    pub pending_count: usize,
    /// Human-readable age of the oldest pending approval (e.g. `"2h 15m"`).
    pub oldest_pending_age: Option<String>,
}

/// Per-agent cost entry from the API.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AgentCostEntry {
    pub agent_id: String,
    pub daily_spend_usd: String,
}

/// API response from `GET /api/v1/costs`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CostResponse {
    pub daily_spend_usd: String,
    pub monthly_spend_usd: Option<String>,
    pub date: String,
    #[serde(default)]
    pub daily_limit_usd: Option<String>,
    #[serde(default)]
    pub monthly_limit_usd: Option<String>,
    #[serde(default)]
    pub per_agent: Vec<AgentCostEntry>,
}

/// Budget display model combining global spend, limits, and per-agent breakdown.
#[derive(Debug, Clone, Serialize)]
pub struct BudgetRow {
    /// Total daily spend in USD.
    pub daily_spend_usd: String,
    /// Monthly spend if available.
    pub monthly_spend_usd: Option<String>,
    /// Configured daily budget limit in USD.
    pub daily_limit_usd: Option<String>,
    /// Configured monthly budget limit in USD.
    pub monthly_limit_usd: Option<String>,
    /// Reporting date.
    pub date: String,
    /// Per-agent cost breakdown sorted by spend descending.
    pub per_agent: Vec<AgentCostEntry>,
}

/// Paginated API response wrapper.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PaginatedResponse<T> {
    pub items: Vec<T>,
    pub page: u32,
    pub per_page: u32,
    pub total: u64,
}

/// Complete status snapshot combining all sections.
#[derive(Debug, Clone, Serialize)]
pub struct StatusSnapshot {
    pub runtime: RuntimeHealth,
    pub agents: Vec<AgentRow>,
    pub approvals: ApprovalsSummary,
    pub budget: BudgetRow,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn health_response_deserializes_minimal() {
        let json = r#"{"status":"ok"}"#;
        let resp: HealthResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.status, "ok");
        assert_eq!(resp.uptime_secs, 0);
        assert_eq!(resp.active_connections, 0);
        assert_eq!(resp.pipeline_lag_ms, 0);
    }

    #[test]
    fn health_response_deserializes_with_new_fields() {
        let json = r#"{"status":"ok","uptime_secs":3600,"active_connections":5,"pipeline_lag_ms":12}"#;
        let resp: HealthResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.status, "ok");
        assert_eq!(resp.uptime_secs, 3600);
        assert_eq!(resp.active_connections, 5);
        assert_eq!(resp.pipeline_lag_ms, 12);
    }

    #[test]
    fn agent_response_deserializes() {
        let json = r#"{
            "id": "abc123",
            "name": "support-agent",
            "framework": "langgraph",
            "version": "1.0.0",
            "status": "Running",
            "tool_names": ["query_db", "send_slack"],
            "metadata": {"team": "support"}
        }"#;
        let resp: AgentResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.id, "abc123");
        assert_eq!(resp.name, "support-agent");
        assert_eq!(resp.framework, "langgraph");
        assert_eq!(resp.tool_names.len(), 2);
        assert_eq!(resp.metadata.get("team").unwrap(), "support");
        // New fields default when missing from JSON.
        assert_eq!(resp.session_count, 0);
        assert_eq!(resp.policy_violations_count, 0);
        assert!(resp.layer.is_none());
        assert!(resp.last_event.is_none());
        assert!(resp.recent_events.is_empty());
    }

    #[test]
    fn agent_response_deserializes_with_new_fields() {
        let json = r#"{
            "id": "abc123",
            "name": "full-agent",
            "framework": "crewai",
            "version": "2.0.0",
            "status": "Active",
            "tool_names": [],
            "metadata": {},
            "session_count": 5,
            "policy_violations_count": 2,
            "layer": "enforced",
            "last_event": "2026-05-01T08:00:00Z",
            "recent_events": [
                {"event_type": "tool_call", "summary": "called bash", "timestamp": "2026-05-01T08:00:00Z"}
            ]
        }"#;
        let resp: AgentResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.session_count, 5);
        assert_eq!(resp.policy_violations_count, 2);
        assert_eq!(resp.layer.as_deref(), Some("enforced"));
        assert_eq!(resp.last_event.as_deref(), Some("2026-05-01T08:00:00Z"));
        assert_eq!(resp.recent_events.len(), 1);
        assert_eq!(resp.recent_events[0].event_type, "tool_call");
    }

    #[test]
    fn approval_response_deserializes() {
        let json = r#"{
            "id": "ap-001",
            "agent_id": "abc123",
            "action": "process_refund",
            "reason": "amount exceeds $100",
            "status": "pending",
            "created_at": "2026-04-30T10:00:00Z"
        }"#;
        let resp: ApprovalResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.id, "ap-001");
        assert_eq!(resp.status, "pending");
        assert_eq!(resp.created_at, "2026-04-30T10:00:00Z");
        // routing fields default to empty when missing from JSON
        assert!(resp.team_id.is_empty());
        assert!(resp.routing_status.is_empty());
    }

    #[test]
    fn approval_response_deserializes_with_routing_fields() {
        let json = r#"{
            "id": "ap-002",
            "agent_id": "abc123",
            "action": "dangerous_action",
            "reason": "requires_approval",
            "status": "pending",
            "created_at": "2026-05-01T09:00:00Z",
            "team_id": "team-x",
            "routing_status": "routed:team-x"
        }"#;
        let resp: ApprovalResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.team_id, "team-x");
        assert_eq!(resp.routing_status, "routed:team-x");
    }

    #[test]
    fn cost_response_deserializes() {
        let json = r#"{
            "daily_spend_usd": "8.10",
            "monthly_spend_usd": "142.50",
            "date": "2026-04-30",
            "daily_limit_usd": "100.00",
            "monthly_limit_usd": "2000.00",
            "per_agent": [
                {"agent_id": "abc123", "daily_spend_usd": "4.10"}
            ]
        }"#;
        let resp: CostResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.daily_spend_usd, "8.10");
        assert_eq!(resp.monthly_spend_usd.as_deref(), Some("142.50"));
        assert_eq!(resp.date, "2026-04-30");
        assert_eq!(resp.daily_limit_usd.as_deref(), Some("100.00"));
        assert_eq!(resp.monthly_limit_usd.as_deref(), Some("2000.00"));
        assert_eq!(resp.per_agent.len(), 1);
        assert_eq!(resp.per_agent[0].agent_id, "abc123");
        assert_eq!(resp.per_agent[0].daily_spend_usd, "4.10");
    }

    #[test]
    fn cost_response_deserializes_without_monthly() {
        let json = r#"{"daily_spend_usd": "0.00", "date": "2026-04-30"}"#;
        let resp: CostResponse = serde_json::from_str(json).unwrap();
        assert!(resp.monthly_spend_usd.is_none());
    }

    #[test]
    fn cost_response_deserializes_without_new_fields() {
        let json = r#"{
            "daily_spend_usd": "5.00",
            "monthly_spend_usd": "50.00",
            "date": "2026-04-30"
        }"#;
        let resp: CostResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.daily_spend_usd, "5.00");
        assert!(resp.daily_limit_usd.is_none());
        assert!(resp.monthly_limit_usd.is_none());
        assert!(resp.per_agent.is_empty());
    }
}
