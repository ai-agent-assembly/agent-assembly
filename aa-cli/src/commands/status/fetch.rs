//! Data composition — transform API responses into display models.

use chrono::Utc;

use super::client::StatusClient;
use super::models::{
    AgentResponse, AgentRow, ApprovalResponse, ApprovalsSummary, BudgetRow, CostResponse, HealthResponse,
    RuntimeHealth, StatusSnapshot,
};

/// Convert a health API response into a display-ready `RuntimeHealth`.
pub fn build_runtime_health(resp: Option<HealthResponse>) -> RuntimeHealth {
    match resp {
        Some(h) => RuntimeHealth {
            reachable: true,
            status: h.status,
            uptime_secs: h.uptime_secs,
            active_connections: h.active_connections,
            pipeline_lag_ms: h.pipeline_lag_ms,
        },
        None => RuntimeHealth {
            reachable: false,
            status: "unreachable".to_string(),
            uptime_secs: 0,
            active_connections: 0,
            pipeline_lag_ms: 0,
        },
    }
}

/// Convert API agent responses into display-ready rows.
pub fn build_agent_rows(agents: Vec<AgentResponse>) -> Vec<AgentRow> {
    agents
        .into_iter()
        .map(|a| {
            let event_type = a.recent_events.first().map(|e| e.event_type.as_str());
            let last_event = format_last_event(a.last_event.as_deref(), event_type);
            AgentRow {
                id: a.id,
                name: a.name,
                framework: a.framework,
                status: a.status,
                sessions: a.session_count,
                violations_today: a.policy_violations_count,
                last_event,
                layer: a.layer.unwrap_or_else(|| "-".to_string()),
            }
        })
        .collect()
}

/// Compute approvals summary from the raw approval list.
pub fn build_approvals_summary(approvals: &[ApprovalResponse]) -> ApprovalsSummary {
    let pending: Vec<&ApprovalResponse> = approvals.iter().filter(|a| a.status == "pending").collect();
    let pending_count = pending.len();

    let oldest_pending_age = pending
        .iter()
        .filter_map(|a| chrono::DateTime::parse_from_rfc3339(&a.created_at).ok())
        .min()
        .map(|oldest| {
            let age = Utc::now().signed_duration_since(oldest);
            format_duration(age)
        });

    ApprovalsSummary {
        pending_count,
        oldest_pending_age,
    }
}

/// Fetch all status data from the gateway in parallel and compose a `StatusSnapshot`.
pub async fn fetch_all(client: &StatusClient) -> StatusSnapshot {
    let (health_result, agents_result, approvals_result, costs_result) = tokio::join!(
        client.check_health(),
        client.list_agents(),
        client.list_approvals(),
        client.get_costs(),
    );

    let runtime = build_runtime_health(health_result.ok());
    let agents = build_agent_rows(agents_result.unwrap_or_default());
    let approvals = build_approvals_summary(&approvals_result.unwrap_or_default());
    let budget = match costs_result {
        Ok(c) => build_budget_row(c),
        Err(_) => BudgetRow {
            daily_spend_usd: "--".to_string(),
            monthly_spend_usd: None,
            daily_limit_usd: None,
            monthly_limit_usd: None,
            date: "--".to_string(),
            per_agent: vec![],
        },
    };

    StatusSnapshot {
        runtime,
        agents,
        approvals,
        budget,
    }
}

/// Convert cost API response into a display-ready `BudgetRow`.
pub fn build_budget_row(cost: CostResponse) -> BudgetRow {
    BudgetRow {
        daily_spend_usd: cost.daily_spend_usd,
        monthly_spend_usd: cost.monthly_spend_usd,
        daily_limit_usd: cost.daily_limit_usd,
        monthly_limit_usd: cost.monthly_limit_usd,
        date: cost.date,
        per_agent: cost.per_agent,
    }
}

/// Combine a relative timestamp with the latest event type for display.
///
/// Returns `"-"` when no timestamp is available.
/// Examples: `"2m ago tool_call"`, `"1h ago violation"`, `"just now"`.
pub fn format_last_event(iso_timestamp: Option<&str>, event_type: Option<&str>) -> String {
    let relative = format_relative_time(iso_timestamp);
    if relative == "-" {
        return relative;
    }
    match event_type {
        Some(et) => format!("{relative} {et}"),
        None => relative,
    }
}

/// Format an optional ISO 8601 timestamp as a compact relative time string.
///
/// Returns `"-"` when the input is `None` or unparseable.
/// Examples: `"just now"`, `"2m ago"`, `"1h ago"`, `"3d ago"`.
pub fn format_relative_time(iso_timestamp: Option<&str>) -> String {
    let ts = match iso_timestamp {
        Some(s) => match chrono::DateTime::parse_from_rfc3339(s) {
            Ok(dt) => dt,
            Err(_) => return "-".to_string(),
        },
        None => return "-".to_string(),
    };

    let age = Utc::now().signed_duration_since(ts);
    let total_secs = age.num_seconds();

    if total_secs < 60 {
        "just now".to_string()
    } else if total_secs < 3600 {
        format!("{}m ago", total_secs / 60)
    } else if total_secs < 86400 {
        format!("{}h ago", total_secs / 3600)
    } else {
        format!("{}d ago", total_secs / 86400)
    }
}

/// Format a chrono duration into a human-readable string (e.g. `"2h 15m"`).
fn format_duration(dur: chrono::Duration) -> String {
    let total_secs = dur.num_seconds().max(0);
    let days = total_secs / 86400;
    let hours = (total_secs % 86400) / 3600;
    let minutes = (total_secs % 3600) / 60;

    if days > 0 {
        format!("{days}d {hours}h")
    } else if hours > 0 {
        format!("{hours}h {minutes}m")
    } else {
        format!("{minutes}m")
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::super::models::RecentEventResponse;
    use super::*;

    #[test]
    fn build_runtime_health_reachable() {
        let resp = Some(HealthResponse {
            status: "ok".to_string(),
            uptime_secs: 120,
            active_connections: 3,
            pipeline_lag_ms: 5,
        });
        let health = build_runtime_health(resp);
        assert!(health.reachable);
        assert_eq!(health.status, "ok");
        assert_eq!(health.uptime_secs, 120);
        assert_eq!(health.active_connections, 3);
        assert_eq!(health.pipeline_lag_ms, 5);
    }

    #[test]
    fn build_runtime_health_unreachable() {
        let health = build_runtime_health(None);
        assert!(!health.reachable);
        assert_eq!(health.status, "unreachable");
        assert_eq!(health.uptime_secs, 0);
        assert_eq!(health.active_connections, 0);
        assert_eq!(health.pipeline_lag_ms, 0);
    }

    #[test]
    fn build_agent_rows_maps_fields() {
        let agents = vec![AgentResponse {
            id: "abc".to_string(),
            name: "test-agent".to_string(),
            framework: "langgraph".to_string(),
            version: "1.0.0".to_string(),
            status: "Running".to_string(),
            tool_names: vec!["tool_a".to_string()],
            metadata: BTreeMap::new(),
            session_count: 3,
            policy_violations_count: 1,
            layer: Some("advisory".to_string()),
            last_event: Some("2026-05-01T08:00:00Z".to_string()),
            recent_events: vec![RecentEventResponse {
                event_type: "tool_call".to_string(),
                summary: "called bash".to_string(),
                timestamp: "2026-05-01T08:00:00Z".to_string(),
            }],
        }];
        let rows = build_agent_rows(agents);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].id, "abc");
        assert_eq!(rows[0].name, "test-agent");
        assert_eq!(rows[0].framework, "langgraph");
        assert_eq!(rows[0].status, "Running");
        assert_eq!(rows[0].sessions, 3);
        assert_eq!(rows[0].violations_today, 1);
        // last_event should contain both relative time and event type
        assert!(rows[0].last_event.contains("tool_call"));
        assert_ne!(rows[0].last_event, "-");
        assert_eq!(rows[0].layer, "advisory");
    }

    #[test]
    fn build_agent_rows_defaults_layer_when_none() {
        let agents = vec![AgentResponse {
            id: "def".to_string(),
            name: "no-layer-agent".to_string(),
            framework: "custom".to_string(),
            version: "0.1.0".to_string(),
            status: "Active".to_string(),
            tool_names: vec![],
            metadata: BTreeMap::new(),
            session_count: 0,
            policy_violations_count: 0,
            layer: None,
            last_event: None,
            recent_events: vec![],
        }];
        let rows = build_agent_rows(agents);
        assert_eq!(rows[0].last_event, "-");
        assert_eq!(rows[0].layer, "-");
    }

    #[test]
    fn build_approvals_summary_with_pending() {
        let approvals = vec![
            ApprovalResponse {
                id: "ap-1".to_string(),
                agent_id: "a1".to_string(),
                action: "refund".to_string(),
                reason: "amount".to_string(),
                status: "pending".to_string(),
                created_at: "2026-04-30T08:00:00Z".to_string(),
                team_id: String::new(),
                routing_status: String::new(),
            },
            ApprovalResponse {
                id: "ap-2".to_string(),
                agent_id: "a2".to_string(),
                action: "delete".to_string(),
                reason: "test".to_string(),
                status: "approved".to_string(),
                created_at: "2026-04-30T07:00:00Z".to_string(),
                team_id: String::new(),
                routing_status: String::new(),
            },
        ];
        let summary = build_approvals_summary(&approvals);
        assert_eq!(summary.pending_count, 1);
        assert!(summary.oldest_pending_age.is_some());
    }

    #[test]
    fn build_approvals_summary_no_pending() {
        let approvals = vec![ApprovalResponse {
            id: "ap-1".to_string(),
            agent_id: "a1".to_string(),
            action: "refund".to_string(),
            reason: "done".to_string(),
            status: "approved".to_string(),
            created_at: "2026-04-30T08:00:00Z".to_string(),
            team_id: String::new(),
            routing_status: String::new(),
        }];
        let summary = build_approvals_summary(&approvals);
        assert_eq!(summary.pending_count, 0);
        assert!(summary.oldest_pending_age.is_none());
    }

    #[test]
    fn format_relative_time_none_returns_dash() {
        assert_eq!(format_relative_time(None), "-");
    }

    #[test]
    fn format_relative_time_invalid_returns_dash() {
        assert_eq!(format_relative_time(Some("not-a-timestamp")), "-");
    }

    #[test]
    fn format_relative_time_just_now() {
        let now = Utc::now().to_rfc3339();
        assert_eq!(format_relative_time(Some(&now)), "just now");
    }

    #[test]
    fn format_relative_time_minutes_ago() {
        let ts = (Utc::now() - chrono::Duration::minutes(5)).to_rfc3339();
        assert_eq!(format_relative_time(Some(&ts)), "5m ago");
    }

    #[test]
    fn format_relative_time_hours_ago() {
        let ts = (Utc::now() - chrono::Duration::hours(3)).to_rfc3339();
        assert_eq!(format_relative_time(Some(&ts)), "3h ago");
    }

    #[test]
    fn format_relative_time_days_ago() {
        let ts = (Utc::now() - chrono::Duration::days(2)).to_rfc3339();
        assert_eq!(format_relative_time(Some(&ts)), "2d ago");
    }

    #[test]
    fn format_duration_minutes_only() {
        let dur = chrono::Duration::minutes(5);
        assert_eq!(format_duration(dur), "5m");
    }

    #[test]
    fn format_duration_hours_and_minutes() {
        let dur = chrono::Duration::hours(2) + chrono::Duration::minutes(15);
        assert_eq!(format_duration(dur), "2h 15m");
    }

    #[test]
    fn format_duration_days() {
        let dur = chrono::Duration::days(1) + chrono::Duration::hours(3);
        assert_eq!(format_duration(dur), "1d 3h");
    }

    #[test]
    fn format_last_event_none_timestamp_returns_dash() {
        assert_eq!(format_last_event(None, Some("tool_call")), "-");
    }

    #[test]
    fn format_last_event_with_event_type() {
        let ts = (Utc::now() - chrono::Duration::minutes(2)).to_rfc3339();
        assert_eq!(format_last_event(Some(&ts), Some("tool_call")), "2m ago tool_call");
    }

    #[test]
    fn format_last_event_without_event_type() {
        let ts = (Utc::now() - chrono::Duration::minutes(5)).to_rfc3339();
        assert_eq!(format_last_event(Some(&ts), None), "5m ago");
    }

    #[test]
    fn format_last_event_just_now_with_event_type() {
        let ts = Utc::now().to_rfc3339();
        assert_eq!(format_last_event(Some(&ts), Some("violation")), "just now violation");
    }
}
