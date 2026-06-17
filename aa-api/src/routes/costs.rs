//! Cost and budget summary endpoints.

use axum::http::StatusCode;
use axum::{Extension, Json};
use serde::Serialize;
use utoipa::ToSchema;

use crate::auth::scope::{RequireRead, Scope};
use crate::state::AppState;

/// Per-agent cost entry within the budget summary.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct AgentCostEntry {
    /// Agent identifier (hex-encoded).
    pub agent_id: String,
    /// Daily spend for this agent in USD.
    pub daily_spend_usd: String,
    /// Total spend this month in USD for this agent (if monthly tracking is enabled).
    pub monthly_spend_usd: Option<String>,
    /// Calendar date (YYYY-MM-DD) the daily spend applies to.
    pub date: String,
}

/// Per-team cost entry within the budget summary.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct TeamCostEntry {
    /// Team identifier.
    pub team_id: String,
    /// Daily spend for this team in USD (sum of all member agent spends today).
    pub daily_spend_usd: String,
    /// Total spend this month in USD for this team (if monthly tracking is enabled).
    pub monthly_spend_usd: Option<String>,
    /// Calendar date (YYYY-MM-DD) the daily spend applies to.
    pub date: String,
}

/// JSON representation of the cost/budget summary.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct CostSummary {
    /// Total spend today in USD.
    pub daily_spend_usd: String,
    /// Total spend this month in USD (if monthly tracking is enabled).
    pub monthly_spend_usd: Option<String>,
    /// Calendar date (YYYY-MM-DD) the daily spend applies to.
    pub date: String,
    /// Configured daily budget limit in USD, if set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub daily_limit_usd: Option<String>,
    /// Configured monthly budget limit in USD, if set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub monthly_limit_usd: Option<String>,
    /// Per-agent cost breakdown for the current day.
    #[serde(default)]
    pub per_agent: Vec<AgentCostEntry>,
    /// Per-team cost rollup for the current day.
    #[serde(default)]
    pub per_team: Vec<TeamCostEntry>,
}

/// `GET /api/v1/costs` — cost and budget summary.
///
/// Retrieve the current daily and monthly cost and budget summary,
/// including per-agent breakdown and configured budget limits.
///
/// Per-tenant filtering (AAASM-3139): an admin caller sees every tenant's
/// per-agent and per-team breakdown; a tenant-scoped caller sees only its own
/// team's row; a caller with neither admin scope nor a team scope receives the
/// aggregate totals only, with the breakdowns elided rather than leaking every
/// tenant's spend (the cross-tenant IDOR that AAASM-3126 admin-gated).
#[utoipa::path(
    get,
    path = "/api/v1/costs",
    responses(
        (status = 200, description = "Cost and budget summary", body = CostSummary),
        (status = 401, description = "Missing or invalid credentials"),
    ),
    tag = "costs"
)]
pub async fn get_cost_summary(
    RequireRead(caller): RequireRead,
    Extension(state): Extension<AppState>,
) -> (StatusCode, Json<CostSummary>) {
    let snapshot = state.budget_tracker.snapshot();

    // Per-tenant filtering (AAASM-3139, completing AAASM-3126's deferral):
    // * Admin callers see every tenant's breakdown.
    // * A tenant-scoped caller sees ONLY its own team's row (and no per-agent
    //   breakdown — the snapshot's per-agent list is not keyed by team, so
    //   including it would leak other tenants' agents).
    // * A caller with neither admin scope nor a team scope sees aggregate
    //   totals only — the breakdowns stay empty rather than leaking spend.
    let is_admin = caller.scopes.contains(&Scope::Admin);
    let caller_team = caller.tenant.team_id.as_deref();

    let per_agent: Vec<AgentCostEntry> = if is_admin {
        snapshot
            .per_agent
            .iter()
            .map(|entry| AgentCostEntry {
                agent_id: entry.agent_id_hex.clone(),
                daily_spend_usd: entry.state.spent_usd.to_string(),
                monthly_spend_usd: entry.state.monthly_spent_usd.map(|d| d.to_string()),
                date: entry.state.date.to_string(),
            })
            .collect()
    } else {
        Vec::new()
    };

    let per_team: Vec<TeamCostEntry> = if is_admin || caller_team.is_some() {
        let mut rows: Vec<TeamCostEntry> = snapshot
            .team_budgets
            .iter()
            // Non-admin tenant callers see only their own team's row.
            .filter(|(team_id, _)| is_admin || caller_team == Some(team_id.as_str()))
            .map(|(team_id, state)| TeamCostEntry {
                team_id: team_id.clone(),
                daily_spend_usd: state.spent_usd.to_string(),
                monthly_spend_usd: state.monthly_spent_usd.map(|d| d.to_string()),
                date: state.date.to_string(),
            })
            .collect();
        rows.sort_by(|a, b| a.team_id.cmp(&b.team_id));
        rows
    } else {
        Vec::new()
    };

    let summary = CostSummary {
        daily_spend_usd: snapshot.global.spent_usd.to_string(),
        monthly_spend_usd: snapshot.global.monthly_spent_usd.map(|d| d.to_string()),
        date: snapshot.global.date.to_string(),
        daily_limit_usd: state.budget_tracker.daily_limit_usd().map(|d| d.to_string()),
        monthly_limit_usd: state.budget_tracker.monthly_limit_usd().map(|d| d.to_string()),
        per_agent,
        per_team,
    };

    (StatusCode::OK, Json(summary))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cost_summary_serialization_includes_per_agent() {
        let summary = CostSummary {
            daily_spend_usd: "8.10".to_string(),
            monthly_spend_usd: Some("142.50".to_string()),
            date: "2026-04-30".to_string(),
            daily_limit_usd: Some("100.00".to_string()),
            monthly_limit_usd: Some("2000.00".to_string()),
            per_agent: vec![AgentCostEntry {
                agent_id: "abc123".to_string(),
                daily_spend_usd: "4.10".to_string(),
                monthly_spend_usd: Some("80.00".to_string()),
                date: "2026-04-30".to_string(),
            }],
            per_team: vec![],
        };
        let json = serde_json::to_value(&summary).unwrap();
        assert_eq!(json["per_agent"][0]["agent_id"], "abc123");
        assert_eq!(json["per_agent"][0]["daily_spend_usd"], "4.10");
        assert_eq!(json["daily_limit_usd"], "100.00");
        assert_eq!(json["monthly_limit_usd"], "2000.00");
    }

    #[test]
    fn cost_summary_omits_limits_when_none() {
        let summary = CostSummary {
            daily_spend_usd: "0.00".to_string(),
            monthly_spend_usd: None,
            date: "2026-04-30".to_string(),
            daily_limit_usd: None,
            monthly_limit_usd: None,
            per_agent: vec![],
            per_team: vec![],
        };
        let json = serde_json::to_value(&summary).unwrap();
        assert!(json.get("daily_limit_usd").is_none());
        assert!(json.get("monthly_limit_usd").is_none());
        assert!(json["monthly_spend_usd"].is_null());
    }

    #[test]
    fn cost_summary_backward_compatible_fields_unchanged() {
        let summary = CostSummary {
            daily_spend_usd: "8.10".to_string(),
            monthly_spend_usd: Some("142.50".to_string()),
            date: "2026-04-30".to_string(),
            daily_limit_usd: None,
            monthly_limit_usd: None,
            per_agent: vec![],
            per_team: vec![],
        };
        let json = serde_json::to_value(&summary).unwrap();
        assert_eq!(json["daily_spend_usd"], "8.10");
        assert_eq!(json["monthly_spend_usd"], "142.50");
        assert_eq!(json["date"], "2026-04-30");
    }

    #[test]
    fn cost_summary_serialization_includes_per_team() {
        let summary = CostSummary {
            daily_spend_usd: "12.00".to_string(),
            monthly_spend_usd: None,
            date: "2026-04-30".to_string(),
            daily_limit_usd: None,
            monthly_limit_usd: None,
            per_agent: vec![],
            per_team: vec![TeamCostEntry {
                team_id: "platform".to_string(),
                daily_spend_usd: "12.00".to_string(),
                monthly_spend_usd: None,
                date: "2026-04-30".to_string(),
            }],
        };
        let json = serde_json::to_value(&summary).unwrap();
        assert!(json["per_team"].is_array());
        assert_eq!(json["per_team"][0]["team_id"], "platform");
        assert_eq!(json["per_team"][0]["daily_spend_usd"], "12.00");
        assert!(json["per_team"][0]["monthly_spend_usd"].is_null());
    }
}
