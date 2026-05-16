//! Agent management endpoints.

use std::collections::BTreeMap;

use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::{Extension, Json};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use aa_gateway::registry::OrphanMode;

use crate::error::ProblemDetail;
use crate::pagination::{PaginatedResponse, PaginationParams};
use crate::state::AppState;

/// Parse a hex-encoded agent ID string into a 16-byte array.
fn parse_agent_id(id: &str) -> Result<[u8; 16], ProblemDetail> {
    let bytes: Vec<u8> = (0..id.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&id[i..i + 2], 16))
        .collect::<Result<Vec<u8>, _>>()
        .map_err(|_| {
            ProblemDetail::from_status(StatusCode::BAD_REQUEST).with_detail(format!("Invalid agent ID format: {id}"))
        })?;

    let arr: [u8; 16] = bytes.try_into().map_err(|_| {
        ProblemDetail::from_status(StatusCode::BAD_REQUEST)
            .with_detail(format!("Agent ID must be 32 hex characters: {id}"))
    })?;

    Ok(arr)
}

/// Convert an [`AgentRecord`] into an [`AgentResponse`].
fn record_to_response(r: aa_gateway::registry::AgentRecord) -> AgentResponse {
    let active_sessions = r
        .active_sessions
        .into_iter()
        .map(|s| ActiveSessionResponse {
            session_id: s.session_id,
            started_at: s.started_at.to_rfc3339(),
            status: s.status,
        })
        .collect();

    let recent_events = r
        .recent_events
        .into_iter()
        .map(|e| RecentEventResponse {
            event_type: e.event_type,
            summary: e.summary,
            timestamp: e.timestamp.to_rfc3339(),
        })
        .collect();

    let recent_traces = r
        .recent_traces
        .into_iter()
        .map(|t| RecentTraceResponse {
            session_id: t.session_id,
            timestamp: t.timestamp.to_rfc3339(),
        })
        .collect();

    AgentResponse {
        id: r.agent_id.iter().map(|b| format!("{b:02x}")).collect::<String>(),
        name: r.name,
        framework: r.framework,
        version: r.version,
        status: format!("{:?}", r.status),
        tool_names: r.tool_names,
        metadata: r.metadata,
        pid: r.pid,
        session_count: r.session_count,
        last_event: r.last_event.map(|t| t.to_rfc3339()),
        policy_violations_count: r.policy_violations_count,
        active_sessions,
        recent_events,
        recent_traces,
        layer: r.layer,
    }
}

/// JSON representation of an agent returned by the API.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct AgentResponse {
    /// Hex-encoded agent UUID.
    pub id: String,
    /// Human-readable agent name.
    pub name: String,
    /// Agent framework (e.g. "langgraph", "crewai").
    pub framework: String,
    /// Semver version string.
    pub version: String,
    /// Current runtime status.
    pub status: String,
    /// Tools declared at registration.
    pub tool_names: Vec<String>,
    /// Arbitrary metadata key-value pairs.
    pub metadata: BTreeMap<String, String>,
    /// OS process ID, if known.
    pub pid: Option<u32>,
    /// Number of sessions handled.
    pub session_count: u32,
    /// ISO 8601 timestamp of the most recent event.
    pub last_event: Option<String>,
    /// Number of policy violations recorded.
    pub policy_violations_count: u32,
    /// Currently active sessions for this agent.
    pub active_sessions: Vec<ActiveSessionResponse>,
    /// Most recent events emitted by this agent.
    pub recent_events: Vec<RecentEventResponse>,
    /// Most recent trace session IDs for this agent.
    pub recent_traces: Vec<RecentTraceResponse>,
    /// Governance layer this agent is assigned to (e.g. "advisory", "enforced").
    pub layer: Option<String>,
}

/// Summary of an active session in the API response.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ActiveSessionResponse {
    /// Hex-encoded session UUID.
    pub session_id: String,
    /// ISO 8601 timestamp when the session started.
    pub started_at: String,
    /// Current status of the session.
    pub status: String,
}

/// Summary of a recent event in the API response.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct RecentEventResponse {
    /// Event type classification (e.g. "violation", "approval", "budget").
    pub event_type: String,
    /// Short human-readable summary.
    pub summary: String,
    /// ISO 8601 timestamp when the event occurred.
    pub timestamp: String,
}

/// Summary of a recent trace session for an agent.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct RecentTraceResponse {
    /// Hex-encoded session UUID, usable with `aasm trace <session-id>`.
    pub session_id: String,
    /// ISO 8601 timestamp when the trace session started.
    pub timestamp: String,
}

/// Request body for `POST /api/v1/agents/:id/suspend`.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct SuspendRequest {
    /// Reason for suspending the agent (logged for audit).
    pub reason: String,
}

/// Response from `POST /api/v1/agents/:id/suspend`.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct SuspendResponse {
    /// Hex-encoded agent UUID.
    pub agent_id: String,
    /// Agent status before the suspend operation.
    pub previous_status: String,
    /// Agent status after the suspend operation.
    pub new_status: String,
}

/// Response from `POST /api/v1/agents/:id/resume`.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ResumeResponse {
    /// Hex-encoded agent UUID.
    pub agent_id: String,
    /// Agent status before the resume operation.
    pub previous_status: String,
    /// Agent status after the resume operation.
    pub new_status: String,
}

/// `GET /api/v1/agents` — list all registered agents with pagination.
///
/// Returns a paginated list of all agents currently known to the registry.
#[utoipa::path(
    get,
    path = "/api/v1/agents",

    params(PaginationParams),
    responses(
        (status = 200, description = "Paginated list of agents", body = Vec<AgentResponse>)
    ),
    tag = "agents"
)]
pub async fn list_agents(
    Extension(state): Extension<AppState>,
    axum::extract::Query(params): axum::extract::Query<PaginationParams>,
) -> impl IntoResponse {
    let all = state.agent_registry.list();
    let total = all.len() as u64;
    let offset = params.offset();
    let per_page = params.per_page();

    let items: Vec<AgentResponse> = all
        .into_iter()
        .skip(offset)
        .take(per_page as usize)
        .map(record_to_response)
        .collect();

    (
        StatusCode::OK,
        Json(PaginatedResponse {
            items,
            page: params.page(),
            per_page,
            total,
        }),
    )
}

/// `GET /api/v1/agents/:id` — inspect a specific agent by ID.
///
/// Retrieve details of a specific agent by its hex-encoded UUID.
#[utoipa::path(
    get,
    path = "/api/v1/agents/{id}",

    params(("id" = String, Path, description = "Hex-encoded agent UUID")),
    responses(
        (status = 200, description = "Agent details", body = AgentResponse),
        (status = 400, description = "Invalid agent ID format"),
        (status = 404, description = "Agent not found")
    ),
    tag = "agents"
)]
pub async fn get_agent(
    Extension(state): Extension<AppState>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<(StatusCode, Json<AgentResponse>), ProblemDetail> {
    let agent_id = parse_agent_id(&id)?;

    let record = state.agent_registry.get(&agent_id).ok_or_else(|| {
        ProblemDetail::from_status(StatusCode::NOT_FOUND).with_detail(format!("Agent not found: {id}"))
    })?;

    Ok((StatusCode::OK, Json(record_to_response(record))))
}

/// `DELETE /api/v1/agents/:id` — deregister (kill) an agent.
///
/// Deregister and terminate the agent process.
#[utoipa::path(
    delete,
    path = "/api/v1/agents/{id}",

    params(("id" = String, Path, description = "Hex-encoded agent UUID")),
    responses(
        (status = 204, description = "Agent deregistered"),
        (status = 400, description = "Invalid agent ID format"),
        (status = 404, description = "Agent not found")
    ),
    tag = "agents"
)]
pub async fn delete_agent(
    Extension(state): Extension<AppState>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<StatusCode, ProblemDetail> {
    let agent_id = parse_agent_id(&id)?;

    state
        .agent_registry
        .deregister(&agent_id, OrphanMode::Suspend)
        .map_err(|_| ProblemDetail::from_status(StatusCode::NOT_FOUND).with_detail(format!("Agent not found: {id}")))?;

    Ok(StatusCode::NO_CONTENT)
}

/// `POST /api/v1/agents/:id/suspend` — suspend an agent.
///
/// Suspend a running agent with a reason logged for audit.
#[utoipa::path(
    post,
    path = "/api/v1/agents/{id}/suspend",

    params(("id" = String, Path, description = "Hex-encoded agent UUID")),
    request_body = SuspendRequest,
    responses(
        (status = 200, description = "Agent suspended", body = SuspendResponse),
        (status = 400, description = "Invalid agent ID format"),
        (status = 404, description = "Agent not found")
    ),
    tag = "agents"
)]
pub async fn suspend_agent(
    Extension(state): Extension<AppState>,
    axum::extract::Path(id): axum::extract::Path<String>,
    Json(body): Json<SuspendRequest>,
) -> Result<(StatusCode, Json<SuspendResponse>), ProblemDetail> {
    let agent_id = parse_agent_id(&id)?;

    let previous_status = state
        .agent_registry
        .agent_status(&agent_id)
        .map(|s| format!("{s:?}"))
        .map_err(|_| ProblemDetail::from_status(StatusCode::NOT_FOUND).with_detail(format!("Agent not found: {id}")))?;

    state
        .agent_registry
        .suspend_and_notify(&agent_id, aa_gateway::registry::SuspendReason::Manual, &body.reason)
        .await
        .map_err(|_| ProblemDetail::from_status(StatusCode::NOT_FOUND).with_detail(format!("Agent not found: {id}")))?;

    Ok((
        StatusCode::OK,
        Json(SuspendResponse {
            agent_id: id,
            previous_status,
            new_status: "Suspended(Manual)".to_string(),
        }),
    ))
}

/// `POST /api/v1/agents/:id/resume` — resume a suspended agent.
///
/// Resume an agent that was previously suspended back to Active status.
#[utoipa::path(
    post,
    path = "/api/v1/agents/{id}/resume",

    params(("id" = String, Path, description = "Hex-encoded agent UUID")),
    responses(
        (status = 200, description = "Agent resumed", body = ResumeResponse),
        (status = 400, description = "Invalid agent ID format"),
        (status = 404, description = "Agent not found")
    ),
    tag = "agents"
)]
pub async fn resume_agent(
    Extension(state): Extension<AppState>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<(StatusCode, Json<ResumeResponse>), ProblemDetail> {
    let agent_id = parse_agent_id(&id)?;

    let previous_status = state
        .agent_registry
        .agent_status(&agent_id)
        .map(|s| format!("{s:?}"))
        .map_err(|_| ProblemDetail::from_status(StatusCode::NOT_FOUND).with_detail(format!("Agent not found: {id}")))?;

    state
        .agent_registry
        .resume_agent(&agent_id)
        .map_err(|_| ProblemDetail::from_status(StatusCode::NOT_FOUND).with_detail(format!("Agent not found: {id}")))?;

    Ok((
        StatusCode::OK,
        Json(ResumeResponse {
            agent_id: id,
            previous_status,
            new_status: "Active".to_string(),
        }),
    ))
}

/// Per-scope contribution to an agent's effective permissions.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PermissionSourceResponse {
    /// Wire-format scope label (e.g. `"global"`, `"team:platform"`).
    pub scope: String,
    /// Capability identifiers this scope explicitly allows.
    pub allow: Vec<String>,
    /// Capability identifiers this scope explicitly denies.
    pub deny: Vec<String>,
}

/// Effective permission set for an agent, with cascade provenance.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct EffectivePermissionsResponse {
    /// Capabilities allowed after merging the cascade (most-restrictive-wins).
    pub allow: Vec<String>,
    /// Capabilities denied after merging the cascade.
    pub deny: Vec<String>,
    /// Per-scope contribution, in cascade order (broadest → narrowest).
    pub sources: Vec<PermissionSourceResponse>,
}

fn cap_set_to_strings(set: &aa_core::CapabilitySet) -> (Vec<String>, Vec<String>) {
    let allow = set.allow.iter().map(|c| c.to_string()).collect();
    let deny = set.deny.iter().map(|c| c.to_string()).collect();
    (allow, deny)
}

/// `GET /api/v1/agents/:id/capabilities` — effective permissions with provenance.
///
/// Returns the agent's merged `allow`/`deny` capability set plus the per-scope
/// contribution from every policy in its cascade. Used by `aasm policy show
/// <agent_id> --show-permissions` and `aasm topology lineage <agent_id>
/// --show-permissions`, and by the dashboard's inherited-permissions panel.
#[utoipa::path(
    get,
    path = "/api/v1/agents/{id}/capabilities",
    params(("id" = String, Path, description = "Hex-encoded agent UUID")),
    responses(
        (status = 200, description = "Effective permissions", body = EffectivePermissionsResponse),
        (status = 400, description = "Invalid agent ID format"),
        (status = 404, description = "Agent not found"),
    ),
    tag = "agents"
)]
pub async fn get_agent_capabilities(
    Extension(state): Extension<AppState>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<(StatusCode, Json<EffectivePermissionsResponse>), ProblemDetail> {
    let agent_id_bytes = parse_agent_id(&id)?;
    let agent_id = aa_core::identity::AgentId::from_bytes(agent_id_bytes);

    if state.agent_registry.get(&agent_id_bytes).is_none() {
        return Err(ProblemDetail::from_status(StatusCode::NOT_FOUND).with_detail(format!("Agent not found: {id}")));
    }

    let effective = state.policy_engine.effective_permissions(&agent_id);
    let (merged_allow, merged_deny) = cap_set_to_strings(&effective.merged);
    let sources = effective
        .sources
        .into_iter()
        .map(|s| PermissionSourceResponse {
            scope: s.scope,
            allow: s.allow.iter().map(|c| c.to_string()).collect(),
            deny: s.deny.iter().map(|c| c.to_string()).collect(),
        })
        .collect();

    Ok((
        StatusCode::OK,
        Json(EffectivePermissionsResponse {
            allow: merged_allow,
            deny: merged_deny,
            sources,
        }),
    ))
}

/// One budget row in the rollup — agent / team / org / subtree × daily / monthly.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct BudgetRowResponse {
    /// Scope label: `"agent"`, `"team:<id>"`, `"org"`, or `"subtree"`.
    pub scope: String,
    /// Period the row covers: `"daily"`, `"monthly"`, or `"today"` (subtree).
    pub period: String,
    /// Total USD spent in the period (string-encoded Decimal).
    pub spent_usd: String,
    /// Configured limit for the period, if any (string-encoded Decimal).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit_usd: Option<String>,
    /// `limit_usd - spent_usd`, clamped at zero. Omitted when no limit.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remaining_usd: Option<String>,
    /// Spend / limit × 100. Omitted when no limit.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub percent_used: Option<f64>,
}

/// Aggregated budget rollup for an agent across its scope hierarchy.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct BudgetRollupResponse {
    /// Rows ordered narrowest scope first (agent → team → org → subtree).
    pub rows: Vec<BudgetRowResponse>,
}

fn budget_row_to_response(row: aa_gateway::budget::BudgetRow) -> BudgetRowResponse {
    // AAASM-1051 AC: "Format USD using `Decimal::round_dp(2)`". Wire strings
    // always have exactly two decimals; the CLI presentation layer adds
    // thousands separators on top, JSON / YAML consumers get the canonical
    // rounded value so downstream code can re-format as needed.
    let fmt_usd = |d: rust_decimal::Decimal| format!("{:.2}", d.round_dp(2));
    BudgetRowResponse {
        scope: row.scope,
        period: row.period,
        spent_usd: fmt_usd(row.spent_usd),
        limit_usd: row.limit_usd.map(fmt_usd),
        remaining_usd: row.remaining_usd.map(fmt_usd),
        percent_used: row.percent_used,
    }
}

/// `GET /api/v1/agents/:id/budget` — per-scope budget rollup for an agent.
///
/// Returns rows for the agent itself, its team (if it belongs to one), the
/// org / global totals, and its delegation subtree (if it has descendants).
/// Each row carries `spent_usd`, `limit_usd`, `remaining_usd`, and
/// `percent_used` (the latter two omitted when no limit is configured).
/// Backs `aasm policy show <agent_id> --show-budget` (AAASM-1051) and the
/// dashboard's budget-burn surface (AAASM-1055).
#[utoipa::path(
    get,
    path = "/api/v1/agents/{id}/budget",
    params(("id" = String, Path, description = "Hex-encoded agent UUID")),
    responses(
        (status = 200, description = "Budget rollup rows", body = BudgetRollupResponse),
        (status = 400, description = "Invalid agent ID format"),
        (status = 404, description = "Agent not found"),
    ),
    tag = "agents"
)]
pub async fn get_agent_budget(
    Extension(state): Extension<AppState>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<(StatusCode, Json<BudgetRollupResponse>), ProblemDetail> {
    let agent_id_bytes = parse_agent_id(&id)?;
    let agent_id = aa_core::identity::AgentId::from_bytes(agent_id_bytes);

    if state.agent_registry.get(&agent_id_bytes).is_none() {
        return Err(ProblemDetail::from_status(StatusCode::NOT_FOUND).with_detail(format!("Agent not found: {id}")));
    }

    let lineage = state.agent_registry.lineage(&agent_id_bytes);
    let team_id = lineage.as_ref().and_then(|l| l.team_id.as_deref());
    let descendants = state.agent_registry.descendants_of(&agent_id_bytes);

    let rollup = aa_gateway::budget::compute_budget_rollup(
        &agent_id,
        team_id,
        state.budget_tracker.as_ref(),
        &descendants,
        None,
        None,
    );

    let rows = rollup.rows.into_iter().map(budget_row_to_response).collect();

    Ok((StatusCode::OK, Json(BudgetRollupResponse { rows })))
}

// ---------------------------------------------------------------------------
// Subtree-burn (AAASM-1055 / F100)
// ---------------------------------------------------------------------------

/// Per-direct-child contribution to a single day's subtree spend.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ChildSpendResponse {
    /// Hex-encoded child agent ID.
    pub child_agent_id: String,
    /// Display name of the child agent.
    pub child_name: String,
    /// USD spent by this child on the given date (string-encoded Decimal).
    pub spent_usd: String,
}

/// One point in the subtree-burn time series.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DailyBurnPointResponse {
    /// ISO 8601 calendar date (YYYY-MM-DD) the point covers.
    pub date: String,
    /// Per-direct-child contributions, ordered by child agent ID for stability.
    pub per_child: Vec<ChildSpendResponse>,
    /// Total subtree spend for the date (root + descendants, string-encoded Decimal).
    pub total_usd: String,
}

/// Response for `GET /api/v1/agents/{id}/subtree-burn`.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct SubtreeBurnResponse {
    /// Hex-encoded root agent ID.
    pub agent_id: String,
    /// Requested period: `"7d"` or `"30d"`.
    pub period: String,
    /// Time series, ordered oldest → newest.
    pub points: Vec<DailyBurnPointResponse>,
}

#[derive(Debug, Deserialize, utoipa::IntoParams)]
pub struct SubtreeBurnParams {
    /// Period string: `7d` (default) or `30d`.
    pub period: Option<String>,
}

fn parse_subtree_burn_period(s: Option<&str>) -> &'static str {
    match s {
        Some("30d") => "30d",
        _ => "7d",
    }
}

/// `GET /api/v1/agents/{id}/subtree-burn` — per-direct-child subtree spend time series.
///
/// **Current behaviour (preview)**: returns a single data point for today
/// only. The wire schema accepts and echoes back the `period=7d|30d`
/// parameter so consumers can pin a contract, but real per-day historical
/// aggregation requires a daily-spend history store that does not yet
/// exist in `aa-gateway::budget`. A follow-up Subtask will extend the
/// tracker with persistent history and populate the full series; the
/// dashboard chart already handles `points.len() >= 1` so it will pick
/// up the additional points without any frontend change.
///
/// Each child's spend is read from `BudgetTracker::agent_state` for the
/// agent's direct descendants (via `AgentRegistry::children_of`). The
/// agent's own spend is included as a synthetic `child_name: "(self)"`
/// row when the root has its own recorded spend, so the stack adds up to
/// the subtree total.
#[utoipa::path(
    get,
    path = "/api/v1/agents/{id}/subtree-burn",
    params(
        ("id" = String, Path, description = "Hex-encoded agent UUID"),
        SubtreeBurnParams,
    ),
    responses(
        (status = 200, description = "Subtree-burn time series", body = SubtreeBurnResponse),
        (status = 400, description = "Invalid agent ID format"),
        (status = 404, description = "Agent not found"),
    ),
    tag = "agents"
)]
pub async fn get_agent_subtree_burn(
    Extension(state): Extension<AppState>,
    axum::extract::Path(id): axum::extract::Path<String>,
    axum::extract::Query(params): axum::extract::Query<SubtreeBurnParams>,
) -> Result<(StatusCode, Json<SubtreeBurnResponse>), ProblemDetail> {
    let agent_id_bytes = parse_agent_id(&id)?;
    let agent_id = aa_core::identity::AgentId::from_bytes(agent_id_bytes);

    if state.agent_registry.get(&agent_id_bytes).is_none() {
        return Err(ProblemDetail::from_status(StatusCode::NOT_FOUND).with_detail(format!("Agent not found: {id}")));
    }

    let period = parse_subtree_burn_period(params.period.as_deref());

    let mut per_child: Vec<ChildSpendResponse> = Vec::new();
    let mut total = rust_decimal::Decimal::ZERO;

    if let Some(root_state) = state.budget_tracker.agent_state(&agent_id) {
        if root_state.spent_usd > rust_decimal::Decimal::ZERO {
            per_child.push(ChildSpendResponse {
                child_agent_id: hex::encode(agent_id.as_bytes()),
                child_name: "(self)".to_string(),
                spent_usd: root_state.spent_usd.to_string(),
            });
            total += root_state.spent_usd;
        }
    }

    let mut children = state.agent_registry.children_of(&agent_id_bytes);
    children.sort();
    for child_id_bytes in children {
        let child_id = aa_core::identity::AgentId::from_bytes(child_id_bytes);
        let child_state = match state.budget_tracker.agent_state(&child_id) {
            Some(s) => s,
            None => continue,
        };
        let child_name = state
            .agent_registry
            .get(&child_id_bytes)
            .map(|rec| rec.name)
            .unwrap_or_else(|| hex::encode(child_id_bytes));
        per_child.push(ChildSpendResponse {
            child_agent_id: hex::encode(child_id_bytes),
            child_name,
            spent_usd: child_state.spent_usd.to_string(),
        });
        total += child_state.spent_usd;
    }

    let today = chrono::Utc::now().date_naive().to_string();
    let point = DailyBurnPointResponse {
        date: today,
        per_child,
        total_usd: total.to_string(),
    };

    Ok((
        StatusCode::OK,
        Json(SubtreeBurnResponse {
            agent_id: hex::encode(agent_id.as_bytes()),
            period: period.to_string(),
            points: vec![point],
        }),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suspend_request_deserializes() {
        let json = r#"{"reason":"anomaly spike, under investigation"}"#;
        let req: SuspendRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.reason, "anomaly spike, under investigation");
    }

    #[test]
    fn suspend_response_serializes() {
        let resp = SuspendResponse {
            agent_id: "aabbccdd00112233".to_string(),
            previous_status: "Active".to_string(),
            new_status: "Suspended(Manual)".to_string(),
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["agent_id"], "aabbccdd00112233");
        assert_eq!(json["previous_status"], "Active");
        assert_eq!(json["new_status"], "Suspended(Manual)");
    }

    #[test]
    fn resume_response_serializes() {
        let resp = ResumeResponse {
            agent_id: "aabbccdd00112233".to_string(),
            previous_status: "Suspended(Manual)".to_string(),
            new_status: "Active".to_string(),
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["agent_id"], "aabbccdd00112233");
        assert_eq!(json["previous_status"], "Suspended(Manual)");
        assert_eq!(json["new_status"], "Active");
    }
}
