//! Agent management endpoints.

use std::collections::BTreeMap;

use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::{Extension, Json};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use aa_core::audit::AuditEntry;
use aa_gateway::registry::{AgentStatus, OrphanMode};

use crate::auth::scope::{RequireRead, RequireWrite, Scope};
use crate::auth::AuthenticatedCaller;
use crate::error::ProblemDetail;
use crate::pagination::PaginationParams;
use crate::state::AppState;

/// Enforce tenant ownership of an agent for a caller that already cleared the
/// scope gate (AAASM-3726 / AAASM-3687).
///
/// Mirrors the per-tenant authz of [`get_agent_budget`]: an admin may act on any
/// agent; a tenant-scoped caller may act only on agents in its own team; a
/// caller with neither admin scope nor any team scope is denied up front so it
/// cannot enumerate agents via a 403-vs-404 oracle. Returns `Ok(())` when the
/// caller is authorized and the agent exists, otherwise the appropriate
/// `ProblemDetail` (403 for an unauthorized caller, 404 when the agent is
/// unknown to an authorized caller).
fn authorize_agent_access(
    caller: &AuthenticatedCaller,
    state: &AppState,
    agent_id_bytes: &[u8; 16],
    id: &str,
) -> Result<(), ProblemDetail> {
    let is_admin = caller.scopes.contains(&Scope::Admin);
    if !is_admin && caller.tenant.team_id.is_none() {
        return Err(ProblemDetail::from_status(StatusCode::FORBIDDEN)
            .with_detail("This operation requires admin scope or a team scope"));
    }

    if state.agent_registry.get(agent_id_bytes).is_none() {
        return Err(ProblemDetail::from_status(StatusCode::NOT_FOUND).with_detail(format!("Agent not found: {id}")));
    }

    let lineage = state.agent_registry.lineage(agent_id_bytes);
    let team_id = lineage.as_ref().and_then(|l| l.team_id.as_deref());
    let authorized = match team_id {
        Some(team) => caller.can_access_team(team),
        // The agent has no team — only an admin may act on it.
        None => is_admin,
    };
    if !authorized {
        return Err(ProblemDetail::from_status(StatusCode::FORBIDDEN)
            .with_detail("This operation requires admin scope or membership in the agent's team"));
    }
    Ok(())
}

/// Whether a descendant discovered while walking an authorized root's subtree
/// is itself visible to `caller` (AAASM-4841).
///
/// A subtree endpoint authorizes its root once (via [`authorize_agent_access`]),
/// but the root's descendants can be delegated into *other* teams — the same
/// cross-tenant hazard the topology tree closed in AAASM-4819. Emitting such a
/// node's id / name / spend, or folding it into a subtree aggregate, is a
/// cross-tenant IDOR. Gate every descendant on the same team boundary as
/// [`list_agents`] (AAASM-3865): an admin sees all; a team-scoped caller sees
/// only its own team's nodes; a team-less node is admin-only.
fn descendant_visible_to(caller: &AuthenticatedCaller, record: &aa_gateway::registry::AgentRecord) -> bool {
    match record.team_id.as_deref() {
        Some(team) => caller.can_access_team(team),
        None => caller.scopes.contains(&Scope::Admin),
    }
}

/// Parse a hex-encoded agent ID string into a 16-byte array.
///
/// Decodes via [`hex::decode`] rather than slicing the input by byte index: the
/// previous `&id[i..i + 2]` implementation panicked on an odd-length id (index
/// past the end) or a multibyte path segment (a non-char-boundary slice),
/// turning a malformed `{id}` path parameter into a request-thread panic
/// (AAASM-4018). `hex::decode` rejects odd-length and non-hex input with a
/// clean `Err`, so every malformed id now surfaces as a `400` instead.
fn parse_agent_id(id: &str) -> Result<[u8; 16], ProblemDetail> {
    let bytes = hex::decode(id).map_err(|_| {
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

/// A currently-open agent session in the fleet-wide active-sessions listing
/// (AAASM-5038).
///
/// Enriches the per-agent [`ActiveSessionResponse`] with the owning agent's
/// identity so the dashboard Fleet → Active Sessions tab can render one flat,
/// fleet-wide table without a second lookup. `actions_count` / `current_task`
/// from the design mock are deliberately omitted: the registry does not track
/// them per session, and this endpoint only surfaces state that already exists
/// (it must not invent a session store).
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct FleetActiveSessionResponse {
    /// Hex-encoded UUID of the agent that owns the session.
    pub agent_id: String,
    /// Human-readable name of the owning agent.
    pub agent_name: String,
    /// Team the owning agent belongs to, if any.
    pub team_id: Option<String>,
    /// Hex-encoded session UUID.
    pub session_id: String,
    /// ISO 8601 timestamp when the session started.
    pub started_at: String,
    /// Current status of the session (e.g. "running", "idle").
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

/// Paginated `GET /api/v1/agents` body (AAASM-4892).
///
/// A named wrapper (mirroring `PaginatedApprovalResponse`) so the OpenAPI schema
/// `$ref`s `AgentResponse` and matches the `{ items, total }` object the handler
/// actually serializes — not the bare array a generic `Vec<T>` annotation implied.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct PaginatedAgentResponse {
    /// Agents in the current page.
    pub items: Vec<AgentResponse>,
    /// 1-indexed page number echoed from the request.
    pub page: u32,
    /// Items per page echoed from the request.
    pub per_page: u32,
    /// Total agents visible to the caller across all pages.
    pub total: u64,
}

/// `GET /api/v1/agents` — list all registered agents with pagination.
///
/// Returns a paginated list of all agents currently known to the registry.
#[utoipa::path(
    get,
    path = "/api/v1/agents",

    params(PaginationParams),
    responses(
        (status = 200, description = "Paginated list of agents", body = PaginatedAgentResponse)
    ),
    tag = "agents"
)]
pub async fn list_agents(
    RequireRead(caller): RequireRead,
    Extension(state): Extension<AppState>,
    axum::extract::Query(params): axum::extract::Query<PaginationParams>,
) -> impl IntoResponse {
    // AAASM-3865: confine the listing to agents the caller's tenant owns. The
    // single-record sibling `get_agent` gates on `authorize_agent_access`
    // (AAASM-3790); the collection path was missed, letting any authenticated
    // key enumerate every tenant's agents. Filter BEFORE pagination so `total`
    // reflects only the caller's own agents. An admin sees all; a team-scoped
    // caller sees only its team's agents; an agent with no team is visible only
    // to an admin.
    let is_admin = caller.scopes.contains(&Scope::Admin);
    let visible: Vec<_> = state
        .agent_registry
        .list()
        .into_iter()
        .filter(|r| match r.team_id.as_deref() {
            Some(team) => caller.can_access_team(team),
            None => is_admin,
        })
        .collect();
    let total = visible.len() as u64;
    let offset = params.offset();
    let per_page = params.per_page();

    let items: Vec<AgentResponse> = visible
        .into_iter()
        .skip(offset)
        .take(per_page as usize)
        .map(record_to_response)
        .collect();

    (
        StatusCode::OK,
        Json(PaginatedAgentResponse {
            items,
            page: params.page(),
            per_page,
            total,
        }),
    )
}

/// `GET /api/v1/fleet/active-sessions` — list currently-open agent sessions
/// across the whole fleet.
///
/// Read-only observability surface for the dashboard Fleet → Active Sessions tab
/// (AAASM-5038). Flattens the `active_sessions` the registry already tracks on
/// each [`aa_gateway::registry::AgentRecord`] into one fleet-wide list, tagging
/// every session with its owning agent's id, name, and team. Purely derived from
/// existing registry state — it opens, mutates, and closes nothing, so it changes
/// neither session lifecycle nor enforcement.
///
/// Tenant-scoped exactly like [`list_agents`] (AAASM-3865): an admin sees every
/// agent's sessions; a team-scoped caller sees only its own team's; an agent with
/// no team is admin-only. Results are ordered newest-first by `started_at`.
#[utoipa::path(
    get,
    path = "/api/v1/fleet/active-sessions",
    responses(
        (status = 200, description = "Active agent sessions across the fleet", body = Vec<FleetActiveSessionResponse>)
    ),
    tag = "agents"
)]
pub async fn list_active_sessions(
    RequireRead(caller): RequireRead,
    Extension(state): Extension<AppState>,
) -> impl IntoResponse {
    // Same tenant confinement as `list_agents` (AAASM-3865): filter the agents a
    // caller may see BEFORE flattening their sessions, so a team-scoped key can
    // never enumerate another tenant's open sessions.
    let is_admin = caller.scopes.contains(&Scope::Admin);
    let mut sessions: Vec<FleetActiveSessionResponse> = state
        .agent_registry
        .list()
        .into_iter()
        .filter(|r| match r.team_id.as_deref() {
            Some(team) => caller.can_access_team(team),
            None => is_admin,
        })
        .flat_map(|r| {
            let agent_id = r.agent_id.iter().map(|b| format!("{b:02x}")).collect::<String>();
            let agent_name = r.name.clone();
            let team_id = r.team_id.clone();
            r.active_sessions.into_iter().map(move |s| FleetActiveSessionResponse {
                agent_id: agent_id.clone(),
                agent_name: agent_name.clone(),
                team_id: team_id.clone(),
                session_id: s.session_id,
                started_at: s.started_at.to_rfc3339(),
                status: s.status,
            })
        })
        .collect();

    // Newest-first: the dashboard surfaces the most recently started sessions at
    // the top. RFC 3339 UTC timestamps sort lexicographically by instant.
    sessions.sort_by(|a, b| b.started_at.cmp(&a.started_at));

    (StatusCode::OK, Json(sessions))
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
    RequireRead(caller): RequireRead,
    Extension(state): Extension<AppState>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<(StatusCode, Json<AgentResponse>), ProblemDetail> {
    let agent_id = parse_agent_id(&id)?;

    // AAASM-3790: read-scope + tenant ownership before exposing the record.
    // The delete/suspend siblings already gate on `authorize_agent_access`;
    // the read path was missed, letting any caller read any team's agent.
    authorize_agent_access(&caller, &state, &agent_id, &id)?;

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
    RequireWrite(caller): RequireWrite,
    Extension(state): Extension<AppState>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<StatusCode, ProblemDetail> {
    let agent_id = parse_agent_id(&id)?;

    // AAASM-3726: write-scope + tenant ownership before any state change.
    authorize_agent_access(&caller, &state, &agent_id, &id)?;

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
    RequireWrite(caller): RequireWrite,
    Extension(state): Extension<AppState>,
    axum::extract::Path(id): axum::extract::Path<String>,
    Json(body): Json<SuspendRequest>,
) -> Result<(StatusCode, Json<SuspendResponse>), ProblemDetail> {
    let agent_id = parse_agent_id(&id)?;

    // AAASM-3726: write-scope + tenant ownership before suspending.
    authorize_agent_access(&caller, &state, &agent_id, &id)?;

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
    RequireWrite(caller): RequireWrite,
    Extension(state): Extension<AppState>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<(StatusCode, Json<ResumeResponse>), ProblemDetail> {
    let agent_id = parse_agent_id(&id)?;

    // AAASM-3726: write-scope + tenant ownership before resuming.
    authorize_agent_access(&caller, &state, &agent_id, &id)?;

    let current_status = state
        .agent_registry
        .agent_status(&agent_id)
        .map_err(|_| ProblemDetail::from_status(StatusCode::NOT_FOUND).with_detail(format!("Agent not found: {id}")))?;

    if current_status == AgentStatus::Active {
        return Err(ProblemDetail::from_status(StatusCode::CONFLICT)
            .with_detail("Agent is already active; only suspended agents can be resumed"));
    }

    let previous_status = format!("{current_status:?}");

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
    RequireRead(caller): RequireRead,
    Extension(state): Extension<AppState>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<(StatusCode, Json<EffectivePermissionsResponse>), ProblemDetail> {
    let agent_id_bytes = parse_agent_id(&id)?;
    let agent_id = aa_core::identity::AgentId::from_bytes(agent_id_bytes);

    // AAASM-3824: read-scope + tenant ownership before exposing the cascade.
    // Siblings `get_agent` / `get_agent_budget` already gate here; the
    // capabilities path was missed, letting any caller read any team's
    // effective permissions.
    authorize_agent_access(&caller, &state, &agent_id_bytes, &id)?;

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
    RequireRead(caller): RequireRead,
    Extension(state): Extension<AppState>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<(StatusCode, Json<BudgetRollupResponse>), ProblemDetail> {
    // Per-tenant authz (AAASM-3139, completing AAASM-3126's deferral): admin
    // callers may read any agent's budget; a tenant-scoped caller may read only
    // agents that belong to its own team. A caller with neither admin scope nor
    // any team scope can never be authorized — deny it up front, before any
    // existence check, so it cannot enumerate agents via 403-vs-404.
    let is_admin = caller.scopes.contains(&Scope::Admin);
    if !is_admin && caller.tenant.team_id.is_none() {
        return Err(ProblemDetail::from_status(StatusCode::FORBIDDEN)
            .with_detail("Reading an agent's budget rollup requires admin scope or a team scope"));
    }

    let agent_id_bytes = parse_agent_id(&id)?;
    let agent_id = aa_core::identity::AgentId::from_bytes(agent_id_bytes);

    if state.agent_registry.get(&agent_id_bytes).is_none() {
        return Err(ProblemDetail::from_status(StatusCode::NOT_FOUND).with_detail(format!("Agent not found: {id}")));
    }

    let lineage = state.agent_registry.lineage(&agent_id_bytes);
    let team_id = lineage.as_ref().and_then(|l| l.team_id.as_deref());

    // A tenant-scoped (non-admin) caller may only read agents in its own team;
    // the rollup spans the agent's team / org / global totals, so a mismatch is
    // a cross-tenant IDOR.
    let authorized = match team_id {
        Some(team) => caller.can_access_team(team),
        // The agent has no team — only admin may read its (global-scoped) rollup.
        None => is_admin,
    };
    if !authorized {
        return Err(ProblemDetail::from_status(StatusCode::FORBIDDEN)
            .with_detail("Reading this agent's budget rollup requires admin scope or membership in its team"));
    }
    // AAASM-4841: descendants can be delegated into other teams, and
    // `subtree_spend` sums every descendant's spend regardless of team. Without
    // filtering, the "subtree" row would fold a cross-tenant descendant's spend
    // into the aggregate shown to this caller — an aggregate cross-tenant leak
    // of the same class as the per-child subtree-burn IDOR. Confine the subtree
    // to descendants the caller may see (an admin sees all).
    let descendants: Vec<[u8; 16]> = state
        .agent_registry
        .descendants_of(&agent_id_bytes)
        .into_iter()
        .filter(|d| {
            state
                .agent_registry
                .get(d)
                .is_some_and(|rec| descendant_visible_to(&caller, &rec))
        })
        .collect();

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

fn parse_subtree_burn_period(s: Option<&str>) -> (&'static str, u32) {
    match s {
        Some("30d") => ("30d", 30),
        _ => ("7d", 7),
    }
}

/// `GET /api/v1/agents/{id}/subtree-burn` — per-direct-child subtree spend time series.
///
/// Reads `BudgetTracker::agent_spend_history` for the agent itself and each
/// direct descendant from `AgentRegistry::children_of`, then aligns the
/// per-child series day-by-day so the response has one point per day in the
/// requested window (`7d` default, `30d` opt-in). Days with no recorded
/// spend appear with `spent_usd = "0"` for that child rather than being
/// omitted, so the dashboard's stacked area renders without gaps.
///
/// The agent's own spend is included as a synthetic `child_name: "(self)"`
/// row whenever it has any recorded spend across the window, so the stack
/// adds up to the subtree total.
///
/// The history store is in-memory only (not persisted across restarts);
/// the chart will populate progressively as agents accrue spend after
/// the most recent gateway start.
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
    RequireRead(caller): RequireRead,
    Extension(state): Extension<AppState>,
    axum::extract::Path(id): axum::extract::Path<String>,
    axum::extract::Query(params): axum::extract::Query<SubtreeBurnParams>,
) -> Result<(StatusCode, Json<SubtreeBurnResponse>), ProblemDetail> {
    let agent_id_bytes = parse_agent_id(&id)?;
    let agent_id = aa_core::identity::AgentId::from_bytes(agent_id_bytes);

    // AAASM-3687: read-scope + tenant ownership — the subtree-burn series
    // exposes per-child spend / topology, so a cross-tenant caller must not
    // read another team's agent. Mirrors get_agent_budget.
    authorize_agent_access(&caller, &state, &agent_id_bytes, &id)?;

    let (period_label, period_days) = parse_subtree_burn_period(params.period.as_deref());

    // Materialise the per-child history grids once, then transpose into
    // per-day points. Each grid entry shares the same date sequence (the
    // tracker zero-fills any day with no spend), so the dates align across
    // children for stable stacking on the dashboard chart.
    struct ChildGrid {
        agent_id_hex: String,
        name: String,
        series: Vec<(chrono::NaiveDate, rust_decimal::Decimal)>,
    }

    let mut grids: Vec<ChildGrid> = Vec::new();

    // Root's own spend appears first as the synthetic "(self)" row when
    // anything was recorded for it across the window.
    let root_series = state.budget_tracker.agent_spend_history(&agent_id, period_days);
    if root_series
        .iter()
        .any(|(_, amount)| *amount > rust_decimal::Decimal::ZERO)
    {
        grids.push(ChildGrid {
            agent_id_hex: hex::encode(agent_id.as_bytes()),
            name: "(self)".to_string(),
            series: root_series,
        });
    }

    // Direct children, sorted for deterministic stack ordering.
    let mut children = state.agent_registry.children_of(&agent_id_bytes);
    children.sort();
    for child_id_bytes in children {
        let child_id = aa_core::identity::AgentId::from_bytes(child_id_bytes);
        // AAASM-4841: the root was authorized by `authorize_agent_access`, but a
        // direct child may be delegated into another team. Emitting its id /
        // name / daily spend without a per-child tenant check leaks a
        // cross-tenant child, exactly the class AAASM-4819 closed in the
        // topology tree. Omit any child the caller may not see (a missing
        // record is likewise skipped) so the series never crosses the boundary.
        let Some(child_record) = state.agent_registry.get(&child_id_bytes) else {
            continue;
        };
        if !descendant_visible_to(&caller, &child_record) {
            continue;
        }
        let series = state.budget_tracker.agent_spend_history(&child_id, period_days);
        // Skip children with no recorded spend across the entire window — they
        // would render as a flat zero band and add noise to the legend.
        if !series.iter().any(|(_, amount)| *amount > rust_decimal::Decimal::ZERO) {
            continue;
        }
        grids.push(ChildGrid {
            agent_id_hex: hex::encode(child_id_bytes),
            name: child_record.name,
            series,
        });
    }

    // Build the dense per-day point list. If no child ever recorded spend
    // (grids empty), still emit one zero-point per day so the chart shows
    // an empty axis rather than a "no data" placeholder.
    let day_count = if grids.is_empty() {
        period_days as usize
    } else {
        grids[0].series.len()
    };
    let mut points: Vec<DailyBurnPointResponse> = Vec::with_capacity(day_count);
    for day_idx in 0..day_count {
        let date = if let Some(first) = grids.first() {
            first.series[day_idx].0
        } else {
            // No spend ever recorded — synthesise dates from the tracker
            // accessor on the root agent (returns zero-filled today-back).
            state.budget_tracker.agent_spend_history(&agent_id, period_days)[day_idx].0
        };

        let mut per_child: Vec<ChildSpendResponse> = Vec::with_capacity(grids.len());
        let mut total = rust_decimal::Decimal::ZERO;
        for grid in &grids {
            let amount = grid.series[day_idx].1;
            per_child.push(ChildSpendResponse {
                child_agent_id: grid.agent_id_hex.clone(),
                child_name: grid.name.clone(),
                spent_usd: amount.to_string(),
            });
            total += amount;
        }
        points.push(DailyBurnPointResponse {
            date: date.to_string(),
            per_child,
            total_usd: total.to_string(),
        });
    }

    Ok((
        StatusCode::OK,
        Json(SubtreeBurnResponse {
            agent_id: hex::encode(agent_id.as_bytes()),
            period: period_label.to_string(),
            points,
        }),
    ))
}

/// One row of the agent's recent decision stream (AAASM-5058).
///
/// Backs the agent-detail Traffic tab's per-decision table
/// (`design/v1/hi-fi/agent-detail.jsx`), one row per governance decision the
/// gateway recorded for this agent. Every field is read straight from the
/// existing audit log — no enforcement or audit-write path is touched. Columns
/// the audit log has no source for are surfaced as `null` rather than
/// fabricated (see [`AgentDecisionResponse::latency_ms`]).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct AgentDecisionResponse {
    /// Decision timestamp as an RFC 3339 UTC string (audit `timestamp_ns`).
    pub timestamp: String,
    /// Hex-encoded id of the session the decision was recorded under. Lets the
    /// UI link a row to its trace; not part of the visible design columns.
    pub session_id: String,
    /// Per-session monotonic sequence of the audit entry. Combined with
    /// `sessionId` it uniquely identifies the row.
    pub seq: u64,
    /// The recorded action category (audit payload `action_type`, e.g.
    /// `TOOL_CALL` / `FILE_OPERATION`). The design's `verb` column: the audit
    /// log records the action *category*, not a fine-grained read/write verb,
    /// so this is the closest recorded source. `null` when unrecorded.
    pub verb: Option<String>,
    /// The action's primary target derived from the audit `detail` (tool name,
    /// file path, network host, process command, or LLM model). The design's
    /// `resource` column. `null` when the detail carries no resolvable target.
    pub resource: Option<String>,
    /// The policy `decision` as the proto [`Decision`](aa_proto::assembly::common::v1::Decision)
    /// enum's **integer** discriminant, exactly as the gateway writes it (see
    /// the AAASM-5035 note in `analytics::decision_is_error`): `1` = Allow,
    /// `2` = Deny, `3` = Pending, `4` = Redact, `0` = Unspecified.
    pub decision: i64,
    /// Lowercase label derived from `decision` (`allow` / `deny` / `pending` /
    /// `redact` / `unspecified`) so the UI can map to its verdict styling
    /// without re-deriving the enum. Derived, not a separate audit field.
    pub decision_label: String,
    /// The matched policy rule id (audit `policy_rule`, top-level or under
    /// `detail`). The design's `policy` column. `null` when the decision
    /// recorded no rule (e.g. a baseline allow with no matching rule).
    pub matched_policy: Option<String>,
    /// The design's `latency` column. **Always `null`: the audit log records no
    /// per-decision latency today**, so it is surfaced nullable rather than
    /// fabricated. Wired through so the column lands the day a latency source is
    /// added, without another contract change.
    pub latency_ms: Option<u64>,
}

/// Recent per-agent decision stream (AAASM-5058).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct AgentDecisionsResponse {
    /// Decisions newest-first, capped to the request's `limit`.
    pub decisions: Vec<AgentDecisionResponse>,
}

/// Query parameters for the recent-decisions endpoint.
#[derive(Debug, Clone, Deserialize, ToSchema, utoipa::IntoParams)]
pub struct AgentDecisionsParams {
    /// Maximum number of decision rows to return (newest-first). Defaults to
    /// [`DEFAULT_DECISIONS_LIMIT`], clamped to [`MAX_DECISIONS_LIMIT`].
    pub limit: Option<usize>,
}

/// Default number of decision rows returned when `?limit` is omitted.
const DEFAULT_DECISIONS_LIMIT: usize = 50;
/// Upper bound on the `?limit` query parameter.
const MAX_DECISIONS_LIMIT: usize = 500;
/// Upper bound on audit entries scanned per request before filtering to
/// decision-bearing rows. Bounds per-request work the way the analytics reads
/// do (AAASM-4145); a caller that wants more history pages via `limit`.
const MAX_DECISIONS_SCAN: usize = 10_000;

/// Lowercase label for a [`Decision`](aa_proto::assembly::common::v1::Decision)
/// discriminant, used for `decisionLabel`.
fn decision_label(discriminant: i64) -> &'static str {
    use aa_proto::assembly::common::v1::Decision;
    match discriminant {
        d if d == Decision::Allow as i64 => "allow",
        d if d == Decision::Deny as i64 => "deny",
        d if d == Decision::Pending as i64 => "pending",
        d if d == Decision::Redact as i64 => "redact",
        _ => "unspecified",
    }
}

/// Extract the action's primary target from an audit `detail` object, by kind.
/// Returns `None` when the detail carries no resolvable target.
fn resource_from_detail(detail: &serde_json::Value) -> Option<String> {
    let key = match detail.get("kind").and_then(|v| v.as_str())? {
        "tool_call" => "tool_name",
        "file_op" => "path",
        "network_call" => "host",
        "process_exec" => "command",
        "llm_call" => "model",
        "policy_violation" => "blocked_action",
        "approval" => "approval_id",
        _ => return None,
    };
    detail
        .get(key)
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

/// Build a decision row from an audit entry, or `None` when the entry carries
/// no policy `decision` (i.e. it is not a governance decision — e.g. a session
/// lifecycle event).
fn entry_to_decision_row(entry: &AuditEntry) -> Option<AgentDecisionResponse> {
    let payload: serde_json::Value = serde_json::from_str(entry.payload()).ok()?;
    let decision = payload.get("decision").and_then(|v| v.as_i64())?;

    let ts_secs = (entry.timestamp_ns() / 1_000_000_000) as i64;
    let ts_nanos = (entry.timestamp_ns() % 1_000_000_000) as u32;
    let timestamp = chrono::DateTime::from_timestamp(ts_secs, ts_nanos)
        .map(|dt| dt.to_rfc3339())
        .unwrap_or_default();

    let verb = payload
        .get("action_type")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(str::to_string);

    let detail = payload.get("detail");
    let resource = detail.and_then(resource_from_detail);

    // `policy_rule` is written top-level on some paths and under `detail` on
    // others (the violation summary); accept either, preferring the explicit
    // top-level value.
    let matched_policy = payload
        .get("policy_rule")
        .and_then(|v| v.as_str())
        .or_else(|| detail.and_then(|d| d.get("policy_rule")).and_then(|v| v.as_str()))
        .filter(|s| !s.is_empty())
        .map(str::to_string);

    Some(AgentDecisionResponse {
        timestamp,
        session_id: hex::encode(entry.session_id().as_bytes()),
        seq: entry.seq(),
        verb,
        resource,
        decision,
        decision_label: decision_label(decision).to_string(),
        matched_policy,
        // No per-decision latency source exists in the audit log (AAASM-5058);
        // report it honestly as absent rather than inventing a value.
        latency_ms: None,
    })
}

/// `GET /api/v1/agents/:id/decisions` — recent per-agent decision stream.
///
/// Read-only projection of the existing audit log: the agent's most recent
/// governance decisions, newest-first, one row per decision
/// (`design/v1/hi-fi/agent-detail.jsx` Traffic tab). Backs the agent-detail
/// Traffic tab's per-decision table beneath its aggregate summary (AAASM-5058).
///
/// Deny-by-default and tenant-scoped: [`authorize_agent_access`] confines the
/// caller to an agent in its own team (admin sees any; a caller with no team
/// scope is denied before any audit read), so the returned decisions never
/// cross a tenant boundary. Entries carrying no policy `decision` are skipped so
/// the stream is decisions only. No audit-write or enforcement path is touched.
#[utoipa::path(
    get,
    path = "/api/v1/agents/{id}/decisions",
    params(
        ("id" = String, Path, description = "Hex-encoded agent UUID"),
        AgentDecisionsParams,
    ),
    responses(
        (status = 200, description = "Recent per-agent decisions, newest-first", body = AgentDecisionsResponse),
        (status = 400, description = "Invalid agent ID format"),
        (status = 401, description = "Missing or invalid credentials"),
        (status = 403, description = "Caller lacks access to the agent's team"),
        (status = 404, description = "Agent not found"),
    ),
    tag = "agents"
)]
pub async fn get_agent_decisions(
    RequireRead(caller): RequireRead,
    Extension(state): Extension<AppState>,
    axum::extract::Path(id): axum::extract::Path<String>,
    axum::extract::Query(params): axum::extract::Query<AgentDecisionsParams>,
) -> Result<(StatusCode, Json<AgentDecisionsResponse>), ProblemDetail> {
    let agent_id_bytes = parse_agent_id(&id)?;

    // Read-scope + tenant ownership before exposing the agent's decision
    // history — mirrors get_agent_capabilities / get_agent_subtree_burn.
    authorize_agent_access(&caller, &state, &agent_id_bytes, &id)?;

    let limit = params.limit.unwrap_or(DEFAULT_DECISIONS_LIMIT).min(MAX_DECISIONS_LIMIT);

    // `list` returns the agent's entries newest-first (server-side agent
    // filter); scan a bounded page, keep decision-bearing rows, take `limit`.
    let (entries, _total) = state
        .audit_reader
        .list(MAX_DECISIONS_SCAN, 0, Some(&id), None, None)
        .await
        .unwrap_or_default();

    let decisions: Vec<AgentDecisionResponse> = entries.iter().filter_map(entry_to_decision_row).take(limit).collect();

    Ok((StatusCode::OK, Json(AgentDecisionsResponse { decisions })))
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

    // ── AAASM-5058: per-agent decision-row projection ──────────────────────

    fn decision_entry(payload: &str) -> AuditEntry {
        use aa_core::audit::AuditEventType;
        use aa_core::SessionId;
        AuditEntry::new(
            7,
            1_700_000_000_000_000_000,
            AuditEventType::ToolCallIntercepted,
            aa_core::identity::AgentId::from_bytes([0xAB; 16]),
            SessionId::from_bytes([0xEE; 16]),
            payload.to_string(),
            [0u8; 32],
        )
    }

    #[test]
    fn decision_label_maps_each_discriminant() {
        assert_eq!(decision_label(1), "allow");
        assert_eq!(decision_label(2), "deny");
        assert_eq!(decision_label(3), "pending");
        assert_eq!(decision_label(4), "redact");
        assert_eq!(decision_label(0), "unspecified");
        assert_eq!(decision_label(99), "unspecified");
    }

    #[test]
    fn resource_from_detail_extracts_target_per_kind() {
        let cases = [
            (r#"{"kind":"tool_call","tool_name":"gmail.send"}"#, "gmail.send"),
            (r#"{"kind":"file_op","path":"/etc/passwd"}"#, "/etc/passwd"),
            (r#"{"kind":"network_call","host":"api.example.com"}"#, "api.example.com"),
            (r#"{"kind":"process_exec","command":"rm -rf"}"#, "rm -rf"),
            (r#"{"kind":"llm_call","model":"gpt-4"}"#, "gpt-4"),
        ];
        for (json, expected) in cases {
            let detail: serde_json::Value = serde_json::from_str(json).unwrap();
            assert_eq!(resource_from_detail(&detail).as_deref(), Some(expected));
        }
    }

    #[test]
    fn resource_from_detail_none_when_no_target() {
        let detail: serde_json::Value = serde_json::from_str(r#"{"kind":"approval"}"#).unwrap();
        assert_eq!(resource_from_detail(&detail), None);
        let unknown: serde_json::Value = serde_json::from_str(r#"{"kind":"mystery"}"#).unwrap();
        assert_eq!(resource_from_detail(&unknown), None);
    }

    #[test]
    fn entry_to_decision_row_maps_tool_call_fields() {
        let entry = decision_entry(
            r#"{"action_type":"TOOL_CALL","decision":1,"detail":{"kind":"tool_call","tool_name":"pg.users"}}"#,
        );
        let row = entry_to_decision_row(&entry).expect("tool_call carries a decision");
        assert_eq!(row.decision, 1);
        assert_eq!(row.decision_label, "allow");
        assert_eq!(row.verb.as_deref(), Some("TOOL_CALL"));
        assert_eq!(row.resource.as_deref(), Some("pg.users"));
        assert_eq!(row.matched_policy, None);
        // No per-decision latency source exists — it must be reported as absent.
        assert_eq!(row.latency_ms, None);
        assert_eq!(row.seq, 7);
        assert_eq!(row.session_id, "ee".repeat(16));
    }

    #[test]
    fn entry_to_decision_row_skips_entry_without_decision() {
        let entry = decision_entry(r#"{"action_type":"AGENT_SPAWN","detail":{"kind":"spawn"}}"#);
        assert!(entry_to_decision_row(&entry).is_none());
    }

    #[test]
    fn entry_to_decision_row_reads_policy_rule_from_detail_and_top_level() {
        // Violation summary carries policy_rule under `detail`.
        let nested = decision_entry(
            r#"{"action_type":"TOOL_CALL","decision":2,"detail":{"kind":"policy_violation","policy_rule":"P-066","blocked_action":"gmail.send"}}"#,
        );
        let row = entry_to_decision_row(&nested).unwrap();
        assert_eq!(row.decision_label, "deny");
        assert_eq!(row.matched_policy.as_deref(), Some("P-066"));
        assert_eq!(row.resource.as_deref(), Some("gmail.send"));

        // A top-level policy_rule wins over the detail one.
        let top = decision_entry(r#"{"action_type":"TOOL_CALL","decision":1,"policy_rule":"P-001"}"#);
        assert_eq!(
            entry_to_decision_row(&top).unwrap().matched_policy.as_deref(),
            Some("P-001")
        );
    }

    #[test]
    fn parse_agent_id_accepts_valid_32_hex() {
        let id = "aabbccdd00112233445566778899aabb";
        assert_eq!(
            parse_agent_id(id).unwrap(),
            [0xaa, 0xbb, 0xcc, 0xdd, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,]
        );
    }

    #[test]
    fn parse_agent_id_odd_length_is_bad_request_not_panic() {
        // AAASM-4018: an odd-length id previously sliced past the end and
        // panicked. It must now surface as a clean 400.
        let err = parse_agent_id("abc").unwrap_err();
        assert_eq!(err.status, StatusCode::BAD_REQUEST.as_u16());
    }

    #[test]
    fn parse_agent_id_multibyte_is_bad_request_not_panic() {
        // AAASM-4018: a multibyte path segment previously sliced on a non-char
        // boundary and panicked. It must now surface as a clean 400.
        let err = parse_agent_id("éééééééééééééééé").unwrap_err();
        assert_eq!(err.status, StatusCode::BAD_REQUEST.as_u16());
    }

    #[test]
    fn parse_agent_id_wrong_length_is_bad_request() {
        // Valid hex but not 16 bytes → 400 rather than a truncated id.
        let err = parse_agent_id("aabb").unwrap_err();
        assert_eq!(err.status, StatusCode::BAD_REQUEST.as_u16());
    }
}
