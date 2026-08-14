//! Agent management endpoints.

use std::collections::BTreeMap;

use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::{Extension, Json};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use aa_core::audit::{AuditEntry, GovernanceMutationAudit};
use aa_core::SessionId;
use aa_gateway::registry::{AgentStatus, OrphanMode};

use crate::auth::scope::{RequireRead, RequireWrite, Scope};
use crate::auth::AuthenticatedCaller;
use crate::error::ProblemDetail;
use crate::models::disposition::SensitiveDataDisposition;
use crate::models::verdict::RuntimeVerdict;
use crate::pagination::PaginationParams;
use crate::state::AppState;
use chrono::{DateTime, Utc};

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

/// Emit an actor-attributed [`GovernanceMutationAudit`] for an enforcement- or
/// authorization-relevant mutation on `agent_id` (AAASM-5287 / ADR 0021
/// prerequisite 1).
///
/// This is the reusable actor-aware audit path the future enforcement-mode
/// toggle (gated behind AAASM-5097) will reuse. Its security contract: `actor`
/// and `tenant` are taken **only** from the authenticated `caller` — never the
/// request body — so a caller cannot forge who performed the action or under
/// which tenant it is recorded. `reason` is the caller-supplied justification,
/// which must already be validated non-empty (the audit record rejects an empty
/// reason as a defence-in-depth backstop).
///
/// Emission is best-effort onto the existing `audit_sender` channel, matching
/// the dispatch path (`dispatch.rs`): a full or disconnected channel drops the
/// entry rather than failing the mutation the operator already performed. The
/// `seq` / `previous_hash` are zero because the audit sink re-sequences and
/// re-chains entries as it persists them.
fn emit_governance_mutation_audit(
    state: &AppState,
    caller: &AuthenticatedCaller,
    agent_id: &[u8; 16],
    action: &str,
    reason: &str,
    before: &str,
    after: &str,
) {
    let Some(sender) = state.audit_sender.as_ref() else {
        return;
    };
    let record = match GovernanceMutationAudit::new(
        aa_core::AgentId::from_bytes(*agent_id),
        // Actor + tenant come from the authenticated identity, NEVER the body.
        caller.key_id.clone(),
        caller.tenant.org_id.clone(),
        caller.tenant.team_id.clone(),
        action,
        reason,
        before,
        after,
    ) {
        Ok(r) => r,
        Err(e) => {
            // The reason was already validated non-empty at the call site; a
            // failure here means a programming error, not caller input. Log and
            // skip rather than fail the mutation.
            tracing::error!(error = %e, "governance mutation audit not emitted");
            return;
        }
    };
    let entry = record.to_audit_entry(0, unix_now_ns(), SessionId::from_bytes([0u8; 16]), [0u8; 32]);
    // Best-effort, non-blocking: backpressure is non-fatal for the response.
    let _ = sender.try_send(entry);
}

/// Current Unix timestamp in nanoseconds. Mirrors the dispatch-path helper so
/// governance-mutation audit entries carry a real wall-clock time.
fn unix_now_ns() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

/// Convert an [`AgentRecord`] into an [`AgentResponse`].
fn record_to_response(
    r: aa_gateway::registry::AgentRecord,
    violations: &crate::routes::agent_violations::AgentViolationCounts,
) -> AgentResponse {
    let active_sessions = r
        .active_sessions
        .into_iter()
        .map(|s| ActiveSessionResponse {
            session_id: s.session_id,
            started_at: s.started_at.to_rfc3339(),
            status: s.status,
            actions_count: s.actions_count,
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

    // AAASM-5103 — the violation count is derived from the PolicyViolation audit
    // events (the canonical source), not read off the record: the record's old
    // `policy_violations_count` field was dead state (never incremented) and has
    // been removed. `is_flagged` is `count > 0`, superseding the dead >= 50
    // threshold the dashboard used to apply client-side.
    let policy_violations_count = violations.count(&r.agent_id);
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
        policy_violations_count,
        is_flagged: policy_violations_count > 0,
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
    /// Number of policy violations recorded for this agent, derived from the
    /// `PolicyViolation` audit events (AAASM-5103) — the same canonical source
    /// the analytics `agent-enforcement` aggregation counts. `0` when the agent
    /// has recorded none.
    pub policy_violations_count: u32,
    /// Whether the agent is policy-flagged — it has recorded at least one policy
    /// violation (`policy_violations_count > 0`, AAASM-5103). Clients should read
    /// this rather than re-deriving a threshold, so the Fleet and Topology
    /// surfaces cannot diverge on whether a given agent is flagged.
    pub is_flagged: bool,
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
    /// Number of governed actions observed on this session so far (AAASM-5088).
    pub actions_count: u32,
}

/// A currently-open agent session in the fleet-wide active-sessions listing
/// (AAASM-5038).
///
/// Enriches the per-agent [`ActiveSessionResponse`] with the owning agent's
/// identity so the dashboard Fleet → Active Sessions tab can render one flat,
/// fleet-wide table without a second lookup. `actions_count` is now sourced
/// from real gateway traffic (AAASM-5088): each CheckAction / BatchCheck the
/// gateway evaluates for the session increments it. `current_task` from the
/// design mock stays omitted — the session layer has no real source for a task
/// label, and this endpoint surfaces only state that already exists.
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
    /// Number of governed actions observed on this session so far (AAASM-5088).
    pub actions_count: u32,
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

/// Maximum shadow (weakening) window a single `POST
/// /api/v1/agents/{id}/enforcement-mode` call may request, in hours (ADR 0021
/// §Decision item 3, `MAX_SHADOW_DURATION`).
///
/// A weakening change (`→ Observe`) must carry a mandatory `expires_at` that is
/// in the future and no further than this bound from now; a request beyond it is
/// rejected `422` rather than clamped. Bounds the realistic failure the ADR
/// names — a shadow toggle left on after a 2am incident — so a forgotten window
/// self-heals when the reconciliation watcher (AAASM-5339, out of scope here)
/// reverts it.
const SHADOW_MAX_HOURS: i64 = 72;

/// Target enforcement mode a `POST /api/v1/agents/{id}/enforcement-mode` request
/// may ask for (AAASM-5097 / ADR 0021).
///
/// **`Disabled` is intentionally not a variant.** ADR 0021 §Decision item 2
/// forbids exposing `Disabled` via the API under any input (its own definition
/// restricts it to hermetic test environments), so it is unrepresentable here —
/// a body of `{"mode":"disabled"}` fails deserialization and never reaches the
/// handler. Serializes the same `snake_case` wire labels as
/// [`aa_core::EnforcementMode`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum EnforcementModeTarget {
    /// Strengthen governance back to full enforcement (the safe direction).
    Enforce,
    /// Weaken to shadow (observe-only) mode — the high-privilege, fail-open
    /// direction (Admin + reason + bounded expiry required).
    Observe,
}

/// Request body for `POST /api/v1/agents/:id/enforcement-mode` (AAASM-5097).
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct EnforcementModeRequest {
    /// Target enforcement mode. `enforce` (strengthen) or `observe` (weaken /
    /// shadow); `disabled` is not accepted (ADR 0021).
    pub mode: EnforcementModeTarget,
    /// Operator justification. **Required and non-empty on a weakening
    /// (`observe`) change** — the audit record has nothing to say otherwise;
    /// ignored on a strengthening (`enforce`) change.
    #[serde(default)]
    pub reason: Option<String>,
    /// When the shadow window ends. **Required on a weakening (`observe`)
    /// change**, must be in the future and within [`SHADOW_MAX_HOURS`] of now;
    /// ignored (and cleared) on a strengthening (`enforce`) change.
    #[serde(default)]
    #[schema(value_type = Option<String>, format = DateTime)]
    pub expires_at: Option<DateTime<Utc>>,
    /// Optional cascade confirmation (AAASM-5340). When present, the toggle is a
    /// **cascade** over the subtree rooted at `{id}` (root included) rather than
    /// the single agent, and the caller must echo back the exact affected-id set
    /// and count it was shown by the `/enforcement-mode/preview` dry-run. The
    /// handler recomputes the current subtree and rejects a mismatch (`409`) — a
    /// TOCTOU / mis-click guard. Absent → the single-agent path (unchanged from
    /// AAASM-5338).
    #[serde(default)]
    pub cascade: Option<CascadeConfirmation>,
}

/// Upper bound on the number of agents a single cascade may touch (AAASM-5340,
/// ADR 0021 Option B).
///
/// A cascade whose affected set (root + descendants) exceeds this bound is
/// **rejected outright** (`422`), never truncated: a partially applied
/// fail-open weakening across an unbounded subtree is a worse governance state
/// than an outright refusal that forces the operator to narrow the scope.
/// Applies identically to both the preview dry-run and the apply path.
const MAX_CASCADE_AGENTS: usize = 50;

/// Echo-back confirmation a cascade apply must carry (AAASM-5340).
///
/// The `/enforcement-mode/preview` dry-run returns the explicit affected-id set
/// and count; a subsequent cascade apply echoes them back here. The handler
/// recomputes the current subtree and compares as an **order-independent set**
/// (plus the count): if the tree changed between preview and apply — an agent
/// spawned or deregistered, a mis-click on a stale UI — the apply is rejected
/// `409` so the operator re-previews rather than acting on a stale picture.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct CascadeConfirmation {
    /// The hex-encoded affected agent ids the caller was shown by the preview.
    /// Compared as a set (order-independent) against the recomputed subtree.
    pub expected_ids: Vec<String>,
    /// The affected-agent count the caller was shown by the preview. Must equal
    /// the recomputed subtree size.
    pub expected_count: usize,
}

/// Response from `POST /api/v1/agents/{id}/enforcement-mode/preview`
/// (AAASM-5340).
///
/// The explicit affected-agent set for a cascade rooted at `{id}`, computed
/// without mutating anything. The order is deterministic: the root first, then
/// its descendants in the BFS order [`AgentRegistry::descendants_of`] returns.
/// The set is what a subsequent cascade apply must echo back verbatim.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct EnforcementModeCascadePreviewResponse {
    /// Hex-encoded affected agent ids: root first, then descendants in BFS order.
    pub affected_ids: Vec<String>,
    /// The number of affected agents (`affected_ids.len()`, i.e. root + descendants).
    pub count: usize,
}

/// Response from a cascade `POST /api/v1/agents/{id}/enforcement-mode`
/// (AAASM-5340) — returned only when the request carried a `cascade`
/// confirmation. Reports the full affected set the mode was applied to.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct EnforcementModeCascadeResponse {
    /// Hex-encoded affected agent ids the mode was applied to: root first, then
    /// descendants in BFS order.
    pub affected_ids: Vec<String>,
    /// The number of affected agents the mode was applied to.
    pub count: usize,
    /// The enforcement mode now in force across the whole affected set.
    pub new_mode: EnforcementModeLabel,
    /// The shadow-window deadline, echoed on a weakening cascade; `null` on a
    /// strengthening cascade (the expiry is cleared).
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<String>, format = DateTime)]
    pub expires_at: Option<DateTime<Utc>>,
}

/// The body of a successful `POST /api/v1/agents/{id}/enforcement-mode`
/// response (AAASM-5340). Untagged so the wire shape is exactly the inner
/// variant: a single-agent toggle (no `cascade` field) serializes as an
/// [`EnforcementModeResponse`] — byte-identical to AAASM-5338 — while a cascade
/// serializes as an [`EnforcementModeCascadeResponse`]. Discriminated by the
/// presence of `affected_ids`.
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(untagged)]
pub enum EnforcementModeApplyResponse {
    /// A single-agent toggle result (the AAASM-5338 shape, unchanged).
    Single(EnforcementModeResponse),
    /// A cascade toggle result over the subtree (AAASM-5340).
    Cascade(EnforcementModeCascadeResponse),
}

/// Response from `POST /api/v1/agents/:id/enforcement-mode`.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct EnforcementModeResponse {
    /// Hex-encoded agent UUID.
    pub agent_id: String,
    /// The agent's enforcement mode before the change (`enforce` / `observe` /
    /// `disabled`), or `null` when it had no per-agent override (inheriting the
    /// policy default).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_mode: Option<EnforcementModeLabel>,
    /// The enforcement mode now in force after the change.
    pub new_mode: EnforcementModeLabel,
    /// The shadow-window deadline, echoed back on a weakening change; `null` on a
    /// strengthening change (the expiry is cleared).
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<String>, format = DateTime)]
    pub expires_at: Option<DateTime<Utc>>,
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

    // AAASM-5103 — one grouped audit pass, looked up per agent below (no N+1).
    let violations = crate::routes::agent_violations::AgentViolationCounts::from_audit(&state.audit_reader).await;
    let items: Vec<AgentResponse> = visible
        .into_iter()
        .skip(offset)
        .take(per_page as usize)
        .map(|r| record_to_response(r, &violations))
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
                actions_count: s.actions_count,
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

    // AAASM-5103 — derive the violation count / flag from the audit log.
    let violations = crate::routes::agent_violations::AgentViolationCounts::from_audit(&state.audit_reader).await;
    Ok((StatusCode::OK, Json(record_to_response(record, &violations))))
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

    // AAASM-5287: a governance mutation must carry a non-empty reason so the
    // actor-attributed audit record has a justification to record.
    if body.reason.trim().is_empty() {
        return Err(ProblemDetail::from_status(StatusCode::UNPROCESSABLE_ENTITY)
            .with_detail("A non-empty 'reason' is required to suspend an agent"));
    }

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

    let new_status = "Suspended(Manual)".to_string();
    // AAASM-5287: record who suspended the agent, under which tenant, and why —
    // actor + tenant from the authenticated identity, never the request body.
    emit_governance_mutation_audit(
        &state,
        &caller,
        &agent_id,
        "suspend",
        &body.reason,
        &previous_status,
        &new_status,
    );

    Ok((
        StatusCode::OK,
        Json(SuspendResponse {
            agent_id: id,
            previous_status,
            new_status,
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

/// Resolve the durable mode + expiry for a requested direction, running the
/// full ADR 0021 direction-asymmetric authz + validation **once** (AAASM-5340).
///
/// This is the single-agent decision logic of [`set_enforcement_mode`] factored
/// out so a cascade can run it exactly once for the whole affected set (the
/// direction, the Admin gate, the reason, and the expiry window are set-wide
/// properties, not per-agent). It performs no state mutation and no per-agent
/// tenant check — the caller is responsible for authorizing each affected agent
/// via [`authorize_agent_access`]. Returns the `(mode, expiry)` to persist, or a
/// `ProblemDetail` (`403` for a Write-only caller attempting to weaken, `422`
/// for a missing/empty reason or a missing/past/too-distant `expires_at`).
fn resolve_enforcement_transition(
    caller: &AuthenticatedCaller,
    mode: EnforcementModeTarget,
    reason: Option<&str>,
    expires_at: Option<DateTime<Utc>>,
) -> Result<(aa_core::EnforcementMode, Option<DateTime<Utc>>), ProblemDetail> {
    match mode {
        // ── Strengthening (→ Enforce): the safe direction. Write + tenant only,
        // no ceremony. Clears any prior shadow expiry.
        EnforcementModeTarget::Enforce => Ok((aa_core::EnforcementMode::Enforce, None)),

        // ── Weakening (→ Observe / shadow): the fail-open, high-privilege path.
        EnforcementModeTarget::Observe => {
            if !caller.scopes.contains(&Scope::Admin) {
                return Err(ProblemDetail::from_status(StatusCode::FORBIDDEN)
                    .with_detail("Weakening enforcement to shadow (observe) mode requires admin scope"));
            }

            let reason = reason.unwrap_or("").trim();
            if reason.is_empty() {
                return Err(ProblemDetail::from_status(StatusCode::UNPROCESSABLE_ENTITY)
                    .with_detail("A non-empty 'reason' is required to weaken enforcement to shadow (observe) mode"));
            }

            let expires_at = expires_at.ok_or_else(|| {
                ProblemDetail::from_status(StatusCode::UNPROCESSABLE_ENTITY)
                    .with_detail("An 'expires_at' deadline is required to weaken enforcement to shadow (observe) mode")
            })?;
            let now = Utc::now();
            if expires_at <= now {
                return Err(ProblemDetail::from_status(StatusCode::UNPROCESSABLE_ENTITY)
                    .with_detail("'expires_at' must be in the future"));
            }
            if expires_at > now + chrono::Duration::hours(SHADOW_MAX_HOURS) {
                return Err(ProblemDetail::from_status(StatusCode::UNPROCESSABLE_ENTITY)
                    .with_detail(format!("'expires_at' must be within {SHADOW_MAX_HOURS}h of now")));
            }

            Ok((aa_core::EnforcementMode::Observe, Some(expires_at)))
        }
    }
}

/// Map a resolved [`aa_core::EnforcementMode`] to its API wire label.
fn mode_label(mode: aa_core::EnforcementMode) -> EnforcementModeLabel {
    match mode {
        aa_core::EnforcementMode::Enforce => EnforcementModeLabel::Enforce,
        aa_core::EnforcementMode::Observe => EnforcementModeLabel::Observe,
        aa_core::EnforcementMode::Disabled => EnforcementModeLabel::Disabled,
    }
}

/// Build the ordered, tenant-authorized affected set for a cascade rooted at
/// `root` (AAASM-5340).
///
/// The affected set is `[root] ++ descendants_of(root)` — the root first, then
/// its descendants in the BFS order [`AgentRegistry::descendants_of`] returns
/// (a deterministic order the preview publishes and the apply echo-back is
/// compared against). Security invariants, enforced here as a unit:
///
/// - **Root authorization**: the root is gated by [`authorize_agent_access`]
///   (403 for an unauthorized caller, 404 when the root is unknown).
/// - **Tenant confinement on every descendant**: a descendant the caller cannot
///   access (delegated into another team) causes an outright `403` — the node is
///   never silently dropped, which would let a cross-tenant subtree be partially
///   cascaded (AAASM-4841 hazard). An admin may act on any node.
/// - **Bounded blast radius**: a set larger than [`MAX_CASCADE_AGENTS`] is
///   rejected `422`, never truncated.
fn build_cascade_set(
    caller: &AuthenticatedCaller,
    state: &AppState,
    root: &[u8; 16],
    root_id: &str,
) -> Result<Vec<[u8; 16]>, ProblemDetail> {
    // Authorize the root (existence + tenant ownership) before disclosing the
    // subtree — mirrors the single-agent path.
    authorize_agent_access(caller, state, root, root_id)?;

    let mut affected = Vec::with_capacity(1 + state.agent_registry.descendants_of(root).len());
    affected.push(*root);
    affected.extend(state.agent_registry.descendants_of(root));

    // Bounded blast radius: reject outright, never truncate.
    if affected.len() > MAX_CASCADE_AGENTS {
        return Err(
            ProblemDetail::from_status(StatusCode::UNPROCESSABLE_ENTITY).with_detail(format!(
                "Cascade affects {} agents, exceeding the maximum of {MAX_CASCADE_AGENTS}; narrow the scope",
                affected.len()
            )),
        );
    }

    // Tenant confinement on EVERY affected agent. The root cleared the up-front
    // scope floor in `authorize_agent_access`; each descendant is gated on the
    // same team boundary `list_agents` uses. A node the caller cannot see is a
    // hard 403 — never dropped.
    let is_admin = caller.scopes.contains(&Scope::Admin);
    if !is_admin {
        for id in affected.iter().skip(1) {
            let visible = state
                .agent_registry
                .get(id)
                .map(|r| descendant_visible_to(caller, &r))
                .unwrap_or(false);
            if !visible {
                return Err(ProblemDetail::from_status(StatusCode::FORBIDDEN).with_detail(
                    "The cascade subtree contains an agent outside the caller's tenant; \
                     re-scope or use an admin credential",
                ));
            }
        }
    }

    Ok(affected)
}

/// Hex-encode a 16-byte agent id (matches the encoding used across the API).
fn hex_id(id: &[u8; 16]) -> String {
    id.iter().map(|b| format!("{b:02x}")).collect()
}

/// `POST /api/v1/agents/{id}/enforcement-mode/preview` — dry-run the cascade.
///
/// Compute the explicit affected-agent set for a cascade rooted at `{id}`.
///
/// Returns the affected agent ids (the subtree rooted at `{id}`, **including the
/// root**) and their count without mutating any agent — a preview the UI shows
/// before an operator commits a subtree-wide enforcement-mode change
/// (AAASM-5340, ADR 0021 Option B). The order is deterministic: the root first,
/// then its descendants in BFS order. A subsequent cascade apply must echo this
/// exact set + count back (the TOCTOU / mis-click guard).
///
/// It shares the whole authorization contract of the apply path: the root is
/// tenant-authorized (403/404), every descendant is tenant-confined (a node
/// outside the caller's tenant is a `403`, never dropped), and a set larger than
/// `MAX_CASCADE_AGENTS` (50) is rejected `422` — matching apply so the UI can
/// surface the over-limit rejection before the operator commits. The `Write`
/// floor authenticates the caller; the preview is direction-agnostic (it takes
/// no body) so it needs no Admin gate — the weakening Admin check happens on the
/// apply path.
#[utoipa::path(
    post,
    path = "/api/v1/agents/{id}/enforcement-mode/preview",
    params(("id" = String, Path, description = "Hex-encoded root agent UUID")),
    responses(
        (status = 200, description = "Affected agent set for the cascade", body = EnforcementModeCascadePreviewResponse),
        (status = 400, description = "Invalid agent ID format"),
        (status = 401, description = "Missing or invalid credentials"),
        (status = 403, description = "Caller lacks access to the root or a subtree agent"),
        (status = 404, description = "Root agent not found"),
        (status = 422, description = "Cascade exceeds the maximum affected-agent count"),
    ),
    tag = "agents"
)]
pub async fn preview_enforcement_mode_cascade(
    // A preview is a read of governance state; the `Write` floor (not `Read`)
    // matches the mutating apply it precedes, so a read-only caller cannot probe
    // the subtree it could never toggle.
    RequireWrite(caller): RequireWrite,
    Extension(state): Extension<AppState>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<(StatusCode, Json<EnforcementModeCascadePreviewResponse>), ProblemDetail> {
    let root = parse_agent_id(&id)?;
    let affected = build_cascade_set(&caller, &state, &root, &id)?;
    let affected_ids: Vec<String> = affected.iter().map(hex_id).collect();
    let count = affected_ids.len();
    Ok((
        StatusCode::OK,
        Json(EnforcementModeCascadePreviewResponse { affected_ids, count }),
    ))
}

/// `POST /api/v1/agents/:id/enforcement-mode` — set an agent's enforcement mode.
///
/// Direction-asymmetric governance mutation (AAASM-5097, ADR 0021 Option B).
/// The operation is split by *direction of effect*, because the two directions
/// have opposite blast radius:
///
/// - **Strengthening** (`→ enforce`) turns governance back *on* — it fails safe.
///   It needs only tenant-scoped `Write` (via [`authorize_agent_access`]), no
///   `reason`, no `expires_at`; the per-agent expiry is cleared so the agent
///   returns to permanent enforcement.
/// - **Weakening** (`→ observe`, i.e. shadow) turns denials *and credential
///   redaction off* for the agent — it fails **open**. It is the high-privilege
///   path: it requires `Admin` scope in addition to tenant ownership, a required
///   non-empty `reason`, and a required `expires_at` that is in the future and
///   within [`SHADOW_MAX_HOURS`] of now. A missing/empty reason or a
///   missing/past/too-distant deadline is rejected `422`.
///
/// `disabled` is not reachable under any input (it is not a variant of
/// [`EnforcementModeTarget`], so it fails deserialization — ADR 0021).
///
/// A single handler gates both directions rather than two extractors: the
/// `Write` floor authenticates and denies a read-only caller up front
/// (deny-by-default — an unauthenticated caller never reaches the logic), then
/// the weakening path additionally requires `Admin` in-handler. On success the
/// canonical `enforcement_mode` (the field the enforcement resolver reads, not
/// `metadata["mode"]`) is written durably and a `GovernanceMutation` audit is
/// emitted with the **verified** actor + tenant from the authenticated caller —
/// never the request body.
///
/// **Cascade (AAASM-5340).** When the request carries a `cascade`
/// confirmation, the toggle applies to the whole subtree rooted at `{id}` (root
/// included) rather than the single agent. The direction, Admin gate, reason,
/// and expiry window are validated **once** for the set; then the mode is
/// persisted to every affected agent, each with its **own** actor-attributed
/// `GovernanceMutation` audit. The caller must echo back the exact affected-id
/// set + count it was shown by `/enforcement-mode/preview`:
/// - the recomputed subtree (compared as an order-independent **set**, plus the
///   count) differing from the echo-back → **`409` Conflict** (the tree changed
///   since preview — re-preview), chosen over `422` because the request is
///   well-formed but *stale* against current state, exactly the semantics of a
///   version conflict;
/// - a recomputed set larger than `MAX_CASCADE_AGENTS` → **`422`** (an
///   unprocessable over-limit request, never truncated);
/// - a subtree agent outside the caller's tenant → **`403`** (never dropped).
///
/// Without a `cascade` field the behaviour is byte-identical to AAASM-5338.
#[utoipa::path(
    post,
    path = "/api/v1/agents/{id}/enforcement-mode",
    params(("id" = String, Path, description = "Hex-encoded agent UUID")),
    request_body = EnforcementModeRequest,
    responses(
        (status = 200, description = "Enforcement mode changed", body = EnforcementModeApplyResponse),
        (status = 400, description = "Invalid agent ID format"),
        (status = 401, description = "Missing or invalid credentials"),
        (status = 403, description = "Caller lacks the scope required for the requested direction, or a subtree agent is out of tenant"),
        (status = 404, description = "Agent not found"),
        (status = 409, description = "Cascade echo-back set/count differs from the current subtree (re-preview)"),
        (status = 422, description = "Weakening request missing/invalid reason or expires_at, or cascade exceeds the maximum agent count"),
    ),
    tag = "agents"
)]
pub async fn set_enforcement_mode(
    // The `Write` floor authenticates the caller and rejects anything below
    // Write up front (deny-by-default). Strengthening needs exactly Write;
    // weakening additionally requires Admin, enforced in-handler below.
    RequireWrite(caller): RequireWrite,
    Extension(state): Extension<AppState>,
    axum::extract::Path(id): axum::extract::Path<String>,
    Json(body): Json<EnforcementModeRequest>,
) -> Result<(StatusCode, Json<EnforcementModeApplyResponse>), ProblemDetail> {
    let agent_id = parse_agent_id(&id)?;

    // A cascade confirmation routes to the subtree path; its absence preserves
    // the AAASM-5338 single-agent behaviour exactly.
    if let Some(cascade) = body.cascade.as_ref() {
        return apply_enforcement_cascade(&caller, &state, &agent_id, &id, &body, cascade).await;
    }

    // Tenant ownership before any state change or existence disclosure — mirrors
    // suspend/resume. An admin may act on any agent; a team-scoped caller only on
    // its own team's; a caller with neither is denied before the mode branch.
    authorize_agent_access(&caller, &state, &agent_id, &id)?;

    // Snapshot the prior override so the audit before/after and the response are
    // truthful. `None` (no per-agent override) is recorded as "inherit".
    let previous_override = state.agent_registry.get(&agent_id).and_then(|r| r.enforcement_mode);
    let previous_label = project_config_mode(previous_override);
    let previous_wire = previous_override.map(|m| m.as_wire()).unwrap_or("inherit");

    // Resolve the durable mode + expiry per direction, enforcing the
    // direction-specific authz and validation. `Disabled` is unreachable: it is
    // not a variant of `EnforcementModeTarget`.
    let (new_mode, new_expiry) =
        resolve_enforcement_transition(&caller, body.mode, body.reason.as_deref(), body.expires_at)?;

    // Persist durably (in-memory + storage write-through, AAASM-5288 bridge). A
    // missing agent surfaces as 404 — the tenant check above already confirmed
    // it exists, so this guards a concurrent deregister.
    state
        .agent_registry
        .set_enforcement_mode_persisted(&agent_id, Some(new_mode), new_expiry)
        .await
        .map_err(|_| ProblemDetail::from_status(StatusCode::NOT_FOUND).with_detail(format!("Agent not found: {id}")))?;

    // Actor-attributed audit: actor + tenant come from the authenticated caller,
    // NEVER the body (AAASM-5287). A weakening carries the operator reason; a
    // strengthening has none, so record a fixed non-empty justification (the
    // audit rejects an empty reason).
    let audit_reason = cascade_audit_reason(body.mode, body.reason.as_deref());
    emit_governance_mutation_audit(
        &state,
        &caller,
        &agent_id,
        "enforcement_mode",
        &audit_reason,
        previous_wire,
        new_mode.as_wire(),
    );

    Ok((
        StatusCode::OK,
        Json(EnforcementModeApplyResponse::Single(EnforcementModeResponse {
            agent_id: id,
            previous_mode: previous_label,
            new_mode: mode_label(new_mode),
            expires_at: new_expiry,
        })),
    ))
}

/// The non-empty justification recorded on the `GovernanceMutation` audit for an
/// enforcement toggle. A weakening carries the operator's reason; a
/// strengthening has none, so a fixed non-empty label is recorded (the audit
/// record rejects an empty reason).
fn cascade_audit_reason(mode: EnforcementModeTarget, reason: Option<&str>) -> String {
    match mode {
        EnforcementModeTarget::Observe => reason.unwrap_or("").trim().to_string(),
        EnforcementModeTarget::Enforce => "strengthen to enforce".to_string(),
    }
}

/// Apply an enforcement-mode change to the whole subtree rooted at `root`
/// (AAASM-5340), gated by an echo-back confirmation.
///
/// Runs the ADR 0021 direction/authz/expiry validation **once** for the set,
/// verifies the caller's echoed affected-id set + count against the recomputed
/// current subtree (a `409` on mismatch — the TOCTOU / mis-click guard), then
/// persists the mode to every affected agent, each with its own
/// actor-attributed `GovernanceMutation` audit (actor + tenant from the
/// authenticated caller, never the body). The subtree is bounded to
/// [`MAX_CASCADE_AGENTS`] (`422` if exceeded) and tenant-confined on every node
/// (`403` if any node is out of tenant), both enforced by [`build_cascade_set`].
async fn apply_enforcement_cascade(
    caller: &AuthenticatedCaller,
    state: &AppState,
    root: &[u8; 16],
    root_id: &str,
    body: &EnforcementModeRequest,
    cascade: &CascadeConfirmation,
) -> Result<(StatusCode, Json<EnforcementModeApplyResponse>), ProblemDetail> {
    // Build + authorize the affected set (root authz, per-node tenant
    // confinement, and the MAX_CASCADE_AGENTS bound) before any mutation.
    let affected = build_cascade_set(caller, state, root, root_id)?;
    let affected_ids: Vec<String> = affected.iter().map(hex_id).collect();

    // Echo-back check: the recomputed set must match what the caller previewed,
    // compared order-independently (as a set) plus the count. A change since
    // preview — a spawn, a deregister, a stale UI — is a well-formed but STALE
    // request, so it is a 409 Conflict (re-preview), not a 422.
    let recomputed: std::collections::HashSet<&String> = affected_ids.iter().collect();
    let echoed: std::collections::HashSet<&String> = cascade.expected_ids.iter().collect();
    if cascade.expected_count != affected_ids.len() || recomputed != echoed {
        return Err(ProblemDetail::from_status(StatusCode::CONFLICT).with_detail(
            "The cascade set changed since it was previewed; re-preview and retry with the current affected set",
        ));
    }

    // Resolve the transition ONCE — the direction, Admin gate, reason, and
    // expiry window are set-wide, not per-agent.
    let (new_mode, new_expiry) =
        resolve_enforcement_transition(caller, body.mode, body.reason.as_deref(), body.expires_at)?;
    let audit_reason = cascade_audit_reason(body.mode, body.reason.as_deref());

    // Apply the mode + emit an OWN audit for every affected agent. Each agent's
    // prior override is snapshotted for its own before/after.
    for id in &affected {
        let previous_override = state.agent_registry.get(id).and_then(|r| r.enforcement_mode);
        let previous_wire = previous_override.map(|m| m.as_wire()).unwrap_or("inherit");
        state
            .agent_registry
            .set_enforcement_mode_persisted(id, Some(new_mode), new_expiry)
            .await
            .map_err(|_| {
                ProblemDetail::from_status(StatusCode::NOT_FOUND)
                    .with_detail(format!("Agent not found: {}", hex_id(id)))
            })?;
        emit_governance_mutation_audit(
            state,
            caller,
            id,
            "enforcement_mode",
            &audit_reason,
            previous_wire,
            new_mode.as_wire(),
        );
    }

    let count = affected_ids.len();
    Ok((
        StatusCode::OK,
        Json(EnforcementModeApplyResponse::Cascade(EnforcementModeCascadeResponse {
            affected_ids,
            count,
            new_mode: mode_label(new_mode),
            expires_at: new_expiry,
        })),
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
    pub decision_label: DecisionLabel,
    /// The canonical 5-way runtime verdict (`allow` / `narrow` / `scrub` /
    /// `pending` / `deny`, AAASM-5086) for this action — the vocabulary the
    /// dashboard renders. Distinct from `decision`/`decisionLabel`, which are the
    /// coarse proto enforcement outcome: a proto `deny` cannot tell a full block
    /// from a scoped `narrow`, nor a proto `allow` from a `scrub`. **Always
    /// `null` today**: deriving the verdict requires capturing it at decision
    /// time on the enforcement hot path, which is the ADR-0018-gated follow-up
    /// (populated once decision-capture lands — ADR 0018 / AAASM-5086 follow-up).
    /// Wired through now so the column lands without another contract change.
    pub verdict: Option<RuntimeVerdict>,
    /// Distributed-trace id linking this decision to its session trace
    /// (`/api/v1/traces/...`). **Always `null` today**: the audit log records no
    /// per-decision trace id, so it is surfaced nullable rather than fabricated.
    /// Populated once trace-id propagation lands on the runtime — the
    /// ADR-0018-gated follow-up (ADR 0018 / AAASM-5086 follow-up).
    pub trace_id: Option<String>,
    /// The matched policy rule id (audit `policy_rule`, top-level or under
    /// `detail`). The design's `policy` column. `null` when the decision
    /// recorded no rule (e.g. a baseline allow with no matching rule).
    pub matched_policy: Option<String>,
    /// The design's `latency` column. **Always `null`: the audit log records no
    /// per-decision latency today**, so it is surfaced nullable rather than
    /// fabricated. Wired through so the column lands the day a latency source is
    /// added, without another contract change.
    pub latency_ms: Option<u64>,
    /// What the sensitive-data pipeline did to this action's payload and to the
    /// approval of the action (AAASM-5356, ADR 0032 §10 D-2) — a finer
    /// vocabulary than `verdict`, which stays the authoritative outcome and is
    /// frozen at five values.
    ///
    /// **Additive and optional.** The key is *omitted entirely* when there is no
    /// disposition to report, so a response for an action that has none is
    /// byte-for-byte what this endpoint returned before the field existed. An
    /// absent key and an explicit `"none"` say the same thing: this field adds
    /// nothing and `verdict` carries the whole meaning. A client that has never
    /// heard of the field reads exactly the object it read before.
    ///
    /// Declared last, so a response that *does* carry a disposition is a pure
    /// suffix append to the object as it was.
    ///
    /// **Absent on every row today**: no writer populates the audit payload's
    /// `sensitive_data_disposition` yet — that is AAASM-5357's projection. The
    /// read is wired through now so the day it lands there is no second contract
    /// change, which is the pattern `verdict` followed.
    ///
    /// **Reporting only.** Nothing consults this to decide whether an action is
    /// permitted — `verdict` remains the authoritative outcome. It is a field of
    /// this response like any other, so it inherits the endpoint's tenant
    /// scoping unchanged: `authorize_agent_access` gates the whole row, so the
    /// `approval_*` values it can carry are visible to exactly the callers
    /// already entitled to the decision record.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sensitive_data_disposition: Option<SensitiveDataDisposition>,
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

/// Wire vocabulary for [`AgentDecisionResponse::decision_label`].
///
/// AAASM-5219 — constrains the `decisionLabel` field to the closed set of
/// lowercase labels [`decision_label`] can emit, one per proto
/// [`Decision`](aa_proto::assembly::common::v1::Decision) discriminant plus the
/// `unspecified` fallback, so the generated OpenAPI spec advertises an enum
/// rather than a free-form `string`. Serializes lowercase.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum DecisionLabel {
    Allow,
    Deny,
    Pending,
    Redact,
    Unspecified,
}

/// Lowercase label for a [`Decision`](aa_proto::assembly::common::v1::Decision)
/// discriminant, used for `decisionLabel`.
fn decision_label(discriminant: i64) -> DecisionLabel {
    use aa_proto::assembly::common::v1::Decision;
    match discriminant {
        d if d == Decision::Allow as i64 => DecisionLabel::Allow,
        d if d == Decision::Deny as i64 => DecisionLabel::Deny,
        d if d == Decision::Pending as i64 => DecisionLabel::Pending,
        d if d == Decision::Redact as i64 => DecisionLabel::Redact,
        _ => DecisionLabel::Unspecified,
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

    // AAASM-5100 / ADR-0018 item A — the 5-way runtime verdict, now captured at
    // decision time on the audit write path (`policy_service::record_audit`).
    // Parsed from the payload string into the canonical enum; absent on legacy
    // rows written before capture landed, which stay `null`.
    let verdict = payload
        .get("verdict")
        .and_then(serde_json::Value::as_str)
        .and_then(|s| serde_json::from_value::<RuntimeVerdict>(serde_json::Value::String(s.to_string())).ok());

    // AAASM-5100 / ADR-0018 item B — per-decision latency in ms, now recorded on
    // the audit write path. Absent on legacy rows, which stay `null`.
    let latency_ms = payload.get("latency_ms").and_then(serde_json::Value::as_u64);

    // AAASM-5356 / ADR 0032 §10 D-2 — the additive finer disposition. No writer
    // emits this key yet (AAASM-5357 owns the projection), so it is absent on
    // every row today and the field is omitted from the response entirely.
    //
    // An unrecognised spelling degrades to absent rather than failing the row.
    // That can only under-report the *optional* field: `verdict` above is parsed
    // independently and remains the authoritative outcome, so a reader falling
    // back to it is never misled about whether the action was permitted.
    let sensitive_data_disposition = payload
        .get("sensitive_data_disposition")
        .and_then(serde_json::Value::as_str)
        .and_then(|s| {
            serde_json::from_value::<SensitiveDataDisposition>(serde_json::Value::String(s.to_string())).ok()
        });

    Some(AgentDecisionResponse {
        timestamp,
        session_id: hex::encode(entry.session_id().as_bytes()),
        seq: entry.seq(),
        verb,
        resource,
        decision,
        decision_label: decision_label(decision),
        verdict,
        matched_policy,
        latency_ms,
        // Item C (trace-id propagation) is NOT implemented — it is gated to a
        // separate Phase 2 ticket. The audit write records no per-decision trace
        // id, so this stays null.
        trace_id: None,
        sensitive_data_disposition,
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

// ---------------------------------------------------------------------------
// Per-agent config projection (AAASM-5098, ADR-0022 narrow Option C)
// ---------------------------------------------------------------------------

/// Recent window (7 days) the config recommendation aggregates denials over.
const CONFIG_RECO_WINDOW_LABEL: &str = "7d";
/// `CONFIG_RECO_WINDOW_LABEL` expressed in seconds.
const CONFIG_RECO_WINDOW_SECS: u64 = 7 * 86_400;
/// Minimum denials in the window before a dominant-resource finding is ranked.
///
/// Below this floor the ranking is noise (a single denial is "100% of denials"),
/// so the recommendation is withheld entirely rather than shipped as a
/// low-confidence finding — ADR-0022's validation requirement that the block
/// return empty when the agent has too few denials to rank.
const CONFIG_RECO_MIN_DENIALS: u64 = 5;
/// Most dominant resources the recommendation names.
const CONFIG_RECO_TOP_N: usize = 3;
/// Upper bound on audit entries scanned when building the recommendation.
/// Bounds per-request work the way the analytics reads do (AAASM-4145).
const CONFIG_RECO_SCAN: usize = 10_000;

/// Map the agent's registered enforcement-mode override onto the config wire
/// label. `None` (no per-agent override declared) stays `None` — the effective
/// mode is then decided per policy document, so this response omits it rather
/// than fabricating a per-agent posture (ADR-0022).
fn project_config_mode(mode: Option<aa_core::EnforcementMode>) -> Option<EnforcementModeLabel> {
    match mode? {
        aa_core::EnforcementMode::Enforce => Some(EnforcementModeLabel::Enforce),
        aa_core::EnforcementMode::Observe => Some(EnforcementModeLabel::Observe),
        aa_core::EnforcementMode::Disabled => Some(EnforcementModeLabel::Disabled),
    }
}

/// Project the agent's effective policy cascade into config policy refs,
/// broadest → narrowest, deduplicated on `(scope, name)`.
///
/// Uses the same scope-qualified id (`{scope}/{name}`) the capability matrix
/// emits so the Config tab and Capability page name the same document alike.
/// A document contributes at most one ref regardless of how many times it
/// appears in the cascade.
fn cascade_to_policy_refs(cascade: &[std::sync::Arc<aa_gateway::policy::PolicyDocument>]) -> Vec<AgentConfigPolicyRef> {
    let mut seen: std::collections::BTreeSet<(String, Option<String>)> = std::collections::BTreeSet::new();
    let mut refs = Vec::new();
    for doc in cascade {
        let scope = doc.scope.to_string();
        let key = (scope.clone(), doc.name.clone());
        if !seen.insert(key) {
            continue;
        }
        let id = match &doc.name {
            Some(n) => format!("{scope}/{n}"),
            None => scope.clone(),
        };
        refs.push(AgentConfigPolicyRef {
            id,
            name: doc.name.clone().unwrap_or_else(|| scope.clone()),
            scope,
            version: doc.policy_version.clone(),
        });
    }
    refs
}

/// The resource a denial applies to, read from the audit payload.
///
/// Mirrors `analytics::extract_tool_name` (the proven denial/tool grouping key):
/// tries the explicit `tool` / `tool_name` keys first, falling back to the
/// policy `action_type` label the gateway records for every evaluated action
/// (`aa-gateway/src/service/policy_service.rs` writes `action_type` on the
/// `PolicyViolation` payload). Returns `None` when no non-empty identifier is
/// present, so a denial with no resolvable resource is counted in the total but
/// not attributed to a resource — never fabricated.
fn denied_resource(payload: &serde_json::Value) -> Option<String> {
    for key in ["tool", "tool_name", "action_type"] {
        if let Some(s) = payload.get(key).and_then(|v| v.as_str()) {
            if !s.is_empty() {
                return Some(s.to_string());
            }
        }
    }
    None
}

/// Build the qualitative denial-dominance recommendation from a set of the
/// agent's `PolicyViolation` audit entries, or `None` when there are too few
/// denials in the window to rank a dominant resource (ADR-0022).
///
/// Groups denials by resource (via [`denied_resource`], the same grouping key
/// the tool-usage analytics uses), ranks the top [`CONFIG_RECO_TOP_N`], and
/// reports each resource's historical share of the window's denials. No
/// projected-improvement percentage is produced — that is the AAASM-5094
/// counterfactual, deliberately withheld.
fn build_denial_recommendation(entries: &[AuditEntry]) -> Option<AgentConfigRecommendation> {
    let mut by_resource: BTreeMap<String, u64> = BTreeMap::new();
    let mut total_denials: u64 = 0;
    for entry in entries {
        let Ok(payload) = serde_json::from_str::<serde_json::Value>(entry.payload()) else {
            continue;
        };
        total_denials += 1;
        if let Some(resource) = denied_resource(&payload) {
            *by_resource.entry(resource).or_insert(0) += 1;
        }
    }

    // Below the confidence floor the ranking is noise — withhold the block
    // rather than ship a low-confidence finding (ADR-0022 validation req).
    if total_denials < CONFIG_RECO_MIN_DENIALS || by_resource.is_empty() {
        return None;
    }

    // Rank most-denied first; ties broken by resource name for determinism.
    let mut ranked: Vec<(String, u64)> = by_resource.into_iter().collect();
    ranked.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    ranked.truncate(CONFIG_RECO_TOP_N);

    let share = |n: u64| (n as f64 / total_denials as f64) * 100.0;
    let top_resources: Vec<DeniedResourceShare> = ranked
        .iter()
        .map(|(resource, denials)| DeniedResourceShare {
            resource: resource.clone(),
            denials: *denials,
            share_pct: share(*denials),
        })
        .collect();
    let top_sum: u64 = ranked.iter().map(|(_, n)| *n).sum();
    let top_resources_share_pct = share(top_sum);

    let names: Vec<&str> = top_resources.iter().map(|r| r.resource.as_str()).collect();
    let summary =
        format!(
        "{} {} account for {:.0}% of this agent's denials in the last {} ({}). Review whether these can be narrowed.",
        top_resources.len(),
        if top_resources.len() == 1 { "resource" } else { "resources" },
        top_resources_share_pct,
        CONFIG_RECO_WINDOW_LABEL,
        names.join(", "),
    );

    Some(AgentConfigRecommendation {
        window: CONFIG_RECO_WINDOW_LABEL.to_string(),
        total_denials,
        top_resources,
        top_resources_share_pct,
        summary,
    })
}

/// `GET /api/v1/agents/:id/config` — per-agent config projection (AAASM-5098).
///
/// Read-only projection backing the Agent-Detail Config-YAML tab (ADR-0022,
/// narrow Option C). Returns **only fields with a real per-agent source**: the
/// registered `enforcement_mode` (the field the enforcement path consults, not
/// `metadata["mode"]`), the agent's effective policy cascade, and a *qualitative*
/// recommendation naming the resources that dominate its recent denials. The
/// mock's `fail_open`, `rate_limit`, `observability`, and `issuer` are omitted
/// from the contract entirely — ADR-0022 verified none has a per-agent source,
/// and emitting them as `null` would imply a concept that does not exist. The
/// recommendation carries no quantified improvement estimate: the `−N%`
/// counterfactual is blocked on AAASM-5094's traffic replay.
///
/// Deny-by-default and tenant-scoped: [`authorize_agent_access`] confines the
/// caller to an agent in its own team (admin sees any; a caller with no team
/// scope is denied before any read), so neither the cascade nor the denial
/// rollup crosses a tenant boundary. No enforcement or audit-write path is touched.
#[utoipa::path(
    get,
    path = "/api/v1/agents/{id}/config",
    params(("id" = String, Path, description = "Hex-encoded agent UUID")),
    responses(
        (status = 200, description = "Per-agent config projection", body = AgentConfigResponse),
        (status = 400, description = "Invalid agent ID format"),
        (status = 401, description = "Missing or invalid credentials"),
        (status = 403, description = "Caller lacks access to the agent's team"),
        (status = 404, description = "Agent not found"),
    ),
    tag = "agents"
)]
pub async fn get_agent_config(
    RequireRead(caller): RequireRead,
    Extension(state): Extension<AppState>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<(StatusCode, Json<AgentConfigResponse>), ProblemDetail> {
    let agent_id_bytes = parse_agent_id(&id)?;

    // Read-scope + tenant ownership before exposing the agent's config — mirrors
    // get_agent_capabilities / get_agent_decisions.
    authorize_agent_access(&caller, &state, &agent_id_bytes, &id)?;

    let record = state.agent_registry.get(&agent_id_bytes).ok_or_else(|| {
        ProblemDetail::from_status(StatusCode::NOT_FOUND).with_detail(format!("Agent not found: {id}"))
    })?;

    // Effective policy cascade, resolved with the agent's real lineage so
    // Org/Team-scoped documents are not dropped (AAASM-5102).
    let agent_id = aa_core::identity::AgentId::from_bytes(agent_id_bytes);
    let lineage = state.agent_registry.lineage(&agent_id_bytes).unwrap_or_default();
    let cascade = state.policy_engine.collect_cascade_with_lineage(&agent_id, &lineage);
    let policies = cascade_to_policy_refs(&cascade);

    // Qualitative recommendation from the agent's recent denials. The agent-id
    // filter keeps the read to this agent (already tenant-authorized above);
    // `PolicyViolation` is the audit event the gateway records for a proto
    // `Decision::DENY` (see analytics::get_agent_enforcement).
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;
    let since = now.saturating_sub(CONFIG_RECO_WINDOW_SECS.saturating_mul(1_000_000_000));
    let (denials, _total) = state
        .audit_reader
        .list_windowed(since, CONFIG_RECO_SCAN, 0, Some(&id), Some("PolicyViolation"), None)
        .await
        .unwrap_or_default();
    let recommendation = build_denial_recommendation(&denials);

    Ok((
        StatusCode::OK,
        Json(AgentConfigResponse {
            agent_id: hex::encode(agent_id_bytes),
            enforcement_mode: project_config_mode(record.enforcement_mode),
            policies,
            recommendation,
        }),
    ))
}

/// Wire vocabulary for [`AgentConfigResponse::enforcement_mode`].
///
/// AAASM-5098 / ADR-0022 — the agent's registered enforcement-mode override,
/// serialized as the same `snake_case` labels the core [`aa_core::EnforcementMode`]
/// uses. A dedicated schema (rather than surfacing the core enum) so the
/// generated OpenAPI advertises a closed enum. Emitted only when the agent
/// declares an override; see [`AgentConfigResponse::enforcement_mode`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum EnforcementModeLabel {
    Enforce,
    Observe,
    Disabled,
}

/// One policy document in the agent's effective cascade.
///
/// AAASM-5098 — the honest identity of a document already loaded in the engine:
/// its scope-qualified id, human name, optional version, and scope label. Mirrors
/// the `Policy` identity the capability matrix emits (`{scope}/{name}` id) so the
/// Config-YAML tab and the Capability page name the same document the same way.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct AgentConfigPolicyRef {
    /// Scope-qualified id (`{scope}/{name}`, or the bare scope when the document
    /// is unnamed) — matches the capability matrix's per-policy id.
    pub id: String,
    /// Human-readable document name, falling back to the scope label when unnamed.
    pub name: String,
    /// Wire-format scope label (e.g. `"global"`, `"team:platform"`).
    pub scope: String,
    /// Document `policy_version`, if the source declared one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

/// A qualitative posture recommendation for the agent (AAASM-5098, ADR-0022).
///
/// Names the resources that dominate the agent's recent denials so an operator
/// can see *what* to narrow, without asserting a quantified improvement. The
/// `−N%` counterfactual is deliberately withheld — producing it requires the
/// traffic replay AAASM-5094 builds, and fabricating a percentage would ship a
/// number the product cannot stand behind (ADR-0022 §Option C). Every count here
/// is a historical denial tally over the window, not a prediction.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct AgentConfigRecommendation {
    /// Recent window the finding covers (e.g. `"7d"`).
    pub window: String,
    /// Total denials (`PolicyViolation` audit events) counted in the window.
    pub total_denials: u64,
    /// The resources responsible for the most denials, most-denied first.
    pub top_resources: Vec<DeniedResourceShare>,
    /// Share of the window's denials the `top_resources` together account for,
    /// as a 0–100 percentage of `total_denials` (a historical count ratio, not a
    /// projected improvement).
    pub top_resources_share_pct: f64,
    /// Human-readable qualitative finding, e.g. "3 resources account for 78% of
    /// this agent's denials in the last 7 days". Names resources, never a policy
    /// (naming a specific policy needs a matcher that does not exist) and never a
    /// projected improvement percentage.
    pub summary: String,
}

/// One resource's contribution to an agent's recent denials.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DeniedResourceShare {
    /// The denied resource (the audit `blocked_action`, e.g. `"gmail/write"`).
    pub resource: String,
    /// Denials attributed to this resource in the window.
    pub denials: u64,
    /// This resource's share of `total_denials`, as a 0–100 percentage.
    pub share_pct: f64,
}

/// Per-agent config projection returned by `GET /api/v1/agents/{id}/config`.
///
/// AAASM-5098 (ADR-0022, narrow Option C). Backs the Agent-Detail Config-YAML
/// tab. **Every field carries a real per-agent server-side source** — the
/// contract deliberately omits the mock's `fail_open`, `rate_limit`,
/// `observability`, and `issuer` because ADR-0022 verified none of them has a
/// per-agent source. They are absent from this schema entirely rather than
/// emitted as `null`: a null `observability` would imply the concept exists and
/// is unset, a stronger claim than the truth.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct AgentConfigResponse {
    /// Hex-encoded agent UUID.
    pub agent_id: String,
    /// The agent's registered enforcement-mode override, sourced from
    /// `AgentRecord.enforcement_mode` — the field the enforcement path consults,
    /// **not** the free-form `metadata["mode"]` the Topology/Fleet views render
    /// (ADR-0021 / ADR-0022). `None` (omitted) when the agent declares no
    /// per-agent override, in which case the effective mode is decided per policy
    /// document, not per agent — omitted rather than defaulted so the response
    /// never fabricates a posture the agent did not set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enforcement_mode: Option<EnforcementModeLabel>,
    /// The policy documents in the agent's effective cascade, broadest → narrowest.
    pub policies: Vec<AgentConfigPolicyRef>,
    /// Qualitative posture recommendation, or `None` (omitted) when the agent has
    /// too few denials in the window to rank a dominant resource. Qualitative
    /// only — no quantified improvement estimate (ADR-0022; the `−N%` is blocked
    /// on AAASM-5094's replay).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recommendation: Option<AgentConfigRecommendation>,
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
        assert_eq!(decision_label(1), DecisionLabel::Allow);
        assert_eq!(decision_label(2), DecisionLabel::Deny);
        assert_eq!(decision_label(3), DecisionLabel::Pending);
        assert_eq!(decision_label(4), DecisionLabel::Redact);
        assert_eq!(decision_label(0), DecisionLabel::Unspecified);
        assert_eq!(decision_label(99), DecisionLabel::Unspecified);
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
        assert_eq!(row.decision_label, DecisionLabel::Allow);
        assert_eq!(row.verb.as_deref(), Some("TOOL_CALL"));
        assert_eq!(row.resource.as_deref(), Some("pg.users"));
        assert_eq!(row.matched_policy, None);
        // A legacy payload carrying no verdict/latency_ms keys (written before
        // AAASM-5100 capture landed) must still read null — the capture is
        // additive, never fabricated for rows that lack a source.
        assert_eq!(row.latency_ms, None);
        assert_eq!(row.verdict, None);
        assert_eq!(row.trace_id, None);
        assert_eq!(row.seq, 7);
        assert_eq!(row.session_id, "ee".repeat(16));
    }

    // ── AAASM-5356: the sensitive-data disposition read path ──────────────
    //
    // `entry_to_decision_row` is the *only* code that ever populates
    // `sensitive_data_disposition`. Without the four tests below the field
    // could be permanently unpopulatable and nothing would notice: the wire
    // contract tests assert the published *shape*, and the OpenAPI drift gate
    // derives the spec from the struct rather than from this reader, so both
    // stay green against a read path gutted to `let x = None;`.

    /// A payload carrying a disposition surfaces it on the row.
    ///
    /// The case the writer AAASM-5357 will produce. Asserted against the real
    /// audit-payload key (`sensitive_data_disposition`, snake_case like every
    /// other payload key) rather than the camelCase wire name, because this is
    /// the read side of the audit log, not the response.
    #[test]
    fn a_payload_carrying_a_disposition_surfaces_it_on_the_row() {
        let entry = decision_entry(
            r#"{"action_type":"TOOL_CALL","decision":4,"verdict":"scrub","sensitive_data_disposition":"redact","detail":{"kind":"tool_call","tool_name":"gmail.send"}}"#,
        );
        let row = entry_to_decision_row(&entry).expect("redact carries a decision");

        assert_eq!(row.sensitive_data_disposition, Some(SensitiveDataDisposition::Redact));
        // The coarse verdict a disposition-blind reader falls back to agrees
        // with the finer field, which is the whole point of the mapping.
        assert_eq!(row.verdict, Some(RuntimeVerdict::Scrub));
        assert_eq!(
            row.sensitive_data_disposition
                .and_then(SensitiveDataDisposition::implied_verdict),
            row.verdict,
        );
    }

    /// Every one of the eight spellings survives the read path.
    ///
    /// A loop, but not a vacuous one: the expectations come from the wire
    /// spellings the audit log would carry, and each is fed through
    /// `entry_to_decision_row` rather than through `Deserialize` directly, so
    /// this fails if the reader looks up the wrong payload key or parses the
    /// wrong way.
    #[test]
    fn every_disposition_spelling_survives_the_read_path() {
        use SensitiveDataDisposition as D;
        let cases = [
            ("redact", D::Redact),
            ("mask", D::Mask),
            ("tokenize", D::Tokenize),
            ("require_approval", D::RequireApproval),
            ("approval_granted", D::ApprovalGranted),
            ("approval_denied", D::ApprovalDenied),
            ("shadow_only", D::ShadowOnly),
            ("none", D::None),
        ];
        assert_eq!(cases.len(), 8, "ADR 0032 §10 D-2 fixes eight dispositions");

        for (spelling, expected) in cases {
            let entry = decision_entry(&format!(
                r#"{{"action_type":"TOOL_CALL","decision":1,"sensitive_data_disposition":"{spelling}"}}"#
            ));
            let row = entry_to_decision_row(&entry).expect("the payload carries a decision");
            assert_eq!(
                row.sensitive_data_disposition,
                Some(expected),
                "the read path lost {spelling:?}",
            );
        }
    }

    /// A payload omitting the key reads as absent — the legacy-row case, which
    /// is every row today.
    ///
    /// This is ADR 0032 §10 D-2's first binding rule at the read boundary: an
    /// absent key must not become a default that claims something happened.
    #[test]
    fn a_payload_omitting_the_disposition_reads_as_absent() {
        let entry = decision_entry(
            r#"{"action_type":"TOOL_CALL","decision":1,"detail":{"kind":"tool_call","tool_name":"pg.users"}}"#,
        );
        let row = entry_to_decision_row(&entry).expect("tool_call carries a decision");

        assert_eq!(row.sensitive_data_disposition, None);
        // And absence is invisible on the wire, not a null.
        let json = serde_json::to_string(&row).unwrap();
        assert!(
            !json.contains("sensitiveDataDisposition"),
            "an absent disposition leaked onto the wire: {json}",
        );
    }

    /// An unparseable spelling reads as **absent**, not as an error and not as
    /// a defaulted value.
    ///
    /// Pinned because it is a real semantic cost, not an accident: after this
    /// change "absent" means *no disposition recorded* **or** *a disposition
    /// this build could not parse*. It is bounded — `verdict` is parsed
    /// independently on the line above and stays the authoritative outcome, so
    /// a fallback reader is never misled about whether the action was permitted
    /// — and it mirrors how the `verdict` read itself already degrades. The
    /// alternative, failing the whole row, would hide a decision from the
    /// operator over an optional reporting field.
    #[test]
    fn an_unparseable_disposition_reads_as_absent_rather_than_failing_the_row() {
        let entry = decision_entry(
            r#"{"action_type":"TOOL_CALL","decision":2,"verdict":"deny","sensitive_data_disposition":"quarantine"}"#,
        );
        let row = entry_to_decision_row(&entry).expect("the row survives an unknown disposition");

        assert_eq!(row.sensitive_data_disposition, None);
        // The bound on the cost: the authoritative outcome is untouched.
        assert_eq!(row.verdict, Some(RuntimeVerdict::Deny));
    }

    #[test]
    fn scrubbed_action_records_scrub_verdict_distinct_from_allow() {
        // AAASM-5100 item A — a DLP-scrubbed action is forwarded (proto Redact,
        // decision=4) but its captured verdict must be `scrub`, never `allow`,
        // so scrubbed traffic is visible as distinct from a clean allow.
        let entry = decision_entry(
            r#"{"action_type":"TOOL_CALL","decision":4,"verdict":"scrub","latency_ms":3,"detail":{"kind":"tool_call","tool_name":"gmail.send"}}"#,
        );
        let row = entry_to_decision_row(&entry).expect("redact carries a decision");
        assert_eq!(row.verdict, Some(RuntimeVerdict::Scrub));
        assert_ne!(row.verdict, Some(RuntimeVerdict::Allow));
    }

    #[test]
    fn narrowed_action_records_narrow_verdict_distinct_from_deny() {
        // AAASM-5100 item A — a scoped-but-permitted action (proto Allow,
        // decision=1, but the gateway flagged it narrowed) records the `narrow`
        // verdict, distinct from `deny` — the UI shows partial success, not a
        // block.
        let entry = decision_entry(
            r#"{"action_type":"FILE_OPERATION","decision":1,"verdict":"narrow","latency_ms":1,"detail":{"kind":"file_op","path":"/tmp/x"}}"#,
        );
        let row = entry_to_decision_row(&entry).expect("allow carries a decision");
        assert_eq!(row.verdict, Some(RuntimeVerdict::Narrow));
        assert_ne!(row.verdict, Some(RuntimeVerdict::Deny));
    }

    #[test]
    fn normal_decision_records_positive_latency_ms() {
        // AAASM-5100 item B — a normal allow decision now carries the captured
        // per-decision latency (ms) rather than the frozen null.
        let entry = decision_entry(
            r#"{"action_type":"TOOL_CALL","decision":1,"verdict":"allow","latency_ms":5,"detail":{"kind":"tool_call","tool_name":"pg.read"}}"#,
        );
        let row = entry_to_decision_row(&entry).expect("allow carries a decision");
        assert_eq!(row.latency_ms, Some(5));
        assert!(
            row.latency_ms.unwrap() > 0,
            "a measured decision reports positive latency"
        );
    }

    #[test]
    fn trace_id_stays_null_item_c_not_implemented() {
        // AAASM-5100 scope guard — item C (trace-id propagation) is Phase 2 and
        // NOT implemented here. Even when the payload carries a trace_id (used by
        // the /traces surface), the decision row's trace_id must stay null so no
        // consumer assumes item C shipped with items A+B.
        let entry = decision_entry(
            r#"{"action_type":"TOOL_CALL","decision":1,"verdict":"allow","latency_ms":2,"trace_id":"abc123"}"#,
        );
        let row = entry_to_decision_row(&entry).expect("allow carries a decision");
        assert_eq!(row.trace_id, None, "trace_id must stay null until Phase 2");
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
        assert_eq!(row.decision_label, DecisionLabel::Deny);
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

    // ── AAASM-5102: the cascade this endpoint reports must be tenancy-aware ──

    fn admin() -> RequireRead {
        RequireRead(AuthenticatedCaller {
            key_id: "k".to_string(),
            scopes: vec![Scope::Admin],
            tenant: crate::auth::Tenant {
                org_id: None,
                team_id: None,
            },
        })
    }

    /// Minimal registered agent owned by `team_id`. Only the fields the
    /// capabilities path reads (id, tenancy) carry meaningful values.
    fn record(id_byte: u8, team_id: Option<&str>) -> aa_gateway::registry::AgentRecord {
        aa_gateway::registry::AgentRecord {
            agent_id: [id_byte; 16],
            name: "a".to_string(),
            framework: "langgraph".to_string(),
            version: "0.1.0".to_string(),
            risk_tier: 1,
            tool_names: Vec::new(),
            public_key: "pk".to_string(),
            credential_token: "tok".to_string(),
            metadata: BTreeMap::new(),
            registered_at: chrono::Utc::now(),
            last_heartbeat: chrono::Utc::now(),
            status: AgentStatus::Active,
            pid: None,
            session_count: 0,
            last_event: None,
            active_sessions: Vec::new(),
            recent_events: std::collections::VecDeque::new(),
            recent_traces: Vec::new(),
            layer: None,
            governance_level: aa_core::GovernanceLevel::default(),
            parent_agent_id: None,
            team_id: team_id.map(str::to_string),
            org_id: None,
            depth: 0,
            delegation_reason: None,
            spawned_by_tool: None,
            root_agent_id: Some([id_byte; 16]),
            children: Vec::new(),
            parent_key: None,
            enforcement_mode: None,
            enforcement_mode_expires_at: None,
        }
    }

    /// A policy document carrying only the capability block the cascade reads.
    fn policy_doc(
        name: &str,
        scope: aa_gateway::policy::PolicyScope,
        capabilities: aa_core::CapabilitySet,
    ) -> aa_gateway::policy::PolicyDocument {
        aa_gateway::policy::PolicyDocument {
            name: Some(name.to_string()),
            policy_version: Some("1".to_string()),
            version: None,
            scope,
            network: None,
            schedule: None,
            budget: None,
            data: None,
            approval_timeout_secs: 300,
            approval_policy: None,
            tools: Default::default(),
            capabilities: Some(capabilities),
            filesystem: None,
        }
    }

    /// `AppState::local_in_memory` loads a budget-only policy file, so the
    /// documents under test have to be pushed into the engine directly.
    fn state_with_policies(
        records: Vec<aa_gateway::registry::AgentRecord>,
        docs: Vec<aa_gateway::policy::PolicyDocument>,
    ) -> AppState {
        let mut state = AppState::local_in_memory().expect("state builds");
        for r in records {
            state.agent_registry.register(r).expect("register");
        }
        let engine =
            std::sync::Arc::get_mut(&mut state.policy_engine).expect("engine is unshared until the state is cloned");
        for doc in docs {
            engine.load_policy(doc);
        }
        state
    }

    /// Regression guard for AAASM-5102. `AppState::local_in_memory` never called
    /// `PolicyEngine::with_registry`, so `effective_permissions` resolved
    /// `Lineage::default()` and walked only Global and Agent — this endpoint
    /// dropped every Org- and Team-scoped allow *and* deny, reporting a
    /// team-denied capability as permitted (a reporting fail-open). Enforcement
    /// was never affected; it resolves tenancy itself (AAASM-3729).
    #[tokio::test]
    async fn a_team_scoped_deny_reaches_the_capabilities_response() {
        let mut caps = aa_core::CapabilitySet::default();
        caps.deny.insert(aa_core::Capability::TerminalExec);

        let state = state_with_policies(
            vec![record(0x01, Some("team-alpha"))],
            vec![policy_doc(
                "team-rules",
                aa_gateway::policy::PolicyScope::Team("team-alpha".to_string()),
                caps,
            )],
        );

        let (status, Json(body)) = get_agent_capabilities(
            admin(),
            Extension(state),
            axum::extract::Path(hex::encode([0x01u8; 16])),
        )
        .await
        .expect("admin may read a registered agent's capabilities");

        assert_eq!(status, StatusCode::OK);
        assert!(
            body.deny.iter().any(|c| c == "terminal_exec"),
            "a Team-scoped deny must reach the merged set: {:?}",
            body.deny
        );
        assert!(
            body.sources.iter().any(|s| s.scope == "team:team-alpha"),
            "the Team tier must appear in the cascade provenance: {:?}",
            body.sources.iter().map(|s| &s.scope).collect::<Vec<_>>()
        );
    }

    // ── AAASM-5098 / ADR-0022: per-agent config projection ──────────────────

    /// A team-scoped (non-admin) caller belonging to `team_id`.
    fn team_caller(team_id: &str) -> RequireRead {
        RequireRead(AuthenticatedCaller {
            key_id: "k".to_string(),
            scopes: vec![Scope::Read],
            tenant: crate::auth::Tenant {
                org_id: None,
                team_id: Some(team_id.to_string()),
            },
        })
    }

    #[test]
    fn project_config_mode_maps_each_override_and_omits_absent() {
        use aa_core::EnforcementMode as M;
        assert_eq!(
            project_config_mode(Some(M::Enforce)),
            Some(EnforcementModeLabel::Enforce)
        );
        assert_eq!(
            project_config_mode(Some(M::Observe)),
            Some(EnforcementModeLabel::Observe)
        );
        assert_eq!(
            project_config_mode(Some(M::Disabled)),
            Some(EnforcementModeLabel::Disabled)
        );
        // No per-agent override → omitted, never defaulted to a fabricated mode.
        assert_eq!(project_config_mode(None), None);
    }

    /// ADR-0022 validation requirement: undefined config keys are absent from the
    /// serialized response, not `null`. `fail_open` / `rate_limit` /
    /// `observability` / `issuer` have no per-agent source, so they must never
    /// appear as keys; `enforcement_mode` and `recommendation` are absent (not
    /// null) when they have no value.
    #[test]
    fn unsupported_and_empty_fields_are_absent_not_null() {
        let resp = AgentConfigResponse {
            agent_id: "ab".repeat(16),
            enforcement_mode: None,
            policies: Vec::new(),
            recommendation: None,
        };
        let json = serde_json::to_value(&resp).unwrap();
        let obj = json.as_object().unwrap();

        // The ADR-0022 fields with no per-agent source are not in the contract.
        for absent in ["fail_open", "rate_limit", "observability", "issuer", "identity"] {
            assert!(
                !obj.contains_key(absent),
                "`{absent}` must not be in the config contract"
            );
        }
        // A `None` value is omitted, never emitted as an explicit null.
        assert!(
            !obj.contains_key("enforcement_mode"),
            "an absent enforcement_mode must be omitted, not null"
        );
        assert!(
            !obj.contains_key("recommendation"),
            "an absent recommendation must be omitted, not null"
        );
        // The always-present fields are still there.
        assert!(obj.contains_key("agent_id"));
        assert!(obj.contains_key("policies"));
    }

    #[test]
    fn enforcement_mode_serializes_snake_case() {
        let json = serde_json::to_value(EnforcementModeLabel::Observe).unwrap();
        assert_eq!(json, serde_json::json!("observe"));
    }

    /// Build a `PolicyViolation`-shaped audit entry whose payload names a denied
    /// resource via `action_type` (the real gateway denial write shape — no
    /// `detail` object).
    fn denial_entry(action_type: &str) -> AuditEntry {
        decision_entry(&format!(r#"{{"action_type":"{action_type}","decision":2}}"#))
    }

    #[test]
    fn recommendation_ranks_dominant_resources_and_reports_shares() {
        // 10 denials: 5×gmail/write, 3×gdrive/write, 2×http/write.
        let mut entries = Vec::new();
        for _ in 0..5 {
            entries.push(denial_entry("gmail/write"));
        }
        for _ in 0..3 {
            entries.push(denial_entry("gdrive/write"));
        }
        for _ in 0..2 {
            entries.push(denial_entry("http/write"));
        }

        let reco = build_denial_recommendation(&entries).expect("10 denials clears the floor");
        assert_eq!(reco.total_denials, 10);
        assert_eq!(reco.window, "7d");
        // Ranked most-denied first.
        let names: Vec<&str> = reco.top_resources.iter().map(|r| r.resource.as_str()).collect();
        assert_eq!(names, vec!["gmail/write", "gdrive/write", "http/write"]);
        assert_eq!(reco.top_resources[0].denials, 5);
        assert!((reco.top_resources[0].share_pct - 50.0).abs() < 1e-9);
        // All three fit within CONFIG_RECO_TOP_N, so they account for 100%.
        assert!((reco.top_resources_share_pct - 100.0).abs() < 1e-9);
        // Qualitative only: no percentage-improvement claim, no policy named.
        assert!(reco.summary.contains("gmail/write"));
        assert!(!reco.summary.contains('%') || reco.summary.contains("of this agent's denials"));
        assert!(
            !reco.summary.to_lowercase().contains("p-0"),
            "must not name a specific policy"
        );
    }

    #[test]
    fn recommendation_caps_at_top_n_and_reports_partial_share() {
        // 4 distinct resources, 10 denials: 4,3,2,1. Only top 3 are named; their
        // share is (4+3+2)/10 = 90%.
        let mut entries = Vec::new();
        for (res, n) in [("a", 4), ("b", 3), ("c", 2), ("d", 1)] {
            for _ in 0..n {
                entries.push(denial_entry(res));
            }
        }
        let reco = build_denial_recommendation(&entries).unwrap();
        assert_eq!(reco.top_resources.len(), CONFIG_RECO_TOP_N);
        assert_eq!(reco.total_denials, 10);
        assert!((reco.top_resources_share_pct - 90.0).abs() < 1e-9);
    }

    /// ADR-0022 validation requirement: the recommendation returns empty rather
    /// than a low-confidence finding when the agent has too few denials to rank.
    #[test]
    fn recommendation_withheld_below_confidence_floor() {
        let entries: Vec<AuditEntry> = (0..(CONFIG_RECO_MIN_DENIALS - 1))
            .map(|_| denial_entry("gmail/write"))
            .collect();
        assert!(
            build_denial_recommendation(&entries).is_none(),
            "below the floor the finding must be withheld, not shipped low-confidence"
        );
        // No denials at all → also withheld.
        assert!(build_denial_recommendation(&[]).is_none());
    }

    /// The config endpoint sources `enforcement_mode` from `AgentRecord`, not
    /// from `metadata["mode"]` (ADR-0022), and projects the effective cascade.
    #[tokio::test]
    async fn config_sources_mode_from_record_not_metadata() {
        let mut rec = record(0x01, Some("team-alpha"));
        rec.enforcement_mode = Some(aa_core::EnforcementMode::Observe);
        // A conflicting free-form metadata mode must NOT be what the endpoint reports.
        rec.metadata.insert("mode".to_string(), "enforce".to_string());

        let state = state_with_policies(
            vec![rec],
            vec![policy_doc(
                "team-rules",
                aa_gateway::policy::PolicyScope::Team("team-alpha".to_string()),
                aa_core::CapabilitySet::default(),
            )],
        );

        let (status, Json(body)) = get_agent_config(
            admin(),
            Extension(state),
            axum::extract::Path(hex::encode([0x01u8; 16])),
        )
        .await
        .expect("admin may read config");

        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            body.enforcement_mode,
            Some(EnforcementModeLabel::Observe),
            "mode must come from enforcement_mode (Observe), not metadata[\"mode\"] (enforce)"
        );
        assert!(
            body.policies.iter().any(|p| p.scope == "team:team-alpha"),
            "the team policy must appear in the cascade: {:?}",
            body.policies.iter().map(|p| &p.id).collect::<Vec<_>>()
        );
        // No denials seeded → recommendation withheld, not fabricated.
        assert!(body.recommendation.is_none());
    }

    /// Tenant scoping: a caller from another team may not read the agent's config
    /// — a per-agent config leak across tenants would be an IDOR (ADR-0022).
    #[tokio::test]
    async fn config_denies_cross_tenant_caller() {
        let state = state_with_policies(vec![record(0x02, Some("team-alpha"))], vec![]);

        let err = get_agent_config(
            team_caller("team-beta"),
            Extension(state),
            axum::extract::Path(hex::encode([0x02u8; 16])),
        )
        .await
        .expect_err("a team-beta caller must not read a team-alpha agent's config");

        assert_eq!(err.status, StatusCode::FORBIDDEN.as_u16());
    }

    // ── AAASM-5097 / ADR-0021: enforcement-mode toggle ──────────────────────

    /// A tenant-scoped caller holding `Write` (but not `Admin`) in `team_id`.
    fn write_caller(team_id: &str) -> RequireWrite {
        RequireWrite(AuthenticatedCaller {
            key_id: "writer".to_string(),
            scopes: vec![Scope::Write],
            tenant: crate::auth::Tenant {
                org_id: None,
                team_id: Some(team_id.to_string()),
            },
        })
    }

    /// An `Admin` caller (satisfies the `RequireWrite` extractor floor and the
    /// in-handler Admin gate). No team scope — an admin is not tenant-confined.
    fn admin_write() -> RequireWrite {
        RequireWrite(AuthenticatedCaller {
            key_id: "root".to_string(),
            scopes: vec![Scope::Admin],
            tenant: crate::auth::Tenant {
                org_id: None,
                team_id: None,
            },
        })
    }

    fn enforce_body() -> EnforcementModeRequest {
        EnforcementModeRequest {
            mode: EnforcementModeTarget::Enforce,
            reason: None,
            expires_at: None,
            cascade: None,
        }
    }

    fn observe_body(reason: Option<&str>, expires_at: Option<DateTime<Utc>>) -> EnforcementModeRequest {
        EnforcementModeRequest {
            mode: EnforcementModeTarget::Observe,
            reason: reason.map(str::to_string),
            expires_at,
            cascade: None,
        }
    }

    /// Unwrap a single-agent apply response, failing loudly on a cascade shape.
    fn expect_single(body: EnforcementModeApplyResponse) -> EnforcementModeResponse {
        match body {
            EnforcementModeApplyResponse::Single(r) => r,
            EnforcementModeApplyResponse::Cascade(_) => panic!("expected a single-agent response, got a cascade"),
        }
    }

    /// Unwrap a cascade apply response, failing loudly on a single shape.
    fn expect_cascade(body: EnforcementModeApplyResponse) -> EnforcementModeCascadeResponse {
        match body {
            EnforcementModeApplyResponse::Cascade(r) => r,
            EnforcementModeApplyResponse::Single(_) => panic!("expected a cascade response, got a single-agent one"),
        }
    }

    /// `disabled` is not a variant of the request target, so a body naming it
    /// fails deserialization and never reaches the handler (ADR-0021: Disabled
    /// is not exposed via the API under any input).
    #[test]
    fn disabled_mode_is_not_deserializable() {
        let err = serde_json::from_str::<EnforcementModeRequest>(r#"{"mode":"disabled"}"#);
        assert!(err.is_err(), "'disabled' must not deserialize as a target mode");
        // The two legitimate targets do deserialize.
        assert!(serde_json::from_str::<EnforcementModeRequest>(r#"{"mode":"enforce"}"#).is_ok());
        assert!(serde_json::from_str::<EnforcementModeRequest>(
            r#"{"mode":"observe","reason":"x","expires_at":"2030-01-01T00:00:00Z"}"#
        )
        .is_ok());
    }

    /// Weakening to shadow requires Admin: a Write-but-not-Admin caller is
    /// refused 403 even with a valid reason + expiry, and the agent's mode is
    /// left untouched (the fail-open direction is Admin-only).
    #[tokio::test]
    async fn weaken_requires_admin() {
        let state = state_with_policies(vec![record(0x01, Some("team-alpha"))], vec![]);
        let registry = state.agent_registry.clone();

        let err = set_enforcement_mode(
            write_caller("team-alpha"),
            Extension(state),
            axum::extract::Path(hex::encode([0x01u8; 16])),
            Json(observe_body(
                Some("incident debug"),
                Some(Utc::now() + chrono::Duration::hours(1)),
            )),
        )
        .await
        .expect_err("a Write-only caller must not weaken enforcement");

        assert_eq!(err.status, StatusCode::FORBIDDEN.as_u16());
        // Mode unchanged — the refused mutation never touched the record.
        assert_eq!(registry.get(&[0x01u8; 16]).unwrap().enforcement_mode, None);
    }

    /// Weakening requires a non-empty reason: an Admin caller with a valid
    /// expiry but a missing or whitespace-only reason is refused 422.
    #[tokio::test]
    async fn weaken_requires_non_empty_reason() {
        for reason in [None, Some("   ")] {
            let state = state_with_policies(vec![record(0x01, Some("team-alpha"))], vec![]);
            let err = set_enforcement_mode(
                admin_write(),
                Extension(state),
                axum::extract::Path(hex::encode([0x01u8; 16])),
                Json(observe_body(reason, Some(Utc::now() + chrono::Duration::hours(1)))),
            )
            .await
            .expect_err("a weaken with no reason must be rejected");
            assert_eq!(err.status, StatusCode::UNPROCESSABLE_ENTITY.as_u16());
        }
    }

    /// Weakening requires an expiry: an Admin caller with a valid reason but no
    /// `expires_at` is refused 422 (a shadow window must self-heal).
    #[tokio::test]
    async fn weaken_requires_expires_at() {
        let state = state_with_policies(vec![record(0x01, Some("team-alpha"))], vec![]);
        let err = set_enforcement_mode(
            admin_write(),
            Extension(state),
            axum::extract::Path(hex::encode([0x01u8; 16])),
            Json(observe_body(Some("incident debug"), None)),
        )
        .await
        .expect_err("a weaken with no expires_at must be rejected");
        assert_eq!(err.status, StatusCode::UNPROCESSABLE_ENTITY.as_u16());
    }

    /// The shadow window is bounded: an `expires_at` beyond SHADOW_MAX_HOURS, or
    /// one in the past, is refused 422.
    #[tokio::test]
    async fn weaken_rejects_expiry_past_or_beyond_max() {
        // Beyond the 72h cap.
        let state = state_with_policies(vec![record(0x01, Some("team-alpha"))], vec![]);
        let err = set_enforcement_mode(
            admin_write(),
            Extension(state),
            axum::extract::Path(hex::encode([0x01u8; 16])),
            Json(observe_body(
                Some("too long"),
                Some(Utc::now() + chrono::Duration::hours(SHADOW_MAX_HOURS + 1)),
            )),
        )
        .await
        .expect_err("an expiry beyond the max must be rejected");
        assert_eq!(err.status, StatusCode::UNPROCESSABLE_ENTITY.as_u16());

        // In the past.
        let state = state_with_policies(vec![record(0x01, Some("team-alpha"))], vec![]);
        let err = set_enforcement_mode(
            admin_write(),
            Extension(state),
            axum::extract::Path(hex::encode([0x01u8; 16])),
            Json(observe_body(
                Some("already gone"),
                Some(Utc::now() - chrono::Duration::minutes(1)),
            )),
        )
        .await
        .expect_err("a past expiry must be rejected");
        assert_eq!(err.status, StatusCode::UNPROCESSABLE_ENTITY.as_u16());
    }

    /// A valid weaken by an Admin sets the canonical `enforcement_mode` to
    /// Observe and records the shadow deadline durably; the response echoes both.
    #[tokio::test]
    async fn weaken_success_sets_observe_and_expiry() {
        let state = state_with_policies(vec![record(0x01, Some("team-alpha"))], vec![]);
        let registry = state.agent_registry.clone();
        let deadline = Utc::now() + chrono::Duration::hours(2);

        let (status, Json(body)) = set_enforcement_mode(
            admin_write(),
            Extension(state),
            axum::extract::Path(hex::encode([0x01u8; 16])),
            Json(observe_body(Some("incident debug"), Some(deadline))),
        )
        .await
        .expect("a valid weaken succeeds");

        assert_eq!(status, StatusCode::OK);
        let body = expect_single(body);
        assert_eq!(body.new_mode, EnforcementModeLabel::Observe);
        assert_eq!(body.expires_at, Some(deadline));
        // The canonical field the enforcement resolver reads is set, with expiry.
        let rec = registry.get(&[0x01u8; 16]).unwrap();
        assert_eq!(rec.enforcement_mode, Some(aa_core::EnforcementMode::Observe));
        assert_eq!(rec.enforcement_mode_expires_at, Some(deadline));
    }

    /// Strengthening (→ enforce) is the safe direction: a plain `Write` caller
    /// may do it with no reason and no expiry, and any prior shadow expiry is
    /// cleared so the agent returns to permanent enforcement.
    #[tokio::test]
    async fn strengthen_allowed_for_write_and_clears_expiry() {
        let mut rec = record(0x01, Some("team-alpha"));
        // Pre-existing shadow window that the strengthen must clear.
        rec.enforcement_mode = Some(aa_core::EnforcementMode::Observe);
        rec.enforcement_mode_expires_at = Some(Utc::now() + chrono::Duration::hours(1));
        let state = state_with_policies(vec![rec], vec![]);
        let registry = state.agent_registry.clone();

        let (status, Json(body)) = set_enforcement_mode(
            write_caller("team-alpha"),
            Extension(state),
            axum::extract::Path(hex::encode([0x01u8; 16])),
            Json(enforce_body()),
        )
        .await
        .expect("a Write caller may strengthen with no ceremony");

        assert_eq!(status, StatusCode::OK);
        let body = expect_single(body);
        assert_eq!(body.new_mode, EnforcementModeLabel::Enforce);
        assert_eq!(body.previous_mode, Some(EnforcementModeLabel::Observe));
        assert_eq!(body.expires_at, None, "strengthen echoes no expiry");
        let after = registry.get(&[0x01u8; 16]).unwrap();
        assert_eq!(after.enforcement_mode, Some(aa_core::EnforcementMode::Enforce));
        assert_eq!(
            after.enforcement_mode_expires_at, None,
            "strengthen must clear the prior shadow expiry"
        );
    }

    /// Deny-by-default / tenant confinement: a Write caller from another team
    /// may not toggle a team-alpha agent (mirrors suspend's tenant gate).
    #[tokio::test]
    async fn toggle_denies_cross_tenant_caller() {
        let state = state_with_policies(vec![record(0x01, Some("team-alpha"))], vec![]);
        let err = set_enforcement_mode(
            write_caller("team-beta"),
            Extension(state),
            axum::extract::Path(hex::encode([0x01u8; 16])),
            Json(enforce_body()),
        )
        .await
        .expect_err("a team-beta caller must not toggle a team-alpha agent");
        assert_eq!(err.status, StatusCode::FORBIDDEN.as_u16());
    }

    // ── AAASM-5340 / ADR-0021: cascade preview + echo-back apply ─────────────

    /// A child agent under `parent`, owned by `team_id`. `register` wires the
    /// parent→child link from `parent_key`, so `descendants_of(root)` sees it.
    fn child_record(id_byte: u8, parent_byte: u8, team_id: Option<&str>) -> aa_gateway::registry::AgentRecord {
        let mut r = record(id_byte, team_id);
        r.parent_key = Some([parent_byte; 16]);
        r.parent_agent_id = Some(hex::encode([parent_byte; 16]));
        r.root_agent_id = Some([parent_byte; 16]);
        r.depth = 1;
        r
    }

    /// An admin-scoped `RequireWrite` caller wired with an audit sink, returning
    /// the state plus a receiver the test drains to count emitted audits.
    fn state_with_audit(
        records: Vec<aa_gateway::registry::AgentRecord>,
    ) -> (AppState, tokio::sync::mpsc::Receiver<AuditEntry>) {
        let mut state = state_with_policies(records, vec![]);
        let (tx, rx) = tokio::sync::mpsc::channel::<AuditEntry>(4096);
        state.audit_sender = Some(tx);
        (state, rx)
    }

    fn cascade_body(
        mode: EnforcementModeTarget,
        reason: Option<&str>,
        expires_at: Option<DateTime<Utc>>,
        expected_ids: Vec<String>,
        expected_count: usize,
    ) -> EnforcementModeRequest {
        EnforcementModeRequest {
            mode,
            reason: reason.map(str::to_string),
            expires_at,
            cascade: Some(CascadeConfirmation {
                expected_ids,
                expected_count,
            }),
        }
    }

    /// Preview lists the subtree (root first, then descendants) with the count,
    /// and mutates nothing — every agent's mode is unchanged after the call.
    #[tokio::test]
    async fn preview_lists_subtree_and_mutates_nothing() {
        // root(0x01) → child(0x02), child(0x03); child(0x02) → grandchild(0x04).
        let state = state_with_policies(
            vec![
                record(0x01, Some("team-alpha")),
                child_record(0x02, 0x01, Some("team-alpha")),
                child_record(0x03, 0x01, Some("team-alpha")),
                child_record(0x04, 0x02, Some("team-alpha")),
            ],
            vec![],
        );
        let registry = state.agent_registry.clone();

        let (status, Json(body)) = preview_enforcement_mode_cascade(
            admin_write(),
            Extension(state),
            axum::extract::Path(hex::encode([0x01u8; 16])),
        )
        .await
        .expect("admin may preview the cascade");

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body.count, 4, "root + 3 descendants");
        assert_eq!(body.affected_ids.len(), 4);
        assert_eq!(body.affected_ids[0], hex::encode([0x01u8; 16]), "root is first");
        for b in [0x02u8, 0x03, 0x04] {
            assert!(
                body.affected_ids.contains(&hex::encode([b; 16])),
                "descendant {b} present"
            );
        }
        // Nothing mutated.
        for b in [0x01u8, 0x02, 0x03, 0x04] {
            assert_eq!(
                registry.get(&[b; 16]).unwrap().enforcement_mode,
                None,
                "preview must not mutate agent {b}"
            );
        }
    }

    /// A valid echo-back cascade applies the mode to EVERY agent in the set,
    /// and emits one GovernanceMutation audit per agent.
    #[tokio::test]
    async fn cascade_apply_mutates_all_and_audits_per_agent() {
        let (state, mut rx) = state_with_audit(vec![
            record(0x01, Some("team-alpha")),
            child_record(0x02, 0x01, Some("team-alpha")),
            child_record(0x03, 0x01, Some("team-alpha")),
        ]);
        let registry = state.agent_registry.clone();
        let ids: Vec<String> = [0x01u8, 0x02, 0x03].iter().map(|b| hex::encode([*b; 16])).collect();

        let (status, Json(body)) = set_enforcement_mode(
            admin_write(),
            Extension(state),
            axum::extract::Path(hex::encode([0x01u8; 16])),
            Json(cascade_body(EnforcementModeTarget::Enforce, None, None, ids, 3)),
        )
        .await
        .expect("a valid echo-back cascade succeeds");

        assert_eq!(status, StatusCode::OK);
        let body = expect_cascade(body);
        assert_eq!(body.count, 3);
        assert_eq!(body.new_mode, EnforcementModeLabel::Enforce);
        // Every agent in the set is at the target mode.
        for b in [0x01u8, 0x02, 0x03] {
            assert_eq!(
                registry.get(&[b; 16]).unwrap().enforcement_mode,
                Some(aa_core::EnforcementMode::Enforce),
                "agent {b} must be at enforce after the cascade"
            );
        }
        // One GovernanceMutation audit per affected agent.
        let mut govern = 0;
        while let Ok(entry) = rx.try_recv() {
            if entry.event_type() == aa_core::audit::AuditEventType::GovernanceMutation {
                govern += 1;
            }
        }
        assert_eq!(govern, 3, "one governance-mutation audit per affected agent");
    }

    /// A cascade whose echoed id set differs from the current subtree → 409.
    #[tokio::test]
    async fn cascade_apply_rejects_wrong_id_set() {
        let state = state_with_policies(
            vec![
                record(0x01, Some("team-alpha")),
                child_record(0x02, 0x01, Some("team-alpha")),
            ],
            vec![],
        );
        // Echo an id that is not in the subtree (0x09) in place of 0x02.
        let ids = vec![hex::encode([0x01u8; 16]), hex::encode([0x09u8; 16])];
        let err = set_enforcement_mode(
            admin_write(),
            Extension(state),
            axum::extract::Path(hex::encode([0x01u8; 16])),
            Json(cascade_body(EnforcementModeTarget::Enforce, None, None, ids, 2)),
        )
        .await
        .expect_err("a mismatched echo-back id set must be rejected");
        assert_eq!(err.status, StatusCode::CONFLICT.as_u16());
    }

    /// A cascade whose echoed count differs from the current subtree → 409,
    /// even when the id set matches (defence against a count/set desync).
    #[tokio::test]
    async fn cascade_apply_rejects_wrong_count() {
        let state = state_with_policies(
            vec![
                record(0x01, Some("team-alpha")),
                child_record(0x02, 0x01, Some("team-alpha")),
            ],
            vec![],
        );
        let ids = vec![hex::encode([0x01u8; 16]), hex::encode([0x02u8; 16])];
        let err = set_enforcement_mode(
            admin_write(),
            Extension(state),
            axum::extract::Path(hex::encode([0x01u8; 16])),
            Json(cascade_body(EnforcementModeTarget::Enforce, None, None, ids, 3)),
        )
        .await
        .expect_err("a mismatched echo-back count must be rejected");
        assert_eq!(err.status, StatusCode::CONFLICT.as_u16());
    }

    /// A subtree larger than MAX_CASCADE_AGENTS is rejected 422 — for BOTH the
    /// preview and the apply — never truncated. Built as a root with 50 direct
    /// children (51 total).
    #[tokio::test]
    async fn cascade_over_limit_rejected_on_preview_and_apply() {
        let mut records = vec![record(0x01, Some("team-alpha"))];
        for i in 0..(MAX_CASCADE_AGENTS as u8) {
            // Distinct non-root ids: 0x64.. avoids colliding with the root.
            records.push(child_record(0x64 + i, 0x01, Some("team-alpha")));
        }
        assert_eq!(records.len(), MAX_CASCADE_AGENTS + 1);

        // Preview: 422.
        let state = state_with_policies(records.clone(), vec![]);
        let err = preview_enforcement_mode_cascade(
            admin_write(),
            Extension(state),
            axum::extract::Path(hex::encode([0x01u8; 16])),
        )
        .await
        .expect_err("an over-limit subtree preview must be rejected");
        assert_eq!(err.status, StatusCode::UNPROCESSABLE_ENTITY.as_u16());

        // Apply: also 422 (the guard runs before the echo-back compare).
        let state = state_with_policies(records, vec![]);
        let ids = vec![hex::encode([0x01u8; 16])];
        let err = set_enforcement_mode(
            admin_write(),
            Extension(state),
            axum::extract::Path(hex::encode([0x01u8; 16])),
            Json(cascade_body(
                EnforcementModeTarget::Enforce,
                None,
                None,
                ids,
                MAX_CASCADE_AGENTS + 1,
            )),
        )
        .await
        .expect_err("an over-limit subtree apply must be rejected");
        assert_eq!(err.status, StatusCode::UNPROCESSABLE_ENTITY.as_u16());
    }

    /// Weakening a cascade carries the same direction-asymmetric gates as the
    /// single-agent case, applied to the set as a unit: Write-only → 403,
    /// missing reason → 422, missing expiry → 422.
    #[tokio::test]
    async fn cascade_weaken_requires_admin_reason_and_expiry() {
        let subtree = || {
            vec![
                record(0x01, Some("team-alpha")),
                child_record(0x02, 0x01, Some("team-alpha")),
            ]
        };
        let ids = || vec![hex::encode([0x01u8; 16]), hex::encode([0x02u8; 16])];
        let future = Utc::now() + chrono::Duration::hours(1);

        // Write-only caller weakening → 403.
        let state = state_with_policies(subtree(), vec![]);
        let err = set_enforcement_mode(
            write_caller("team-alpha"),
            Extension(state),
            axum::extract::Path(hex::encode([0x01u8; 16])),
            Json(cascade_body(
                EnforcementModeTarget::Observe,
                Some("dbg"),
                Some(future),
                ids(),
                2,
            )),
        )
        .await
        .expect_err("a Write-only caller must not weaken a cascade");
        assert_eq!(err.status, StatusCode::FORBIDDEN.as_u16());

        // Admin, missing reason → 422.
        let state = state_with_policies(subtree(), vec![]);
        let err = set_enforcement_mode(
            admin_write(),
            Extension(state),
            axum::extract::Path(hex::encode([0x01u8; 16])),
            Json(cascade_body(
                EnforcementModeTarget::Observe,
                None,
                Some(future),
                ids(),
                2,
            )),
        )
        .await
        .expect_err("a weaken cascade with no reason must be rejected");
        assert_eq!(err.status, StatusCode::UNPROCESSABLE_ENTITY.as_u16());

        // Admin, missing expiry → 422.
        let state = state_with_policies(subtree(), vec![]);
        let err = set_enforcement_mode(
            admin_write(),
            Extension(state),
            axum::extract::Path(hex::encode([0x01u8; 16])),
            Json(cascade_body(
                EnforcementModeTarget::Observe,
                Some("dbg"),
                None,
                ids(),
                2,
            )),
        )
        .await
        .expect_err("a weaken cascade with no expiry must be rejected");
        assert_eq!(err.status, StatusCode::UNPROCESSABLE_ENTITY.as_u16());
    }

    /// Tenant confinement: a subtree containing an agent the caller cannot
    /// access → 403 (the node is never silently dropped). The root is in the
    /// caller's team but a descendant was delegated into another team.
    #[tokio::test]
    async fn cascade_denies_when_subtree_crosses_tenant() {
        let state = state_with_policies(
            vec![
                record(0x01, Some("team-alpha")),
                // Descendant delegated into team-beta — invisible to a team-alpha caller.
                child_record(0x02, 0x01, Some("team-beta")),
            ],
            vec![],
        );

        // Preview surfaces the 403.
        let err = preview_enforcement_mode_cascade(
            write_caller("team-alpha"),
            Extension(state.clone()),
            axum::extract::Path(hex::encode([0x01u8; 16])),
        )
        .await
        .expect_err("a cross-tenant descendant must forbid the preview");
        assert_eq!(err.status, StatusCode::FORBIDDEN.as_u16());

        // An admin, not tenant-confined, may cascade over the mixed subtree.
        let (status, Json(body)) = preview_enforcement_mode_cascade(
            admin_write(),
            Extension(state),
            axum::extract::Path(hex::encode([0x01u8; 16])),
        )
        .await
        .expect("an admin is not tenant-confined");
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body.count, 2);
    }

    /// REGRESSION (AAASM-5338): the single-agent path (no `cascade` field) is
    /// unchanged — a Write caller strengthens one agent and nothing else, and
    /// the response is the single-agent shape.
    #[tokio::test]
    async fn single_agent_path_unchanged_without_cascade_field() {
        let state = state_with_policies(
            vec![
                record(0x01, Some("team-alpha")),
                child_record(0x02, 0x01, Some("team-alpha")),
            ],
            vec![],
        );
        let registry = state.agent_registry.clone();

        let (status, Json(body)) = set_enforcement_mode(
            write_caller("team-alpha"),
            Extension(state),
            axum::extract::Path(hex::encode([0x01u8; 16])),
            Json(enforce_body()),
        )
        .await
        .expect("the single-agent path still works");

        assert_eq!(status, StatusCode::OK);
        let body = expect_single(body);
        assert_eq!(body.agent_id, hex::encode([0x01u8; 16]));
        assert_eq!(body.new_mode, EnforcementModeLabel::Enforce);
        // Only the root changed — the child (a descendant) is untouched.
        assert_eq!(
            registry.get(&[0x01u8; 16]).unwrap().enforcement_mode,
            Some(aa_core::EnforcementMode::Enforce)
        );
        assert_eq!(
            registry.get(&[0x02u8; 16]).unwrap().enforcement_mode,
            None,
            "a non-cascade toggle must not touch descendants"
        );
    }
}
