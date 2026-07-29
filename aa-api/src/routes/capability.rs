//! Capability matrix endpoints (AAASM-1366, made live in AAASM-5090).
//!
//! `GET /capability/matrix` is a **read-only projection** of state the gateway
//! already holds — the agent registry plus the policy engine's capability
//! cascade. It evaluates nothing and enforces nothing: no runtime, proxy or
//! eBPF path is touched, and the projection cannot change a verdict.
//!
//! ## Where each cell comes from
//!
//! A cell is the merged capability grant for one agent, computed with the same
//! public `aa_core` helpers the enforcement guard uses
//! ([`aa_core::capability_is_denied`] and [`aa_core::CapabilitySet::allow_is_restricted`]),
//! so the matrix cannot drift from the guard's own most-restrictive-wins /
//! fail-closed semantics. The four matrix verbs are exactly the four verb-shaped
//! capability variants that [`aa_core::action_to_capability`] already maps
//! governance actions onto (`file_read` / `file_write` / `file_delete` /
//! `terminal_exec`), so no new verb-mapping rule is introduced here.
//!
//! ## What this projection deliberately does not cover
//!
//! Cells carry only `allow` / `deny` / `na`. The `narrow` and `approval`
//! decisions are products of *other* policy stages (credential scrubbing, and a
//! tool's `requires_approval_if` CEL condition evaluated against a concrete
//! action) — they cannot be read off a static capability set, and deciding them
//! for a whole grid would mean running the simulation oracle per cell. That view
//! is owned by the policy-replay story (AAASM-5094), so those decisions simply
//! never appear here rather than being approximated.
//!
//! Fields with no source in the gateway at all (trust score, over-permission
//! flags, per-policy 24h hit counts) are emitted as absent — see the field docs
//! on [`crate::models::capability`] for which story owns each one.
//!
//! ## Overrides are a display overlay
//!
//! `POST`/`DELETE /capability/override` record operator intent and are replayed
//! over the projection on read. They have never fed enforcement — the store is
//! read by these four handlers and nothing else — so an override annotates the
//! view without changing what the gateway actually permits.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::Path;
use axum::extract::Query;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::{Extension, Json};
use serde::Deserialize;
use tokio::sync::RwLock;
use utoipa::IntoParams;
use uuid::Uuid;

use aa_gateway::policy::rbac::MutationKind;
use aa_gateway::policy::scope::PolicyScope;

use crate::auth::policy_auth::{PolicyAuthorizationDenied, PolicyWriteAuth};
use crate::auth::scope::{RequireRead, Scope};
use crate::error::ProblemDetail;
use crate::models::capability::{
    AgentMode, AgentStatus, CapCell, CapabilityAgent, CapabilityMatrix, CapabilityOverrideRequest,
    CapabilityOverrideResponse, Decision, OverrideRecord, Policy, PolicyRule, PolicyStatus, Resource, ResourceGroup,
    Verb,
};
use crate::routes::enforcement_mirror::{agent_tool_ids, cascade_denies_all_egress, cascade_denies_tool};
use crate::routes::over_permission;
use crate::state::AppState;

/// Reasons a revoke request can fail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RevokeOverrideError {
    /// No active override with the supplied id exists.
    NotFound,
}

/// Append-only log of operator capability overrides, replayed over the live
/// projection on every read of the matrix.
///
/// The store deliberately holds no matrix of its own: the base values come from
/// the registry + policy cascade on each request, so an override never has to be
/// reconciled against a stale copy, and revoking one restores the projected
/// value with no bookkeeping. Nothing outside this module reads the store, so an
/// entry here annotates the dashboard view only — it does not reach enforcement.
#[derive(Debug, Default)]
pub struct CapabilityStore {
    overrides: RwLock<Vec<OverrideRecord>>,
}

impl CapabilityStore {
    /// Build an empty store. The matrix it overlays is projected per request.
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Return all recorded overrides, optionally filtered to those affecting
    /// a specific `agent_id`.
    pub async fn list_overrides(&self, agent_id: Option<&str>) -> Vec<OverrideRecord> {
        let log = self.overrides.read().await;
        match agent_id {
            None => log.clone(),
            Some(id) => log
                .iter()
                .filter(|r| r.agent_ids.iter().any(|a| a == id))
                .cloned()
                .collect(),
        }
    }

    /// Record a `(resource_id, verb, decision)` override across `req.agent_ids`
    /// and return its stable UUID.
    ///
    /// When `req.ttl_seconds` is `Some(n)`, a background Tokio task deactivates
    /// the entry after `n` seconds. The `Arc<Self>` receiver lets that task
    /// outlive the call.
    pub async fn record_override(self: Arc<Self>, req: &CapabilityOverrideRequest) -> String {
        let override_id = Uuid::new_v4().to_string();
        self.overrides.write().await.push(OverrideRecord {
            id: override_id.clone(),
            agent_ids: req.agent_ids.clone(),
            resource_id: req.resource_id.clone(),
            verb: req.verb,
            decision: req.decision,
            created_at: chrono::Utc::now().to_rfc3339(),
            active: true,
        });

        if let Some(ttl_secs) = req.ttl_seconds {
            let store = Arc::clone(&self);
            let id = override_id.clone();
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_secs(ttl_secs)).await;
                let _ = store.revoke_override(&id).await;
            });
        }

        override_id
    }

    /// Deactivate the override identified by `id` so it stops being replayed.
    ///
    /// Returns [`RevokeOverrideError::NotFound`] when no *active* entry carries
    /// that id — either it never existed or it was already revoked/expired.
    pub async fn revoke_override(&self, id: &str) -> Result<(), RevokeOverrideError> {
        let mut log = self.overrides.write().await;
        match log.iter_mut().find(|r| r.id == id && r.active) {
            Some(entry) => {
                entry.active = false;
                Ok(())
            }
            None => Err(RevokeOverrideError::NotFound),
        }
    }

    /// Replay every active override onto `matrix`, newest last so a later
    /// override of the same cell wins.
    ///
    /// An override naming an agent or resource the projection does not contain
    /// is skipped: the underlying grant may have gone away since it was
    /// recorded, and inventing a row for it would show a cell the policy
    /// cascade does not actually produce.
    pub async fn apply_overlay(&self, matrix: &mut CapabilityMatrix) {
        let log = self.overrides.read().await;
        for record in log.iter().filter(|r| r.active) {
            for agent in matrix.agents.iter_mut() {
                if !record.agent_ids.contains(&agent.id) {
                    continue;
                }
                if let Some(cell) = agent.caps.get_mut(&record.resource_id) {
                    match record.verb {
                        Verb::Read => cell.read = record.decision,
                        Verb::Write => cell.write = record.decision,
                        Verb::Delete => cell.delete = record.decision,
                        Verb::Exec => cell.exec = record.decision,
                    }
                }
            }
        }
    }
}

/// Query parameters for `GET /api/v1/capability/matrix`.
#[derive(Debug, Default, Deserialize, IntoParams)]
pub struct MatrixQueryParams {
    /// Return only the agent row whose `id` matches this value.
    #[param(example = "research-bot-04")]
    pub team_id: Option<String>,
    /// Return only the resource column whose `id` matches this value, and
    /// filter each agent's caps map to that single resource key.
    #[param(example = "gmail")]
    pub tool: Option<String>,
    /// When `true`, exclude capability cells where all four verb decisions are `na`.
    #[param(example = true)]
    pub effective_only: Option<bool>,
}

/// Project the live matrix and replay the active override overlay onto it.
///
/// Shared by the read and the override-write handlers so both agree on which
/// agents and resources exist at this instant.
async fn projected_matrix(state: &AppState) -> CapabilityMatrix {
    let records = state.agent_registry.list();
    let mut matrix = project_matrix(&records, state);
    state.capability_store.apply_overlay(&mut matrix).await;
    matrix
}

/// `GET /api/v1/capability/matrix` — return the agent × resource × verb ×
/// decision matrix that backs the dashboard Capability Matrix page.
///
/// Optional filters:
/// - `team_id` — return only the agent row whose `id` matches.
/// - `tool` — return only the resource column whose `id` matches and filter
///   each agent's `caps` map to that single key.
/// - `effective_only=true` — exclude cells where all four verb decisions are `na`.
#[utoipa::path(
    get,
    path = "/api/v1/capability/matrix",
    params(MatrixQueryParams),
    responses(
        (status = 200, description = "Capability matrix snapshot (filtered)", body = CapabilityMatrix),
        (status = 401, description = "Missing or invalid credentials"),
        (status = 403, description = "Caller lacks the admin role required to read the capability matrix")
    ),
    tag = "capability"
)]
pub async fn get_matrix(
    // AAASM-3846 — the capability matrix is sensitive policy state; require an
    // authenticated reader rather than serving it unauthenticated.
    // AAASM-4841 — like its `list_overrides` sibling (AAASM-4829), the matrix is
    // global control-plane state with no per-team partition: a `CapabilityAgent`
    // row names an agent but carries no team scope, so there is no tenant slice
    // to hand a team-scoped caller. Gate it to the same admin posture as the
    // apply/revoke mutation handlers rather than to any authenticated reader.
    RequireRead(caller): RequireRead,
    Query(params): Query<MatrixQueryParams>,
    Extension(state): Extension<AppState>,
) -> Result<(StatusCode, Json<CapabilityMatrix>), ProblemDetail> {
    if !caller.scopes.contains(&Scope::Admin) {
        return Err(ProblemDetail::from_status(StatusCode::FORBIDDEN)
            .with_detail("Reading the capability matrix requires admin scope".to_string()));
    }
    let mut matrix = projected_matrix(&state).await;

    if let Some(ref tid) = params.team_id {
        matrix.agents.retain(|a| &a.id == tid);
    }

    if let Some(ref tool) = params.tool {
        matrix.resources.retain(|r| &r.id == tool);
        for agent in &mut matrix.agents {
            agent.caps.retain(|k, _| k == tool);
        }
    }

    if params.effective_only == Some(true) {
        use Decision::Na;
        for agent in &mut matrix.agents {
            agent
                .caps
                .retain(|_, cell| !(cell.read == Na && cell.write == Na && cell.delete == Na && cell.exec == Na));
        }
    }

    Ok((StatusCode::OK, Json(matrix)))
}

/// `POST /api/v1/capability/override` — apply a capability override across
/// one or more agents. Mutating capability state is treated as a
/// `Global`-scope policy update, so the caller must hold the `OrgAdmin`
/// role (Admin API scope).
///
/// Returns the subset of agent rows that actually changed — the dashboard
/// uses this to drive an optimistic-UI rollback when an override fails.
/// An unknown `agentId` rejects the request with 400 and leaves the store
/// untouched; an unknown `resourceId` on an agent is silently skipped. A
/// `narrow` or `approval` decision is also rejected with 400 — the projection
/// emits only allow / deny / na, so no revoke could restore such a cell.
///
/// When `ttlSeconds` is present the override is automatically reverted after
/// that many seconds and the response status is **201 Created**. Without a
/// TTL the response is **200 OK** (unchanged behaviour).
#[utoipa::path(
    post,
    path = "/api/v1/capability/override",
    request_body = CapabilityOverrideRequest,
    responses(
        (status = 200, description = "Updated agent rows (no TTL)", body = CapabilityOverrideResponse),
        (status = 201, description = "Updated agent rows with TTL scheduled", body = CapabilityOverrideResponse),
        (status = 400, description = "Unknown agent id, or a decision the projection cannot express (narrow / approval)"),
        (status = 403, description = "Caller lacks the role required to mutate capability state")
    ),
    tag = "capability"
)]
pub async fn apply_override(
    policy_auth: PolicyWriteAuth,
    Extension(state): Extension<AppState>,
    Json(body): Json<CapabilityOverrideRequest>,
) -> Result<(StatusCode, Json<CapabilityOverrideResponse>), OverrideHandlerError> {
    policy_auth
        .check_mutation(&PolicyScope::Global, MutationKind::Update)
        .map_err(OverrideHandlerError::Forbidden)?;

    let has_ttl = body.ttl_seconds.is_some();

    // The projection emits only allow / deny / na (see the module docs: `narrow`
    // and `approval` are products of stages this endpoint does not run). An
    // override that wrote one of those would put a decision in the grid that no
    // projection can ever produce or restore.
    if matches!(body.decision, Decision::Narrow | Decision::Approval) {
        return Err(OverrideHandlerError::BadRequest(
            ProblemDetail::from_status(StatusCode::BAD_REQUEST).with_detail(
                "Capability overrides accept only allow, deny or na; narrow and approval are \
                 decided per action by other policy stages"
                    .to_string(),
            ),
        ));
    }

    // Validate every requested agent against the live projection before
    // recording anything, so one unknown id rejects the whole request rather
    // than logging an override that can never apply to a real row.
    let mut matrix = projected_matrix(&state).await;
    if let Some(unknown) = body
        .agent_ids
        .iter()
        .find(|id| !matrix.agents.iter().any(|a| &&a.id == id))
    {
        return Err(OverrideHandlerError::BadRequest(
            ProblemDetail::from_status(StatusCode::BAD_REQUEST).with_detail(format!("Unknown agent id: {unknown}")),
        ));
    }

    let override_id = Arc::clone(&state.capability_store).record_override(&body).await;

    // Re-apply the overlay so the echoed rows already carry the new decision.
    state.capability_store.apply_overlay(&mut matrix).await;
    let updated: Vec<CapabilityAgent> = matrix
        .agents
        .into_iter()
        .filter(|a| body.agent_ids.contains(&a.id) && a.caps.contains_key(&body.resource_id))
        .collect();

    let status = if has_ttl { StatusCode::CREATED } else { StatusCode::OK };
    Ok((status, Json(CapabilityOverrideResponse { override_id, updated })))
}

/// Unified error type for the override handler so 400 and 403 paths render
/// through their respective ProblemDetail / PolicyAuthorizationDenied
/// `IntoResponse` impls.
#[derive(Debug)]
pub enum OverrideHandlerError {
    BadRequest(ProblemDetail),
    Forbidden(PolicyAuthorizationDenied),
}

impl IntoResponse for OverrideHandlerError {
    fn into_response(self) -> axum::response::Response {
        match self {
            Self::BadRequest(p) => p.into_response(),
            Self::Forbidden(d) => d.into_response(),
        }
    }
}

/// Query parameters accepted by `GET /api/v1/capability/override`.
#[derive(serde::Deserialize)]
pub struct ListOverridesParams {
    agent_id: Option<String>,
}

/// `GET /api/v1/capability/override` — list all active capability overrides
/// recorded since the server started, optionally filtered to a single agent.
///
/// The response is an array of [`OverrideRecord`] objects. Each record
/// corresponds to one successful `POST /capability/override` call and carries
/// the agents, resource, verb, decision, and ISO 8601 timestamp of when the
/// override was applied.
#[utoipa::path(
    get,
    path = "/api/v1/capability/override",
    params(("agent_id" = Option<String>, Query, description = "Filter results to overrides that affect this agent id")),
    responses(
        (status = 200, description = "Active override records", body = Vec<OverrideRecord>),
        (status = 401, description = "Missing or invalid credentials"),
        (status = 403, description = "Caller lacks the admin role required to read the global override log")
    ),
    tag = "capability"
)]
pub async fn list_overrides(
    // AAASM-3846 / AAASM-4829 — the override log is global control-plane state:
    // it discloses every capability override applied across the whole fleet and
    // carries no per-team partition (an `OverrideRecord` names agent ids but no
    // team scope), so there is no tenant slice to hand a team-scoped caller.
    // Applying or revoking an override is a `PolicyScope::Global` / `OrgAdmin`
    // mutation (see `apply_override` / `revoke_override`); reading the log of
    // those mutations is gated to the same admin posture rather than to any
    // authenticated reader.
    RequireRead(caller): RequireRead,
    Query(params): Query<ListOverridesParams>,
    Extension(state): Extension<AppState>,
) -> Result<(StatusCode, Json<Vec<OverrideRecord>>), ProblemDetail> {
    if !caller.scopes.contains(&Scope::Admin) {
        return Err(ProblemDetail::from_status(StatusCode::FORBIDDEN)
            .with_detail("Reading the capability override log requires admin scope".to_string()));
    }
    let overrides = state.capability_store.list_overrides(params.agent_id.as_deref()).await;
    Ok((StatusCode::OK, Json(overrides)))
}

/// `DELETE /api/v1/capability/override/{id}` — revert a previously applied
/// capability override, restoring each affected cell to its pre-override value.
///
/// Returns 204 No Content on success.  Returns 404 when no active override
/// with the supplied `id` exists (either it was never created or has already
/// been revoked).
#[utoipa::path(
    delete,
    path = "/api/v1/capability/override/{id}",
    params(
        ("id" = String, Path, description = "UUID of the override to revoke")
    ),
    responses(
        (status = 204, description = "Override revoked; cells restored to base policy"),
        (status = 403, description = "Caller lacks the role required to mutate capability state"),
        (status = 404, description = "No active override with this id", body = ProblemDetail)
    ),
    tag = "capability"
)]
pub async fn revoke_override(
    // AAASM-3846 — revoking an override mutates capability state, so it must be
    // gated identically to `apply_override` (a `Global`-scope policy update),
    // not left open to any caller.
    policy_auth: PolicyWriteAuth,
    Extension(state): Extension<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    if let Err(denied) = policy_auth.check_mutation(&PolicyScope::Global, MutationKind::Update) {
        return denied.into_response();
    }

    match state.capability_store.revoke_override(&id).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(RevokeOverrideError::NotFound) => ProblemDetail::from_status(StatusCode::NOT_FOUND)
            .with_detail(format!("No active override with id: {id}"))
            .with_instance(format!("/api/v1/capability/override/{id}"))
            .into_response(),
    }
}

// ── Live projection from the agent registry + policy capability cascade ──────

/// The fixed, non-parameterised capability families, as `(resource id, display
/// name, group)`.
///
/// These are the only resources whose domain the [`aa_core::Capability`] enum
/// itself names, so they are the only ones that can carry a [`ResourceGroup`]
/// without guessing. Tool columns are discovered per agent and left ungrouped.
const SYSTEM_RESOURCES: [(&str, &str, ResourceGroup); 3] = [
    ("filesystem", "Filesystem", ResourceGroup::Files),
    ("terminal", "Terminal", ResourceGroup::Infra),
    ("network_outbound", "Network (outbound)", ResourceGroup::Infra),
];

/// Whether `id` is one of the reserved system-family column ids.
///
/// A tool may legally be *named* `filesystem`; without this guard it would
/// collide with the system column and silently overwrite that agent's real
/// filesystem cell.
fn is_system_resource(id: &str) -> bool {
    SYSTEM_RESOURCES.iter().any(|(sid, _, _)| *sid == id)
}

/// Resolve one capability to a matrix decision using the same public helpers as
/// the enforcement guard's capability stage.
///
/// Mirrors `stage_capability` in `aa-gateway`: an explicit deny (honouring the
/// `file_write` ⇒ `file_delete` superset rule) wins, then a live allow-list
/// restriction denies anything it omits — fail-closed even when the allow set
/// merged down to empty. Anything else is allowed because no capability rule
/// constrains it.
fn decide(caps: &aa_core::CapabilitySet, cap: &aa_core::Capability) -> Decision {
    if aa_core::capability_is_denied(&caps.deny, cap) {
        return Decision::Deny;
    }
    if caps.allow_is_restricted() && !caps.allow.contains(cap) {
        return Decision::Deny;
    }
    Decision::Allow
}

/// Build the cell for a system capability family. Verbs the family does not
/// model stay `Na` — the capability enum draws no read/write/delete distinction
/// for terminal or network access, so reporting anything else would invent one.
///
/// `egress_denied` carries the network stage's verdict (see
/// [`cascade_denies_all_egress`]); the capability set alone cannot see an
/// allowlist-based deny.
///
/// `tier` is the agent's resolved [`aa_core::RiskTier`] baseline (ADR 0029). When
/// present, a verb's grant that is *effectively* `Allow` **and** exceeds the tier
/// baseline (`over_permission::is_over_permission`) marks the cell
/// `flag: Some(true)`. When `tier` is `None` (undeclared / UNSPECIFIED) the agent
/// is not evaluated for over-permission and the flag stays `None` — never a
/// fabricated `false`.
fn system_cell(
    caps: &aa_core::CapabilitySet,
    resource_id: &str,
    egress_denied: bool,
    tier: Option<aa_core::RiskTier>,
) -> CapCell {
    use aa_core::Capability as C;
    let na = Decision::Na;
    // A (decision, capability) pair is over-permission when the grant is
    // effectively allowed and the tier baseline does not warrant it. A denied or
    // `na` verb is never flagged, so an egress-denied network cell cannot flag.
    let over = |decision: Decision, cap: &C| match tier {
        Some(t) => decision == Decision::Allow && over_permission::is_over_permission(t, cap),
        None => false,
    };
    // Per-cell, only the *offending* marker is emitted: `Some(true)` when a verb
    // in this cell is over-permission, else absent (ADR 0029). A cell-level
    // `false` on every non-offending cell would be a negative marker the UI does
    // not consume — the agent-level `flagged` carries the "evaluated, clean"
    // signal instead.
    let flag_of = |flagged: bool| flagged.then_some(true);
    match resource_id {
        "filesystem" => {
            let write = decide(caps, &C::FileWrite);
            let delete = decide(caps, &C::FileDelete);
            CapCell {
                read: decide(caps, &C::FileRead),
                write,
                delete,
                exec: na,
                flag: flag_of(over(write, &C::FileWrite) || over(delete, &C::FileDelete)),
            }
        }
        "terminal" => {
            let exec = decide(caps, &C::TerminalExec);
            CapCell {
                read: na,
                write: na,
                delete: na,
                exec,
                flag: flag_of(over(exec, &C::TerminalExec)),
            }
        }
        _ => {
            let exec = if egress_denied {
                Decision::Deny
            } else {
                decide(caps, &C::NetworkOutbound)
            };
            CapCell {
                read: na,
                write: na,
                delete: na,
                exec,
                flag: flag_of(over(exec, &C::NetworkOutbound)),
            }
        }
    }
}

/// The over-permission-eligible capabilities and the (system resource, verb)
/// cell coordinates they occupy in the matrix. The single source both
/// [`system_cell`] flags and [`over_permission_offenders`] names offenders from,
/// so the two can never disagree about which grant drove a flag (ADR 0029).
fn high_privilege_cells() -> [(&'static str, Verb, aa_core::Capability); 4] {
    use aa_core::Capability as C;
    [
        ("filesystem", Verb::Write, C::FileWrite),
        ("filesystem", Verb::Delete, C::FileDelete),
        ("terminal", Verb::Exec, C::TerminalExec),
        ("network_outbound", Verb::Exec, C::NetworkOutbound),
    ]
}

/// Read the display names of the capabilities that drove an agent's
/// over-permission flag, in stable column order. A capability offends when its
/// cell is effectively `Allow` and the tier baseline does not warrant it — the
/// same test [`system_cell`] applied per cell — so the agent-level note names
/// exactly the grants the per-cell flags mark.
fn over_permission_offenders(cells: &BTreeMap<String, CapCell>, tier: aa_core::RiskTier) -> Vec<String> {
    high_privilege_cells()
        .into_iter()
        .filter_map(|(resource, verb, cap)| {
            let cell = cells.get(resource)?;
            let decision = match verb {
                Verb::Write => cell.write,
                Verb::Delete => cell.delete,
                Verb::Exec => cell.exec,
                Verb::Read => cell.read,
            };
            (decision == Decision::Allow && over_permission::is_over_permission(tier, &cap))
                .then(|| cap.to_string())
        })
        .collect()
}

/// Map the registry's liveness status onto the matrix's. `Idle` is never
/// produced: the registry has no idle state, and deriving one from heartbeat
/// staleness would be a threshold this endpoint has no mandate to pick.
fn project_status(status: &aa_gateway::registry::AgentStatus) -> AgentStatus {
    match status {
        aa_gateway::registry::AgentStatus::Active => AgentStatus::Active,
        _ => AgentStatus::Suspended,
    }
}

/// Map the agent's registered enforcement-mode override onto the matrix's
/// two-value view. `Disabled` and "no override declared" both yield `None` —
/// neither is representable as enforce-or-shadow, and the effective mode for the
/// latter is decided per policy document, not per agent.
fn project_mode(mode: Option<aa_core::EnforcementMode>) -> Option<AgentMode> {
    match mode {
        Some(aa_core::EnforcementMode::Enforce) => Some(AgentMode::Enforce),
        Some(aa_core::EnforcementMode::Observe) => Some(AgentMode::Shadow),
        _ => None,
    }
}

/// (scope label, document name). Keyed on both because one scope may carry
/// several documents; collapsing them on scope alone would drop all but the first
/// from the policies list.
type PolicyKey = (String, Option<String>);

/// Fold one agent's cascade into the shared policy rows, recording the agent as
/// affected by every document that declares capabilities or tools.
///
/// A document declaring neither contributes no rule, so it is skipped rather than
/// listed as a policy row with an empty rule set.
fn collect_policy_rows(
    cascade: &[Arc<aa_gateway::policy::PolicyDocument>],
    id_hex: &str,
    policy_rows: &mut BTreeMap<PolicyKey, (Arc<aa_gateway::policy::PolicyDocument>, Vec<String>)>,
) {
    for doc in cascade {
        if doc.capabilities.is_none() && doc.tools.is_empty() {
            continue;
        }
        let entry = policy_rows
            .entry((doc.scope.to_string(), doc.name.clone()))
            .or_insert_with(|| (Arc::clone(doc), Vec::new()));
        entry.1.push(id_hex.to_string());
    }
}

/// Project the capability matrix from the registry and the policy cascade.
///
/// `records` is the whole fleet: the endpoint is admin-global by design
/// (AAASM-4841), and its only caller passes `agent_registry.list()`. The
/// projection therefore does no tenant filtering of its own — the `team_id`
/// query parameter narrows the result afterwards, it is not an authorization
/// boundary.
///
/// The cascade is collected with an explicit lineage rather than via
/// `PolicyEngine::effective_permissions`: without a lineage the engine falls
/// back to `Lineage::default()` and resolves only the Global and Agent tiers,
/// silently dropping every Org- and Team-scoped policy. AAASM-5102 wired the
/// registry into the engine `AppState::local_in_memory` builds, so that
/// fallback no longer fires in the shipped composition root — this projection
/// keeps the explicit lineage anyway so it stays correct under any engine,
/// registry-wired or not.
fn project_matrix(records: &[aa_gateway::registry::AgentRecord], state: &AppState) -> CapabilityMatrix {
    use aa_core::Capability as C;

    // Resource columns: the three system families, then every tool any visible
    // agent declared or any applicable policy names, de-duplicated and sorted so
    // the column order is stable across requests.
    let mut tool_ids: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let mut agents: Vec<CapabilityAgent> = Vec::with_capacity(records.len());
    // Policy key -> (document, agent ids it applies to).
    let mut policy_rows: BTreeMap<PolicyKey, (Arc<aa_gateway::policy::PolicyDocument>, Vec<String>)> = BTreeMap::new();

    for record in records {
        let agent_id = aa_core::identity::AgentId::from_bytes(record.agent_id);
        let id_hex = hex::encode(record.agent_id);
        let lineage = state.agent_registry.lineage(&record.agent_id).unwrap_or_default();
        let cascade = state.policy_engine.collect_cascade_with_lineage(&agent_id, &lineage);
        let caps = aa_gateway::engine::PolicyEngine::collect_merged_capabilities(&cascade);

        let agent_tools = agent_tool_ids(record, &caps, &cascade);
        collect_policy_rows(&cascade, &id_hex, &mut policy_rows);
        tool_ids.extend(agent_tools.iter().cloned());

        // Over-permission baseline (ADR 0029). The agent is evaluated only when
        // it declares a resolvable RiskTier *and* has a non-empty cascade: an
        // empty cascade makes `decide` fall through to `Allow` for every cell
        // (ADR 0024), which would mass-flag every low-tier agent against grants no
        // policy actually made. An unevaluated agent carries no flag anywhere.
        let over_perm_tier = if cascade.is_empty() {
            None
        } else {
            aa_core::RiskTier::from_proto_i32(record.risk_tier)
        };

        let egress_denied = cascade_denies_all_egress(&cascade);
        let mut cells: BTreeMap<String, CapCell> = BTreeMap::new();
        for (rid, _, _) in SYSTEM_RESOURCES {
            cells.insert(rid.to_string(), system_cell(&caps, rid, egress_denied, over_perm_tier));
        }
        for tool in agent_tools.iter().filter(|t| !is_system_resource(t)) {
            // A tool is invoked, never read/written/deleted — the capability
            // model has one grant per tool, so only `exec` is meaningful.
            //
            // Most-restrictive wins across the two stages that can block a tool:
            // the `tools` map (stage 3) and the capability set (stage 3.5). The
            // evaluator returns on the first `Deny`, so either one is final.
            let exec = if cascade_denies_tool(&cascade, tool) {
                Decision::Deny
            } else {
                decide(&caps, &C::McpTool(tool.clone()))
            };
            cells.insert(
                tool.clone(),
                CapCell {
                    read: Decision::Na,
                    write: Decision::Na,
                    delete: Decision::Na,
                    exec,
                    flag: None,
                },
            );
        }

        // Agent-level over-permission signal (ADR 0029). Present only for an
        // evaluated agent (resolvable tier + non-empty cascade); `Some(true)`
        // when any system cell is flagged, else the honest `Some(false)`
        // "evaluated, within baseline". Unevaluated agents stay `None` — never a
        // fabricated verdict.
        let (flagged, note) = match over_perm_tier {
            Some(tier) => {
                let offenders = over_permission_offenders(&cells, tier);
                let flagged = !offenders.is_empty();
                let note = flagged.then(|| {
                    format!(
                        "{tier:?}-risk agent granted {} beyond its tier baseline",
                        offenders.join(", ")
                    )
                });
                (Some(flagged), note)
            }
            None => (None, None),
        };

        agents.push(CapabilityAgent {
            id: id_hex,
            name: record.name.clone(),
            framework: record.framework.clone(),
            owner: record.team_id.clone().or_else(|| record.org_id.clone()),
            trust: None,
            mode: project_mode(record.enforcement_mode),
            status: project_status(&record.status),
            last_seen: record.last_heartbeat.to_rfc3339(),
            flagged,
            note,
            caps: cells,
        });
    }

    let mut resources: Vec<Resource> = SYSTEM_RESOURCES
        .iter()
        .map(|(id, name, group)| Resource {
            id: (*id).to_string(),
            name: (*name).to_string(),
            group: Some(*group),
            paths: Vec::new(),
        })
        .collect();
    resources.extend(
        tool_ids
            .into_iter()
            .filter(|id| !is_system_resource(id))
            .map(|id| Resource {
                name: id.clone(),
                id,
                group: None,
                paths: Vec::new(),
            }),
    );

    let policies = policy_rows
        .into_iter()
        .map(|((scope, name), (doc, mut affects))| {
            affects.sort();
            affects.dedup();
            Policy {
                // Scope-qualified so two same-named documents at different tiers
                // stay distinguishable in the UI's per-policy links.
                id: match &name {
                    Some(n) => format!("{scope}/{n}"),
                    None => scope.clone(),
                },
                name: name.unwrap_or_else(|| scope.clone()),
                version: doc.policy_version.clone(),
                scope,
                // Every document reached here is in a live cascade, so it is by
                // definition the active one for its scope. `Proposed` /
                // `Archived` have no representation in the loaded engine.
                status: PolicyStatus::Active,
                hits_24h: None,
                affects,
                rules: project_rules(&doc),
            }
        })
        .collect();

    CapabilityMatrix {
        resources,
        agents,
        policies,
        // Representative call samples require a proposed-vs-current policy diff
        // that nothing computes today; the policy-replay story (AAASM-5094) owns
        // that surface, so the dimension is reported empty rather than invented.
        sample_calls: Vec::new(),
    }
}

/// Resolve a system capability to its matrix column and verb, or `None` when the
/// capability has no column.
fn verbs_for(cap: &aa_core::Capability) -> Option<(&'static str, Verb)> {
    use aa_core::Capability as C;

    match cap {
        C::FileRead => Some(("filesystem", Verb::Read)),
        C::FileWrite => Some(("filesystem", Verb::Write)),
        C::FileDelete => Some(("filesystem", Verb::Delete)),
        C::TerminalExec => Some(("terminal", Verb::Exec)),
        C::NetworkOutbound => Some(("network_outbound", Verb::Exec)),
        _ => None,
    }
}

/// Flatten one capability set's allow and deny declarations into rule rows,
/// carrying the declaration verbatim as the rule's `action`.
fn capability_rules(caps: &aa_core::CapabilitySet) -> Vec<PolicyRule> {
    use aa_core::Capability as C;

    let mut rules: Vec<PolicyRule> = Vec::new();
    for (set, action) in [(&caps.allow, "allow"), (&caps.deny, "deny")] {
        for cap in set {
            let (resource, verb) = match cap {
                C::McpTool(name) => (name.clone(), Verb::Exec),
                other => match verbs_for(other) {
                    Some((r, v)) => (r.to_string(), v),
                    // Model / inbound-network / agent-spawn grants are inert
                    // (`Capability::is_enforceable`) and have no column.
                    None => continue,
                },
            };
            rules.push(PolicyRule {
                resource,
                verb: vec![verb],
                action: action.to_string(),
                condition: String::new(),
            });
        }
    }
    rules
}

/// Flatten one policy document's capability and tool declarations into the
/// matrix's rule rows.
///
/// `action` carries the declaration verbatim (`allow` / `deny`); `condition` is
/// the tool's own `requires_approval_if` expression, or empty when it declares
/// none.
fn project_rules(doc: &aa_gateway::policy::PolicyDocument) -> Vec<PolicyRule> {
    let mut rules: Vec<PolicyRule> = Vec::new();
    if let Some(caps) = doc.capabilities.as_ref() {
        rules.extend(capability_rules(caps));
    }
    for (tool, policy) in &doc.tools {
        rules.push(PolicyRule {
            resource: tool.clone(),
            verb: vec![Verb::Exec],
            action: if policy.allow { "allow" } else { "deny" }.to_string(),
            condition: policy.requires_approval_if.clone().unwrap_or_default(),
        });
    }
    rules.sort_by(|a, b| a.resource.cmp(&b.resource).then(a.action.cmp(&b.action)));
    rules
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{AuthenticatedCaller, Tenant};
    use crate::routes::enforcement_mirror::TOOL_WILDCARD;
    use aa_gateway::policy::rbac::CallerRole;
    use aa_gateway::registry::AgentRecord;

    /// An `OrgAdmin` writer — the role `apply_override` / `revoke_override`
    /// require for a `Global`-scope policy mutation.
    fn org_admin_writer() -> PolicyWriteAuth {
        PolicyWriteAuth {
            caller: AuthenticatedCaller {
                key_id: "k".to_string(),
                scopes: vec![Scope::Admin],
                tenant: Tenant {
                    team_id: None,
                    org_id: None,
                },
            },
            role: CallerRole::OrgAdmin,
        }
    }

    fn reader(scopes: Vec<Scope>) -> RequireRead {
        RequireRead(AuthenticatedCaller {
            key_id: "k".to_string(),
            scopes,
            tenant: Tenant {
                team_id: None,
                org_id: None,
            },
        })
    }

    /// Minimal registered agent. Only the fields the projection reads carry
    /// meaningful values.
    fn record(id_byte: u8, name: &str, tools: &[&str]) -> AgentRecord {
        AgentRecord {
            agent_id: [id_byte; 16],
            name: name.to_string(),
            framework: "langgraph".to_string(),
            version: "0.1.0".to_string(),
            risk_tier: 1,
            tool_names: tools.iter().map(|t| (*t).to_string()).collect(),
            public_key: "pk".to_string(),
            credential_token: "tok".to_string(),
            metadata: std::collections::BTreeMap::new(),
            registered_at: chrono::Utc::now(),
            last_heartbeat: chrono::Utc::now(),
            status: aa_gateway::registry::AgentStatus::Active,
            pid: None,
            session_count: 0,
            last_event: None,
            policy_violations_count: 0,
            active_sessions: Vec::new(),
            recent_events: std::collections::VecDeque::new(),
            recent_traces: Vec::new(),
            layer: None,
            governance_level: aa_core::GovernanceLevel::default(),
            parent_agent_id: None,
            team_id: Some("team-alpha".to_string()),
            org_id: None,
            depth: 0,
            delegation_reason: None,
            spawned_by_tool: None,
            root_agent_id: Some([id_byte; 16]),
            children: Vec::new(),
            parent_key: None,
            enforcement_mode: None,
        }
    }

    fn state_with(records: Vec<AgentRecord>) -> AppState {
        let state = AppState::local_in_memory().expect("state builds");
        for r in records {
            state.agent_registry.register(r).expect("register");
        }
        state
    }

    /// A policy document carrying only the sections the projection reads.
    fn policy_doc(
        name: &str,
        scope: PolicyScope,
        capabilities: Option<aa_core::CapabilitySet>,
        tools: &[(&str, bool)],
        network_allowlist: Option<Vec<String>>,
    ) -> aa_gateway::policy::PolicyDocument {
        aa_gateway::policy::PolicyDocument {
            name: Some(name.to_string()),
            policy_version: Some("1".to_string()),
            version: None,
            scope,
            network: network_allowlist.map(|allowlist| aa_gateway::policy::NetworkPolicy { allowlist }),
            schedule: None,
            budget: None,
            data: None,
            approval_timeout_secs: 300,
            approval_policy: None,
            tools: tools
                .iter()
                .map(|(n, allow)| {
                    (
                        (*n).to_string(),
                        aa_gateway::policy::ToolPolicy {
                            allow: *allow,
                            limit_per_hour: None,
                            requires_approval_if: None,
                        },
                    )
                })
                .collect(),
            capabilities,
        }
    }

    /// `state_with` plus real policy documents in the engine.
    ///
    /// The engine `local_in_memory` builds is loaded from a budget-only file, so
    /// without this every projection test asserts cells that are `allow` purely
    /// because nothing constrains them.
    fn state_with_policies(records: Vec<AgentRecord>, docs: Vec<aa_gateway::policy::PolicyDocument>) -> AppState {
        let mut state = state_with(records);
        let engine = Arc::get_mut(&mut state.policy_engine).expect("engine is unshared until the state is cloned");
        for doc in docs {
            engine.load_policy(doc);
        }
        state
    }

    fn hex_id(b: u8) -> String {
        hex::encode([b; 16])
    }

    async fn matrix_for(state: &AppState) -> CapabilityMatrix {
        let (status, Json(m)) = get_matrix(
            reader(vec![Scope::Admin]),
            Query(MatrixQueryParams::default()),
            Extension(state.clone()),
        )
        .await
        .expect("admin may read");
        assert_eq!(status, StatusCode::OK);
        m
    }

    // ── Projection ──────────────────────────────────────────────────────────

    #[tokio::test]
    async fn matrix_projects_registered_agents_not_fixtures() {
        let state = state_with(vec![record(0x01, "checkout-agent", &["search"])]);
        let m = matrix_for(&state).await;

        assert_eq!(m.agents.len(), 1, "one registered agent yields one row");
        let agent = &m.agents[0];
        assert_eq!(agent.id, hex_id(0x01));
        assert_eq!(agent.name, "checkout-agent");
        assert_eq!(agent.framework, "langgraph");
        assert_eq!(agent.owner.as_deref(), Some("team-alpha"));
        assert_eq!(agent.status, AgentStatus::Active);
        // The declared tool becomes a column, alongside the system families.
        let ids: Vec<&str> = m.resources.iter().map(|r| r.id.as_str()).collect();
        assert!(ids.contains(&"filesystem"), "system families are always present");
        assert!(ids.contains(&"terminal"));
        assert!(ids.contains(&"network_outbound"));
        assert!(ids.contains(&"search"), "declared tool becomes a resource column");
    }

    #[tokio::test]
    async fn matrix_is_empty_when_no_agent_is_registered() {
        let state = state_with(vec![]);
        let m = matrix_for(&state).await;
        assert!(m.agents.is_empty(), "no agents registered -> no rows");
        assert!(m.sample_calls.is_empty());
        // Resource columns still describe the fixed capability families.
        assert_eq!(m.resources.len(), SYSTEM_RESOURCES.len());
    }

    #[tokio::test]
    async fn fields_without_a_real_source_are_never_faked() {
        let state = state_with(vec![record(0x01, "a", &[])]);
        let m = matrix_for(&state).await;
        let agent = &m.agents[0];
        assert!(agent.trust.is_none(), "no trust score exists; must not be faked");
        assert!(agent.flagged.is_none());
        assert!(agent.note.is_none());
        // No enforcement_mode override was declared.
        assert!(agent.mode.is_none());
        for policy in &m.policies {
            assert!(policy.hits_24h.is_none(), "24h hit counts have no source here");
        }
        let json = serde_json::to_value(agent).unwrap();
        // AAASM-5104 — `trust` is required-but-nullable: the key is always on the
        // wire so a consumer must handle an explicit `null` instead of shrugging
        // off a missing key with `?? 0`. It must still be unreadable as a score.
        assert!(json.get("trust").is_some(), "trust key must be present");
        assert!(json["trust"].is_null(), "trust must serialize as null");
        assert!(!json["trust"].is_number(), "an unmeasured trust must not be a number");
        assert_ne!(json["trust"], 0, "trust must never fold to a scored zero");
        // Fields with no wire contract of their own are still omitted entirely.
        assert!(json.get("mode").is_none());
    }

    #[tokio::test]
    async fn last_seen_is_the_real_heartbeat_timestamp() {
        let mut rec = record(0x01, "a", &[]);
        rec.last_heartbeat = chrono::DateTime::parse_from_rfc3339("2026-07-25T10:11:12Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let state = state_with(vec![rec]);
        let m = matrix_for(&state).await;
        assert!(
            m.agents[0].last_seen.starts_with("2026-07-25T10:11:12"),
            "lastSeen is the registry heartbeat, not a rendered phrase: {}",
            m.agents[0].last_seen
        );
    }

    #[tokio::test]
    async fn enforcement_mode_override_maps_observe_to_shadow() {
        let mut enforce = record(0x01, "enforced", &[]);
        enforce.enforcement_mode = Some(aa_core::EnforcementMode::Enforce);
        let mut observe = record(0x02, "shadowed", &[]);
        observe.enforcement_mode = Some(aa_core::EnforcementMode::Observe);
        let mut disabled = record(0x03, "disabled", &[]);
        disabled.enforcement_mode = Some(aa_core::EnforcementMode::Disabled);

        let state = state_with(vec![enforce, observe, disabled]);
        let m = matrix_for(&state).await;
        let by_name = |n: &str| m.agents.iter().find(|a| a.name == n).unwrap();
        assert_eq!(by_name("enforced").mode, Some(AgentMode::Enforce));
        assert_eq!(by_name("shadowed").mode, Some(AgentMode::Shadow));
        assert_eq!(
            by_name("disabled").mode,
            None,
            "Disabled has no enforce/shadow representation and must not be coerced"
        );
    }

    /// Every deny the enforcement stages would produce has to reach the grid.
    /// Before AAASM-5090's review pass the tool and network cells were read off
    /// the merged capability set alone, so a tool denied by `tools:` and an
    /// agent with a deny-all egress allowlist both reported `allow`.
    #[tokio::test]
    async fn every_stage_that_denies_is_visible_in_the_cells() {
        use aa_core::Capability as C;

        let mut caps = aa_core::CapabilitySet::default();
        caps.deny.insert(C::FileWrite);

        let state = state_with_policies(
            vec![record(0x01, "a", &["send_email", "read_file"])],
            vec![policy_doc(
                "strict",
                PolicyScope::Global,
                Some(caps),
                // Wildcard denies every unlisted tool; the exact entry wins.
                &[("*", false), ("read_file", true)],
                // Declared-but-empty allowlist is deny-all egress.
                Some(Vec::new()),
            )],
        );
        let m = matrix_for(&state).await;
        let cells = &m.agents[0].caps;

        assert_eq!(cells["filesystem"].write, Decision::Deny, "capability stage");
        assert_eq!(cells["send_email"].exec, Decision::Deny, "tool wildcard fallback");
        assert_eq!(
            cells["read_file"].exec,
            Decision::Allow,
            "exact tool entry beats the wildcard"
        );
        assert_eq!(
            cells["network_outbound"].exec,
            Decision::Deny,
            "empty allowlist is deny-all"
        );
        // Unconstrained families are still allowed — the deny is not blanket.
        assert_eq!(cells["filesystem"].read, Decision::Allow);
        assert_eq!(cells["terminal"].exec, Decision::Allow);
    }

    // ── Over-permission (ADR 0029) ───────────────────────────────────────────

    /// `record` with an explicit proto risk-tier value (`record` fixes Low = 1).
    fn record_with_tier(id_byte: u8, name: &str, tools: &[&str], risk_tier: i32) -> AgentRecord {
        AgentRecord {
            risk_tier,
            ..record(id_byte, name, tools)
        }
    }

    /// A Global policy that constrains nothing — enough to give the agent a
    /// non-empty cascade so over-permission is evaluated rather than skipped.
    fn permissive_cascade() -> Vec<aa_gateway::policy::PolicyDocument> {
        vec![policy_doc(
            "baseline",
            PolicyScope::Global,
            Some(aa_core::CapabilitySet::default()),
            &[],
            None,
        )]
    }

    #[tokio::test]
    async fn low_tier_granted_a_destructive_verb_is_flagged_with_a_note() {
        // Low (risk_tier 1) with an unconstrained cascade: file_delete and
        // terminal_exec fall through to Allow, both beyond the Low baseline.
        let state = state_with_policies(vec![record_with_tier(0x01, "a", &[], 1)], permissive_cascade());
        let agent = &matrix_for(&state).await.agents[0];

        assert_eq!(agent.flagged, Some(true), "a Low agent with destructive grants is over-permissioned");
        assert!(agent.caps["terminal"].flag == Some(true), "the driving cell is marked");
        assert!(agent.caps["filesystem"].flag == Some(true), "file_delete drives the filesystem cell");
        let note = agent.note.as_deref().expect("a flag carries a note");
        assert!(note.contains("file_delete"), "note names the offending grant: {note}");
        assert!(note.contains("terminal_exec"), "note names the offending grant: {note}");
    }

    #[tokio::test]
    async fn high_tier_with_the_same_grants_is_within_baseline() {
        // High (risk_tier 3) permits every modelled system verb, so the same
        // grants are evaluated and found clean — Some(false), not a flag.
        let state = state_with_policies(vec![record_with_tier(0x01, "a", &[], 3)], permissive_cascade());
        let agent = &matrix_for(&state).await.agents[0];

        assert_eq!(agent.flagged, Some(false), "High permits these grants; evaluated but not flagged");
        assert!(agent.note.is_none(), "a within-baseline agent carries no note");
        assert!(
            agent.caps.values().all(|c| c.flag.is_none()),
            "no cell is marked when nothing is over-permission"
        );
    }

    #[tokio::test]
    async fn an_agent_with_no_declared_tier_is_not_evaluated() {
        // risk_tier 0 is the proto UNSPECIFIED sentinel: no baseline, no
        // comparison. flagged and every flag stay absent — never a false false.
        let state = state_with_policies(vec![record_with_tier(0x01, "a", &[], 0)], permissive_cascade());
        let agent = &matrix_for(&state).await.agents[0];

        assert!(agent.flagged.is_none(), "no tier -> not evaluated, not Some(false)");
        assert!(agent.note.is_none());
        assert!(agent.caps.values().all(|c| c.flag.is_none()));
    }

    #[tokio::test]
    async fn an_empty_cascade_is_not_mass_flagged() {
        // No policy loaded: every cell is Allow by fall-through (ADR 0024).
        // Flagging a Low agent against those phantom grants would be a false
        // positive, so an empty cascade is not evaluated at all.
        let state = state_with(vec![record_with_tier(0x01, "a", &[], 1)]);
        let agent = &matrix_for(&state).await.agents[0];

        assert_eq!(agent.caps["terminal"].exec, Decision::Allow, "empty cascade allows by fall-through");
        assert!(agent.flagged.is_none(), "an empty cascade is not evaluated for over-permission");
        assert!(agent.note.is_none());
        assert!(agent.caps.values().all(|c| c.flag.is_none()));
    }

    #[tokio::test]
    async fn a_denied_destructive_grant_is_never_flagged() {
        use aa_core::Capability as C;

        // Low agent, but terminal_exec is explicitly denied: a denied grant is
        // not a grant, so it cannot be over-permission.
        let mut caps = aa_core::CapabilitySet::default();
        caps.deny.insert(C::FileDelete);
        caps.deny.insert(C::TerminalExec);
        caps.deny.insert(C::FileWrite);
        let state = state_with_policies(
            vec![record_with_tier(0x01, "a", &[], 1)],
            vec![policy_doc(
                "deny-destructive",
                PolicyScope::Global,
                Some(caps),
                &[],
                // Deny-all egress too, so no high-privilege verb is granted.
                Some(Vec::new()),
            )],
        );
        let agent = &matrix_for(&state).await.agents[0];

        assert_eq!(agent.caps["terminal"].exec, Decision::Deny);
        assert_eq!(
            agent.flagged,
            Some(false),
            "the agent is evaluated but nothing is granted beyond baseline"
        );
        assert!(agent.caps.values().all(|c| c.flag.is_none()));
    }

    /// The `"*"` tools key is a fallback pattern, not a tool. A column named `*`
    /// reading `allow` is the exact inverse of what `"*": { allow: false }` says.
    #[tokio::test]
    async fn the_tool_wildcard_never_becomes_a_resource_column() {
        let state = state_with_policies(
            vec![record(0x01, "a", &[])],
            vec![policy_doc("strict", PolicyScope::Global, None, &[("*", false)], None)],
        );
        let m = matrix_for(&state).await;

        assert!(
            m.resources.iter().all(|r| r.id != TOOL_WILDCARD),
            "wildcard leaked into the resource columns: {:?}",
            m.resources.iter().map(|r| &r.id).collect::<Vec<_>>()
        );
        assert!(!m.agents[0].caps.contains_key(TOOL_WILDCARD));
    }

    /// Guards the explicit lineage at the top of [`project_matrix`]: resolving
    /// the cascade without a lineage silently drops every Org- and Team-scoped
    /// document. Since AAASM-5102 the engine is registry-wired too, so this now
    /// guards the projection against a *second* regression rather than the only
    /// one — see `agents::tests::a_team_scoped_deny_reaches_the_capabilities_response`
    /// for the composition-root guard.
    #[tokio::test]
    async fn a_team_scoped_deny_reaches_the_projection() {
        use aa_core::Capability as C;

        let mut caps = aa_core::CapabilitySet::default();
        caps.deny.insert(C::TerminalExec);

        // `record` registers the agent under team-alpha.
        let state = state_with_policies(
            vec![record(0x01, "a", &[])],
            vec![policy_doc(
                "team-rules",
                PolicyScope::Team("team-alpha".to_string()),
                Some(caps),
                &[],
                None,
            )],
        );
        let m = matrix_for(&state).await;

        assert_eq!(
            m.agents[0].caps["terminal"].exec,
            Decision::Deny,
            "a Team-scoped policy must reach the cascade"
        );
        assert!(
            m.policies.iter().any(|p| p.scope == "team:team-alpha"),
            "and be listed as a responsible policy: {:?}",
            m.policies.iter().map(|p| &p.scope).collect::<Vec<_>>()
        );
    }

    #[test]
    fn decide_honours_the_guard_fail_closed_rules() {
        use aa_core::Capability as C;
        let mut caps = aa_core::CapabilitySet::default();

        // No restriction declared at all -> unconstrained.
        assert_eq!(decide(&caps, &C::FileRead), Decision::Allow);

        // An explicit deny wins.
        caps.deny.insert(C::FileWrite);
        assert_eq!(decide(&caps, &C::FileWrite), Decision::Deny);
        // deny(file_write) is a superset that also blocks delete (AAASM-4103).
        assert_eq!(decide(&caps, &C::FileDelete), Decision::Deny);

        // A live allow-list denies anything it omits, even when empty
        // (AAASM-4154 fail-closed).
        let restricted = aa_core::CapabilitySet {
            allow: Default::default(),
            deny: Default::default(),
            allow_restricted: true,
        };
        assert_eq!(decide(&restricted, &C::TerminalExec), Decision::Deny);
    }

    #[test]
    fn system_cell_leaves_unmodelled_verbs_na() {
        let caps = aa_core::CapabilitySet::default();
        // `None` tier: no over-permission evaluation, so this pins decision
        // placement only (the flag concern is covered separately).
        let fs = system_cell(&caps, "filesystem", false, None);
        assert_eq!(fs.exec, Decision::Na, "the capability model has no filesystem exec");
        assert_eq!(fs.read, Decision::Allow);

        let term = system_cell(&caps, "terminal", false, None);
        assert_eq!(term.read, Decision::Na);
        assert_eq!(term.write, Decision::Na);
        assert_eq!(term.delete, Decision::Na);
        assert_eq!(term.exec, Decision::Allow);

        // The egress verdict only reaches the network family.
        let net = system_cell(&caps, "network_outbound", true, None);
        assert_eq!(net.exec, Decision::Deny);
        assert_eq!(system_cell(&caps, "terminal", true, None).exec, Decision::Allow);
    }

    /// Pins the rule flattening directly, covering the capability variants no
    /// projection test declares.
    #[test]
    fn project_rules_flattens_capabilities_and_tools() {
        use aa_core::Capability as C;

        let mut caps = aa_core::CapabilitySet::default();
        caps.allow.insert(C::FileRead);
        caps.allow.insert(C::McpTool("search".to_string()));
        // Inert grants (`Capability::is_enforceable` is false) have no column.
        caps.allow.insert(C::AgentSpawn);
        caps.deny.insert(C::FileWrite);

        let doc = aa_gateway::policy::PolicyDocument {
            name: Some("baseline".to_string()),
            policy_version: None,
            version: None,
            scope: PolicyScope::Global,
            network: None,
            schedule: None,
            budget: None,
            data: None,
            approval_timeout_secs: 300,
            approval_policy: None,
            tools: std::collections::HashMap::from([(
                "deploy".to_string(),
                aa_gateway::policy::ToolPolicy {
                    allow: false,
                    limit_per_hour: None,
                    requires_approval_if: Some("size > 1".to_string()),
                },
            )]),
            capabilities: Some(caps),
        };

        let rules = project_rules(&doc);
        let flat: Vec<(&str, &str, &[Verb], &str)> = rules
            .iter()
            .map(|r| {
                (
                    r.resource.as_str(),
                    r.action.as_str(),
                    r.verb.as_slice(),
                    r.condition.as_str(),
                )
            })
            .collect();
        assert_eq!(
            flat,
            vec![
                // Sorted by (resource, action); the tool policy carries its own
                // approval condition, capability rules carry none.
                ("deploy", "deny", &[Verb::Exec][..], "size > 1"),
                ("filesystem", "allow", &[Verb::Read][..], ""),
                ("filesystem", "deny", &[Verb::Write][..], ""),
                ("search", "allow", &[Verb::Exec][..], ""),
            ],
            "agent_spawn contributes no row"
        );
    }

    // ── Authorization ───────────────────────────────────────────────────────

    #[tokio::test]
    async fn get_matrix_denies_non_admin_reader() {
        let state = state_with(vec![record(0x01, "a", &[])]);
        let err = get_matrix(
            reader(vec![Scope::Read]),
            Query(MatrixQueryParams::default()),
            Extension(state),
        )
        .await
        .expect_err("a plain reader is forbidden");
        assert_eq!(err.status, StatusCode::FORBIDDEN.as_u16());
    }

    #[tokio::test]
    async fn list_overrides_denies_non_admin_reader() {
        // AAASM-4829: the override log is global control-plane state; a mere
        // read-scoped caller must be refused, mirroring the admin posture of the
        // apply/revoke mutation handlers.
        let state = AppState::local_in_memory().expect("state builds");
        let err = list_overrides(
            reader(vec![Scope::Read]),
            Query(ListOverridesParams { agent_id: None }),
            Extension(state),
        )
        .await
        .expect_err("non-admin is forbidden");
        assert_eq!(err.status, StatusCode::FORBIDDEN.as_u16());
    }

    // ── Query filters ───────────────────────────────────────────────────────

    #[tokio::test]
    async fn team_id_and_tool_filters_narrow_the_projection() {
        let state = state_with(vec![record(0x01, "a", &["search"]), record(0x02, "b", &["search"])]);

        let (_s, Json(by_agent)) = get_matrix(
            reader(vec![Scope::Admin]),
            Query(MatrixQueryParams {
                team_id: Some(hex_id(0x01)),
                ..Default::default()
            }),
            Extension(state.clone()),
        )
        .await
        .unwrap();
        assert_eq!(by_agent.agents.len(), 1);
        assert_eq!(by_agent.agents[0].id, hex_id(0x01));

        let (_s, Json(by_tool)) = get_matrix(
            reader(vec![Scope::Admin]),
            Query(MatrixQueryParams {
                tool: Some("search".into()),
                ..Default::default()
            }),
            Extension(state),
        )
        .await
        .unwrap();
        assert_eq!(by_tool.resources.len(), 1);
        for agent in &by_tool.agents {
            assert_eq!(agent.caps.len(), 1, "caps narrow to the selected tool");
            assert!(agent.caps.contains_key("search"));
        }
    }

    // ── Override overlay ────────────────────────────────────────────────────

    #[tokio::test]
    async fn override_overlays_the_projection_and_revoke_restores_it() {
        let state = state_with(vec![record(0x01, "a", &[])]);
        let target = hex_id(0x01);
        let base = matrix_for(&state).await.agents[0].caps["filesystem"].read;
        assert_eq!(base, Decision::Allow);

        let (status, Json(resp)) = apply_override(
            org_admin_writer(),
            Extension(state.clone()),
            Json(CapabilityOverrideRequest {
                agent_ids: vec![target.clone()],
                resource_id: "filesystem".into(),
                verb: Verb::Read,
                decision: Decision::Deny,
                ttl_seconds: None,
            }),
        )
        .await
        .expect("org admin may override");
        assert_eq!(status, StatusCode::OK);
        assert_eq!(resp.updated.len(), 1);
        assert_eq!(resp.updated[0].caps["filesystem"].read, Decision::Deny);

        // The overlay is visible on a fresh read of the live projection.
        let after = matrix_for(&state).await;
        assert_eq!(after.agents[0].caps["filesystem"].read, Decision::Deny);
        // and only the targeted verb moved.
        assert_eq!(after.agents[0].caps["filesystem"].write, Decision::Allow);

        state
            .capability_store
            .revoke_override(&resp.override_id)
            .await
            .expect("revoke succeeds");
        let restored = matrix_for(&state).await;
        assert_eq!(
            restored.agents[0].caps["filesystem"].read, base,
            "revoking restores the projected value with no bookkeeping"
        );
    }

    #[tokio::test]
    async fn override_rejects_an_agent_absent_from_the_projection() {
        let state = state_with(vec![record(0x01, "a", &[])]);
        let err = apply_override(
            org_admin_writer(),
            Extension(state.clone()),
            Json(CapabilityOverrideRequest {
                agent_ids: vec!["does-not-exist".into()],
                resource_id: "filesystem".into(),
                verb: Verb::Read,
                decision: Decision::Deny,
                ttl_seconds: None,
            }),
        )
        .await
        .expect_err("unknown agent is rejected");
        match err {
            OverrideHandlerError::BadRequest(p) => assert_eq!(p.status, StatusCode::BAD_REQUEST.as_u16()),
            other => panic!("expected 400, got {other:?}"),
        }
        // Nothing was recorded.
        assert!(state.capability_store.list_overrides(None).await.is_empty());
    }

    /// The projection emits only allow / deny / na, so an override may not
    /// write a decision no revoke could ever restore.
    #[tokio::test]
    async fn override_rejects_a_decision_the_projection_cannot_express() {
        for decision in [Decision::Narrow, Decision::Approval] {
            let state = state_with(vec![record(0x01, "a", &[])]);
            let err = apply_override(
                org_admin_writer(),
                Extension(state.clone()),
                Json(CapabilityOverrideRequest {
                    agent_ids: vec![hex_id(0x01)],
                    resource_id: "filesystem".into(),
                    verb: Verb::Read,
                    decision,
                    ttl_seconds: None,
                }),
            )
            .await
            .expect_err("narrow / approval are rejected");
            match err {
                OverrideHandlerError::BadRequest(p) => assert_eq!(p.status, StatusCode::BAD_REQUEST.as_u16()),
                other => panic!("expected 400 for {decision:?}, got {other:?}"),
            }
            assert!(state.capability_store.list_overrides(None).await.is_empty());
        }
    }

    #[tokio::test]
    async fn revoking_an_unknown_override_is_not_found() {
        let state = state_with(vec![]);
        let err = state
            .capability_store
            .revoke_override("no-such-id")
            .await
            .expect_err("unknown id");
        assert_eq!(err, RevokeOverrideError::NotFound);
    }

    #[tokio::test]
    async fn list_overrides_admin_sees_applied_override_and_filter_works() {
        let state = state_with(vec![record(0x01, "a", &[])]);
        let target = hex_id(0x01);
        Arc::clone(&state.capability_store)
            .record_override(&CapabilityOverrideRequest {
                agent_ids: vec![target.clone()],
                resource_id: "filesystem".into(),
                verb: Verb::Write,
                decision: Decision::Deny,
                ttl_seconds: None,
            })
            .await;

        let (status, Json(all)) = list_overrides(
            reader(vec![Scope::Admin]),
            Query(ListOverridesParams { agent_id: None }),
            Extension(state.clone()),
        )
        .await
        .expect("admin may list");
        assert_eq!(status, StatusCode::OK);
        assert_eq!(all.len(), 1);
        assert!(all[0].agent_ids.contains(&target));

        let (_status, Json(filtered)) = list_overrides(
            reader(vec![Scope::Admin]),
            Query(ListOverridesParams {
                agent_id: Some("no-such-agent".into()),
            }),
            Extension(state),
        )
        .await
        .expect("admin may list filtered");
        assert!(filtered.is_empty(), "filter to an unaffected agent yields nothing");
    }
}
