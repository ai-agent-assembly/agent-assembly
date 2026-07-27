//! Topology REST API endpoints.
//!
//! Five read-only endpoints for querying the agent topology tree, team
//! membership, ancestry lineage, and aggregate statistics — all backed by
//! the in-memory `AgentRegistry`.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use axum::extract::{Path, Query};
use axum::http::StatusCode;
use axum::{Extension, Json};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use utoipa::IntoParams;

use aa_core::identity::AgentId;
use aa_core::topology::EdgeType;
use aa_gateway::policy::PolicyScope;
use aa_gateway::registry::{AgentRecord, AgentRegistry, AgentStatus, Lineage};
use rust_decimal::prelude::ToPrimitive;

use crate::auth::scope::{RequireRead, Scope};
use crate::auth::AuthenticatedCaller;
use crate::error::ProblemDetail;
use crate::models::topology::{agent_flagged, agent_mode, format_id, status_str};
pub use crate::models::topology::{
    AgentLineage, AgentNode, AgentTree, LineageStep, NodeBudget, NodeEffectivePermissions, PolicyChainTier,
    TeamSummary, TeamTopology, TopologyGraphEdge, TopologyGraphResponse, TopologyOverview, TopologyStats,
};
use crate::routes::enforcement_mirror::{agent_tool_ids, cascade_denies_all_egress, cascade_denies_tool};
use crate::state::AppState;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Parse a hex-encoded agent ID string into a 16-byte array.
///
/// Decodes via [`hex::decode`] rather than slicing the input by byte index: the
/// previous `&id[i..i + 2]` implementation panicked on an odd-length id (index
/// past the end) or a multibyte path segment (a non-char-boundary slice),
/// turning a malformed `{id}` path parameter into a request-thread panic
/// (AAASM-4018 / AAASM-4150). `hex::decode` rejects odd-length and non-hex input
/// with a clean `Err`, so every malformed id now surfaces as a `400` instead.
fn parse_agent_id(id: &str) -> Result<[u8; 16], ProblemDetail> {
    let bytes = hex::decode(id).map_err(|_| {
        ProblemDetail::from_status(StatusCode::BAD_REQUEST).with_detail(format!("Invalid agent ID format: {id}"))
    })?;
    bytes.try_into().map_err(|_| {
        ProblemDetail::from_status(StatusCode::BAD_REQUEST)
            .with_detail(format!("Agent ID must be 32 hex characters: {id}"))
    })
}

fn matches_status_filter(status: &AgentStatus, filter: &str) -> bool {
    match filter.to_ascii_lowercase().as_str() {
        "active" => matches!(status, AgentStatus::Active),
        "suspended" => matches!(status, AgentStatus::Suspended(_)),
        "deregistered" => matches!(status, AgentStatus::Deregistered),
        _ => true,
    }
}

// ---------------------------------------------------------------------------
// Tenant scoping (AAASM-3483)
// ---------------------------------------------------------------------------
//
// The topology surface is per-tenant data, but the org/team/agent selector is
// caller-controlled. Without scoping, any read-scoped caller can read another
// tenant's topology, or omit the filter to enumerate every tenant. Mirror the
// cost / agent-budget reference pattern (AAASM-3139): admin bypasses; a
// tenant-scoped caller is confined to its own org / team; a non-admin caller
// with no tenant scope at all sees nothing (deny / empty, never a cross-tenant
// dump).

/// Whether a single record is visible to `caller` under tenant scoping.
///
/// Admin sees every record. A non-admin caller only sees a record whose
/// `org_id` matches its org scope (when it has one) AND whose `team_id` matches
/// its team scope (when it has one). A record carrying no `org_id` / `team_id`
/// never matches a scoped non-admin caller — untagged records are not exposed
/// across the tenant boundary.
pub(crate) fn record_visible_to(caller: &AuthenticatedCaller, record: &AgentRecord) -> bool {
    if caller.scopes.contains(&Scope::Admin) {
        return true;
    }
    // A non-admin caller with no tenant scope at all can never be confined to a
    // tenant, so it sees nothing (fail-closed; never a cross-tenant dump).
    if caller.tenant.org_id.is_none() && caller.tenant.team_id.is_none() {
        return false;
    }
    if let Some(org) = caller.tenant.org_id.as_deref() {
        if record.org_id.as_deref() != Some(org) {
            return false;
        }
    }
    if let Some(team) = caller.tenant.team_id.as_deref() {
        if record.team_id.as_deref() != Some(team) {
            return false;
        }
    }
    true
}

/// A non-admin caller with neither an org nor a team scope can never be
/// confined to a tenant, so it must not receive any per-tenant topology data.
fn caller_has_no_tenant_scope(caller: &AuthenticatedCaller) -> bool {
    !caller.scopes.contains(&Scope::Admin) && caller.tenant.org_id.is_none() && caller.tenant.team_id.is_none()
}

/// Join cache-key components into a string that only an equal component list
/// can produce.
///
/// Every component here is caller-controlled: the registry validates a tenant id
/// against control characters *only* (`AgentRegistry::validate_tenant_id`,
/// AAASM-4190), so `|` is legal inside an `org_id` / `team_id`, and `status` and
/// the `{team_id}` / `{agent_id}` path segments are free-form request input.
/// Joining those raw lets two *different* requests assemble one key — an
/// `org="acme"` + `team="x|team=y"` caller and an `org="acme|team=x"` +
/// `team="y"` caller both rendered `org=acme|team=x|team=y` — which is a
/// cross-tenant read and equally a cross-tenant write, since either caller can
/// be the one that populates the shared entry. Length-prefixing each component
/// makes the encoding decodable, hence injective, extending AAASM-4190's
/// bucket-key defence to the response caches.
fn cache_key_of(parts: &[&str]) -> String {
    let mut key = String::new();
    for part in parts {
        if !key.is_empty() {
            key.push('|');
        }
        key.push_str(&part.len().to_string());
        key.push(':');
        key.push_str(part);
    }
    key
}

/// Encode an optional cache-key component so an absent value and a present
/// empty one cannot collide.
///
/// The two are different queries, not two spellings of one: `?org_id=` selects
/// the records whose `org_id` is empty, while omitting it selects every record;
/// likewise a caller scoped to `org_id: Some("")` is confined by
/// [`record_visible_to`] where a caller with `None` is not.
fn opt_part(value: Option<&str>) -> String {
    match value {
        Some(v) => format!("={v}"),
        None => "-".to_string(),
    }
}

/// Cache-key fragment that makes a cached topology response specific to the
/// caller's tenant scope, so a tenant-scoped response is never served to a
/// caller from a different tenant.
///
/// The tag alone is *not* sufficient to isolate a response: it is the constant
/// `admin` for every admin caller, so any handler whose body also varies with a
/// request parameter must name that parameter in its key too (AAASM-5181).
fn tenant_cache_tag(caller: &AuthenticatedCaller) -> String {
    if caller.scopes.contains(&Scope::Admin) {
        return cache_key_of(&["admin"]);
    }
    cache_key_of(&[
        "tenant",
        &opt_part(caller.tenant.org_id.as_deref()),
        &opt_part(caller.tenant.team_id.as_deref()),
    ])
}

// ---------------------------------------------------------------------------
// Query parameter structs
// ---------------------------------------------------------------------------

/// Common filter parameters for topology listing endpoints.
#[derive(Debug, Default, Deserialize, IntoParams)]
pub struct TopologyFilterParams {
    /// Filter by agent status: `active`, `suspended`, or `deregistered`.
    pub status: Option<String>,
    /// Only include agents at or above this delegation depth.
    pub min_depth: Option<u32>,
    /// When `true`, include the governance level in each agent node.
    pub show_budget: Option<bool>,
    /// AAASM-2008 — scope the query to a single organisation. When set,
    /// only agents whose `org_id` matches are returned (multi-tenancy
    /// isolation). Empty / absent agents (no `org_id` on the record)
    /// never match an explicit filter.
    pub org_id: Option<String>,
}

/// Query parameters for the tree endpoint.
#[derive(Debug, Default, Deserialize, IntoParams)]
pub struct TreeParams {
    /// Maximum traversal depth from the root (default 10, capped at 10).
    pub depth: Option<u32>,
    /// Filter tree nodes by status: `active`, `suspended`, or `deregistered`.
    pub status: Option<String>,
    /// When `true`, include the governance level in each tree node.
    pub show_budget: Option<bool>,
}

// ---------------------------------------------------------------------------
// Tree builder helper
// ---------------------------------------------------------------------------

const MAX_TREE_DEPTH: u32 = 10;

fn build_tree(
    registry: &AgentRegistry,
    caller: &AuthenticatedCaller,
    agent_id: &[u8; 16],
    remaining_depth: u32,
    status_filter: Option<&str>,
    show_budget: bool,
) -> Option<AgentTree> {
    let record = registry.get(agent_id)?;
    // AAASM-4819 — the handler authorizes only the root; `children_of` recursion
    // otherwise walks into descendants registered under other teams and leaks
    // their name / team_id / delegation_reason. Enforce the tenant boundary on
    // every recursively-discovered node: an out-of-tenant node is omitted, and
    // because that returns `None` its whole subtree is pruned too, so the walk
    // never crosses a tenant boundary (mirrors the edges.rs BFS guard,
    // AAASM-3825).
    if !record_visible_to(caller, &record) {
        return None;
    }
    if let Some(f) = status_filter {
        if !matches_status_filter(&record.status, f) {
            return None;
        }
    }
    let children = if remaining_depth > 0 {
        registry
            .children_of(agent_id)
            .iter()
            .filter_map(|child_id| {
                build_tree(
                    registry,
                    caller,
                    child_id,
                    remaining_depth - 1,
                    status_filter,
                    show_budget,
                )
            })
            .collect()
    } else {
        vec![]
    };
    // Derive the badge fields before moving the record's owned fields into the
    // struct literal below (both helpers borrow `record`).
    let mode = agent_mode(&record);
    let flagged = agent_flagged(&record);
    Some(AgentTree {
        id: format_id(agent_id),
        name: record.name,
        depth: record.depth,
        status: status_str(&record.status).to_owned(),
        team_id: record.team_id,
        delegation_reason: record.delegation_reason,
        spawned_by_tool: record.spawned_by_tool,
        governance_level: if show_budget {
            Some(format!("{:?}", record.governance_level))
        } else {
            None
        },
        mode,
        flagged,
        // No per-agent trust-analytics source exists yet; emit `null` (matches
        // AgentNode / the Fleet page) rather than a misleading default.
        trust: None,
        children,
    })
}

// ---------------------------------------------------------------------------
// Graph projection helpers (AAASM-5099)
// ---------------------------------------------------------------------------

/// Per-edge-type page size for the graph projection. Matches the `EdgeRepo`
/// contract's own cap, so the request never asks for more than a store can
/// return.
const EDGE_BATCH_LIMIT: u32 = 1000;

/// Wire `kind` for a stored [`EdgeType`].
///
/// The two structural kinds keep the graph vocabulary the dashboard already
/// renders (`delegates_to` → `delegation`, `calls` → `call`, unchanged since
/// AAASM-5040); the other four pass their canonical wire string through.
fn graph_edge_kind(edge_type: EdgeType) -> &'static str {
    match edge_type {
        EdgeType::DelegatesTo => "delegation",
        EdgeType::Calls => "call",
        other => other.as_str(),
    }
}

/// Whether an edge crosses a team boundary.
///
/// True only when both endpoints carry a team and the two differ. Mirrors
/// `edges::compute_cross_team` (the rule `/topology/edges` reports as
/// `is_cross_team`) so the graph and the edge list can never disagree about the
/// same edge — an endpoint with no team is not a boundary crossing.
fn is_cross_team(source_team: Option<&str>, target_team: Option<&str>) -> bool {
    matches!((source_team, target_team), (Some(a), Some(b)) if a != b)
}

/// The agent's policy-inheritance chain: one row per cascade tier that applies
/// to it, broadest → narrowest, listing the policy documents loaded there.
///
/// A tier appears only when the agent has that selector — an agent with no
/// `org_id` has no Org row. `Tool` is not a tier here: it is selected per action
/// (`aa_gateway::engine::action_tool_name`), so there is no agent-level answer.
fn build_policy_chain(
    cascade: &[Arc<aa_gateway::policy::PolicyDocument>],
    agent_id: &AgentId,
    lineage: &Lineage,
) -> Vec<PolicyChainTier> {
    let mut tiers: Vec<(&str, PolicyScope)> = vec![("global", PolicyScope::Global)];
    if let Some(org_id) = lineage.org_id.as_deref() {
        tiers.push(("org", PolicyScope::Org(org_id.to_owned())));
    }
    if let Some(team_id) = lineage.team_id.as_deref() {
        tiers.push(("team", PolicyScope::Team(team_id.to_owned())));
    }
    tiers.push(("agent", PolicyScope::Agent(*agent_id)));

    tiers
        .into_iter()
        .map(|(tier, scope)| {
            let label = scope.to_string();
            let policies = cascade
                .iter()
                .filter(|doc| doc.scope == scope)
                // An unnamed document is identified by its scope, matching how
                // `capability::project_matrix` names a scope-only policy row.
                .map(|doc| doc.name.clone().unwrap_or_else(|| label.clone()))
                .collect();
            PolicyChainTier {
                tier: tier.to_owned(),
                scope: label,
                policies,
            }
        })
        .collect()
}

/// Whether the cascade denies `cap`, folding in the enforcement stages that run
/// *before* the capability stage.
///
/// `evaluate_single_doc` (`aa-gateway/src/engine/decision.rs`) returns on the
/// first `Deny`, so an earlier stage's verdict is final and the capability set
/// never gets consulted. Ordered here as the evaluator orders them:
/// `stage_network` (via [`cascade_denies_all_egress`]), then `stage_tool_allow`
/// (via [`cascade_denies_tool`]), then the capability stage itself — whose
/// `file_write` ⇒ `file_delete` superset rule lives in
/// [`aa_core::capability_is_denied`], not in this projection.
fn cascade_denies(
    cascade: &[Arc<aa_gateway::policy::PolicyDocument>],
    merged: &aa_core::CapabilitySet,
    egress_denied: bool,
    cap: &aa_core::Capability,
) -> bool {
    match cap {
        aa_core::Capability::NetworkOutbound if egress_denied => true,
        aa_core::Capability::McpTool(name) if cascade_denies_tool(cascade, name) => true,
        _ => aa_core::capability_is_denied(&merged.deny, cap),
    }
}

/// Project one agent's effective permissions from an already-resolved cascade.
///
/// **Mirrors three of the four stages `evaluate_single_doc`
/// (`aa-gateway/src/engine/decision.rs`) runs**, and says so precisely because an
/// earlier version claimed to mirror the gateway while reading only the last of
/// them (AAASM-5090's fail-open, repeated here):
///
/// * `stage_network` — only its answerable case, [`cascade_denies_all_egress`]:
///   a declared-but-empty allowlist is deny-all egress. A non-empty allowlist
///   restricts egress *per host*, and a per-agent view has no host to test, so
///   `network_outbound` keeps its capability-derived answer there.
/// * `stage_tool_allow` — [`cascade_denies_tool`], over the tool names this agent
///   is known to have ([`agent_tool_ids`]). A `tools: { "*": { allow: false } }`
///   cascade also denies tools nobody has named yet; those cannot be listed, so
///   absence from `deny` is not a grant.
/// * `stage_capability` — `collect_merged_capabilities` plus
///   `allow_is_restricted()`, the two values `PolicyEngine::capability_guard`
///   (`aa-gateway/src/engine/mod.rs`) consults, with the `file_write` ⇒
///   `file_delete` superset rule applied via [`aa_core::capability_is_denied`] so
///   `deny` states both capabilities the guard blocks, not just the one authored.
///
/// `stage_approval` is **not** mirrored: it evaluates a tool's
/// `requires_approval_if` CEL condition against a concrete action, which a
/// per-agent projection has none of. It can only ever add friction to something
/// already allowed here, never grant, so omitting it cannot make this permissive.
///
/// Deny wins at every stage, so `deny` is built first and filters `allow`: a
/// capability an earlier stage blocks must never be reported as granted.
fn project_effective_permissions(
    record: &AgentRecord,
    cascade: &[Arc<aa_gateway::policy::PolicyDocument>],
    agent_id: &AgentId,
    lineage: &Lineage,
) -> NodeEffectivePermissions {
    use aa_core::Capability as C;

    let merged = aa_gateway::engine::PolicyEngine::collect_merged_capabilities(cascade);
    let egress_denied = cascade_denies_all_egress(cascade);

    let mut deny: std::collections::BTreeSet<String> = merged.deny.iter().map(ToString::to_string).collect();
    if aa_core::capability_is_denied(&merged.deny, &C::FileDelete) {
        deny.insert(C::FileDelete.to_string());
    }
    if egress_denied {
        deny.insert(C::NetworkOutbound.to_string());
    }
    for tool in agent_tool_ids(record, &merged, cascade) {
        if cascade_denies_tool(cascade, &tool) {
            deny.insert(C::McpTool(tool).to_string());
        }
    }

    let mut allow: Vec<String> = merged
        .allow
        .iter()
        .filter(|cap| !cascade_denies(cascade, &merged, egress_denied, cap))
        .map(ToString::to_string)
        .collect();
    allow.sort();

    NodeEffectivePermissions {
        chain: build_policy_chain(cascade, agent_id, lineage),
        allow,
        deny: deny.into_iter().collect(),
        allow_restricted: merged.allow_is_restricted(),
    }
}

/// Enrich the caller-visible records into graph nodes, resolving each agent's
/// policy cascade, effective permissions, and daily budget.
///
/// The cascade is collected with an **explicitly resolved** lineage rather than
/// via `PolicyEngine::collect_cascade` / `effective_permissions`: an engine with
/// no registry attached resolves `Lineage::default()` and silently walks only
/// the Global and Agent tiers, dropping every Org- and Team-scoped allow *and*
/// deny. AAASM-5102 attached the registry in `AppState::local_in_memory`, so the
/// shipped engine no longer takes that fallback — the explicit lineage stays as
/// the guard that keeps this projection correct under any engine. Same guard as
/// `capability::project_matrix` (AAASM-5090).
fn project_graph_nodes(records: &[AgentRecord], state: &AppState) -> Vec<AgentNode> {
    // Budget: snapshot once (not per node) and index today's per-agent spend by
    // the same 32-char hex the node id uses, mirroring the `/api/v1/costs`
    // per-agent breakdown that reads the identical tracker state.
    let budget_snapshot = state.budget_tracker.snapshot();
    let spend_by_id: HashMap<String, f64> = budget_snapshot
        .per_agent
        .iter()
        .map(|e| (e.agent_id_hex.clone(), e.state.spent_usd.to_f64().unwrap_or(0.0)))
        .collect();
    // Effective daily limit = per-agent override, else the server-wide daily
    // limit; `null` when neither is configured (the panel then shows the
    // "no limit" placeholder rather than a misleading 0).
    let global_daily_limit = state.budget_tracker.daily_limit_usd();

    let mut nodes: Vec<AgentNode> = records
        .iter()
        .map(|record| {
            let mut node = AgentNode::from(record);
            let agent_id = AgentId::from_bytes(record.agent_id);
            let lineage = state.agent_registry.lineage(&record.agent_id).unwrap_or_default();
            let cascade = state.policy_engine.collect_cascade_with_lineage(&agent_id, &lineage);
            node.policy_count = Some(cascade.len() as u32);
            node.effective_permissions = Some(project_effective_permissions(record, &cascade, &agent_id, &lineage));
            let limit_usd = state
                .budget_tracker
                .agent_daily_limit_usd(&agent_id)
                .or(global_daily_limit)
                .and_then(|d| d.to_f64());
            node.budget = Some(NodeBudget {
                spend_usd: spend_by_id.get(&node.id).copied().unwrap_or(0.0),
                limit_usd,
            });
            node
        })
        .collect();
    nodes.sort_by(|a, b| a.id.cmp(&b.id));
    nodes
}

/// Collect every stored edge whose endpoints are both visible graph nodes.
///
/// `teams_by_id` doubles as the visibility set and the team lookup: an edge
/// touching an id it does not contain is dropped, so an edge can never cross the
/// tenant boundary or point at a node the client wasn't given (mirrors the
/// edges.rs BFS tenant boundary, AAASM-3825).
async fn collect_graph_edges(
    state: &AppState,
    teams_by_id: &HashMap<[u8; 16], Option<String>>,
) -> Result<Vec<TopologyGraphEdge>, ProblemDetail> {
    let epoch = DateTime::<Utc>::from_timestamp(0, 0).unwrap_or_default();
    let mut edges: Vec<TopologyGraphEdge> = Vec::new();
    for &edge_type in EdgeType::ALL {
        let batch = state
            .edge_repo
            .list_by_type(edge_type, epoch, EDGE_BATCH_LIMIT)
            .await
            .map_err(|e| {
                // Mirror the edges.rs 500 mapping (AAASM-4950): log the underlying
                // store error server-side, return a generic body.
                tracing::error!(error = %e, "failed to list topology graph edges by type");
                ProblemDetail::from_status(StatusCode::INTERNAL_SERVER_ERROR)
                    .with_detail("Failed to list topology edges".to_string())
            })?;
        let kind = graph_edge_kind(edge_type);
        for edge in batch {
            let (Some(source_team), Some(target_team)) = (
                teams_by_id.get(edge.source.as_bytes()),
                teams_by_id.get(edge.target.as_bytes()),
            ) else {
                continue;
            };
            edges.push(TopologyGraphEdge {
                source: format_id(edge.source.as_bytes()),
                target: format_id(edge.target.as_bytes()),
                kind: kind.to_owned(),
                cross_team: is_cross_team(source_team.as_deref(), target_team.as_deref()),
            });
        }
    }
    Ok(edges)
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// `GET /api/v1/topology/overview` — summary of all teams and root agents.
///
/// Returns a count of teams, root agents, and total agents across the registry,
/// with a per-team breakdown and a list of standalone root agents not assigned
/// to any team. Supports optional filtering by status, minimum depth, and
/// governance level visibility.
#[utoipa::path(
    get,
    path = "/api/v1/topology/overview",
    params(TopologyFilterParams),
    responses(
        (status = 200, description = "Topology overview", body = TopologyOverview)
    ),
    tag = "topology"
)]
pub async fn get_overview(
    RequireRead(caller): RequireRead,
    Extension(state): Extension<AppState>,
    Query(params): Query<TopologyFilterParams>,
) -> (StatusCode, Json<TopologyOverview>) {
    // AAASM-3483 — a non-admin caller with no tenant scope receives an empty
    // overview rather than a cross-tenant dump.
    if caller_has_no_tenant_scope(&caller) {
        return (StatusCode::OK, Json(TopologyOverview::default()));
    }

    // AAASM-3483 — a tenant-scoped caller is confined to its own org; an
    // explicit `?org_id` selector outside that scope yields no agents. Force
    // the effective org filter to the caller's own org for non-admins.
    let is_admin = caller.scopes.contains(&Scope::Admin);
    let effective_org: Option<String> = if is_admin {
        params.org_id.clone()
    } else {
        caller.tenant.org_id.clone()
    };

    // AAASM-5181 — the key must name every input that shapes the body: the
    // caller's tenant AND the org actually queried. Keying on the tenant tag
    // alone did not deliver the isolation the comment here used to claim: the
    // tag is the constant `admin` for every admin caller, so `?org_id=A` and
    // `?org_id=B` produced one key and whichever arrived second was served the
    // first org's overview for the rest of the TTL.
    let cache_key = cache_key_of(&[
        &tenant_cache_tag(&caller),
        &opt_part(effective_org.as_deref()),
        &opt_part(params.status.as_deref()),
        &params.min_depth.unwrap_or(0).to_string(),
        &params.show_budget.unwrap_or(false).to_string(),
    ]);
    if let Some(cached) = state.topology_overview_cache.get(&cache_key).await {
        return (StatusCode::OK, Json((*cached).clone()));
    }

    // AAASM-2008 — when org_id is set, scope to that org's members
    // (O(members) lookup). Otherwise list all agents.
    let all: Vec<AgentRecord> = match effective_org.as_deref() {
        Some(oid) => {
            let keys = state.agent_registry.org_members(oid);
            keys.into_iter().filter_map(|k| state.agent_registry.get(&k)).collect()
        }
        None => state.agent_registry.list(),
    };
    let show_budget = params.show_budget.unwrap_or(false);

    let filtered: Vec<_> = all
        .iter()
        // AAASM-3483 — confine the result to records the caller's tenant may see
        // (team-tier scoping; org-tier handled by `effective_org` above).
        .filter(|r| record_visible_to(&caller, r))
        .filter(|r| {
            params
                .status
                .as_deref()
                .map_or(true, |f| matches_status_filter(&r.status, f))
                && params.min_depth.map_or(true, |d| r.depth >= d)
        })
        .collect();

    let total_agent_count = filtered.len();

    let mut team_map: HashMap<String, (usize, usize)> = HashMap::new();
    for r in &filtered {
        if let Some(tid) = &r.team_id {
            let entry = team_map.entry(tid.clone()).or_insert((0, 0));
            entry.0 += 1;
            if r.depth == 0 {
                entry.1 += 1;
            }
        }
    }

    let team_count = team_map.len();
    let root_agent_count = filtered.iter().filter(|r| r.depth == 0).count();

    let teams = {
        let mut v: Vec<TeamSummary> = team_map
            .into_iter()
            .map(|(team_id, (agent_count, root_count))| TeamSummary {
                team_id,
                agent_count,
                root_agent_count: root_count,
            })
            .collect();
        v.sort_by(|a, b| a.team_id.cmp(&b.team_id));
        v
    };

    let mut standalone_root_agents: Vec<AgentNode> = filtered
        .iter()
        .filter(|r| r.depth == 0 && r.team_id.is_none())
        .map(|r| {
            let mut node = AgentNode::from(*r);
            if show_budget {
                node.governance_level = Some(format!("{:?}", r.governance_level));
            }
            node
        })
        .collect();
    standalone_root_agents.sort_by(|a, b| a.id.cmp(&b.id));

    let overview = TopologyOverview {
        team_count,
        root_agent_count,
        total_agent_count,
        teams,
        standalone_root_agents,
    };
    state
        .topology_overview_cache
        .insert(cache_key, Arc::new(overview.clone()))
        .await;
    (StatusCode::OK, Json(overview))
}

/// `GET /api/v1/topology/tree/{root_id}` — full subtree from a given root agent.
///
/// Recursively walks the delegation tree starting from the given agent, up to
/// a configurable depth (default 10, maximum 10). Nodes can be filtered by
/// status. Returns a nested JSON tree with each agent's children inline.
/// Returns 422 if the agent exists but is not a root (depth > 0).
#[utoipa::path(
    get,
    path = "/api/v1/topology/tree/{root_id}",
    params(
        ("root_id" = String, Path, description = "Hex-encoded UUID of the starting agent"),
        TreeParams
    ),
    responses(
        (status = 200, description = "Agent subtree", body = AgentTree),
        (status = 400, description = "Invalid agent ID format"),
        (status = 404, description = "Agent not found"),
        (status = 422, description = "Agent is not a root agent")
    ),
    tag = "topology"
)]
pub async fn get_tree(
    RequireRead(caller): RequireRead,
    Extension(state): Extension<AppState>,
    Path(root_id): Path<String>,
    Query(params): Query<TreeParams>,
) -> Result<(StatusCode, Json<AgentTree>), ProblemDetail> {
    let agent_id = parse_agent_id(&root_id)?;
    let max_depth = params.depth.unwrap_or(MAX_TREE_DEPTH).min(MAX_TREE_DEPTH);
    let show_budget = params.show_budget.unwrap_or(false);

    // AAASM-3483 — a non-admin caller with no tenant scope sees no per-tenant
    // topology; report 404 (not 403) so it cannot probe agent existence.
    if caller_has_no_tenant_scope(&caller) {
        return Err(
            ProblemDetail::from_status(StatusCode::NOT_FOUND).with_detail(format!("Agent not found: {root_id}"))
        );
    }

    // Validate the starting agent exists and is a root before hitting the cache.
    if let Some(record) = state.agent_registry.get(&agent_id) {
        // AAASM-3483 — a root outside the caller's tenant is reported as not
        // found, so the tree of another tenant's agent never leaks and the
        // 404-vs-422 distinction cannot be used to enumerate cross-tenant roots.
        if !record_visible_to(&caller, &record) {
            return Err(
                ProblemDetail::from_status(StatusCode::NOT_FOUND).with_detail(format!("Agent not found: {root_id}"))
            );
        }
        if record.depth > 0 {
            return Err(ProblemDetail::from_status(StatusCode::UNPROCESSABLE_ENTITY)
                .with_detail(format!("Agent {root_id} is not a root agent (depth {})", record.depth)));
        }
    } else {
        return Err(
            ProblemDetail::from_status(StatusCode::NOT_FOUND).with_detail(format!("Agent not found: {root_id}"))
        );
    }

    let cache_key = cache_key_of(&[
        &tenant_cache_tag(&caller),
        &root_id,
        &max_depth.to_string(),
        &opt_part(params.status.as_deref()),
        &show_budget.to_string(),
    ]);
    if let Some(cached) = state.topology_tree_cache.get(&cache_key).await {
        return Ok((StatusCode::OK, Json((*cached).clone())));
    }

    let tree = build_tree(
        &state.agent_registry,
        &caller,
        &agent_id,
        max_depth,
        params.status.as_deref(),
        show_budget,
    )
    .ok_or_else(|| {
        ProblemDetail::from_status(StatusCode::NOT_FOUND).with_detail(format!("Agent not found: {root_id}"))
    })?;

    state
        .topology_tree_cache
        .insert(cache_key, Arc::new(tree.clone()))
        .await;
    Ok((StatusCode::OK, Json(tree)))
}

/// `GET /api/v1/topology/team/{team_id}` — all agents in a team with depth info.
///
/// Returns all agents belonging to the given team, sorted by delegation depth.
/// Results can be filtered by status and minimum depth. Returns 404 if the
/// team identifier is not known to the registry.
#[utoipa::path(
    get,
    path = "/api/v1/topology/team/{team_id}",
    params(
        ("team_id" = String, Path, description = "Team identifier"),
        TopologyFilterParams
    ),
    responses(
        (status = 200, description = "Team topology", body = TeamTopology),
        (status = 404, description = "Team not found")
    ),
    tag = "topology"
)]
pub async fn get_team(
    RequireRead(caller): RequireRead,
    Extension(state): Extension<AppState>,
    Path(team_id): Path<String>,
    Query(params): Query<TopologyFilterParams>,
) -> Result<(StatusCode, Json<TeamTopology>), ProblemDetail> {
    // AAASM-3483 — a tenant-scoped caller may only read its own team; any other
    // team (and an unscoped non-admin caller) is denied, so a team's membership
    // never leaks across the tenant boundary.
    if !caller.can_access_team(&team_id) {
        return Err(ProblemDetail::from_status(StatusCode::FORBIDDEN)
            .with_detail("Reading a team's topology requires admin scope or membership in that team"));
    }

    // `params.org_id` is deliberately absent: unlike `get_overview`, this handler
    // never reads it, so it cannot shape the body and naming it would only split
    // the entry. If it ever starts filtering by org, it belongs in this key.
    let cache_key = cache_key_of(&[
        &tenant_cache_tag(&caller),
        &team_id,
        &opt_part(params.status.as_deref()),
        &params.min_depth.unwrap_or(0).to_string(),
        &params.show_budget.unwrap_or(false).to_string(),
    ]);
    if let Some(cached) = state.topology_team_cache.get(&cache_key).await {
        return Ok((StatusCode::OK, Json((*cached).clone())));
    }

    let member_ids = state.agent_registry.team_members(&team_id);
    // Return 200 + empty list rather than 404 when no agents are registered for
    // the team yet — distinguishes "team known but empty" from "route not found".
    let show_budget = params.show_budget.unwrap_or(false);

    let mut members: Vec<AgentNode> = member_ids
        .iter()
        .filter_map(|id| state.agent_registry.get(id))
        // AAASM-3483 — apply org-tier scoping too: a caller scoped to both an
        // org and a team must not see a same-named team's members in another org.
        .filter(|r| record_visible_to(&caller, r))
        .filter(|r| {
            params
                .status
                .as_deref()
                .map_or(true, |f| matches_status_filter(&r.status, f))
                && params.min_depth.map_or(true, |d| r.depth >= d)
        })
        .map(|r| {
            let mut node = AgentNode::from(&r);
            if show_budget {
                node.governance_level = Some(format!("{:?}", r.governance_level));
            }
            node
        })
        .collect();
    members.sort_by_key(|m| m.depth);

    let agent_count = members.len();
    let topology = TeamTopology {
        team_id,
        agent_count,
        members,
    };
    state
        .topology_team_cache
        .insert(cache_key, Arc::new(topology.clone()))
        .await;
    Ok((StatusCode::OK, Json(topology)))
}

/// `GET /api/v1/topology/lineage/{agent_id}` — ancestor chain from root down to agent.
///
/// Returns the ordered ancestry for the given agent, starting from the root
/// (depth 0) and ending with the requested agent as the last element.
/// A root agent returns a list of length 1 containing only itself.
/// Returns 404 if the agent is unknown.
#[utoipa::path(
    get,
    path = "/api/v1/topology/lineage/{agent_id}",
    params(
        ("agent_id" = String, Path, description = "Hex-encoded UUID of the agent")
    ),
    responses(
        (status = 200, description = "Agent lineage chain", body = AgentLineage),
        (status = 400, description = "Invalid agent ID format"),
        (status = 404, description = "Agent not found")
    ),
    tag = "topology"
)]
pub async fn get_lineage(
    RequireRead(caller): RequireRead,
    Extension(state): Extension<AppState>,
    Path(agent_id_str): Path<String>,
) -> Result<(StatusCode, Json<AgentLineage>), ProblemDetail> {
    // AAASM-3483 — a non-admin caller with no tenant scope sees no per-tenant
    // topology; report 404 so it cannot probe agent existence.
    if caller_has_no_tenant_scope(&caller) {
        return Err(
            ProblemDetail::from_status(StatusCode::NOT_FOUND).with_detail(format!("Agent not found: {agent_id_str}"))
        );
    }

    let cache_key = cache_key_of(&[&tenant_cache_tag(&caller), &agent_id_str]);
    if let Some(cached) = state.topology_lineage_cache.get(&cache_key).await {
        return Ok((StatusCode::OK, Json((*cached).clone())));
    }

    let agent_id = parse_agent_id(&agent_id_str)?;

    let record = state.agent_registry.get(&agent_id).ok_or_else(|| {
        ProblemDetail::from_status(StatusCode::NOT_FOUND).with_detail(format!("Agent not found: {agent_id_str}"))
    })?;

    // AAASM-3483 — an agent outside the caller's tenant is reported as not found
    // so its delegation lineage (and that of its ancestors) never leaks.
    if !record_visible_to(&caller, &record) {
        return Err(
            ProblemDetail::from_status(StatusCode::NOT_FOUND).with_detail(format!("Agent not found: {agent_id_str}"))
        );
    }

    // ancestors_of returns parent-first (direct parent at [0], root at end).
    // AAASM-4819 — walk outward from the requested agent (which is already
    // authorized) toward the root and stop at the first ancestor outside the
    // caller's tenant: a cross-tenant parent's name / team_id / delegation_reason
    // (and everything above it) must not leak. This mirrors the edges.rs BFS
    // tenant boundary (AAASM-3825), which never continues through an
    // unauthorized node. The visible ancestors are then reversed to the
    // root-first order the response expects.
    let ancestor_ids = state.agent_registry.ancestors_of(&agent_id);
    let mut ancestors: Vec<LineageStep> = Vec::new();
    for id in &ancestor_ids {
        let Some(r) = state.agent_registry.get(id) else {
            continue;
        };
        if !record_visible_to(&caller, &r) {
            break;
        }
        ancestors.push(LineageStep {
            id: format_id(&r.agent_id),
            name: r.name.clone(),
            depth: r.depth,
            delegation_reason: r.delegation_reason.clone(),
            team_id: r.team_id.clone(),
        });
    }
    ancestors.reverse();

    ancestors.push(LineageStep {
        id: format_id(&record.agent_id),
        name: record.name.clone(),
        depth: record.depth,
        delegation_reason: record.delegation_reason.clone(),
        team_id: record.team_id.clone(),
    });

    let ancestor_count = ancestors.len();
    let lineage = AgentLineage {
        agent_id: agent_id_str.clone(),
        ancestor_count,
        ancestors,
    };
    state
        .topology_lineage_cache
        .insert(cache_key, Arc::new(lineage.clone()))
        .await;
    Ok((StatusCode::OK, Json(lineage)))
}

/// `GET /api/v1/topology/stats` — aggregate topology statistics.
///
/// Returns aggregate counts and histograms across the entire registry.
/// Includes depth distribution, team-size distribution, child-count distribution,
/// orphan count, and average children per parent. Never returns 404.
#[utoipa::path(
    get,
    path = "/api/v1/topology/stats",
    responses(
        (status = 200, description = "Topology statistics", body = TopologyStats)
    ),
    tag = "topology"
)]
pub async fn get_stats(
    RequireRead(caller): RequireRead,
    Extension(state): Extension<AppState>,
) -> (StatusCode, Json<TopologyStats>) {
    // AAASM-3483 — stats aggregate the whole registry, so without tenant scoping
    // they leak every tenant's agent counts. The tenant tag scopes the cache and
    // the visibility filter below confines the aggregation to the caller's tenant
    // (a non-admin with no tenant scope aggregates over an empty set → zeros).
    let cache_key = cache_key_of(&["stats", &tenant_cache_tag(&caller)]);
    if let Some(cached) = state.topology_stats_cache.get(&cache_key).await {
        return (StatusCode::OK, Json((*cached).clone()));
    }

    let all: Vec<AgentRecord> = state
        .agent_registry
        .list()
        .into_iter()
        .filter(|r| record_visible_to(&caller, r))
        .collect();

    let mut root_agent_count = 0usize;
    let mut max_depth = 0u32;
    let mut active_count = 0usize;
    let mut suspended_count = 0usize;
    let mut deregistered_count = 0usize;
    let mut team_sizes: HashMap<String, usize> = HashMap::new();
    let mut depth_histogram: BTreeMap<String, u32> = BTreeMap::new();
    let mut spawn_count_histogram: BTreeMap<String, u32> = BTreeMap::new();
    let mut orphan_count = 0usize;

    for r in &all {
        if r.depth == 0 {
            root_agent_count += 1;
        }
        if r.depth > max_depth {
            max_depth = r.depth;
        }
        match &r.status {
            AgentStatus::Active => active_count += 1,
            AgentStatus::Suspended(_) => suspended_count += 1,
            AgentStatus::Deregistered => deregistered_count += 1,
        }
        if let Some(tid) = &r.team_id {
            *team_sizes.entry(tid.clone()).or_insert(0) += 1;
        } else if r.depth > 0 {
            orphan_count += 1;
        }
        *depth_histogram.entry(r.depth.to_string()).or_insert(0) += 1;
        let child_count = state.agent_registry.children_of(&r.agent_id).len() as u32;
        *spawn_count_histogram.entry(child_count.to_string()).or_insert(0) += 1;
    }

    let team_count = team_sizes.len();
    let total_agents = all.len();

    let mut team_size_histogram: BTreeMap<String, u32> = BTreeMap::new();
    for &size in team_sizes.values() {
        *team_size_histogram.entry(size.to_string()).or_insert(0) += 1;
    }

    let parents: Vec<u32> = spawn_count_histogram
        .iter()
        .filter(|(count, _)| count.parse::<u32>().unwrap_or(0) > 0)
        .flat_map(|(count, &n)| {
            let c = count.parse::<u32>().unwrap_or(0);
            std::iter::repeat(c).take(n as usize)
        })
        .collect();
    let avg_children_per_parent = if parents.is_empty() {
        0.0
    } else {
        parents.iter().map(|&c| c as f64).sum::<f64>() / parents.len() as f64
    };

    let stats = TopologyStats {
        total_agents,
        root_agent_count,
        max_depth,
        active_count,
        suspended_count,
        deregistered_count,
        team_count,
        team_sizes,
        depth_histogram,
        team_size_histogram,
        spawn_count_histogram,
        orphan_count,
        avg_children_per_parent,
    };
    state
        .topology_stats_cache
        .insert(cache_key, Arc::new(stats.clone()))
        .await;
    (StatusCode::OK, Json(stats))
}

/// `GET /api/v1/topology` — the node+edge graph rendered by the dashboard
/// Topology page (AAASM-5040).
///
/// Returns every agent the caller's tenant may see as a graph node — reusing
/// the same [`AgentNode`] projection as `/topology/overview`, so the per-node
/// enforcement-mode / flagged / trust badges added in AAASM-5036 flow through
/// end-to-end — plus every stored edge between those nodes, in all six relation
/// kinds with a `cross_team` flag (AAASM-5099).
///
/// Unlike the sibling `/topology/*` routes, this handler additionally enriches
/// each node's `owner` / `policy_count` / `budget` (AAASM-5045) and
/// `effective_permissions` (AAASM-5099) from registry metadata, the policy-engine
/// cascade, and the budget tracker respectively, so the dashboard node-detail
/// panel renders real values rather than placeholders.
///
/// Tenant-scoped, `RequireRead`, deny-by-default exactly like the sibling
/// `/topology/*` routes: a non-admin caller with no tenant scope receives an
/// empty graph rather than a cross-tenant dump (AAASM-3483). An edge is emitted
/// only when BOTH of its endpoints are visible nodes, so the graph never leaks
/// an out-of-tenant peer and never references a node the client didn't receive
/// (mirrors the edges.rs BFS tenant boundary, AAASM-3825).
#[utoipa::path(
    get,
    path = "/api/v1/topology",
    responses(
        (status = 200, description = "Agent topology graph (nodes + edges)", body = TopologyGraphResponse),
        (status = 500, description = "Edge store error", body = ProblemDetail),
    ),
    tag = "topology"
)]
pub async fn get_topology_graph(
    RequireRead(caller): RequireRead,
    Extension(state): Extension<AppState>,
) -> Result<(StatusCode, Json<TopologyGraphResponse>), ProblemDetail> {
    // AAASM-3483 — a non-admin caller with no tenant scope receives an empty
    // graph rather than a cross-tenant dump.
    if caller_has_no_tenant_scope(&caller) {
        return Ok((StatusCode::OK, Json(TopologyGraphResponse::default())));
    }

    // Nodes: reuse the AAASM-5036 `AgentNode` projection, tenant-filtered
    // exactly like `get_overview` (team-tier scoping via `record_visible_to`).
    let records: Vec<AgentRecord> = state
        .agent_registry
        .list()
        .into_iter()
        .filter(|r| record_visible_to(&caller, r))
        .collect();

    // Doubles as the edge-visibility set and the `cross_team` team lookup.
    let teams_by_id: HashMap<[u8; 16], Option<String>> =
        records.iter().map(|r| (r.agent_id, r.team_id.clone())).collect();

    // AAASM-5045 / AAASM-5099 — enrich each node's owner / policy_count /
    // budget / effective_permissions from live registry, policy-engine, and
    // budget-tracker state so the node-detail panel renders real values instead
    // of neutral placeholders. `owner` is set by the `From<&AgentRecord>` impl
    // (a pure metadata read); the rest need the stores only this whole-fleet
    // handler reaches — the list / tree endpoints leave them `null`.
    let nodes = project_graph_nodes(&records, &state);
    let edges = collect_graph_edges(&state, &teams_by_id).await?;

    Ok((StatusCode::OK, Json(TopologyGraphResponse { nodes, edges })))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_id_roundtrip() {
        let id: [u8; 16] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        ];
        let hex = format_id(&id);
        assert_eq!(hex, "0102030405060708090a0b0c0d0e0f10");
        let parsed = parse_agent_id(&hex).unwrap();
        assert_eq!(parsed, id);
    }

    #[test]
    fn parse_agent_id_rejects_short_input() {
        assert!(parse_agent_id("aabb").is_err());
    }

    #[test]
    fn parse_agent_id_rejects_non_hex() {
        let non_hex = "z".repeat(32);
        assert!(parse_agent_id(&non_hex).is_err());
    }

    #[test]
    fn parse_agent_id_rejects_odd_length() {
        // AAASM-4150: an odd-length id previously sliced past the end of the
        // string and panicked; hex::decode must reject it as a clean error.
        assert!(parse_agent_id("abc").is_err());
    }

    #[test]
    fn parse_agent_id_rejects_multibyte() {
        // AAASM-4150: a multibyte segment previously sliced a non-char-boundary
        // and panicked; hex::decode must reject it as a clean error.
        assert!(parse_agent_id("€0").is_err());
    }

    #[test]
    fn matches_status_filter_active() {
        let status = AgentStatus::Active;
        assert!(matches_status_filter(&status, "active"));
        assert!(!matches_status_filter(&status, "suspended"));
        assert!(!matches_status_filter(&status, "deregistered"));
    }

    #[test]
    fn matches_status_filter_case_insensitive() {
        let status = AgentStatus::Active;
        assert!(matches_status_filter(&status, "ACTIVE"));
        assert!(matches_status_filter(&status, "Active"));
    }

    #[test]
    fn matches_status_filter_unknown_passes_all() {
        let status = AgentStatus::Active;
        assert!(matches_status_filter(&status, "unknown_value"));
    }
}

// ---------------------------------------------------------------------------
// Graph projection tests (AAASM-5099)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod graph_tests {
    use super::*;
    use crate::auth::{AuthenticatedCaller, Tenant};
    use aa_core::topology::NewEdge;
    use aa_gateway::policy::PolicyDocument;

    /// A read-scoped caller confined to `org` / `team`. `None` / `None` with no
    /// admin scope is the unscoped caller the deny-by-default guard rejects.
    fn reader(scopes: Vec<Scope>, org_id: Option<&str>, team_id: Option<&str>) -> RequireRead {
        RequireRead(AuthenticatedCaller {
            key_id: "k".to_string(),
            scopes,
            tenant: Tenant {
                org_id: org_id.map(str::to_string),
                team_id: team_id.map(str::to_string),
            },
        })
    }

    fn admin() -> RequireRead {
        reader(vec![Scope::Admin], None, None)
    }

    /// Minimal registered agent. Only the fields the graph projection reads
    /// carry meaningful values.
    fn record(id_byte: u8, name: &str, team_id: Option<&str>) -> AgentRecord {
        AgentRecord {
            agent_id: [id_byte; 16],
            name: name.to_string(),
            framework: "langgraph".to_string(),
            version: "0.1.0".to_string(),
            risk_tier: 1,
            tool_names: Vec::new(),
            public_key: "pk".to_string(),
            credential_token: "tok".to_string(),
            metadata: BTreeMap::new(),
            registered_at: Utc::now(),
            last_heartbeat: Utc::now(),
            status: AgentStatus::Active,
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
            team_id: team_id.map(str::to_string),
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

    /// Same agent as [`record`], but declaring tools at registration — the names
    /// the tool-stage mirror can be asked about.
    fn record_with_tools(id_byte: u8, name: &str, team_id: Option<&str>, tools: &[&str]) -> AgentRecord {
        AgentRecord {
            tool_names: tools.iter().map(|t| (*t).to_string()).collect(),
            ..record(id_byte, name, team_id)
        }
    }

    /// A policy document carrying only the capability block the chain reads.
    fn policy_doc(name: &str, scope: PolicyScope, capabilities: aa_core::CapabilitySet) -> PolicyDocument {
        enforcement_doc(name, scope, Some(capabilities), &[], None)
    }

    /// A policy document that can declare any of the three stages the permission
    /// projection mirrors: capabilities, per-tool entries, and a network
    /// allowlist (`Some(vec![])` being the declared-but-empty deny-all case).
    fn enforcement_doc(
        name: &str,
        scope: PolicyScope,
        capabilities: Option<aa_core::CapabilitySet>,
        tools: &[(&str, bool)],
        network_allowlist: Option<Vec<String>>,
    ) -> PolicyDocument {
        PolicyDocument {
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

    /// `state_with` plus real policy documents in the engine. The engine
    /// `local_in_memory` builds is loaded from a budget-only file, so without
    /// this every chain assertion would pass on an empty cascade.
    fn state_with_policies(records: Vec<AgentRecord>, docs: Vec<PolicyDocument>) -> AppState {
        let mut state = state_with(records);
        let engine = Arc::get_mut(&mut state.policy_engine).expect("engine is unshared until the state is cloned");
        for doc in docs {
            engine.load_policy(doc);
        }
        state
    }

    async fn insert_edge(state: &AppState, source: u8, target: u8, edge_type: EdgeType) {
        state
            .edge_repo
            .insert(NewEdge {
                source: AgentId::from_bytes([source; 16]),
                target: AgentId::from_bytes([target; 16]),
                edge_type,
                metadata: None,
            })
            .await
            .expect("edge inserted");
    }

    async fn graph_for(caller: RequireRead, state: &AppState) -> TopologyGraphResponse {
        let (status, Json(graph)) = get_topology_graph(caller, Extension(state.clone()))
            .await
            .expect("graph projects");
        assert_eq!(status, StatusCode::OK);
        graph
    }

    // ── Edge kinds ─────────────────────────────────────────────────────────

    /// Every stored relation kind has to reach the graph. Before AAASM-5099 the
    /// projection walked only `DelegatesTo` / `Calls`, so the dashboard's
    /// reads / writes / approves / messages checkboxes had nothing to filter.
    #[tokio::test]
    async fn every_stored_edge_kind_reaches_the_graph() {
        let state = state_with(vec![
            record(0x01, "a", Some("team-alpha")),
            record(0x02, "b", Some("team-alpha")),
        ]);
        for &edge_type in EdgeType::ALL {
            insert_edge(&state, 0x01, 0x02, edge_type).await;
        }

        let graph = graph_for(admin(), &state).await;

        let kinds: std::collections::BTreeSet<&str> = graph.edges.iter().map(|e| e.kind.as_str()).collect();
        assert_eq!(
            kinds,
            ["approves", "call", "delegation", "messages", "reads", "writes"]
                .into_iter()
                .collect::<std::collections::BTreeSet<_>>(),
            "all six stored kinds must be emitted, got {kinds:?}"
        );
        assert_eq!(graph.edges.len(), EdgeType::ALL.len());
    }

    /// The two structural kinds keep the wire vocabulary AAASM-5040 shipped —
    /// renaming them would silently break the frontend's edge styling.
    #[test]
    fn the_structural_kinds_keep_their_graph_vocabulary() {
        assert_eq!(graph_edge_kind(EdgeType::DelegatesTo), "delegation");
        assert_eq!(graph_edge_kind(EdgeType::Calls), "call");
        assert_eq!(graph_edge_kind(EdgeType::Reads), "reads");
        assert_eq!(graph_edge_kind(EdgeType::Writes), "writes");
        assert_eq!(graph_edge_kind(EdgeType::Approves), "approves");
        assert_eq!(graph_edge_kind(EdgeType::Messages), "messages");
    }

    // ── cross_team ─────────────────────────────────────────────────────────

    #[tokio::test]
    async fn an_edge_between_two_teams_is_flagged_cross_team() {
        let state = state_with(vec![
            record(0x01, "a", Some("team-alpha")),
            record(0x02, "b", Some("team-beta")),
        ]);
        insert_edge(&state, 0x01, 0x02, EdgeType::Messages).await;

        let graph = graph_for(admin(), &state).await;
        assert_eq!(graph.edges.len(), 1);
        assert!(graph.edges[0].cross_team);
    }

    #[tokio::test]
    async fn an_edge_inside_one_team_is_not_cross_team() {
        let state = state_with(vec![
            record(0x01, "a", Some("team-alpha")),
            record(0x02, "b", Some("team-alpha")),
        ]);
        insert_edge(&state, 0x01, 0x02, EdgeType::Calls).await;

        let graph = graph_for(admin(), &state).await;
        assert!(!graph.edges[0].cross_team);
    }

    /// An endpoint with no team is not a boundary crossing — the same rule
    /// `edges::compute_cross_team` applies, so the two surfaces agree.
    #[test]
    fn a_team_less_endpoint_is_never_cross_team() {
        assert!(!is_cross_team(None, Some("team-alpha")));
        assert!(!is_cross_team(Some("team-alpha"), None));
        assert!(!is_cross_team(None, None));
        assert!(is_cross_team(Some("team-alpha"), Some("team-beta")));
    }

    // ── Effective permissions ──────────────────────────────────────────────

    /// Guards the explicit lineage in [`project_graph_nodes`]: resolving the
    /// cascade without a lineage walks only Global and Agent and drops every
    /// Org- and Team-scoped allow AND deny. Since AAASM-5102 registry-wired the
    /// engine, regressing that call to `collect_cascade` /
    /// `effective_permissions` would no longer break this test on its own — it
    /// guards the projection, and
    /// `agents::tests::a_team_scoped_deny_reaches_the_capabilities_response`
    /// guards the composition root that makes the unlineaged path safe.
    #[tokio::test]
    async fn a_team_scoped_policy_reaches_the_permission_chain() {
        let mut caps = aa_core::CapabilitySet::default();
        caps.deny.insert(aa_core::Capability::TerminalExec);

        let state = state_with_policies(
            vec![record(0x01, "a", Some("team-alpha"))],
            vec![policy_doc(
                "team-rules",
                PolicyScope::Team("team-alpha".to_string()),
                caps,
            )],
        );

        let graph = graph_for(admin(), &state).await;
        let perms = graph.nodes[0]
            .effective_permissions
            .as_ref()
            .expect("the graph endpoint resolves the chain");

        assert!(
            perms.deny.iter().any(|c| c == "terminal_exec"),
            "a Team-scoped deny must reach the merged set: {:?}",
            perms.deny
        );
        let team_tier = perms
            .chain
            .iter()
            .find(|t| t.tier == "team")
            .expect("a team-scoped agent has a team tier");
        assert_eq!(team_tier.scope, "team:team-alpha");
        assert_eq!(team_tier.policies, vec!["team-rules".to_string()]);
        assert_eq!(
            graph.nodes[0].policy_count,
            Some(1),
            "policy_count reads off the same lineage-resolved cascade"
        );
    }

    /// The chain lists only the tiers the agent actually has. An agent with no
    /// `org_id` gets no Org row rather than an invented empty one, and no
    /// parent row exists at all — `PolicyScope` has no parent tier.
    #[tokio::test]
    async fn the_chain_omits_tiers_the_agent_does_not_have() {
        let state = state_with(vec![record(0x01, "a", None)]);

        let graph = graph_for(admin(), &state).await;
        let perms = graph.nodes[0].effective_permissions.as_ref().expect("chain present");

        let tiers: Vec<&str> = perms.chain.iter().map(|t| t.tier.as_str()).collect();
        assert_eq!(tiers, vec!["global", "agent"], "no org / team / parent rows");
        assert!(perms.allow.is_empty());
        assert!(perms.deny.is_empty());
        assert!(!perms.allow_restricted);
    }

    /// An empty merged allow-list carrying a restriction is deny-all, not
    /// "unrestricted" (AAASM-4154) — the flag must survive the projection or the
    /// panel reads a fail-closed cascade as permissive.
    #[tokio::test]
    async fn an_allow_list_restriction_is_carried_through() {
        let mut caps = aa_core::CapabilitySet::default();
        caps.allow.insert(aa_core::Capability::FileRead);

        let state = state_with_policies(
            vec![record(0x01, "a", Some("team-alpha"))],
            vec![policy_doc("global-rules", PolicyScope::Global, caps)],
        );

        let graph = graph_for(admin(), &state).await;
        let perms = graph.nodes[0].effective_permissions.as_ref().expect("chain present");

        assert_eq!(perms.allow, vec!["file_read".to_string()]);
        assert!(perms.allow_restricted);
        let global_tier = &perms.chain[0];
        assert_eq!(global_tier.tier, "global");
        assert_eq!(global_tier.policies, vec!["global-rules".to_string()]);
    }

    // ── Enforcement stages the capability set alone cannot see ─────────────
    //
    // `evaluate_single_doc` returns on the first `Deny`, so `stage_network` and
    // `stage_tool_allow` both run *before* the capability stage. Reading only the
    // merged capability set reported `allow` for actions the gateway refuses —
    // the AAASM-5090 fail-open, repeated in this projection.

    /// A wildcard tool deny blocks every tool call, yet contributes no
    /// `mcp_tool:` capability. Without the `stage_tool_allow` mirror this agent
    /// reported an entirely empty permission set — the panel read "baseline, no
    /// capability restriction" for an agent that cannot invoke a single tool.
    #[tokio::test]
    async fn a_wildcard_tool_deny_reaches_the_permission_set() {
        let state = state_with_policies(
            vec![record_with_tools(
                0x01,
                "a",
                Some("team-alpha"),
                &["search", "send_email"],
            )],
            vec![enforcement_doc(
                "team-rules",
                PolicyScope::Team("team-alpha".to_string()),
                None,
                &[("*", false)],
                None,
            )],
        );

        let graph = graph_for(admin(), &state).await;
        let perms = graph.nodes[0].effective_permissions.as_ref().expect("chain present");

        assert_eq!(
            perms.deny,
            vec!["mcp_tool:search".to_string(), "mcp_tool:send_email".to_string()],
            "every declared tool the wildcard denies must be reported"
        );
        assert!(perms.allow.is_empty());
    }

    /// A `tools` deny and a `capabilities.allow` grant can contradict each other
    /// across the cascade. The evaluator hits `stage_tool_allow` first, so the
    /// tool is denied — reporting it in `allow` advertises a permission the
    /// gateway refuses, the permissive direction of the drift.
    #[tokio::test]
    async fn a_tool_stage_deny_beats_a_capability_grant() {
        let mut caps = aa_core::CapabilitySet::default();
        caps.allow.insert(aa_core::Capability::McpTool("search".to_string()));
        caps.allow.insert(aa_core::Capability::McpTool("summarise".to_string()));

        let state = state_with_policies(
            vec![record(0x01, "a", Some("team-alpha"))],
            vec![
                enforcement_doc("global-grants", PolicyScope::Global, Some(caps), &[], None),
                enforcement_doc(
                    "team-rules",
                    PolicyScope::Team("team-alpha".to_string()),
                    None,
                    &[("search", false)],
                    None,
                ),
            ],
        );

        let graph = graph_for(admin(), &state).await;
        let perms = graph.nodes[0].effective_permissions.as_ref().expect("chain present");

        assert_eq!(
            perms.allow,
            vec!["mcp_tool:summarise".to_string()],
            "a tool the tools stage denies must not be advertised as allowed"
        );
        assert!(
            perms.deny.contains(&"mcp_tool:search".to_string()),
            "and must be reported as denied: {:?}",
            perms.deny
        );
    }

    /// A declared-but-empty network allowlist is deny-all egress (AAASM-3127 /
    /// AAASM-3730). It lives in the `network` block, so the capability set never
    /// mentions `network_outbound` and the projection reported nothing at all.
    #[tokio::test]
    async fn an_empty_network_allowlist_denies_outbound_access() {
        let mut caps = aa_core::CapabilitySet::default();
        caps.allow.insert(aa_core::Capability::NetworkOutbound);

        let state = state_with_policies(
            vec![record(0x01, "a", Some("team-alpha"))],
            vec![enforcement_doc(
                "team-rules",
                PolicyScope::Team("team-alpha".to_string()),
                Some(caps),
                &[],
                Some(Vec::new()),
            )],
        );

        let graph = graph_for(admin(), &state).await;
        let perms = graph.nodes[0].effective_permissions.as_ref().expect("chain present");

        assert!(
            perms.deny.contains(&"network_outbound".to_string()),
            "an empty allowlist is deny-all egress: {:?}",
            perms.deny
        );
        assert!(
            !perms.allow.contains(&"network_outbound".to_string()),
            "and the grant it overrides must not survive into allow: {:?}",
            perms.allow
        );
    }

    /// `deny(file_write)` also blocks `file_delete` (`aa_core::capability_is_denied`
    /// — the fail-closed migration for policies authored before `file_delete`
    /// existed). Emitting the raw merged deny set under-stated the gateway by one
    /// capability, and under-reporting a denial is the permissive direction.
    #[tokio::test]
    async fn a_write_deny_reports_the_delete_it_also_blocks() {
        let mut caps = aa_core::CapabilitySet::default();
        caps.deny.insert(aa_core::Capability::FileWrite);

        let state = state_with_policies(
            vec![record(0x01, "a", Some("team-alpha"))],
            vec![policy_doc(
                "team-rules",
                PolicyScope::Team("team-alpha".to_string()),
                caps,
            )],
        );

        let graph = graph_for(admin(), &state).await;
        let perms = graph.nodes[0].effective_permissions.as_ref().expect("chain present");

        assert_eq!(
            perms.deny,
            vec!["file_delete".to_string(), "file_write".to_string()],
            "a write deny blocks delete too, so both belong in the reported set"
        );
    }

    // ── Authorization / tenancy ────────────────────────────────────────────

    /// Deny-by-default: a non-admin caller with no tenant scope can never be
    /// confined to a tenant, so it gets an empty graph, not a cross-tenant dump.
    #[tokio::test]
    async fn an_unscoped_caller_gets_an_empty_graph() {
        let state = state_with(vec![
            record(0x01, "a", Some("team-alpha")),
            record(0x02, "b", Some("team-alpha")),
        ]);
        insert_edge(&state, 0x01, 0x02, EdgeType::Reads).await;

        let graph = graph_for(reader(vec![Scope::Read], None, None), &state).await;
        assert!(graph.nodes.is_empty());
        assert!(graph.edges.is_empty());
    }

    /// An edge is emitted only when BOTH endpoints are visible nodes, so a
    /// widened projection cannot leak an out-of-tenant peer through a kind the
    /// old two-kind walk never looked at.
    #[tokio::test]
    async fn an_edge_to_an_out_of_tenant_peer_is_dropped() {
        let state = state_with(vec![
            record(0x01, "mine", Some("team-alpha")),
            record(0x02, "theirs", Some("team-beta")),
        ]);
        for &edge_type in EdgeType::ALL {
            insert_edge(&state, 0x01, 0x02, edge_type).await;
        }

        let graph = graph_for(reader(vec![Scope::Read], None, Some("team-alpha")), &state).await;
        assert_eq!(graph.nodes.len(), 1, "only the caller's own team is visible");
        assert_eq!(graph.nodes[0].name, "mine");
        assert!(
            graph.edges.is_empty(),
            "every kind pointing at the other team must be dropped, got {:?}",
            graph.edges
        );
    }

    #[tokio::test]
    async fn an_empty_registry_projects_an_empty_graph() {
        let state = state_with(vec![]);
        let graph = graph_for(admin(), &state).await;
        assert!(graph.nodes.is_empty());
        assert!(graph.edges.is_empty());
    }
}
