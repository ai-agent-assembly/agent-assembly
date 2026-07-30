//! Shared response types for all `/v1/topology/*` endpoints.
//!
//! All types in this module are pure data definitions — no endpoint logic.
//! Endpoint handlers in `routes/topology.rs` import these and convert from
//! `AgentRecord` via the provided `From` impls.

use std::collections::{BTreeMap, HashMap};

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use aa_gateway::registry::{AgentRecord, AgentStatus};

// ---------------------------------------------------------------------------
// Internal helpers (pub(crate) so routes can reuse without duplication)
// ---------------------------------------------------------------------------

pub(crate) fn format_id(id: &[u8; 16]) -> String {
    id.iter().map(|b| format!("{b:02x}")).collect()
}

pub(crate) fn status_str(status: &AgentStatus) -> &'static str {
    match status {
        AgentStatus::Active => "active",
        AgentStatus::Suspended(_) => "suspended",
        AgentStatus::Deregistered => "deregistered",
    }
}

/// Runtime status of an agent node in the topology projection.
///
/// AAASM-5218 — constrains the wire vocabulary of [`AgentNode::status`] at the
/// OpenAPI derive to exactly the three values `status_str` can emit, so the
/// generated spec (and the TypeScript client) advertises a closed enum instead
/// of an unconstrained `string`. Serializes lowercase, matching the strings the
/// registry's [`AgentStatus`] mapped to before this was a free-form field.
///
/// Deliberately distinct from the runtime registry [`AgentStatus`], whose
/// `Suspended(_)` variant carries a parameterised reason an enum cannot express,
/// and from the capability-view `AgentStatus` — the three agent-status
/// vocabularies are not reconciled here (that is an ADR question, see AAASM-5209).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum AgentNodeStatus {
    Active,
    Suspended,
    Deregistered,
}

impl From<&AgentStatus> for AgentNodeStatus {
    fn from(status: &AgentStatus) -> Self {
        match status {
            AgentStatus::Active => AgentNodeStatus::Active,
            AgentStatus::Suspended(_) => AgentNodeStatus::Suspended,
            AgentStatus::Deregistered => AgentNodeStatus::Deregistered,
        }
    }
}

/// Enforcement-mode badge value for a node — `enforce`, `shadow`, or `off`.
///
/// Read from the agent record's `metadata["mode"]`, mirroring the Fleet page's
/// `parseMode` exactly: a recognised value is passed through, and anything else
/// (including an absent key) falls back to `enforce`. Sourcing the badge from the
/// same `metadata.mode` the Fleet chip uses keeps the two surfaces consistent
/// rather than introducing a second, divergent notion of an agent's mode.
pub(crate) fn agent_mode(record: &AgentRecord) -> String {
    match record.metadata.get("mode").map(String::as_str) {
        Some(m @ ("enforce" | "shadow" | "off")) => m.to_owned(),
        _ => "enforce".to_owned(),
    }
}

// ---------------------------------------------------------------------------
// Response types
// ---------------------------------------------------------------------------

/// Overview of the entire agent topology across all teams.
///
/// # Example JSON
/// ```json
/// {
///   "team_count": 2,
///   "root_agent_count": 3,
///   "total_agent_count": 12,
///   "teams": [{ "team_id": "team-alpha", "agent_count": 7, "root_agent_count": 1 }],
///   "standalone_root_agents": []
/// }
/// ```
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, ToSchema)]
#[schema(example = json!({
    "team_count": 2,
    "root_agent_count": 3,
    "total_agent_count": 12,
    "teams": [{"team_id": "team-alpha", "agent_count": 7, "root_agent_count": 1}],
    "standalone_root_agents": []
}))]
pub struct TopologyOverview {
    /// Number of teams with at least one registered agent.
    pub team_count: usize,
    /// Number of root agents (depth == 0) across all teams.
    pub root_agent_count: usize,
    /// Total number of agents in the registry.
    pub total_agent_count: usize,
    /// Per-team agent count summaries, sorted by team_id.
    pub teams: Vec<TeamSummary>,
    /// Root agents that are not assigned to any team, sorted by agent id.
    pub standalone_root_agents: Vec<AgentNode>,
}

/// High-level statistics for a single team.
///
/// # Example JSON
/// ```json
/// { "team_id": "team-alpha", "agent_count": 7, "root_agent_count": 1 }
/// ```
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
#[schema(example = json!({ "team_id": "team-alpha", "agent_count": 7, "root_agent_count": 1 }))]
pub struct TeamSummary {
    /// Team identifier.
    pub team_id: String,
    /// Total agents in this team.
    pub agent_count: usize,
    /// Root agents (depth == 0) in this team.
    pub root_agent_count: usize,
}

/// Per-agent daily budget projection for a topology node (AAASM-5045).
///
/// A slim read-only view of the gateway `BudgetTracker` state for one agent —
/// the same source the `/api/v1/costs` per-agent
/// breakdown reads. `spend_usd` is today's accrued spend (0 when the agent has
/// no accrual yet); `limit_usd` is the agent's effective daily limit
/// (per-agent override, else the server-wide daily limit) or `null` when no
/// limit is configured. Emitted as `f64` (not the tracker's `Decimal`) because
/// the dashboard budget bar renders numbers directly — the two decimals of a
/// USD amount are well within `f64`'s exact range.
///
/// # Example JSON
/// ```json
/// { "spend_usd": 4.10, "limit_usd": 100.0 }
/// ```
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
#[schema(example = json!({ "spend_usd": 4.10, "limit_usd": 100.0 }))]
pub struct NodeBudget {
    /// Daily spend accrued for this agent today, in USD.
    pub spend_usd: f64,
    /// Effective daily budget limit in USD (per-agent override, else the
    /// server-wide daily limit), or `null` when no limit is configured.
    pub limit_usd: Option<f64>,
}

/// One scope tier of an agent's policy-inheritance chain (AAASM-5099).
///
/// A tier is emitted only when the agent actually has that selector: an agent
/// with no `org_id` has no Org tier, so no Org row appears. The `Tool` tier is
/// deliberately absent — it is selected per *action* (see
/// `aa_gateway::engine::action_tool_name`), not per agent, so there is no
/// agent-level answer to project.
///
/// # Example JSON
/// ```json
/// { "tier": "team", "scope": "team:platform", "policies": ["team-baseline"] }
/// ```
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
#[schema(example = json!({ "tier": "team", "scope": "team:platform", "policies": ["team-baseline"] }))]
pub struct PolicyChainTier {
    /// Cascade tier: `global`, `org`, `team`, or `agent`.
    pub tier: String,
    /// Wire-format scope selector this tier resolves to, e.g. `team:platform`
    /// — the same string `PolicyScope`'s `Display` produces, so it matches the
    /// `scope` a policy document declares.
    pub scope: String,
    /// Names of the loaded policy documents at this tier, in cascade order.
    /// Empty when the tier applies to the agent but carries no policy — that is
    /// real state ("no team policy"), not missing data.
    pub policies: Vec<String>,
}

/// The policy cascade that governs one agent, with per-tier provenance
/// (AAASM-5099) — the data behind the node-detail Policy-Inheritance panel.
///
/// `chain` is the `Global → Org → Team → Agent` walk, broadest first. `allow` /
/// `deny` are the capability set that walk produces after the *earlier*
/// enforcement stages are folded in — a capability blocked by the network or
/// tool stage appears in `deny` and never in `allow`, even though the merged
/// capability set alone says nothing about it. See
/// `routes::topology::project_effective_permissions` for exactly which stages are
/// mirrored and which cannot be.
///
/// Two consequences for a reader of this payload:
///
/// * `allow_restricted` must be read together with `allow`: an empty `allow` with
///   `allow_restricted = true` is deny-all, not "unrestricted" (AAASM-4154).
/// * Absence from `deny` is **not** a grant. A `tools: { "*": { allow: false } }`
///   cascade denies tools that have never been named, and no list can enumerate
///   them.
///
/// The hi-fi mock (`design/v1/hi-fi/topology.jsx`) additionally draws a
/// "parent" row. There is no parent tier in the product's scope vocabulary
/// (`aa_gateway::policy::scope::PolicyScope` is `Global | Org | Team | Agent |
/// Tool`) — a parent agent's own `agent:`-scoped policies are not inherited by
/// its children — so no parent row is emitted rather than fabricating one.
///
/// Distinct from `agents::EffectivePermissionsResponse`
/// (`GET /api/v1/agents/{id}/capabilities`), which lists one row per *document*
/// that declares capabilities. This one lists one row per *tier* — including a
/// tier that carries no policy, which is what the panel renders as "no team
/// policy" — and is embedded per node so the graph needs no per-agent fan-out.
///
/// # Example JSON
/// ```json
/// {
///   "chain": [{ "tier": "global", "scope": "global", "policies": ["baseline"] }],
///   "allow": ["file_read"],
///   "deny": ["terminal_exec"],
///   "allow_restricted": true
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
#[schema(example = json!({
    "chain": [{ "tier": "global", "scope": "global", "policies": ["baseline"] }],
    "allow": ["file_read"],
    "deny": ["terminal_exec"],
    "allow_restricted": true
}))]
pub struct NodeEffectivePermissions {
    /// Cascade tiers that apply to this agent, broadest → narrowest.
    pub chain: Vec<PolicyChainTier>,
    /// Capabilities the merged cascade explicitly allows, canonical wire names
    /// (`file_read`, `mcp_tool:<name>`, …), sorted.
    pub allow: Vec<String>,
    /// Capabilities the merged cascade explicitly denies, canonical wire names,
    /// sorted.
    pub deny: Vec<String>,
    /// Whether an allow-list restriction is in force — anything absent from
    /// `allow` is denied, even when `allow` is empty.
    pub allow_restricted: bool,
}

/// Minimal agent representation used in list and tree responses.
///
/// # Example JSON
/// ```json
/// {
///   "id": "0102030405060708090a0b0c0d0e0f10",
///   "name": "my-agent",
///   "depth": 1,
///   "status": "active",
///   "team_id": "team-alpha"
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
#[schema(example = json!({
    "id": "0102030405060708090a0b0c0d0e0f10",
    "name": "my-agent",
    "depth": 1,
    "status": "active",
    "team_id": "team-alpha",
    "mode": "enforce",
    "flagged": false,
    "trust": null,
    "owner": "platform-team",
    "policy_count": 3,
    "budget": { "spend_usd": 4.10, "limit_usd": 100.0 }
}))]
pub struct AgentNode {
    /// Hex-encoded agent UUID.
    pub id: String,
    /// Human-readable agent name.
    pub name: String,
    /// Delegation depth — 0 for root agents.
    pub depth: u32,
    /// Runtime status: `active`, `suspended`, or `deregistered`.
    pub status: AgentNodeStatus,
    /// Team this agent belongs to, if any.
    pub team_id: Option<String>,
    /// Governance level — included only when `show_budget=true`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub governance_level: Option<String>,
    /// Enforcement-mode badge: `enforce`, `shadow`, or `off`. Derived from the
    /// agent record's `metadata["mode"]` (defaulting to `enforce`) so the
    /// topology mode badge matches the Fleet page's mode chip for the same agent.
    pub mode: String,
    /// Whether the agent is policy-flagged — it has recorded at least one
    /// `PolicyViolation` audit event (`count > 0`, AAASM-5103). Drives the
    /// danger-tinted node card and ⚑ marker in the topology graph.
    ///
    /// Derived from the per-agent audit aggregate
    /// ([`crate::routes::agent_violations::AgentViolationCounts`]), which the
    /// topology handlers build once per request and set here — the
    /// `From<&AgentRecord>` conversion leaves it `false` because the record no
    /// longer carries a violation counter (the dead field it used to read was
    /// removed in AAASM-5103).
    pub flagged: bool,
    /// Trust score as an integer on a 0–100 scale, or `null` when no
    /// trust-analytics source exists yet.
    /// The registry does not compute a per-agent trust score today, so this is
    /// currently always `null` — the same placeholder the Fleet page uses. Kept
    /// present (not omitted) so the client renders an explicit "no data" state
    /// instead of inferring a misleading default.
    //
    // AAASM-5104 — integer, not `f64`: the ratified mock renders a whole number
    // and a float implies a precision no scoring formula has agreed to. See
    // [`crate::models::capability::CapabilityAgent::trust`] for the full
    // rationale behind the shared representation and null contract.
    #[schema(required = true, minimum = 0, maximum = 100)]
    pub trust: Option<u8>,
    /// Operator / engineer who owns this agent, read from the agent record's
    /// `metadata["owner"]` (AAASM-5045). `null` when the registrant supplied no
    /// owner tag — kept present (not omitted) so the node-detail panel renders an
    /// explicit "no data" state rather than inferring a value.
    pub owner: Option<String>,
    /// Number of governance policies whose scope cascade applies to this agent
    /// — `Global → Org → Team → Agent`, the same walk `PolicyEngine::evaluate`
    /// uses (AAASM-5045). `null` when this projection is built without a
    /// policy-engine lookup: only the whole-fleet graph endpoint
    /// (`GET /api/v1/topology`) resolves it; the list / tree / team endpoints
    /// leave it `null` rather than emitting a misleading `0`.
    pub policy_count: Option<u32>,
    /// Per-agent daily budget spend / limit (AAASM-5045), or `null` when this
    /// projection is built without a budget-tracker lookup. Like `policy_count`,
    /// only the graph endpoint resolves it; the other endpoints leave it `null`.
    pub budget: Option<NodeBudget>,
    /// The agent's policy-inheritance chain and merged capability set
    /// (AAASM-5099), or `null` when this projection is built without a
    /// policy-engine lookup. Like `policy_count` / `budget`, only the graph
    /// endpoint resolves it — the list / tree / team endpoints leave it `null`
    /// so the client renders "no data" rather than an empty-but-authoritative
    /// chain.
    pub effective_permissions: Option<NodeEffectivePermissions>,
}

impl From<&AgentRecord> for AgentNode {
    fn from(r: &AgentRecord) -> Self {
        AgentNode {
            id: format_id(&r.agent_id),
            name: r.name.clone(),
            depth: r.depth,
            status: AgentNodeStatus::from(&r.status),
            team_id: r.team_id.clone(),
            governance_level: None,
            mode: agent_mode(r),
            // Left `false` here: the record no longer carries a violation counter
            // (AAASM-5103 removed it). The topology handlers enrich `flagged` from
            // the per-agent audit aggregate so every topology surface flags the
            // same agents the Fleet page does.
            flagged: false,
            trust: None,
            // `owner` is a pure record field (agent metadata), so it is resolved
            // here and carried by every AgentNode consumer. `policy_count` /
            // `budget` need the policy engine / budget tracker, which this
            // record-only conversion can't reach — the graph handler enriches
            // them; here they stay `null`.
            owner: r.metadata.get("owner").cloned(),
            policy_count: None,
            budget: None,
            effective_permissions: None,
        }
    }
}

/// One directed edge in the dashboard topology graph (AAASM-5040, widened in
/// AAASM-5099).
///
/// A slim projection of a stored [`aa_core::topology::Edge`] carrying what the
/// dashboard graph renders: the two hex-encoded endpoints, the relation `kind`,
/// and whether the edge crosses a team boundary.
///
/// `kind` covers all six stored [`aa_core::topology::EdgeType`] variants. The
/// two structural kinds keep the graph vocabulary the frontend already renders
/// (`delegates_to` → `delegation`, `calls` → `call`); the other four pass the
/// stored wire string through unchanged (`reads`, `writes`, `approves`,
/// `messages`), matching the frontend `TopologyEdge` 1:1 so the client consumes
/// edges without remapping.
///
/// # Example JSON
/// ```json
/// { "source": "0102030405060708090a0b0c0d0e0f10", "target": "aabbccdd00112233aabbccdd00112233", "kind": "delegation", "cross_team": false }
/// ```
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
#[schema(example = json!({
    "source": "0102030405060708090a0b0c0d0e0f10",
    "target": "aabbccdd00112233aabbccdd00112233",
    "kind": "delegation",
    "cross_team": false
}))]
pub struct TopologyGraphEdge {
    /// Hex-encoded UUID of the source (delegating / calling) agent.
    pub source: String,
    /// Hex-encoded UUID of the target agent.
    pub target: String,
    /// Relation kind rendered by the graph: `delegation`, `call`, `reads`,
    /// `writes`, `approves`, or `messages`.
    pub kind: String,
    /// Whether the two endpoints belong to different teams. Matches the
    /// `is_cross_team` rule `/topology/edges` uses (`edges::compute_cross_team`):
    /// true only when both endpoints carry a `team_id` and the two differ — an
    /// endpoint with no team is never counted as crossing a boundary.
    pub cross_team: bool,
}

/// The whole-fleet topology graph rendered by the dashboard Topology page
/// (AAASM-5040): every agent visible to the caller as a node, plus every stored
/// edge between those nodes (all six relation kinds, AAASM-5099).
///
/// Nodes reuse the [`AgentNode`] projection (so the per-node enforcement-mode,
/// flagged, and trust badges from AAASM-5036 are carried through), letting the
/// dashboard render those badges from live registry data instead of a fixture.
///
/// # Example JSON
/// ```json
/// { "nodes": [], "edges": [] }
/// ```
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, ToSchema)]
#[schema(example = json!({ "nodes": [], "edges": [] }))]
pub struct TopologyGraphResponse {
    /// All agents visible to the caller, one graph node each (sorted by id).
    pub nodes: Vec<AgentNode>,
    /// Edges of every stored relation kind whose endpoints are both visible
    /// nodes.
    pub edges: Vec<TopologyGraphEdge>,
}

/// Recursive tree node representing an agent and all its descendants.
///
/// # Example JSON
/// ```json
/// {
///   "id": "0102030405060708090a0b0c0d0e0f10",
///   "name": "root-agent",
///   "depth": 0,
///   "status": "active",
///   "team_id": "team-alpha",
///   "delegation_reason": null,
///   "spawned_by_tool": null,
///   "children": []
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
#[schema(example = json!({
    "id": "0102030405060708090a0b0c0d0e0f10",
    "name": "root-agent",
    "depth": 0,
    "status": "active",
    "team_id": "team-alpha",
    "delegation_reason": null,
    "spawned_by_tool": null,
    "mode": "enforce",
    "flagged": false,
    "trust": null,
    "children": []
}))]
pub struct AgentTree {
    /// Hex-encoded agent UUID.
    pub id: String,
    /// Human-readable agent name.
    pub name: String,
    /// Delegation depth — 0 for root agents.
    pub depth: u32,
    /// Runtime status: `active`, `suspended`, or `deregistered`.
    pub status: String,
    /// Team this agent belongs to, if any.
    pub team_id: Option<String>,
    /// Reason this agent was delegated from its parent, if recorded.
    pub delegation_reason: Option<String>,
    /// Tool that spawned this agent, if known.
    pub spawned_by_tool: Option<String>,
    /// Governance level — included only when `show_budget=true`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub governance_level: Option<String>,
    /// Enforcement-mode badge: `enforce`, `shadow`, or `off`. Same
    /// `metadata["mode"]` derivation as [`AgentNode::mode`].
    pub mode: String,
    /// Whether the agent is policy-flagged (`count > 0`). Same derivation and
    /// audit source as [`AgentNode::flagged`] (AAASM-5103).
    pub flagged: bool,
    /// Trust score as an integer on a 0–100 scale, or `null` when no
    /// trust-analytics source exists yet.
    /// Same representation, placeholder, and null contract as
    /// [`AgentNode::trust`] (AAASM-5104).
    #[schema(required = true, minimum = 0, maximum = 100)]
    pub trust: Option<u8>,
    /// Direct children of this agent in the delegation tree.
    #[schema(schema_with = agent_tree_children_schema)]
    pub children: Vec<AgentTree>,
}

/// Returns a schema for `Vec<AgentTree>` using a `$ref` to break the recursive cycle.
///
/// Without this, utoipa's ToSchema derive recurses infinitely and overflows the stack.
fn agent_tree_children_schema() -> utoipa::openapi::RefOr<utoipa::openapi::schema::Schema> {
    use utoipa::openapi::schema::{ArrayBuilder, Ref};
    ArrayBuilder::new()
        .items(Ref::from_schema_name("AgentTree"))
        .build()
        .into()
}

/// All agents belonging to a single team.
///
/// # Example JSON
/// ```json
/// { "team_id": "team-alpha", "agent_count": 2, "members": [] }
/// ```
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
#[schema(example = json!({ "team_id": "team-alpha", "agent_count": 2, "members": [] }))]
pub struct TeamTopology {
    /// Team identifier.
    pub team_id: String,
    /// Number of agents in this team (after filtering).
    pub agent_count: usize,
    /// Agents in this team.
    pub members: Vec<AgentNode>,
}

/// An agent's complete ancestry chain ordered root-first.
///
/// The first element is the root agent; the last element is the requested
/// agent itself. A root agent returns a list of length 1 containing only itself.
///
/// # Example JSON
/// ```json
/// {
///   "agent_id": "aabbccdd00112233aabbccdd00112233",
///   "ancestor_count": 2,
///   "ancestors": [
///     { "id": "root000000000000root000000000000", "name": "root", "depth": 0, "delegation_reason": null, "team_id": null },
///     { "id": "aabbccdd00112233aabbccdd00112233", "name": "child", "depth": 1, "delegation_reason": "orchestrate", "team_id": "team-alpha" }
///   ]
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
#[schema(example = json!({
    "agent_id": "aabbccdd00112233aabbccdd00112233",
    "ancestor_count": 2,
    "ancestors": [
        {"id": "root000000000000root000000000000", "name": "root", "depth": 0, "delegation_reason": null, "team_id": null},
        {"id": "aabbccdd00112233aabbccdd00112233", "name": "child", "depth": 1, "delegation_reason": "orchestrate", "team_id": "team-alpha"}
    ]
}))]
pub struct AgentLineage {
    /// The subject agent's hex-encoded UUID.
    pub agent_id: String,
    /// Number of entries in `ancestors` (includes the agent itself).
    pub ancestor_count: usize,
    /// Ordered ancestry: index 0 is the root agent, last element is the requested agent.
    pub ancestors: Vec<LineageStep>,
}

/// One step in an agent's ancestry chain.
///
/// # Example JSON
/// ```json
/// { "id": "root000000000000root000000000000", "name": "root", "depth": 0, "delegation_reason": null, "team_id": null }
/// ```
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
#[schema(example = json!({ "id": "root000000000000root000000000000", "name": "root", "depth": 0, "delegation_reason": null, "team_id": null }))]
pub struct LineageStep {
    /// Hex-encoded UUID of this ancestor (or the subject agent).
    pub id: String,
    /// Human-readable name.
    pub name: String,
    /// Delegation depth of this node.
    pub depth: u32,
    /// Reason the next agent in the chain was delegated from this node.
    pub delegation_reason: Option<String>,
    /// Team this node belongs to.
    pub team_id: Option<String>,
}

/// Aggregate topology statistics across all registered agents.
///
/// # Example JSON
/// ```json
/// {
///   "total_agents": 15,
///   "root_agent_count": 3,
///   "max_depth": 4,
///   "active_count": 12,
///   "suspended_count": 2,
///   "deregistered_count": 1,
///   "team_count": 2,
///   "team_sizes": { "team-alpha": 8, "team-beta": 4 },
///   "depth_histogram": { "0": 3, "1": 7, "2": 5 },
///   "team_size_histogram": { "4": 1, "8": 1 },
///   "spawn_count_histogram": { "0": 8, "2": 4, "4": 1 },
///   "orphan_count": 2,
///   "avg_children_per_parent": 2.5
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
#[schema(example = json!({
    "total_agents": 15,
    "root_agent_count": 3,
    "max_depth": 4,
    "active_count": 12,
    "suspended_count": 2,
    "deregistered_count": 1,
    "team_count": 2,
    "team_sizes": {"team-alpha": 8, "team-beta": 4},
    "depth_histogram": {"0": 3, "1": 7, "2": 5},
    "team_size_histogram": {"4": 1, "8": 1},
    "spawn_count_histogram": {"0": 8, "2": 4, "4": 1},
    "orphan_count": 2,
    "avg_children_per_parent": 2.5
}))]
pub struct TopologyStats {
    /// Total agents in the registry.
    pub total_agents: usize,
    /// Number of root agents (depth == 0).
    pub root_agent_count: usize,
    /// Maximum observed delegation depth.
    pub max_depth: u32,
    /// Agents currently in `Active` status.
    pub active_count: usize,
    /// Agents currently in `Suspended` status.
    pub suspended_count: usize,
    /// Agents in `Deregistered` status.
    pub deregistered_count: usize,
    /// Number of teams with at least one agent.
    pub team_count: usize,
    /// Agent count per team (team_id → count).
    pub team_sizes: HashMap<String, usize>,
    /// Agent count per depth level (depth → count).
    pub depth_histogram: BTreeMap<String, u32>,
    /// Number of teams per team-size bucket (team_size → team_count).
    pub team_size_histogram: BTreeMap<String, u32>,
    /// Number of agents per child-count bucket (child_count → agent_count).
    pub spawn_count_histogram: BTreeMap<String, u32>,
    /// Agents that have no team assignment and are not root agents (depth > 0).
    pub orphan_count: usize,
    /// Average number of children across all agents that have at least one child.
    pub avg_children_per_parent: f64,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json;

    fn roundtrip<T: Serialize + for<'de> Deserialize<'de> + PartialEq + std::fmt::Debug>(val: &T) {
        let json = serde_json::to_string(val).expect("serialize");
        let back: T = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*val, back);
    }

    /// Minimal `AgentRecord` for exercising the badge-derivation helpers and the
    /// `From<&AgentRecord>` impl. Only the `metadata` the `agent_mode` helper
    /// reads is meaningful here; `flagged` is enriched by the handlers from the
    /// audit aggregate, not the record (AAASM-5103).
    fn make_record() -> AgentRecord {
        AgentRecord {
            agent_id: [0x01; 16],
            name: "agent-x".to_string(),
            framework: "langgraph".to_string(),
            version: "0.1.0".to_string(),
            risk_tier: 1,
            tool_names: vec![],
            public_key: "test-pubkey".to_string(),
            credential_token: "test-token".to_string(),
            metadata: std::collections::BTreeMap::new(),
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
            team_id: Some("team-alpha".to_string()),
            org_id: None,
            depth: 0,
            delegation_reason: None,
            spawned_by_tool: None,
            root_agent_id: Some([0x01; 16]),
            children: Vec::new(),
            parent_key: None,
            enforcement_mode: None,
        }
    }

    fn make_agent_node() -> AgentNode {
        AgentNode {
            id: "0102030405060708090a0b0c0d0e0f10".to_string(),
            name: "agent-x".to_string(),
            depth: 1,
            status: AgentNodeStatus::Active,
            team_id: Some("team-alpha".to_string()),
            governance_level: None,
            mode: "enforce".to_string(),
            flagged: false,
            trust: None,
            owner: None,
            policy_count: None,
            budget: None,
            effective_permissions: None,
        }
    }

    #[test]
    fn agent_node_roundtrip() {
        roundtrip(&make_agent_node());
    }

    #[test]
    fn agent_node_omits_governance_level_when_none() {
        let node = make_agent_node();
        let json: serde_json::Value = serde_json::from_str(&serde_json::to_string(&node).unwrap()).unwrap();
        assert!(json.get("governance_level").is_none());
    }

    #[test]
    fn agent_node_emits_trust_null_not_omitted() {
        // `trust` has no data source yet, but the client renders an explicit
        // "no data" state — so `null` must be present, never omitted.
        let node = make_agent_node();
        let json: serde_json::Value = serde_json::from_str(&serde_json::to_string(&node).unwrap()).unwrap();
        assert!(json.get("trust").is_some(), "trust key must be present");
        assert!(json["trust"].is_null(), "trust must serialize as null");
        // AAASM-5104 — an unmeasured score must be unreadable as a real one.
        assert!(!json["trust"].is_number(), "an unmeasured trust must not be a number");
        assert_ne!(json["trust"], 0, "trust must never fold to a scored zero");
        assert_eq!(json["mode"], "enforce");
        assert_eq!(json["flagged"], false);
        // AAASM-5045 — owner / policy_count / budget follow the same "present
        // null, never omitted" contract as trust so the client renders an
        // explicit "no data" state instead of a misleading default.
        for key in ["owner", "policy_count", "budget"] {
            assert!(json.get(key).is_some(), "{key} key must be present");
            assert!(json[key].is_null(), "{key} must serialize as null when unset");
        }
    }

    #[test]
    fn node_budget_roundtrip_and_null_limit() {
        roundtrip(&NodeBudget {
            spend_usd: 4.10,
            limit_usd: Some(100.0),
        });
        let no_limit = NodeBudget {
            spend_usd: 0.0,
            limit_usd: None,
        };
        let json: serde_json::Value = serde_json::from_str(&serde_json::to_string(&no_limit).unwrap()).unwrap();
        assert_eq!(json["spend_usd"], 0.0);
        assert!(json.get("limit_usd").is_some(), "limit_usd key must be present");
        assert!(
            json["limit_usd"].is_null(),
            "limit_usd must serialize as null when unset"
        );
    }

    #[test]
    fn agent_mode_reads_metadata_and_defaults_to_enforce() {
        let mut record = make_record();
        // Recognised values pass through.
        for m in ["enforce", "shadow", "off"] {
            record.metadata.insert("mode".to_string(), m.to_string());
            assert_eq!(agent_mode(&record), m);
        }
        // Unrecognised value falls back to enforce (mirrors Fleet parseMode).
        record.metadata.insert("mode".to_string(), "bogus".to_string());
        assert_eq!(agent_mode(&record), "enforce");
        // Absent key falls back to enforce.
        record.metadata.remove("mode");
        assert_eq!(agent_mode(&record), "enforce");
    }

    #[test]
    fn agent_node_from_record_leaves_flagged_false_for_handler_enrichment() {
        // AAASM-5103 — the record carries no violation counter, so the
        // record-only conversion cannot know whether an agent is flagged. It
        // leaves `flagged = false`; the topology handlers set it from the audit
        // aggregate so every surface flags the same agents.
        let record = make_record();
        assert!(!AgentNode::from(&record).flagged);
    }

    #[test]
    fn agent_node_from_record_derives_badge_fields() {
        let mut record = make_record();
        record.metadata.insert("mode".to_string(), "shadow".to_string());
        let node = AgentNode::from(&record);
        assert_eq!(node.mode, "shadow");
        // `flagged` is enriched by the handler, not the conversion (AAASM-5103).
        assert!(!node.flagged);
        assert!(node.trust.is_none());
        // AAASM-5045 — `owner` is a pure record field, resolved from metadata by
        // the `From` impl; `policy_count` / `budget` need external stores the
        // record-only conversion can't reach, so they stay `None` here.
        assert!(node.owner.is_none());
        assert!(node.policy_count.is_none());
        assert!(node.budget.is_none());
    }

    #[test]
    fn agent_node_from_record_reads_owner_metadata() {
        let mut record = make_record();
        record.metadata.insert("owner".to_string(), "platform-team".to_string());
        assert_eq!(AgentNode::from(&record).owner.as_deref(), Some("platform-team"));
    }

    #[test]
    fn team_summary_roundtrip() {
        roundtrip(&TeamSummary {
            team_id: "team-alpha".to_string(),
            agent_count: 7,
            root_agent_count: 1,
        });
    }

    #[test]
    fn topology_overview_roundtrip() {
        roundtrip(&TopologyOverview {
            team_count: 2,
            root_agent_count: 3,
            total_agent_count: 12,
            teams: vec![TeamSummary {
                team_id: "team-alpha".to_string(),
                agent_count: 7,
                root_agent_count: 1,
            }],
            standalone_root_agents: vec![make_agent_node()],
        });
    }

    #[test]
    fn agent_tree_roundtrip() {
        let leaf = AgentTree {
            id: "cc".to_string(),
            name: "leaf".to_string(),
            depth: 2,
            status: "active".to_string(),
            team_id: None,
            delegation_reason: Some("sub-task".to_string()),
            spawned_by_tool: None,
            governance_level: None,
            mode: "shadow".to_string(),
            flagged: true,
            trust: None,
            children: vec![],
        };
        let root = AgentTree {
            id: "aa".to_string(),
            name: "root".to_string(),
            depth: 0,
            status: "active".to_string(),
            team_id: Some("team-alpha".to_string()),
            delegation_reason: None,
            spawned_by_tool: None,
            governance_level: None,
            mode: "enforce".to_string(),
            flagged: false,
            trust: None,
            children: vec![leaf],
        };
        roundtrip(&root);
    }

    /// AAASM-5104 — `AgentTree` carries the same trust contract as `AgentNode`:
    /// present-and-`null` when unmeasured, and a whole number when scored.
    #[test]
    fn agent_tree_emits_trust_null_not_omitted_and_scores_as_an_integer() {
        let mut tree = AgentTree {
            id: "aa".to_string(),
            name: "root".to_string(),
            depth: 0,
            status: "active".to_string(),
            team_id: None,
            delegation_reason: None,
            spawned_by_tool: None,
            governance_level: None,
            mode: "enforce".to_string(),
            flagged: false,
            trust: None,
            children: vec![],
        };
        let json = serde_json::to_value(&tree).unwrap();
        assert!(json.get("trust").is_some(), "trust key must be present");
        assert!(json["trust"].is_null(), "trust must serialize as null");
        assert!(!json["trust"].is_number(), "an unmeasured trust must not be a number");
        assert_ne!(json["trust"], 0, "trust must never fold to a scored zero");

        tree.trust = Some(78);
        let scored = serde_json::to_value(&tree).unwrap();
        assert_eq!(scored["trust"], 78);
        assert!(
            scored["trust"].is_u64(),
            "a score is a whole number on a 0–100 scale, not a float: {}",
            scored["trust"]
        );
    }

    /// Same integer contract on `AgentNode`, so one agent cannot serialize as
    /// `78` on one topology projection and `78.0` on the other.
    #[test]
    fn agent_node_scores_as_an_integer() {
        let mut node = make_agent_node();
        node.trust = Some(78);
        let json = serde_json::to_value(&node).unwrap();
        assert_eq!(json["trust"], 78);
        assert!(
            json["trust"].is_u64(),
            "a score is a whole number on a 0–100 scale, not a float: {}",
            json["trust"]
        );
    }

    #[test]
    fn team_topology_roundtrip() {
        roundtrip(&TeamTopology {
            team_id: "team-alpha".to_string(),
            agent_count: 1,
            members: vec![make_agent_node()],
        });
    }

    #[test]
    fn lineage_step_roundtrip() {
        roundtrip(&LineageStep {
            id: "root000000000000root000000000000".to_string(),
            name: "root".to_string(),
            depth: 0,
            delegation_reason: None,
            team_id: None,
        });
    }

    #[test]
    fn agent_lineage_roundtrip() {
        roundtrip(&AgentLineage {
            agent_id: "aabbccdd00112233aabbccdd00112233".to_string(),
            ancestor_count: 2,
            ancestors: vec![
                LineageStep {
                    id: "root000000000000root000000000000".to_string(),
                    name: "root".to_string(),
                    depth: 0,
                    delegation_reason: None,
                    team_id: None,
                },
                LineageStep {
                    id: "aabbccdd00112233aabbccdd00112233".to_string(),
                    name: "child".to_string(),
                    depth: 1,
                    delegation_reason: Some("orchestrate".to_string()),
                    team_id: Some("team-alpha".to_string()),
                },
            ],
        });
    }

    #[test]
    fn topology_graph_edge_roundtrip() {
        roundtrip(&TopologyGraphEdge {
            source: "0102030405060708090a0b0c0d0e0f10".to_string(),
            target: "aabbccdd00112233aabbccdd00112233".to_string(),
            kind: "delegation".to_string(),
            cross_team: false,
        });
    }

    #[test]
    fn topology_graph_response_roundtrip_and_default_is_empty() {
        // Default is the deny-by-default / empty-registry shape the handler
        // returns; it must serialize as two empty arrays.
        let empty = TopologyGraphResponse::default();
        let json: serde_json::Value = serde_json::from_str(&serde_json::to_string(&empty).unwrap()).unwrap();
        assert!(json["nodes"].as_array().unwrap().is_empty());
        assert!(json["edges"].as_array().unwrap().is_empty());

        roundtrip(&TopologyGraphResponse {
            nodes: vec![make_agent_node()],
            edges: vec![TopologyGraphEdge {
                source: "aa".to_string(),
                target: "bb".to_string(),
                kind: "call".to_string(),
                cross_team: true,
            }],
        });
    }

    #[test]
    fn topology_stats_roundtrip() {
        roundtrip(&TopologyStats {
            total_agents: 15,
            root_agent_count: 3,
            max_depth: 4,
            active_count: 12,
            suspended_count: 2,
            deregistered_count: 1,
            team_count: 2,
            team_sizes: [("team-alpha".to_string(), 8), ("team-beta".to_string(), 4)].into(),
            depth_histogram: [("0".into(), 3), ("1".into(), 7), ("2".into(), 5)].into(),
            team_size_histogram: [("4".into(), 1), ("8".into(), 1)].into(),
            spawn_count_histogram: [("0".into(), 8), ("2".into(), 4), ("4".into(), 1)].into(),
            orphan_count: 2,
            avg_children_per_parent: 2.5,
        });
    }
}
