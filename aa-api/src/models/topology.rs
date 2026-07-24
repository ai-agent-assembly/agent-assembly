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

/// Policy-violation count at or above which a node is surfaced as "flagged"
/// (danger-tinted card + ⚑ marker) in the topology graph.
///
/// Kept in lock-step with the dashboard Fleet page's `FLEET_FLAGGED_THRESHOLD`
/// (`dashboard/src/features/agents/fleetTypes.ts`) so the topology node badge and
/// the Fleet row light up on exactly the same agents — the two surfaces must not
/// disagree about whether a given agent is flagged.
pub(crate) const FLAGGED_VIOLATION_THRESHOLD: u32 = 50;

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

/// Whether an agent is policy-flagged for the topology view — the same
/// derivation the Fleet page uses (`policy_violations_count >= threshold`).
pub(crate) fn agent_flagged(record: &AgentRecord) -> bool {
    record.policy_violations_count >= FLAGGED_VIOLATION_THRESHOLD
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
    pub status: String,
    /// Team this agent belongs to, if any.
    pub team_id: Option<String>,
    /// Governance level — included only when `show_budget=true`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub governance_level: Option<String>,
    /// Enforcement-mode badge: `enforce`, `shadow`, or `off`. Derived from the
    /// agent record's `metadata["mode"]` (defaulting to `enforce`) so the
    /// topology mode badge matches the Fleet page's mode chip for the same agent.
    pub mode: String,
    /// Whether the agent is policy-flagged — `policy_violations_count` is at or
    /// above [`FLAGGED_VIOLATION_THRESHOLD`]. Drives the danger-tinted node card
    /// and ⚑ marker in the topology graph.
    pub flagged: bool,
    /// Trust score (0–100), or `null` when no trust-analytics source exists yet.
    /// The registry does not compute a per-agent trust score today, so this is
    /// currently always `null` — the same placeholder the Fleet page uses. Kept
    /// present (not omitted) so the client renders an explicit "no data" state
    /// instead of inferring a misleading default.
    pub trust: Option<f64>,
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
}

impl From<&AgentRecord> for AgentNode {
    fn from(r: &AgentRecord) -> Self {
        AgentNode {
            id: format_id(&r.agent_id),
            name: r.name.clone(),
            depth: r.depth,
            status: status_str(&r.status).to_owned(),
            team_id: r.team_id.clone(),
            governance_level: None,
            mode: agent_mode(r),
            flagged: agent_flagged(r),
            trust: None,
            // `owner` is a pure record field (agent metadata), so it is resolved
            // here and carried by every AgentNode consumer. `policy_count` /
            // `budget` need the policy engine / budget tracker, which this
            // record-only conversion can't reach — the graph handler enriches
            // them; here they stay `null`.
            owner: r.metadata.get("owner").cloned(),
            policy_count: None,
            budget: None,
        }
    }
}

/// One directed edge in the dashboard topology graph (AAASM-5040).
///
/// A slim projection of a stored [`aa_core::topology::Edge`] carrying only what
/// the dashboard graph renders: the two hex-encoded endpoints and the relation
/// `kind`. `kind` is one of the two kinds the graph models — `delegation`
/// (from a `delegates_to` edge) or `call` (from a `calls` edge) — matching the
/// frontend `TopologyEdge` 1:1 so the client consumes edges without remapping.
///
/// # Example JSON
/// ```json
/// { "source": "0102030405060708090a0b0c0d0e0f10", "target": "aabbccdd00112233aabbccdd00112233", "kind": "delegation" }
/// ```
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
#[schema(example = json!({
    "source": "0102030405060708090a0b0c0d0e0f10",
    "target": "aabbccdd00112233aabbccdd00112233",
    "kind": "delegation"
}))]
pub struct TopologyGraphEdge {
    /// Hex-encoded UUID of the source (delegating / calling) agent.
    pub source: String,
    /// Hex-encoded UUID of the target agent.
    pub target: String,
    /// Relation kind rendered by the graph: `delegation` or `call`.
    pub kind: String,
}

/// The whole-fleet topology graph rendered by the dashboard Topology page
/// (AAASM-5040): every agent visible to the caller as a node, plus the
/// delegation / call edges between those nodes.
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
    /// Delegation / call edges whose endpoints are both visible nodes.
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
    /// Whether the agent is policy-flagged. Same derivation as
    /// [`AgentNode::flagged`].
    pub flagged: bool,
    /// Trust score (0–100), or `null` when no trust-analytics source exists yet.
    /// Same placeholder as [`AgentNode::trust`].
    pub trust: Option<f64>,
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
    /// `From<&AgentRecord>` impl. Only the fields the helpers read
    /// (`metadata`, `policy_violations_count`) are meaningful here.
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
            status: "active".to_string(),
            team_id: Some("team-alpha".to_string()),
            governance_level: None,
            mode: "enforce".to_string(),
            flagged: false,
            trust: None,
            owner: None,
            policy_count: None,
            budget: None,
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
    fn agent_flagged_uses_violation_threshold() {
        let mut record = make_record();
        record.policy_violations_count = FLAGGED_VIOLATION_THRESHOLD - 1;
        assert!(!agent_flagged(&record));
        record.policy_violations_count = FLAGGED_VIOLATION_THRESHOLD;
        assert!(agent_flagged(&record));
    }

    #[test]
    fn agent_node_from_record_derives_badge_fields() {
        let mut record = make_record();
        record.metadata.insert("mode".to_string(), "shadow".to_string());
        record.policy_violations_count = FLAGGED_VIOLATION_THRESHOLD + 5;
        let node = AgentNode::from(&record);
        assert_eq!(node.mode, "shadow");
        assert!(node.flagged);
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
