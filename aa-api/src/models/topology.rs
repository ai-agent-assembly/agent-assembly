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
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
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
    "team_id": "team-alpha"
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
        }
    }
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
    pub depth_histogram: BTreeMap<u32, u32>,
    /// Number of teams per team-size bucket (team_size → team_count).
    pub team_size_histogram: BTreeMap<u32, u32>,
    /// Number of agents per child-count bucket (child_count → agent_count).
    pub spawn_count_histogram: BTreeMap<u32, u32>,
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

    fn make_agent_node() -> AgentNode {
        AgentNode {
            id: "0102030405060708090a0b0c0d0e0f10".to_string(),
            name: "agent-x".to_string(),
            depth: 1,
            status: "active".to_string(),
            team_id: Some("team-alpha".to_string()),
            governance_level: None,
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
            depth_histogram: [(0, 3), (1, 7), (2, 5)].into(),
            team_size_histogram: [(4, 1), (8, 1)].into(),
            spawn_count_histogram: [(0, 8), (2, 4), (4, 1)].into(),
            orphan_count: 2,
            avg_children_per_parent: 2.5,
        });
    }
}
