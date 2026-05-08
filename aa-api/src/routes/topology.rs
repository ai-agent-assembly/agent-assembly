//! Topology REST API endpoints.
//!
//! Five read-only endpoints for querying the agent topology tree, team
//! membership, ancestry lineage, and aggregate statistics — all backed by
//! the in-memory `AgentRegistry`.

use std::collections::HashMap;

use axum::extract::{Path, Query};
use axum::http::StatusCode;
use axum::{Extension, Json};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

use aa_gateway::registry::{AgentRegistry, AgentStatus};

use crate::error::ProblemDetail;
use crate::state::AppState;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn parse_agent_id(id: &str) -> Result<[u8; 16], ProblemDetail> {
    let bytes: Vec<u8> = (0..id.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&id[i..i + 2], 16))
        .collect::<Result<Vec<u8>, _>>()
        .map_err(|_| {
            ProblemDetail::from_status(StatusCode::BAD_REQUEST)
                .with_detail(format!("Invalid agent ID format: {id}"))
        })?;
    bytes.try_into().map_err(|_| {
        ProblemDetail::from_status(StatusCode::BAD_REQUEST)
            .with_detail(format!("Agent ID must be 32 hex characters: {id}"))
    })
}

fn format_id(id: &[u8; 16]) -> String {
    id.iter().map(|b| format!("{b:02x}")).collect()
}

fn status_str(status: &AgentStatus) -> &'static str {
    match status {
        AgentStatus::Active => "active",
        AgentStatus::Suspended(_) => "suspended",
        AgentStatus::Deregistered => "deregistered",
    }
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
// Response types
// ---------------------------------------------------------------------------

/// Overview of the entire agent topology across all teams.
#[derive(Debug, Serialize, ToSchema)]
pub struct TopologyOverview {
    /// Number of teams with at least one registered agent.
    pub team_count: usize,
    /// Number of root agents (depth == 0) across all teams.
    pub root_agent_count: usize,
    /// Total number of agents in the registry.
    pub total_agent_count: usize,
    /// Per-team agent count summaries.
    pub teams: Vec<TeamSummary>,
    /// Root agents that are not assigned to any team.
    pub standalone_root_agents: Vec<AgentNode>,
}

/// High-level statistics for a single team.
#[derive(Debug, Serialize, ToSchema)]
pub struct TeamSummary {
    /// Team identifier.
    pub team_id: String,
    /// Total agents in this team.
    pub agent_count: usize,
    /// Root agents (depth == 0) in this team.
    pub root_agent_count: usize,
}

/// Minimal agent representation used in list and tree responses.
#[derive(Debug, Serialize, ToSchema)]
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

/// Recursive tree node representing an agent and all its descendants.
#[derive(Debug, Serialize, ToSchema)]
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
    pub children: Vec<AgentTree>,
}

/// All agents belonging to a single team.
#[derive(Debug, Serialize, ToSchema)]
pub struct TeamTopology {
    /// Team identifier.
    pub team_id: String,
    /// Number of agents in this team (after filtering).
    pub agent_count: usize,
    /// Agents in this team.
    pub members: Vec<AgentNode>,
}

/// An agent's complete ancestry chain from direct parent up to root.
#[derive(Debug, Serialize, ToSchema)]
pub struct AgentLineage {
    /// The subject agent's hex-encoded UUID.
    pub agent_id: String,
    /// Number of ancestors — 0 if the agent is a root.
    pub ancestor_count: usize,
    /// Ordered ancestors: index 0 is the direct parent, last element is the root.
    pub ancestors: Vec<LineageStep>,
}

/// One step in an agent's ancestry chain.
#[derive(Debug, Serialize, ToSchema)]
pub struct LineageStep {
    /// Hex-encoded UUID of this ancestor.
    pub id: String,
    /// Human-readable name of this ancestor.
    pub name: String,
    /// Delegation depth of this ancestor.
    pub depth: u32,
    /// Reason the next agent in the chain was delegated from this ancestor.
    pub delegation_reason: Option<String>,
    /// Team this ancestor belongs to.
    pub team_id: Option<String>,
}

/// Aggregate topology statistics across all registered agents.
#[derive(Debug, Serialize, ToSchema)]
pub struct TopologyStats {    /// Total agents in the registry.
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
    /// Agent count per team.
    pub team_sizes: HashMap<String, usize>,
}

// ---------------------------------------------------------------------------
// Tree builder helper
// ---------------------------------------------------------------------------

const MAX_TREE_DEPTH: u32 = 10;

fn build_tree(
    registry: &AgentRegistry,
    agent_id: &[u8; 16],
    remaining_depth: u32,
    status_filter: Option<&str>,
    show_budget: bool,
) -> Option<AgentTree> {
    let record = registry.get(agent_id)?;
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
                build_tree(registry, child_id, remaining_depth - 1, status_filter, show_budget)
            })
            .collect()
    } else {
        vec![]
    };
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
        children,
    })
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// `GET /api/v1/topology/overview` — summary of all teams and root agents.
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
    Extension(state): Extension<AppState>,
    Query(params): Query<TopologyFilterParams>,
) -> (StatusCode, Json<TopologyOverview>) {
    let all = state.agent_registry.list();
    let show_budget = params.show_budget.unwrap_or(false);

    let filtered: Vec<_> = all
        .iter()
        .filter(|r| {
            params.status.as_deref().map_or(true, |f| matches_status_filter(&r.status, f))
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

    let standalone_root_agents = filtered
        .iter()
        .filter(|r| r.depth == 0 && r.team_id.is_none())
        .map(|r| AgentNode {
            id: format_id(&r.agent_id),
            name: r.name.clone(),
            depth: r.depth,
            status: status_str(&r.status).to_owned(),
            team_id: None,
            governance_level: if show_budget {
                Some(format!("{:?}", r.governance_level))
            } else {
                None
            },
        })
        .collect();

    (
        StatusCode::OK,
        Json(TopologyOverview {
            team_count,
            root_agent_count,
            total_agent_count,
            teams,
            standalone_root_agents,
        }),
    )
}

/// `GET /api/v1/topology/tree/{root_id}` — full subtree from a given root agent.
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
        (status = 404, description = "Agent not found")
    ),
    tag = "topology"
)]
pub async fn get_tree(
    Extension(state): Extension<AppState>,
    Path(root_id): Path<String>,
    Query(params): Query<TreeParams>,
) -> Result<(StatusCode, Json<AgentTree>), ProblemDetail> {
    let agent_id = parse_agent_id(&root_id)?;
    let max_depth = params.depth.unwrap_or(MAX_TREE_DEPTH).min(MAX_TREE_DEPTH);
    let show_budget = params.show_budget.unwrap_or(false);

    let tree = build_tree(
        &state.agent_registry,
        &agent_id,
        max_depth,
        params.status.as_deref(),
        show_budget,
    )
    .ok_or_else(|| {
        ProblemDetail::from_status(StatusCode::NOT_FOUND)
            .with_detail(format!("Agent not found: {root_id}"))
    })?;

    Ok((StatusCode::OK, Json(tree)))
}

/// `GET /api/v1/topology/team/{team_id}` — all agents in a team with depth info.
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
    Extension(state): Extension<AppState>,
    Path(team_id): Path<String>,
    Query(params): Query<TopologyFilterParams>,
) -> Result<(StatusCode, Json<TeamTopology>), ProblemDetail> {
    let member_ids = state.agent_registry.team_members(&team_id);
    if member_ids.is_empty() {
        return Err(ProblemDetail::from_status(StatusCode::NOT_FOUND)
            .with_detail(format!("Team not found or has no agents: {team_id}")));
    }
    let show_budget = params.show_budget.unwrap_or(false);

    let mut members: Vec<AgentNode> = member_ids
        .iter()
        .filter_map(|id| state.agent_registry.get(id))
        .filter(|r| {
            params.status.as_deref().map_or(true, |f| matches_status_filter(&r.status, f))
                && params.min_depth.map_or(true, |d| r.depth >= d)
        })
        .map(|r| AgentNode {
            id: format_id(&r.agent_id),
            name: r.name.clone(),
            depth: r.depth,
            status: status_str(&r.status).to_owned(),
            team_id: r.team_id.clone(),
            governance_level: if show_budget {
                Some(format!("{:?}", r.governance_level))
            } else {
                None
            },
        })
        .collect();
    members.sort_by_key(|m| m.depth);

    let agent_count = members.len();
    Ok((StatusCode::OK, Json(TeamTopology { team_id, agent_count, members })))
}

/// `GET /api/v1/topology/lineage/{agent_id}` — ancestor chain from agent up to root.
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
    Extension(state): Extension<AppState>,
    Path(agent_id_str): Path<String>,
) -> Result<(StatusCode, Json<AgentLineage>), ProblemDetail> {
    let agent_id = parse_agent_id(&agent_id_str)?;

    state.agent_registry.get(&agent_id).ok_or_else(|| {
        ProblemDetail::from_status(StatusCode::NOT_FOUND)
            .with_detail(format!("Agent not found: {agent_id_str}"))
    })?;

    let ancestor_ids = state.agent_registry.ancestors_of(&agent_id);
    let ancestors: Vec<LineageStep> = ancestor_ids
        .iter()
        .filter_map(|id| state.agent_registry.get(id))
        .map(|r| LineageStep {
            id: format_id(&r.agent_id),
            name: r.name.clone(),
            depth: r.depth,
            delegation_reason: r.delegation_reason.clone(),
            team_id: r.team_id.clone(),
        })
        .collect();

    let ancestor_count = ancestors.len();
    Ok((
        StatusCode::OK,
        Json(AgentLineage { agent_id: agent_id_str, ancestor_count, ancestors }),
    ))
}

/// `GET /api/v1/topology/stats` — aggregate topology statistics.
#[utoipa::path(
    get,
    path = "/api/v1/topology/stats",
    responses(
        (status = 200, description = "Topology statistics", body = TopologyStats)
    ),
    tag = "topology"
)]
pub async fn get_stats(
    Extension(state): Extension<AppState>,
) -> (StatusCode, Json<TopologyStats>) {
    let all = state.agent_registry.list();

    let mut root_agent_count = 0usize;
    let mut max_depth = 0u32;
    let mut active_count = 0usize;
    let mut suspended_count = 0usize;
    let mut deregistered_count = 0usize;
    let mut team_sizes: HashMap<String, usize> = HashMap::new();

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
        }
    }

    let team_count = team_sizes.len();
    let total_agents = all.len();

    (
        StatusCode::OK,
        Json(TopologyStats {
            total_agents,
            root_agent_count,
            max_depth,
            active_count,
            suspended_count,
            deregistered_count,
            team_count,
            team_sizes,
        }),
    )
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
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10,
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

    #[test]
    fn topology_stats_serializes() {
        let stats = TopologyStats {
            total_agents: 5,
            root_agent_count: 2,
            max_depth: 3,
            active_count: 4,
            suspended_count: 1,
            deregistered_count: 0,
            team_count: 2,
            team_sizes: [("team-a".to_string(), 3), ("team-b".to_string(), 2)].into(),
        };
        let json = serde_json::to_value(&stats).unwrap();
        assert_eq!(json["total_agents"], 5);
        assert_eq!(json["root_agent_count"], 2);
        assert_eq!(json["max_depth"], 3);
        assert_eq!(json["team_count"], 2);
    }

    #[test]
    fn agent_lineage_serializes() {
        let lineage = AgentLineage {
            agent_id: "aabbccdd00112233aabbccdd00112233".to_string(),
            ancestor_count: 1,
            ancestors: vec![LineageStep {
                id: "00112233aabbccdd00112233aabbccdd".to_string(),
                name: "root-agent".to_string(),
                depth: 0,
                delegation_reason: Some("spawned by orchestrator".to_string()),
                team_id: Some("team-a".to_string()),
            }],
        };
        let json = serde_json::to_value(&lineage).unwrap();
        assert_eq!(json["ancestor_count"], 1);
        assert_eq!(json["ancestors"][0]["name"], "root-agent");
        assert_eq!(json["ancestors"][0]["depth"], 0);
    }

    #[test]
    fn agent_node_omits_governance_level_when_none() {
        let node = AgentNode {
            id: "aa".to_string(),
            name: "n".to_string(),
            depth: 0,
            status: "active".to_string(),
            team_id: None,
            governance_level: None,
        };
        let json = serde_json::to_value(&node).unwrap();
        assert!(json.get("governance_level").is_none());
    }

    #[test]
    fn agent_tree_leaf_has_empty_children() {
        let leaf = AgentTree {
            id: "aa".to_string(),
            name: "leaf".to_string(),
            depth: 3,
            status: "active".to_string(),
            team_id: None,
            delegation_reason: None,
            spawned_by_tool: None,
            governance_level: None,
            children: vec![],
        };
        let json = serde_json::to_value(&leaf).unwrap();
        assert_eq!(json["children"].as_array().unwrap().len(), 0);
    }
}
