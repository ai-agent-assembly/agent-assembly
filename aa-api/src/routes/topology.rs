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
use serde::Deserialize;
use utoipa::IntoParams;

use aa_gateway::registry::{AgentRegistry, AgentStatus};

use crate::auth::scope::RequireRead;
use crate::error::ProblemDetail;
use crate::models::topology::{format_id, status_str};
pub use crate::models::topology::{
    AgentLineage, AgentNode, AgentTree, LineageStep, TeamSummary, TeamTopology, TopologyOverview, TopologyStats,
};
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
            .filter_map(|child_id| build_tree(registry, child_id, remaining_depth - 1, status_filter, show_budget))
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
    _auth: RequireRead,
    Extension(state): Extension<AppState>,
    Query(params): Query<TopologyFilterParams>,
) -> (StatusCode, Json<TopologyOverview>) {
    let cache_key = format!(
        "{}|{}|{}",
        params.status.as_deref().unwrap_or(""),
        params.min_depth.unwrap_or(0),
        params.show_budget.unwrap_or(false),
    );
    if let Some(cached) = state.topology_overview_cache.get(&cache_key).await {
        return (StatusCode::OK, Json((*cached).clone()));
    }

    let all = state.agent_registry.list();
    let show_budget = params.show_budget.unwrap_or(false);

    let filtered: Vec<_> = all
        .iter()
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
    _auth: RequireRead,
    Extension(state): Extension<AppState>,
    Path(root_id): Path<String>,
    Query(params): Query<TreeParams>,
) -> Result<(StatusCode, Json<AgentTree>), ProblemDetail> {
    let agent_id = parse_agent_id(&root_id)?;
    let max_depth = params.depth.unwrap_or(MAX_TREE_DEPTH).min(MAX_TREE_DEPTH);
    let show_budget = params.show_budget.unwrap_or(false);

    // Validate the starting agent exists and is a root before hitting the cache.
    if let Some(record) = state.agent_registry.get(&agent_id) {
        if record.depth > 0 {
            return Err(ProblemDetail::from_status(StatusCode::UNPROCESSABLE_ENTITY)
                .with_detail(format!("Agent {root_id} is not a root agent (depth {})", record.depth)));
        }
    } else {
        return Err(
            ProblemDetail::from_status(StatusCode::NOT_FOUND).with_detail(format!("Agent not found: {root_id}"))
        );
    }

    let cache_key = format!(
        "{}|{}|{}|{}",
        root_id,
        max_depth,
        params.status.as_deref().unwrap_or(""),
        show_budget,
    );
    if let Some(cached) = state.topology_tree_cache.get(&cache_key).await {
        return Ok((StatusCode::OK, Json((*cached).clone())));
    }

    let tree = build_tree(
        &state.agent_registry,
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
    _auth: RequireRead,
    Extension(state): Extension<AppState>,
    Path(team_id): Path<String>,
    Query(params): Query<TopologyFilterParams>,
) -> Result<(StatusCode, Json<TeamTopology>), ProblemDetail> {
    let cache_key = format!(
        "{}|{}|{}|{}",
        team_id,
        params.status.as_deref().unwrap_or(""),
        params.min_depth.unwrap_or(0),
        params.show_budget.unwrap_or(false),
    );
    if let Some(cached) = state.topology_team_cache.get(&cache_key).await {
        return Ok((StatusCode::OK, Json((*cached).clone())));
    }

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
    _auth: RequireRead,
    Extension(state): Extension<AppState>,
    Path(agent_id_str): Path<String>,
) -> Result<(StatusCode, Json<AgentLineage>), ProblemDetail> {
    if let Some(cached) = state.topology_lineage_cache.get(&agent_id_str).await {
        return Ok((StatusCode::OK, Json((*cached).clone())));
    }

    let agent_id = parse_agent_id(&agent_id_str)?;

    let record = state.agent_registry.get(&agent_id).ok_or_else(|| {
        ProblemDetail::from_status(StatusCode::NOT_FOUND).with_detail(format!("Agent not found: {agent_id_str}"))
    })?;

    // ancestors_of returns parent-first (direct parent at [0], root at end).
    // Reverse to root-first, then append the requested agent as the final element.
    let mut ancestor_ids = state.agent_registry.ancestors_of(&agent_id);
    ancestor_ids.reverse();

    let mut ancestors: Vec<LineageStep> = ancestor_ids
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
        .insert(agent_id_str, Arc::new(lineage.clone()))
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
    _auth: RequireRead,
    Extension(state): Extension<AppState>,
) -> (StatusCode, Json<TopologyStats>) {
    if let Some(cached) = state.topology_stats_cache.get("stats").await {
        return (StatusCode::OK, Json((*cached).clone()));
    }

    let all = state.agent_registry.list();

    let mut root_agent_count = 0usize;
    let mut max_depth = 0u32;
    let mut active_count = 0usize;
    let mut suspended_count = 0usize;
    let mut deregistered_count = 0usize;
    let mut team_sizes: HashMap<String, usize> = HashMap::new();
    let mut depth_histogram: BTreeMap<u32, u32> = BTreeMap::new();
    let mut spawn_count_histogram: BTreeMap<u32, u32> = BTreeMap::new();
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
        *depth_histogram.entry(r.depth).or_insert(0) += 1;
        let child_count = state.agent_registry.children_of(&r.agent_id).len() as u32;
        *spawn_count_histogram.entry(child_count).or_insert(0) += 1;
    }

    let team_count = team_sizes.len();
    let total_agents = all.len();

    let mut team_size_histogram: BTreeMap<u32, u32> = BTreeMap::new();
    for &size in team_sizes.values() {
        *team_size_histogram.entry(size as u32).or_insert(0) += 1;
    }

    let parents: Vec<u32> = spawn_count_histogram
        .iter()
        .filter(|(&count, _)| count > 0)
        .flat_map(|(&count, &n)| std::iter::repeat(count).take(n as usize))
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
        .insert("stats", Arc::new(stats.clone()))
        .await;
    (StatusCode::OK, Json(stats))
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
