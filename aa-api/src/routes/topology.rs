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
    /// Agent count per team.
    pub team_sizes: HashMap<String, usize>,
}
