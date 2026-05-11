//! Rendering utilities for topology subcommands.

use std::collections::{BTreeMap, HashMap};

use serde::{Deserialize, Serialize};

pub mod json;
pub mod table;
pub mod tree;

/// Overview of the entire agent topology across all teams.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopologyOverview {
    pub team_count: usize,
    pub root_agent_count: usize,
    pub total_agent_count: usize,
    pub teams: Vec<TeamSummary>,
    pub standalone_root_agents: Vec<AgentNode>,
}

/// High-level statistics for a single team.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TeamSummary {
    pub team_id: String,
    pub agent_count: usize,
    pub root_agent_count: usize,
}

/// Minimal agent representation used in list and tree responses.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentNode {
    pub id: String,
    pub name: String,
    pub depth: u32,
    pub status: String,
    pub team_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub governance_level: Option<String>,
}

/// Recursive tree node representing an agent and all its descendants.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentTree {
    pub id: String,
    pub name: String,
    pub depth: u32,
    pub status: String,
    pub team_id: Option<String>,
    pub delegation_reason: Option<String>,
    pub spawned_by_tool: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub governance_level: Option<String>,
    pub children: Vec<AgentTree>,
}

/// All agents belonging to a single team.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TeamTopology {
    pub team_id: String,
    pub agent_count: usize,
    pub members: Vec<AgentNode>,
}

/// An agent's complete ancestry chain ordered root-first.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentLineage {
    pub agent_id: String,
    pub ancestor_count: usize,
    pub ancestors: Vec<LineageStep>,
}

/// One step in an agent's ancestry chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LineageStep {
    pub id: String,
    pub name: String,
    pub depth: u32,
    pub delegation_reason: Option<String>,
    pub team_id: Option<String>,
}

/// Aggregate topology statistics across all registered agents.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopologyStats {
    pub total_agents: usize,
    pub root_agent_count: usize,
    pub max_depth: u32,
    pub active_count: usize,
    pub suspended_count: usize,
    pub deregistered_count: usize,
    pub team_count: usize,
    pub team_sizes: HashMap<String, usize>,
    pub depth_histogram: BTreeMap<String, u32>,
    pub team_size_histogram: BTreeMap<String, u32>,
    pub spawn_count_histogram: BTreeMap<String, u32>,
    pub orphan_count: usize,
    pub avg_children_per_parent: f64,
}

/// Union of all topology API response shapes for rendering.
pub enum TopologyPayload<'a> {
    Overview(&'a TopologyOverview),
    Tree(&'a AgentTree),
    Team(&'a TeamTopology),
    Lineage(&'a AgentLineage),
    Stats(&'a TopologyStats),
}
