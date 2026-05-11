//! `aasm topology` — visualize agent topology and lineage.

use clap::{Args, Subcommand};

pub mod lineage;
pub mod overview;
pub mod render;
pub mod stats;
pub mod team;
pub mod tree;

/// Arguments for the `aasm topology` subcommand group.
#[derive(Args)]
pub struct TopologyArgs {
    #[command(subcommand)]
    pub command: TopologyCommands,
}

/// Available topology subcommands.
#[derive(Subcommand)]
pub enum TopologyCommands {
    /// Show fleet-wide topology overview.
    Overview(overview::OverviewArgs),
    /// Render a subtree rooted at a given agent.
    Tree(tree::TreeArgs),
    /// Show all agents in a team.
    Team(team::TeamArgs),
    /// Show ancestry chain for a given agent.
    Lineage(lineage::LineageArgs),
    /// Show aggregate topology statistics.
    Stats(stats::StatsArgs),
}
