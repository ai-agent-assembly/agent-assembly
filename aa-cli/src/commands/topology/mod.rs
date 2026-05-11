//! `aasm topology` — visualize agent topology and lineage.

use std::process::ExitCode;

use clap::{Args, Subcommand};

use crate::config::ResolvedContext;
use crate::output::OutputFormat;

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

/// Dispatch a topology subcommand.
pub fn dispatch(args: TopologyArgs, ctx: &ResolvedContext, output: OutputFormat) -> ExitCode {
    match args.command {
        TopologyCommands::Overview(a) => overview::run(a, ctx, output),
        TopologyCommands::Tree(a) => tree::run(a, ctx, output),
        TopologyCommands::Team(a) => team::run(a, ctx, output),
        TopologyCommands::Lineage(a) => lineage::run(a, ctx, output),
        TopologyCommands::Stats(a) => stats::run(a, ctx, output),
    }
}
