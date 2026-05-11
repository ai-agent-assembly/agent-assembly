//! `aasm topology` — visualize agent topology and lineage.

use clap::Args;

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
