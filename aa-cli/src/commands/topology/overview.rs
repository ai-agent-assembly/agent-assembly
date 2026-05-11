//! `aasm topology overview` — fleet-wide topology summary.

use clap::Args;

/// Arguments for `aasm topology overview`.
#[derive(Args)]
pub struct OverviewArgs {
    /// Filter agents by status (active, suspended, deregistered).
    #[arg(long)]
    pub status: Option<String>,
    /// Include governance level in agent nodes.
    #[arg(long)]
    pub show_budget: bool,
}
