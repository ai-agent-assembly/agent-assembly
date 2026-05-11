//! `aasm topology team` — show all agents in a team.

use clap::Args;

/// Arguments for `aasm topology team`.
#[derive(Args)]
pub struct TeamArgs {
    /// Team ID.
    pub team_id: String,
    /// Filter members by status.
    #[arg(long)]
    pub status: Option<String>,
    /// Include governance level in agent nodes.
    #[arg(long)]
    pub show_budget: bool,
}
