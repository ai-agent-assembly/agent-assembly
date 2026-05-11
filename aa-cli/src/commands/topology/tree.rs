//! `aasm topology tree` — render agent subtree.

use clap::Args;

/// Arguments for `aasm topology tree`.
#[derive(Args)]
pub struct TreeArgs {
    /// Root agent ID (hex-encoded UUID).
    pub agent_id: String,
    /// Maximum traversal depth from the root (default 10).
    #[arg(long)]
    pub depth: Option<u32>,
    /// Filter tree nodes by status.
    #[arg(long)]
    pub status: Option<String>,
    /// Include governance level in tree nodes.
    #[arg(long)]
    pub show_budget: bool,
}
