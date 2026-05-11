//! `aasm topology lineage` — show ancestry chain for a given agent.

use clap::Args;

/// Arguments for `aasm topology lineage`.
#[derive(Args)]
pub struct LineageArgs {
    /// Agent ID (hex-encoded UUID).
    pub agent_id: String,
}
