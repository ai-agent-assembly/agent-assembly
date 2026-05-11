//! `aasm topology stats` — aggregate topology statistics.

use std::process::ExitCode;

use clap::Args;

use super::render::{render, TopologyPayload, TopologyStats};
use crate::client;
use crate::config::ResolvedContext;
use crate::output::OutputFormat;

/// Arguments for `aasm topology stats`.
#[derive(Args)]
pub struct StatsArgs {}

/// Run the `aasm topology stats` command.
pub fn run(_args: StatsArgs, ctx: &ResolvedContext, output: OutputFormat) -> ExitCode {
    let rt = tokio::runtime::Runtime::new().expect("failed to create tokio runtime");
    let stats: TopologyStats = match rt.block_on(client::get_json(ctx, "/api/v1/topology/stats")) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::FAILURE;
        }
    };

    render(TopologyPayload::Stats(&stats), output);
    ExitCode::SUCCESS
}
