//! `aasm topology lineage` — show ancestry chain for a given agent.

use std::process::ExitCode;

use clap::Args;

use super::render::{render, AgentLineage, TopologyPayload};
use crate::client;
use crate::config::ResolvedContext;
use crate::error::CliError;
use crate::output::OutputFormat;

/// Arguments for `aasm topology lineage`.
#[derive(Args)]
#[command(after_help = "\
Examples:
  aasm topology lineage aabbccdd00112233aabbccdd00112233
  aasm topology lineage aabbccdd00112233aabbccdd00112233 --output json")]
pub struct LineageArgs {
    /// Agent ID (hex-encoded UUID).
    pub agent_id: String,
}

/// Run the `aasm topology lineage` command.
pub fn run(args: LineageArgs, ctx: &ResolvedContext, output: OutputFormat) -> ExitCode {
    let path = format!("/api/v1/topology/lineage/{}", args.agent_id);

    let rt = tokio::runtime::Runtime::new().expect("failed to create tokio runtime");
    let lineage: AgentLineage = match rt.block_on(client::get_json(ctx, &path)) {
        Ok(v) => v,
        Err(CliError::Api(ref e)) if e.status() == Some(reqwest::StatusCode::NOT_FOUND) => {
            eprintln!("error: agent {} not found", args.agent_id);
            return ExitCode::from(4u8);
        }
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::FAILURE;
        }
    };

    render(TopologyPayload::Lineage(&lineage), output);
    ExitCode::SUCCESS
}
