//! `aasm topology team` — show all agents in a team.

use std::process::ExitCode;

use clap::Args;

use super::render::{render, TeamTopology, TopologyPayload};
use crate::client;
use crate::config::ResolvedContext;
use crate::output::OutputFormat;

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

/// Run the `aasm topology team` command.
pub fn run(args: TeamArgs, ctx: &ResolvedContext, output: OutputFormat) -> ExitCode {
    let mut path = format!("/api/v1/topology/team/{}", args.team_id);
    let mut params: Vec<String> = vec![];
    if let Some(ref s) = args.status {
        params.push(format!("status={s}"));
    }
    if args.show_budget {
        params.push("show_budget=true".to_string());
    }
    if !params.is_empty() {
        path = format!("{path}?{}", params.join("&"));
    }

    let rt = tokio::runtime::Runtime::new().expect("failed to create tokio runtime");
    let team: TeamTopology = match rt.block_on(client::get_json(ctx, &path)) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::FAILURE;
        }
    };

    render(TopologyPayload::Team(&team), output);
    ExitCode::SUCCESS
}
