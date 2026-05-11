//! `aasm topology overview` — fleet-wide topology summary.

use std::process::ExitCode;

use clap::Args;

use super::render::{render, TopologyOverview, TopologyPayload};
use crate::client;
use crate::config::ResolvedContext;
use crate::error::CliError;
use crate::output::OutputFormat;

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

/// Run the `aasm topology overview` command.
pub fn run(args: OverviewArgs, ctx: &ResolvedContext, output: OutputFormat) -> ExitCode {
    let mut path = "/api/v1/topology/overview".to_string();
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
    let overview: TopologyOverview = match rt.block_on(client::get_json(ctx, &path)) {
        Ok(v) => v,
        Err(CliError::Api(ref e)) if e.is_connect() => {
            eprintln!("error: registry unreachable — check --api-url");
            return ExitCode::FAILURE;
        }
        Err(CliError::Api(ref e)) if e.status() == Some(reqwest::StatusCode::UNAUTHORIZED) => {
            eprintln!("error: unauthorized — check your API key");
            return ExitCode::FAILURE;
        }
        Err(CliError::Api(ref e)) if e.status() == Some(reqwest::StatusCode::FORBIDDEN) => {
            eprintln!("error: forbidden — insufficient permissions");
            return ExitCode::FAILURE;
        }
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::FAILURE;
        }
    };

    render(TopologyPayload::Overview(&overview), output);
    ExitCode::SUCCESS
}
