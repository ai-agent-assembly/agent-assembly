//! `aasm topology tree` — render agent subtree.

use std::process::ExitCode;

use clap::Args;

use super::render::{render, AgentTree, TopologyPayload};
use crate::client;
use crate::config::ResolvedContext;
use crate::error::CliError;
use crate::output::OutputFormat;

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

/// Run the `aasm topology tree` command.
pub fn run(args: TreeArgs, ctx: &ResolvedContext, output: OutputFormat) -> ExitCode {
    if let Some(d) = args.depth {
        if d == 0 {
            eprintln!("error: --depth must be at least 1");
            return ExitCode::FAILURE;
        }
    }

    let mut path = format!("/api/v1/topology/tree/{}", args.agent_id);
    let mut params: Vec<String> = vec![];
    if let Some(d) = args.depth {
        params.push(format!("depth={d}"));
    }
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
    let tree: AgentTree = match rt.block_on(client::get_json(ctx, &path)) {
        Ok(v) => v,
        Err(CliError::Api(ref e)) if e.status() == Some(reqwest::StatusCode::NOT_FOUND) => {
            eprintln!("error: agent {} not found", args.agent_id);
            return ExitCode::from(4u8);
        }
        Err(CliError::Api(ref e)) if e.status() == Some(reqwest::StatusCode::UNPROCESSABLE_ENTITY) => {
            eprintln!("error: {} is not a root agent", args.agent_id);
            return ExitCode::from(5u8);
        }
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::FAILURE;
        }
    };

    render(TopologyPayload::Tree(&tree), output);
    ExitCode::SUCCESS
}
