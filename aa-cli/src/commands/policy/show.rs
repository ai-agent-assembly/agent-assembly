//! `aasm policy show <agent_id>` — inspect an agent's policy view.
//!
//! Introduced by AAASM-1049 (F100). `--show-permissions` prints the agent's
//! effective capability set with cascade provenance. `--show-budget`
//! (AAASM-1051) prints the agent's budget rollup across the agent / team /
//! org / subtree scopes. Either flag may be passed alone, or both together —
//! in which case the permissions section renders first.

use std::process::ExitCode;

use clap::Args;

use crate::commands::{budget, permissions};
use crate::config::ResolvedContext;
use crate::error::CliError;
use crate::output::OutputFormat;

/// Arguments for `aasm policy show`.
#[derive(Args)]
#[command(after_help = "\
Examples:
  aasm policy show aabbccdd00112233aabbccdd00112233 --show-permissions
  aasm policy show aabbccdd00112233aabbccdd00112233 --show-budget
  aasm policy show aabbccdd00112233aabbccdd00112233 --show-permissions --show-budget
  aasm policy show aabbccdd00112233aabbccdd00112233 --show-budget --output json")]
pub struct ShowArgs {
    /// Hex-encoded agent UUID (32 hex characters).
    pub agent_id: String,

    /// Print the agent's effective capability set with cascade provenance.
    #[arg(long)]
    pub show_permissions: bool,

    /// Print the agent's budget rollup across agent / team / org / subtree.
    #[arg(long)]
    pub show_budget: bool,
}

/// Run the `aasm policy show` command.
pub fn run(args: ShowArgs, ctx: &ResolvedContext, output: OutputFormat) -> ExitCode {
    if !args.show_permissions && !args.show_budget {
        eprintln!("error: nothing to show — pass --show-permissions and/or --show-budget");
        return ExitCode::from(2u8);
    }

    let rt = tokio::runtime::Runtime::new().expect("failed to create tokio runtime");

    if args.show_permissions {
        match rt.block_on(permissions::fetch_effective_permissions(ctx, &args.agent_id)) {
            Ok(perms) => permissions::render(&perms, output),
            Err(e) => return handle_fetch_error(&args.agent_id, e),
        }
    }

    if args.show_budget {
        match rt.block_on(budget::fetch_budget_rollup(ctx, &args.agent_id)) {
            Ok(rollup) => budget::render(&rollup, output),
            Err(e) => return handle_fetch_error(&args.agent_id, e),
        }
    }

    ExitCode::SUCCESS
}

/// Map a `CliError` from the API client into a non-zero exit code with a
/// human-readable stderr message. Shared between the permissions and budget
/// fetch paths so error semantics stay identical.
fn handle_fetch_error(agent_id: &str, err: CliError) -> ExitCode {
    match err {
        CliError::Api(ref e) if e.status() == Some(reqwest::StatusCode::NOT_FOUND) => {
            eprintln!("error: agent {agent_id} not found");
            ExitCode::from(4u8)
        }
        CliError::Api(ref e) if e.status() == Some(reqwest::StatusCode::BAD_REQUEST) => {
            eprintln!("error: invalid agent ID '{agent_id}' (expected 32 hex characters)");
            ExitCode::from(3u8)
        }
        _ => {
            eprintln!("error: {err}");
            ExitCode::FAILURE
        }
    }
}
