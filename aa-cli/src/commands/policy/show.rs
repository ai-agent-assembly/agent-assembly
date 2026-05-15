//! `aasm policy show <agent_id>` — inspect an agent's policy view.
//!
//! New subcommand introduced by AAASM-1049 (F100). Initial scope is the
//! `--show-permissions` flag which prints the agent's effective capability
//! set with cascade provenance. Companion flags (e.g. `--show-budget` from
//! AAASM-1051) will be added in sibling Subtasks of the parent Story.

use std::process::ExitCode;

use clap::Args;

use crate::commands::permissions;
use crate::config::ResolvedContext;
use crate::error::CliError;
use crate::output::OutputFormat;

/// Arguments for `aasm policy show`.
#[derive(Args)]
#[command(after_help = "\
Examples:
  aasm policy show aabbccdd00112233aabbccdd00112233 --show-permissions
  aasm policy show aabbccdd00112233aabbccdd00112233 --show-permissions --output json")]
pub struct ShowArgs {
    /// Hex-encoded agent UUID (32 hex characters).
    pub agent_id: String,

    /// Print the agent's effective capability set with cascade provenance.
    #[arg(long)]
    pub show_permissions: bool,
}

/// Run the `aasm policy show` command.
pub fn run(args: ShowArgs, ctx: &ResolvedContext, output: OutputFormat) -> ExitCode {
    if !args.show_permissions {
        eprintln!("error: nothing to show — pass --show-permissions (more flags coming via AAASM-1051)");
        return ExitCode::from(2u8);
    }

    let rt = tokio::runtime::Runtime::new().expect("failed to create tokio runtime");
    let perms = match rt.block_on(permissions::fetch_effective_permissions(ctx, &args.agent_id)) {
        Ok(p) => p,
        Err(CliError::Api(ref e)) if e.status() == Some(reqwest::StatusCode::NOT_FOUND) => {
            eprintln!("error: agent {} not found", args.agent_id);
            return ExitCode::from(4u8);
        }
        Err(CliError::Api(ref e)) if e.status() == Some(reqwest::StatusCode::BAD_REQUEST) => {
            eprintln!(
                "error: invalid agent ID '{}' (expected 32 hex characters)",
                args.agent_id
            );
            return ExitCode::from(3u8);
        }
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::FAILURE;
        }
    };

    permissions::render(&perms, output);
    ExitCode::SUCCESS
}
