//! `aasm approvals get` — show details of a single pending approval.

use std::process::ExitCode;

use clap::Args;

use crate::config::ResolvedContext;
use crate::output::OutputFormat;
use crate::sanitize::sanitize_terminal;

use super::client;
use super::models::ApprovalResponse;

/// Arguments for the `aasm approvals get` subcommand.
#[derive(Debug, Args)]
pub struct GetArgs {
    /// Approval request ID to look up.
    pub id: String,

    /// Output format override for this subcommand.
    #[arg(long, value_enum)]
    pub output: Option<OutputFormat>,
}

/// Build the human-readable (table-mode) detail block for one approval.
///
/// Every field (`id`, `agent_id`, `action`, `reason`, `status`, `created_at`)
/// is agent/server-controlled and printed verbatim, so each is run through
/// [`sanitize_terminal`] to strip ANSI/OSC escapes and C0 control bytes before
/// it reaches the operator's terminal.
fn format_approval_detail(approval: &ApprovalResponse) -> String {
    format!(
        "ID:         {}\nAgent:      {}\nAction:     {}\nCondition:  {}\nStatus:     {}\nCreated at: {}",
        sanitize_terminal(&approval.id),
        sanitize_terminal(&approval.agent_id),
        sanitize_terminal(&approval.action),
        sanitize_terminal(&approval.reason),
        sanitize_terminal(&approval.status),
        sanitize_terminal(&approval.created_at),
    )
}

/// Execute the `aasm approvals get` subcommand.
pub fn run_get(args: GetArgs, ctx: &ResolvedContext, global_output: OutputFormat) -> ExitCode {
    let rt = tokio::runtime::Runtime::new().expect("failed to create tokio runtime");
    let result = rt.block_on(client::get_approval(ctx, &args.id));

    match result {
        Ok(approval) => {
            let format = args.output.unwrap_or(global_output);
            match format {
                OutputFormat::Json => {
                    println!("{}", serde_json::to_string_pretty(&approval).unwrap_or_default());
                }
                OutputFormat::Yaml => {
                    println!("{}", serde_yaml::to_string(&approval).unwrap_or_default());
                }
                OutputFormat::Table => {
                    println!("{}", format_approval_detail(&approval));
                }
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}
