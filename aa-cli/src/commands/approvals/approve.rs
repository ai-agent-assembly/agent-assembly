//! `aasm approvals approve` — approve a pending action.

use std::process::ExitCode;

use clap::Args;

use crate::config::ResolvedContext;

use super::client;

/// Arguments for the `aasm approvals approve` subcommand.
#[derive(Debug, Args)]
pub struct ApproveArgs {
    /// Approval request ID to approve.
    pub id: String,

    /// Optional reason for the approval.
    #[arg(long)]
    pub reason: Option<String>,
}

/// Execute the `aasm approvals approve` subcommand.
pub fn run_approve(args: ApproveArgs, ctx: &ResolvedContext) -> ExitCode {
    // AAASM-1477: if --reason is omitted and stdin is a pipe, read it.
    let reason = super::reason_io::resolve_reason_from_process_stdin(args.reason);
    let rt = tokio::runtime::Runtime::new().expect("failed to create tokio runtime");
    let result = rt.block_on(client::approve_action(ctx, &args.id, reason.as_deref()));

    match result {
        Ok(resp) => {
            println!("Approved: {} (status: {})", resp.id, resp.status);
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}
