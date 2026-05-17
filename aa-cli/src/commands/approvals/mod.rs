//! `aasm approvals` — human-in-the-loop approval management subcommands.

use std::process::ExitCode;

use clap::{Args, Subcommand};

use crate::config::ResolvedContext;
use crate::output::OutputFormat;

pub mod approve;
pub mod client;
pub mod get;
pub mod list;
pub mod models;
pub mod reason_io;
pub mod reject;
pub mod watch;

/// Subcommands for `aasm approvals`.
#[derive(Debug, Subcommand)]
pub enum ApprovalsSubcommand {
    /// List all pending approval requests.
    List(list::ListArgs),
    /// Show details of a single pending approval request.
    Get(get::GetArgs),
    /// Approve a pending action.
    Approve(approve::ApproveArgs),
    /// Reject a pending action (--reason required).
    Reject(reject::RejectArgs),
    /// Watch for new approval requests in real time.
    Watch(watch::WatchArgs),
}

/// Top-level arguments for the `aasm approvals` command group.
#[derive(Debug, Args)]
pub struct ApprovalsArgs {
    #[command(subcommand)]
    pub command: ApprovalsSubcommand,
}

/// Dispatch the parsed approvals subcommand to the appropriate handler.
pub fn dispatch(args: ApprovalsArgs, ctx: &ResolvedContext, global_output: OutputFormat) -> ExitCode {
    match args.command {
        ApprovalsSubcommand::List(a) => list::run_list(a, ctx, global_output),
        ApprovalsSubcommand::Get(a) => get::run_get(a, ctx, global_output),
        ApprovalsSubcommand::Approve(a) => approve::run_approve(a, ctx),
        ApprovalsSubcommand::Reject(a) => reject::run_reject(a, ctx),
        ApprovalsSubcommand::Watch(a) => watch::run_watch(a, ctx),
    }
}
