//! `aasm admin` — gateway administrative operations.
//!
//! Initial scope (Story S-F): manually trigger a retention pass via
//! `aasm admin run-retention`. Additional admin subcommands land in
//! subsequent stories as the operator surface grows.

pub mod retention;

use std::process::ExitCode;

use clap::{Args, Subcommand};

/// Subcommands for `aasm admin`.
#[derive(Debug, Subcommand)]
pub enum AdminCommands {
    /// Trigger one manual retention pass against the running gateway.
    RunRetention(retention::RunRetentionArgs),
}

/// Arguments for the `aasm admin` subcommand group.
#[derive(Debug, Args)]
pub struct AdminArgs {
    #[command(subcommand)]
    pub command: AdminCommands,
}

/// Dispatch an `aasm admin` subcommand.
pub fn dispatch(args: AdminArgs) -> ExitCode {
    match args.command {
        AdminCommands::RunRetention(a) => retention::dispatch(a),
    }
}
