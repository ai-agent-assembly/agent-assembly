//! `aasm admin` — gateway administrative operations.
//!
//! Initial scope (Story S-F): manually trigger a retention pass via
//! `aasm admin run-retention`. Additional admin subcommands land in
//! subsequent stories as the operator surface grows.

pub mod retention;

use std::process::ExitCode;

use clap::{Args, Subcommand};

use crate::config::ResolvedContext;
use crate::output::OutputFormat;

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
///
/// `ctx` and `output` were threaded through in Epic 18 Story S-I.5
/// (AAASM-1872) so admin subcommands can reach the gateway via the
/// shared HTTP client and respect the global `--output` selection.
pub fn dispatch(args: AdminArgs, ctx: &ResolvedContext, output: OutputFormat) -> ExitCode {
    match args.command {
        AdminCommands::RunRetention(a) => retention::dispatch(a, ctx, output),
    }
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    #[derive(Parser)]
    #[command(name = "aasm")]
    struct TestCli {
        #[command(subcommand)]
        command: TestCommands,
    }

    #[derive(clap::Subcommand)]
    enum TestCommands {
        Admin(super::AdminArgs),
    }

    fn parse(args: &[&str]) -> super::AdminArgs {
        let cli = TestCli::parse_from(args);
        match cli.command {
            TestCommands::Admin(a) => a,
        }
    }

    #[test]
    fn parse_admin_run_retention_defaults_dry_run_to_false() {
        let args = parse(&["aasm", "admin", "run-retention"]);
        match args.command {
            super::AdminCommands::RunRetention(a) => assert!(!a.dry_run),
        }
    }

    #[test]
    fn parse_admin_run_retention_with_dry_run_flag() {
        let args = parse(&["aasm", "admin", "run-retention", "--dry-run"]);
        match args.command {
            super::AdminCommands::RunRetention(a) => assert!(a.dry_run),
        }
    }
}
