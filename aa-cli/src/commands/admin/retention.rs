//! `aasm admin run-retention` — manually trigger one retention pass.
//!
//! Until the gateway admin transport from Story S-I (AAASM-1590) lands,
//! this subcommand parses its arguments and prints a clear stub message
//! pointing at the in-flight wiring ticket; it exits 0 so end-to-end CI
//! that exercises CLI help / arg parsing stays green.

use std::process::ExitCode;

use clap::Args;

use crate::config::ResolvedContext;
use crate::output::OutputFormat;

/// Arguments for `aasm admin run-retention`.
#[derive(Debug, Args)]
pub struct RunRetentionArgs {
    /// Run in dry-run mode — log what would be retained/dropped without
    /// taking any action.
    #[arg(long)]
    pub dry_run: bool,
}

/// Dispatch `aasm admin run-retention [--dry-run]`.
///
/// `ctx` and `output` were threaded through in this commit for Epic 18
/// Story S-I.5 (AAASM-1872); the live transport wire-up that consumes
/// them lands in the next commit.
pub fn dispatch(_args: RunRetentionArgs, _ctx: &ResolvedContext, _output: OutputFormat) -> ExitCode {
    eprintln!(
        "aasm admin run-retention: gateway admin transport not yet wired \
         (tracked under AAASM-1590 / Story S-I). The retention engine \
         (Story S-F) is in place; once the admin transport lands this \
         subcommand will trigger a manual retention pass against the \
         running gateway."
    );
    ExitCode::SUCCESS
}
