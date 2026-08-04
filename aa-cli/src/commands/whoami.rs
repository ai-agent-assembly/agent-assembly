//! `aasm whoami` — show the active session identity, scopes, and expiry (AAASM-5510).
//!
//! STUB: implemented in Wave 2C. Keep the `WhoamiArgs` shape and the
//! `run(args, ctx, output) -> ExitCode` signature — `commands::dispatch` is wired to them.

use std::process::ExitCode;

use clap::Args;

use crate::config::ResolvedContext;
use crate::output::OutputFormat;

/// Arguments for `aasm whoami`.
#[derive(Args)]
pub struct WhoamiArgs {}

/// Run `aasm whoami`.
pub fn run(_args: WhoamiArgs, _ctx: &ResolvedContext, _output: OutputFormat) -> ExitCode {
    eprintln!("aasm whoami: not yet implemented");
    ExitCode::FAILURE
}
