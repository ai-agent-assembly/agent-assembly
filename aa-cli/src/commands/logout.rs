//! `aasm logout` — end the local session for the active context (AAASM-5509).
//!
//! STUB: implemented in Wave 2B. Keep the `LogoutArgs` shape and the
//! `run(args, ctx) -> ExitCode` signature — `commands::dispatch` is wired to them.

use std::process::ExitCode;

use clap::Args;

use crate::config::ResolvedContext;

/// Arguments for `aasm logout`.
#[derive(Args)]
pub struct LogoutArgs {}

/// Run `aasm logout`.
pub fn run(_args: LogoutArgs, _ctx: &ResolvedContext) -> ExitCode {
    eprintln!("aasm logout: not yet implemented");
    ExitCode::FAILURE
}
