//! `aasm login` — exchange an API key for a scoped session token (AAASM-5507).
//!
//! STUB: implemented in Wave 2A. Keep the `LoginArgs` shape and the
//! `run(args, ctx) -> ExitCode` signature — `commands::dispatch` is wired to them.

use std::process::ExitCode;

use clap::Args;

use crate::config::ResolvedContext;

/// Arguments for `aasm login`.
#[derive(Args)]
pub struct LoginArgs {
    /// Requested scope for the session (defaults to the caller's full scopes).
    #[arg(long, value_parser = ["read", "write", "admin"])]
    pub scope: Option<String>,
}

/// Run `aasm login`.
pub fn run(_args: LoginArgs, _ctx: &ResolvedContext) -> ExitCode {
    eprintln!("aasm login: not yet implemented");
    ExitCode::FAILURE
}
