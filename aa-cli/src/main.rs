//! `aasm` — the Agent Assembly command-line tool.
//!
//! Provides commands for managing agents, policies, and the governance
//! gateway from the terminal.

use std::process::ExitCode;

use aa_cli::{commands, config, Cli};
use clap::Parser;

fn main() -> ExitCode {
    // AAASM-5955: marks that the real `aasm` binary is running, before any
    // command dispatches — see `commands::run_registration::identity_fallback_permitted`.
    commands::run_registration::mark_production_entrypoint();

    let cli = Cli::parse();

    let cfg = match config::load() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error loading config: {e}");
            return ExitCode::FAILURE;
        }
    };

    let resolved = match config::resolve_context(
        &cfg,
        cli.context.as_deref(),
        cli.api_url.as_deref(),
        cli.api_key.as_deref(),
    ) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::FAILURE;
        }
    };

    commands::dispatch(cli.command, &resolved, cli.output)
}
