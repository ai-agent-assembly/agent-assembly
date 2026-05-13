//! `aasm dashboard open` — open the browser to a running dashboard.

use std::process::ExitCode;

use clap::Args;

use crate::config::{resolve_dashboard_port, CliConfig};

use super::pid;

/// Arguments for `aasm dashboard open`.
#[derive(Debug, Args)]
pub struct OpenArgs {
    /// Port to connect to (overrides config and AASM_DASHBOARD_PORT env var).
    #[arg(long, env = "AASM_DASHBOARD_PORT")]
    pub port: Option<u16>,
}

pub fn dispatch(args: OpenArgs, config: &CliConfig) -> ExitCode {
    // Prefer port from PID file (records the actual running port), then fall back to flags/config.
    let port = pid::read_pid()
        .map(|(_, p)| p)
        .unwrap_or_else(|| resolve_dashboard_port(config, args.port));

    let url = format!("http://127.0.0.1:{port}");

    // Verify the server is reachable before launching the browser.
    let reachable = reqwest::blocking::get(&url)
        .map(|r| r.status().is_success() || r.status().as_u16() < 500)
        .unwrap_or(false);

    if !reachable {
        eprintln!("error: dashboard is not running at {url}");
        eprintln!("hint: start it first with `aasm dashboard start`");
        return ExitCode::FAILURE;
    }

    if let Err(e) = open::that(&url) {
        eprintln!("error: could not open browser: {e}");
        return ExitCode::FAILURE;
    }

    ExitCode::SUCCESS
}
