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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dispatch_fails_when_dashboard_unreachable() {
        // Serialize env mutation with the crate-wide lock; isolate the PID file
        // to an empty temp dir so no stale running-dashboard record is found.
        let _lock = crate::test_support::env_guard();
        let tmp = tempfile::tempdir().unwrap();
        let prev_data = std::env::var_os("AA_DATA_DIR");
        let prev_port = std::env::var_os("AASM_DASHBOARD_PORT");
        std::env::set_var("AA_DATA_DIR", tmp.path());
        std::env::remove_var("AASM_DASHBOARD_PORT");

        // Port 1 is never listening → reqwest::blocking::get fails → FAILURE.
        let code = dispatch(OpenArgs { port: Some(1) }, &CliConfig::default());

        match prev_data {
            Some(v) => std::env::set_var("AA_DATA_DIR", v),
            None => std::env::remove_var("AA_DATA_DIR"),
        }
        if let Some(v) = prev_port {
            std::env::set_var("AASM_DASHBOARD_PORT", v);
        }

        assert_eq!(code, ExitCode::FAILURE);
    }
}
