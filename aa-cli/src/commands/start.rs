//! `aasm start` — explicit lifecycle command for the locally-managed
//! gateway process (Epic 17 / AAASM-1568 / Story AAASM-1578).
//!
//! This module is the CLI surface. It spawns the existing
//! `aa-gateway` binary, manages the PID file via [`pidfile`], and
//! waits for the listener to come up via [`gw_probe`]. The actual
//! mode-dispatch logic (`--mode local` vs `--mode remote`) is
//! delivered by AAASM-1576 and AAASM-1577 — until those land,
//! `aasm start` translates its high-level flags into the gateway's
//! current `--listen` flag and accepts `--config` / `--no-dashboard`
//! as a no-op so the operator-facing surface is stable.
//!
//! See the sibling `pidfile` and `gw_probe` modules for the
//! primitives used here.
//!
//! [`pidfile`]: super::pidfile
//! [`gw_probe`]: super::gw_probe

use std::path::PathBuf;

/// Which deployment mode `aasm start` should hand off to.
///
/// Mirrors `aa_core::config::DeploymentMode` but is defined here so
/// the CLI parser doesn't pull a runtime dependency into a value-
/// type module that other crates may want to import standalone.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
#[clap(rename_all = "lowercase")]
pub enum ModeArg {
    /// In-process control plane on `127.0.0.1` (default).
    Local,
    /// Remote control plane bound to `0.0.0.0`.
    Remote,
}

/// `aasm start` command-line arguments.
///
/// Defaults mirror the contract laid out in AAASM-1578: local mode,
/// port 7391, config at `~/.aasm/config.yaml`, run in the background,
/// dashboard enabled.
#[derive(Debug, clap::Args)]
pub struct StartArgs {
    /// Deployment mode to start.
    #[arg(long, value_enum, default_value_t = ModeArg::Local)]
    pub mode: ModeArg,
    /// TCP port the gateway should listen on.
    #[arg(long, default_value_t = 7391)]
    pub port: u16,
    /// Path to the YAML config file consumed by the gateway.
    #[arg(long, default_value = "~/.aasm/config.yaml")]
    pub config: PathBuf,
    /// Stay in the foreground; do not daemonize.
    #[arg(long)]
    pub foreground: bool,
    /// Disable dashboard serving even in local mode.
    #[arg(long)]
    pub no_dashboard: bool,
}
