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

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
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

/// Resolve the listen address from `mode` + `port`.
///
/// * **Local** binds to `127.0.0.1` — strictly loopback, no external
///   reachability — matching the developer-laptop story in the Epic 17
///   spec.
/// * **Remote** binds to `0.0.0.0` so multiple machines can reach the
///   control plane.
pub fn resolve_listen_addr(mode: ModeArg, port: u16) -> SocketAddr {
    let ip = match mode {
        ModeArg::Local => IpAddr::V4(Ipv4Addr::LOCALHOST),
        ModeArg::Remote => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
    };
    SocketAddr::new(ip, port)
}

/// Human-readable address an operator would type into a browser
/// for the configured mode + port. For local mode we always show
/// `http://localhost:{port}` rather than `127.0.0.1:{port}` because
/// that's what the dashboard URL looks like in the Epic 17 spec.
fn display_address(mode: ModeArg, port: u16) -> String {
    match mode {
        ModeArg::Local => format!("http://localhost:{port}"),
        ModeArg::Remote => format!("http://0.0.0.0:{port}"),
    }
}

/// Format the success banner printed after a background start.
///
/// Returned as a `String` (rather than printed directly) so the
/// format is unit-testable without capturing stdout.
pub fn format_started_banner(mode: ModeArg, port: u16, pid: u32) -> String {
    let mode_label = match mode {
        ModeArg::Local => "local",
        ModeArg::Remote => "remote",
    };
    format!(
        "✓ Agent Assembly gateway started\n  Mode:    {mode}\n  Address: {addr}\n  PID:     {pid}\n",
        mode = mode_label,
        addr = display_address(mode, port),
        pid = pid,
    )
}

/// Format the "already running" message printed when `aasm start`
/// is called while a gateway is already accepting traffic.
pub fn format_already_running_message(mode: ModeArg, port: u16, pid: u32) -> String {
    format!(
        "Gateway already running at {addr} (PID {pid}). Use 'aasm stop' first.",
        addr = display_address(mode, port),
        pid = pid,
    )
}
