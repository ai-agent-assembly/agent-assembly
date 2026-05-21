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
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::time::Duration;

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

/// Check whether a gateway is already running at `addr`.
///
/// Both conditions must hold:
///
/// 1. The PID file at `pid_file` resolves to a still-alive process.
/// 2. A TCP probe of `addr` succeeds within `probe_timeout`.
///
/// Either condition on its own is ambiguous — a stale PID file
/// can outlive a crashed gateway, and an open port without a PID
/// file might belong to a different service. Both together give
/// the operator a clear "this is our gateway, still running"
/// signal.
pub fn check_already_running(pid_file: &Path, addr: SocketAddr, probe_timeout: Duration) -> Option<u32> {
    let pid = super::pidfile::read_pid(pid_file).ok().flatten()?;
    if !super::pidfile::is_pid_alive(pid) {
        return None;
    }
    if !super::gw_probe::probe_tcp(addr, probe_timeout) {
        return None;
    }
    Some(pid)
}

/// Entry point for `aasm start`.
///
/// Orchestrates the four steps of a successful start:
///
/// 1. Resolve listen address from mode + port.
/// 2. Bail out early if a gateway is already running at that addr.
/// 3. Spawn `aa-gateway` (foreground or background, per `--foreground`).
/// 4. In background mode, write the PID file and wait for the listener
///    to come up before exiting with the success banner.
///
/// Returns `ExitCode::SUCCESS` on a normal start, idempotent
/// "already running" path, or clean foreground exit. Returns
/// `ExitCode::FAILURE` if the readiness probe times out or the
/// spawn itself fails.
pub fn run(args: StartArgs) -> ExitCode {
    let addr = resolve_listen_addr(args.mode, args.port);
    let pid_file = match super::pidfile::pid_file_path() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("aasm start: {e}");
            return ExitCode::FAILURE;
        }
    };

    if let Some(pid) = check_already_running(&pid_file, addr, Duration::from_millis(200)) {
        println!("{}", format_already_running_message(args.mode, args.port, pid));
        return ExitCode::SUCCESS;
    }

    let mut cmd = Command::new("aa-gateway");
    cmd.arg("--listen").arg(addr.to_string());

    if args.foreground {
        match cmd.status() {
            Ok(status) if status.success() => ExitCode::SUCCESS,
            Ok(_) => ExitCode::FAILURE,
            Err(e) => {
                eprintln!("aasm start: failed to exec aa-gateway: {e}");
                ExitCode::FAILURE
            }
        }
    } else {
        let child = match cmd.spawn() {
            Ok(c) => c,
            Err(e) => {
                eprintln!("aasm start: failed to spawn aa-gateway: {e}");
                return ExitCode::FAILURE;
            }
        };
        let pid = child.id();
        if let Err(e) = super::pidfile::write_pid(&pid_file, pid) {
            eprintln!("aasm start: failed to write pid file: {e}");
            return ExitCode::FAILURE;
        }
        match super::gw_probe::wait_for_ready(addr, Duration::from_secs(5), Duration::from_millis(100)) {
            Ok(()) => {
                println!("{}", format_started_banner(args.mode, args.port, pid));
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("aasm start: {e}");
                ExitCode::FAILURE
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_listen_addr_local_binds_loopback() {
        let addr = resolve_listen_addr(ModeArg::Local, 7391);
        assert_eq!(addr.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(addr.port(), 7391);
    }

    #[test]
    fn resolve_listen_addr_remote_binds_unspecified() {
        let addr = resolve_listen_addr(ModeArg::Remote, 7391);
        assert_eq!(addr.ip(), IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        assert_eq!(addr.port(), 7391);
    }

    #[test]
    fn format_started_banner_contains_mode_address_and_pid() {
        let banner = format_started_banner(ModeArg::Local, 7391, 12_345);
        assert!(banner.contains("✓ Agent Assembly gateway started"));
        assert!(banner.contains("Mode:    local"));
        assert!(banner.contains("Address: http://localhost:7391"));
        assert!(banner.contains("PID:     12345"));
    }

    #[test]
    fn format_already_running_message_matches_story_contract() {
        let msg = format_already_running_message(ModeArg::Local, 7391, 12_345);
        assert_eq!(
            msg,
            "Gateway already running at http://localhost:7391 (PID 12345). Use 'aasm stop' first."
        );
    }
}
