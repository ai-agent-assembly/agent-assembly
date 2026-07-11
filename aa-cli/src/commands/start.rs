//! `aasm start` — explicit lifecycle command for the locally-managed
//! gateway process (Epic 17 / AAASM-1568 / Story AAASM-1578).
//!
//! This module is the CLI surface. It spawns the entrypoint binary
//! matching the requested mode (AAASM-3382): `--mode local` launches
//! `aa-api-server` (dashboard SPA + full `/api/v1/*` REST surface from a
//! single process); `--mode remote` launches `aa-gateway` via `--listen`.
//! It manages the PID file via [`pidfile`] and waits for the listener to
//! come up via [`gw_probe`]. `--config` / `--no-dashboard` are accepted as
//! no-ops so the operator-facing surface is stable.
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

/// Strategy used by [`run`] to start the `aa-gateway` subprocess.
///
/// Production code uses [`ProcessSpawner`], which shells out to the
/// real `aa-gateway` binary. Tests inject a mock so the run flow can
/// be driven end-to-end without spawning a real child — the AC bullet
/// "subprocess spawn mocked via a trait/seam".
pub trait GatewaySpawner {
    /// Detach a gateway process listening on `addr` and return its PID.
    fn spawn_background(&self, addr: SocketAddr) -> std::io::Result<u32>;
    /// Run a gateway process in the foreground; block until it exits.
    fn exec_foreground(&self, addr: SocketAddr) -> std::io::Result<std::process::ExitStatus>;
}

/// Name of the entrypoint binary launched for `mode` (AAASM-3382):
/// local mode runs `aa-api-server`, remote mode runs `aa-gateway`.
///
/// Single source of truth so the spawn/exec failure messages name the
/// binary that was actually invoked instead of a hardcoded default —
/// otherwise a `--mode local` failure misleadingly blames `aa-gateway`
/// (AAASM-4450).
fn binary_name(mode: ModeArg) -> &'static str {
    match mode {
        ModeArg::Local => "aa-api-server",
        ModeArg::Remote => "aa-gateway",
    }
}

/// Default [`GatewaySpawner`].
///
/// * **Local mode** invokes the `aa-api-server` binary (AAASM-3382), which
///   serves the dashboard SPA *and* the full `/api/v1/*` REST surface from a
///   single process and port — so one `aasm start --mode local` brings up both.
///   The bind address is passed via the `AA_API_ADDR` environment variable the
///   binary reads.
/// * **Remote mode** invokes the `aa-gateway` binary via its `--listen` flag,
///   exactly as before.
pub struct ProcessSpawner {
    mode: ModeArg,
}

impl ProcessSpawner {
    /// Build a spawner that launches the binary matching `mode`.
    pub fn new(mode: ModeArg) -> Self {
        Self { mode }
    }

    /// Construct the `Command` that starts the right binary for `addr`.
    fn command(&self, addr: SocketAddr) -> Command {
        match self.mode {
            ModeArg::Local => {
                let mut cmd = Command::new(binary_name(self.mode));
                cmd.env("AA_API_ADDR", addr.to_string());
                cmd
            }
            ModeArg::Remote => {
                let mut cmd = Command::new(binary_name(self.mode));
                cmd.arg("--listen").arg(addr.to_string());
                cmd
            }
        }
    }
}

impl GatewaySpawner for ProcessSpawner {
    fn spawn_background(&self, addr: SocketAddr) -> std::io::Result<u32> {
        let child = self.command(addr).spawn()?;
        Ok(child.id())
    }

    fn exec_foreground(&self, addr: SocketAddr) -> std::io::Result<std::process::ExitStatus> {
        self.command(addr).status()
    }
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
    let pid_file = match super::pidfile::pid_file_path() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("aasm start: {e}");
            return ExitCode::FAILURE;
        }
    };
    let spawner = ProcessSpawner::new(args.mode);
    run_with_spawner(args, &spawner, &pid_file)
}

/// Same as [`run`] but with an injectable `Spawner` and PID-file path
/// so unit tests can drive the full flow without spawning a real
/// `aa-gateway` child.
pub fn run_with_spawner<S: GatewaySpawner>(args: StartArgs, spawner: &S, pid_file: &Path) -> ExitCode {
    let addr = resolve_listen_addr(args.mode, args.port);

    if let Some(pid) = check_already_running(pid_file, addr, Duration::from_millis(200)) {
        println!("{}", format_already_running_message(args.mode, args.port, pid));
        return ExitCode::SUCCESS;
    }

    if args.foreground {
        return match spawner.exec_foreground(addr) {
            Ok(status) if status.success() => ExitCode::SUCCESS,
            Ok(_) => ExitCode::FAILURE,
            Err(e) => {
                eprintln!("aasm start: failed to exec {}: {e}", binary_name(args.mode));
                ExitCode::FAILURE
            }
        };
    }

    let pid = match spawner.spawn_background(addr) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("aasm start: failed to spawn {}: {e}", binary_name(args.mode));
            return ExitCode::FAILURE;
        }
    };
    if let Err(e) = super::pidfile::write_pid(pid_file, pid) {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_mode_spawns_aa_api_server_with_bind_env() {
        // AAASM-3382: local mode launches the combined SPA + REST entrypoint and
        // passes the bind address via AA_API_ADDR (the binary reads it from env).
        let addr: SocketAddr = "127.0.0.1:7391".parse().unwrap();
        let cmd = ProcessSpawner::new(ModeArg::Local).command(addr);
        assert_eq!(cmd.get_program(), "aa-api-server");
        let env: Vec<_> = cmd.get_envs().collect();
        assert!(
            env.iter().any(|(k, v)| *k == std::ffi::OsStr::new("AA_API_ADDR")
                && *v == Some(std::ffi::OsStr::new("127.0.0.1:7391"))),
            "local mode must pass the bind address via AA_API_ADDR; got {env:?}",
        );
    }

    #[test]
    fn remote_mode_spawns_aa_gateway_with_listen_flag() {
        let addr: SocketAddr = "0.0.0.0:7391".parse().unwrap();
        let cmd = ProcessSpawner::new(ModeArg::Remote).command(addr);
        assert_eq!(cmd.get_program(), "aa-gateway");
        let args: Vec<_> = cmd.get_args().collect();
        assert_eq!(args, vec!["--listen", "0.0.0.0:7391"]);
    }

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

    #[test]
    fn check_already_running_returns_none_when_pid_file_is_missing() {
        let tmp = tempfile::TempDir::new().unwrap();
        let pid_file = tmp.path().join("gateway.pid");
        // No PID file and no listener => not running.
        assert!(check_already_running(
            &pid_file,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9),
            Duration::from_millis(50)
        )
        .is_none());
    }

    #[test]
    fn check_already_running_returns_some_when_pid_is_self_and_port_listens() {
        let _net = crate::test_support::net_guard();
        let tmp = tempfile::TempDir::new().unwrap();
        let pid_file = tmp.path().join("gateway.pid");
        let self_pid = std::process::id();
        super::super::pidfile::write_pid(&pid_file, self_pid).unwrap();

        // Bind an ephemeral listener to stand in for the gateway port.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let pid = check_already_running(&pid_file, addr, Duration::from_millis(200))
            .expect("should report running when both pid and listener are live");
        assert_eq!(pid, self_pid);
    }

    /// Mock `GatewaySpawner` that returns a predetermined PID instead
    /// of actually spawning a child. Used to drive `run_with_spawner`
    /// end-to-end without an `aa-gateway` binary on PATH.
    struct MockSpawner {
        pid: u32,
    }

    impl GatewaySpawner for MockSpawner {
        fn spawn_background(&self, _: SocketAddr) -> std::io::Result<u32> {
            Ok(self.pid)
        }
        fn exec_foreground(&self, _: SocketAddr) -> std::io::Result<std::process::ExitStatus> {
            // Foreground path is not exercised by these tests yet.
            unimplemented!("MockSpawner::exec_foreground")
        }
    }

    #[test]
    fn run_background_writes_pid_file_via_injected_spawner() {
        let _net = crate::test_support::net_guard();
        // Open a listener so `wait_for_ready` succeeds; the test
        // process owns the socket and the mock spawner only needs
        // to hand back the PID we want pinned to disk.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let tmp = tempfile::TempDir::new().unwrap();
        let pid_file = tmp.path().join("gateway.pid");

        let args = StartArgs {
            mode: ModeArg::Local,
            port: addr.port(),
            config: std::path::PathBuf::from("/dev/null"),
            foreground: false,
            no_dashboard: false,
        };
        let mock = MockSpawner { pid: 424_242 };

        let exit = run_with_spawner(args, &mock, &pid_file);
        assert_eq!(
            format!("{exit:?}"),
            format!("{:?}", ExitCode::SUCCESS),
            "run should succeed when spawner + listener cooperate",
        );
        // Mock's PID, not the test process's PID — proves the
        // injected spawner was actually consulted.
        assert_eq!(super::super::pidfile::read_pid(&pid_file).unwrap(), Some(424_242),);
    }
}
