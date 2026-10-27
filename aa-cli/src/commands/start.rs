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
use std::process::{Command, ExitCode, Stdio};
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

/// Port `aasm start` listens on unless `--port` says otherwise. Also the port
/// the operator commands' built-in API URL points at, so a bare `aasm status`
/// finds a gateway that `aasm start` brought up with its defaults (AAASM-6385).
pub const DEFAULT_PORT: u16 = 7391;

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
    #[arg(long, default_value_t = DEFAULT_PORT)]
    pub port: u16,
    /// Bind address override — an explicit opt-in to a non-default host
    /// (AAASM-6056). Unset preserves the per-mode default (`127.0.0.1` for
    /// `local`, `0.0.0.0` for `remote`); local mode does not otherwise have
    /// a way to listen on anything but loopback. Not gated further here:
    /// `aa-api-server` itself refuses to start on a non-loopback address
    /// while `AASM_API_AUTH=off`, which is the one combination that would
    /// actually expose an unauthenticated admin API.
    #[arg(long)]
    pub host: Option<IpAddr>,
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

/// Resolve the listen address from `mode` + `port`, honouring an explicit
/// `--host` override (AAASM-6056).
///
/// * **Local** binds to `127.0.0.1` — strictly loopback, no external
///   reachability — matching the developer-laptop story in the Epic 17
///   spec.
/// * **Remote** binds to `0.0.0.0` so multiple machines can reach the
///   control plane.
///
/// `host`, when set, wins over both mode defaults — it is the explicit
/// opt-in a non-default bind requires; `None` preserves the exact
/// pre-AAASM-6056 behaviour.
pub fn resolve_listen_addr(mode: ModeArg, host: Option<IpAddr>, port: u16) -> SocketAddr {
    let ip = host.unwrap_or(match mode {
        ModeArg::Local => IpAddr::V4(Ipv4Addr::LOCALHOST),
        ModeArg::Remote => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
    });
    SocketAddr::new(ip, port)
}

/// Base URL operator commands should use to reach a gateway bound to `addr`.
/// An unspecified bind (`0.0.0.0`, `--mode remote`) is reached through
/// `localhost`, since the unspecified address is not one to connect to.
fn client_url(addr: SocketAddr) -> String {
    if addr.ip().is_unspecified() {
        format!("http://localhost:{}", addr.port())
    } else {
        display_address(addr)
    }
}

/// Human-readable address an operator would type into a browser for the
/// resolved bind address. Loopback addresses show as `http://localhost:{port}`
/// rather than the literal loopback IP, because that's what the dashboard URL
/// looks like in the Epic 17 spec — preserved for both mode defaults now that
/// `--host` can produce other loopback addresses too (e.g. `127.0.0.2`).
fn display_address(addr: SocketAddr) -> String {
    if addr.ip().is_loopback() {
        format!("http://localhost:{}", addr.port())
    } else {
        format!("http://{addr}")
    }
}

/// Format the success banner printed after a background start.
///
/// Returned as a `String` (rather than printed directly) so the
/// format is unit-testable without capturing stdout.
pub fn format_started_banner(mode: ModeArg, addr: SocketAddr, pid: u32) -> String {
    let mode_label = match mode {
        ModeArg::Local => "local",
        ModeArg::Remote => "remote",
    };
    format!(
        "✓ Agent Assembly gateway started\n  Mode:    {mode}\n  Address: {addr}\n  PID:     {pid}\n",
        mode = mode_label,
        addr = display_address(addr),
        pid = pid,
    )
}

/// Format the "already running" message printed when `aasm start`
/// is called while a gateway is already accepting traffic.
pub fn format_already_running_message(addr: SocketAddr, pid: u32) -> String {
    format!(
        "Gateway already running at {addr} (PID {pid}). Use 'aasm stop' first.",
        addr = display_address(addr),
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
    /// Where a detached process's output goes, if it is captured (AAASM-6389).
    fn log_path(&self) -> Option<PathBuf> {
        None
    }
    /// The binary this spawner launches, if it resolved to a file (AAASM-6385).
    fn binary_path(&self) -> Option<PathBuf> {
        None
    }
    /// The version the started server reports about itself, if it answers
    /// (AAASM-6385). `None` when it is unreachable or reports none.
    fn server_version(&self, _addr: SocketAddr) -> Option<String> {
        None
    }
}

/// The build command for the binary `mode` launches, for error text and docs.
fn build_command(mode: ModeArg) -> &'static str {
    match mode {
        ModeArg::Local => "cargo build -p aa-api --bin aa-api-server",
        ModeArg::Remote => "cargo build -p aa-gateway",
    }
}

/// The error for a launch binary that cannot be found (AAASM-6389).
///
/// Names the binary, the places the resolver really looks
/// ([`aa_core::binary_resolve`]: next to `aasm`, absolute `$PATH` entries, then
/// `~/.cargo/bin`; never the current directory) and how to build it, because a
/// source build of `aasm` alone does not produce it and the bare OS error
/// ("No such file or directory") says none of that.
fn not_found_error(mode: ModeArg) -> std::io::Error {
    let name = binary_name(mode);
    std::io::Error::new(
        std::io::ErrorKind::NotFound,
        format!(
            "`{name}` was not found (looked next to the `aasm` executable, on $PATH, and in ~/.cargo/bin). \
             `aasm start` launches it; if you built from source, build it with: {}",
            build_command(mode)
        ),
    )
}

/// What `aasm start` says about the server it launched (AAASM-6385).
///
/// `aasm start` runs whichever binary the resolver finds first, so an older one
/// earlier on `$PATH` is used silently and the only trace is a version in
/// `aasm status`. Returns the line to print and, when the server's reported
/// version differs from `aasm`'s own, a warning naming both versions, where the
/// server binary came from and how to fix it. A mismatch warns rather than
/// refuses: the pairing may be deliberate, and refusing would block a start that
/// works. An unreported version is said so, never guessed.
fn server_identity(
    name: &str,
    path: Option<&Path>,
    reported: Option<&str>,
    cli_version: &str,
) -> (String, Option<String>) {
    let from = path.map_or_else(|| "path unknown".to_string(), |p| p.display().to_string());
    let Some(reported) = reported else {
        return (format!("  Server:  {name} (version not reported) from {from}"), None);
    };
    let line = format!("  Server:  {name} {reported} from {from}");
    if reported == cli_version {
        return (line, None);
    }
    let warning = format!(
        "warning: {name} is {reported} but aasm is {cli_version} ({from}). \
         `aasm start` uses the first `{name}` next to aasm, on $PATH or in ~/.cargo/bin, \
         so a stale install can shadow your build. Put the matching binary first, \
         or reinstall both from the same build."
    );
    (line, Some(warning))
}

/// Replace anything shaped like a full API key (`aa_` + 32 hex) with a marker.
/// The server only ever logs a prefix, so this is a guard against ever echoing
/// a credential into an error message, not a path expected to trigger.
fn redact_keys(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(i) = rest.find("aa_") {
        out.push_str(&rest[..i]);
        let tail = &rest[i + 3..];
        let hex = tail.bytes().take_while(u8::is_ascii_hexdigit).count();
        if hex >= 32 {
            out.push_str("aa_<redacted>");
            rest = &tail[hex..];
        } else {
            out.push_str("aa_");
            rest = tail;
        }
    }
    out.push_str(rest);
    out
}

/// The last `max_lines` lines of the log at `path`, key-redacted; empty if it
/// cannot be read.
fn log_tail(path: &Path, max_lines: usize) -> String {
    let Ok(text) = std::fs::read_to_string(path) else {
        return String::new();
    };
    let lines: Vec<&str> = text.lines().collect();
    let start = lines.len().saturating_sub(max_lines);
    redact_keys(&lines[start..].join("\n"))
}

/// Whether `pid` is a child of this process that has already exited. Reaps it.
/// `kill(pid, 0)` cannot tell: an unreaped dead child still "exists".
fn child_exited(pid: u32) -> bool {
    #[cfg(unix)]
    {
        let mut status: libc::c_int = 0;
        // SAFETY: waitpid with WNOHANG writes only to `status`; a pid that is not
        // our child returns -1 (ECHILD) and is treated as "not known to have exited".
        let r = unsafe { libc::waitpid(pid as libc::pid_t, &mut status, libc::WNOHANG) };
        r == pid as libc::pid_t
    }
    #[cfg(not(unix))]
    {
        let _ = pid;
        false
    }
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
    log_path: Option<PathBuf>,
}

impl ProcessSpawner {
    /// Build a spawner that launches the binary matching `mode`.
    pub fn new(mode: ModeArg) -> Self {
        Self { mode, log_path: None }
    }

    /// Send a detached child's stdout and stderr to an owner-only log at `path`
    /// instead of inheriting the caller's (AAASM-6389).
    pub fn with_log(mut self, path: PathBuf) -> Self {
        self.log_path = Some(path);
        self
    }

    /// The program to run: the resolved binary (sibling-first, see
    /// [`aa_core::binary_resolve`]), else the bare name so the OS error is mapped
    /// to [`not_found_error`] at spawn time.
    fn program(&self) -> std::ffi::OsString {
        aa_core::binary_resolve::resolve_binary(binary_name(self.mode))
            .map(PathBuf::into_os_string)
            .unwrap_or_else(|| binary_name(self.mode).into())
    }

    /// Construct the `Command` that starts the right binary for `addr`.
    fn command(&self, addr: SocketAddr) -> Command {
        match self.mode {
            ModeArg::Local => {
                let mut cmd = Command::new(self.program());
                cmd.env("AA_API_ADDR", addr.to_string());
                cmd
            }
            ModeArg::Remote => {
                let mut cmd = Command::new(self.program());
                cmd.arg("--listen").arg(addr.to_string());
                cmd
            }
        }
    }
}

impl GatewaySpawner for ProcessSpawner {
    fn spawn_background(&self, addr: SocketAddr) -> std::io::Result<u32> {
        let mut cmd = self.command(addr);
        // The daemon must not inherit the caller's stdio: `aasm start | head`
        // would otherwise block until the server exits, because the server holds
        // the pipe's write end open.
        cmd.stdin(Stdio::null());
        match &self.log_path {
            Some(path) => {
                let log = open_log(path)?;
                cmd.stdout(Stdio::from(log.try_clone()?)).stderr(Stdio::from(log));
            }
            None => {
                cmd.stdout(Stdio::null()).stderr(Stdio::null());
            }
        }
        match cmd.spawn() {
            Ok(child) => Ok(child.id()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(not_found_error(self.mode)),
            Err(e) => Err(e),
        }
    }

    fn exec_foreground(&self, addr: SocketAddr) -> std::io::Result<std::process::ExitStatus> {
        match self.command(addr).status() {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(not_found_error(self.mode)),
            other => other,
        }
    }

    fn log_path(&self) -> Option<PathBuf> {
        self.log_path.clone()
    }

    fn binary_path(&self) -> Option<PathBuf> {
        aa_core::binary_resolve::resolve_binary(binary_name(self.mode))
    }

    fn server_version(&self, addr: SocketAddr) -> Option<String> {
        // Only the local API server serves `/api/v1/health` with a version.
        match self.mode {
            ModeArg::Local => super::pidfile::server_reported_version(&client_url(addr)),
            ModeArg::Remote => None,
        }
    }
}

/// Open the daemon log for append, owner-only, truncated first so a failed start
/// shows only this run's output. The directory is `~/.aasm`, created `0700`.
fn open_log(path: &Path) -> std::io::Result<std::fs::File> {
    if let Some(parent) = path.parent() {
        aa_core::private_fs::create_private_dir_all(parent)?;
    }
    aa_core::private_fs::write_private_file(path, b"")?;
    std::fs::OpenOptions::new().append(true).open(path)
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
    let log = pid_file.with_file_name(format!("{}.log", binary_name(args.mode)));
    let spawner = ProcessSpawner::new(args.mode).with_log(log);
    run_with_spawner(args, &spawner, &pid_file)
}

/// Same as [`run`] but with an injectable `Spawner` and PID-file path
/// so unit tests can drive the full flow without spawning a real
/// `aa-gateway` child.
pub fn run_with_spawner<S: GatewaySpawner>(args: StartArgs, spawner: &S, pid_file: &Path) -> ExitCode {
    let addr = resolve_listen_addr(args.mode, args.host, args.port);

    if let Some(pid) = check_already_running(pid_file, addr, Duration::from_millis(200)) {
        println!("{}", format_already_running_message(addr, pid));
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
    // Best effort for the URL: a failure there only costs the bare-`aasm status`
    // default, and `--api-url` still works, so it must not fail a start that
    // succeeded. The old URL record is dropped before the PID file changes.
    match super::pidfile::record_gateway(pid_file, pid, &client_url(addr), super::pidfile::write_gateway_url) {
        Err(e) => {
            eprintln!("aasm start: failed to write pid file: {e}");
            return ExitCode::FAILURE;
        }
        Ok(Some(e)) => eprintln!("warning: could not record the gateway address for `aasm status`: {e}"),
        Ok(None) => {}
    }
    let log = spawner.log_path();
    match wait_for_daemon(pid, addr, Duration::from_secs(5), Duration::from_millis(100)) {
        Ok(()) => {
            println!("{}", format_started_banner(args.mode, addr, pid));
            if let Some(log) = &log {
                println!("  Log:     {}", log.display());
            }
            if args.mode == ModeArg::Local {
                let (line, warning) = server_identity(
                    binary_name(args.mode),
                    spawner.binary_path().as_deref(),
                    spawner.server_version(addr).as_deref(),
                    env!("CARGO_PKG_VERSION"),
                );
                println!("{line}");
                if let Some(warning) = warning {
                    eprintln!("{warning}");
                }
            }
            ExitCode::SUCCESS
        }
        Err(failure) => {
            let name = binary_name(args.mode);
            match failure {
                DaemonFailure::Exited => {
                    eprintln!("aasm start: {name} exited before it was ready at {addr}");
                    // Nothing is running: drop the records so `aasm status` does not
                    // follow a dead gateway.
                    let _ = super::pidfile::remove_pid(pid_file);
                }
                DaemonFailure::Timeout => {
                    eprintln!("aasm start: {name} did not become ready at {addr} within 5s");
                }
            }
            if let Some(log) = &log {
                let tail = log_tail(log, 15);
                if tail.is_empty() {
                    eprintln!("  (no output; log: {})", log.display());
                } else {
                    eprintln!("  {name} output (full log: {}):", log.display());
                    for line in tail.lines() {
                        eprintln!("    {line}");
                    }
                }
            }
            ExitCode::FAILURE
        }
    }
}

/// Why a started daemon is not serving.
enum DaemonFailure {
    /// The process exited (a bad key, a busy port, a missing file).
    Exited,
    /// Still running but nothing accepted a connection in time.
    Timeout,
}

/// Wait for `addr` to accept connections, giving up at once if the daemon
/// process `pid` (our child) has already exited so the failure is reported with
/// its output instead of after the full timeout.
fn wait_for_daemon(pid: u32, addr: SocketAddr, timeout: Duration, poll: Duration) -> Result<(), DaemonFailure> {
    let start = std::time::Instant::now();
    loop {
        // Checked first so a stranger already listening on the port cannot
        // make a dead daemon look ready.
        if child_exited(pid) {
            return Err(DaemonFailure::Exited);
        }
        if super::gw_probe::probe_tcp(addr, poll) {
            return Ok(());
        }
        if start.elapsed() >= timeout {
            return Err(DaemonFailure::Timeout);
        }
        std::thread::sleep(poll);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The launched program's file name (the resolver may return a full path).
    fn program_name(cmd: &Command) -> String {
        Path::new(cmd.get_program())
            .file_name()
            .unwrap()
            .to_string_lossy()
            .into_owned()
    }

    #[test]
    fn not_found_error_names_the_binary_where_it_looked_and_the_build_command() {
        let local = not_found_error(ModeArg::Local).to_string();
        assert!(local.contains("`aa-api-server` was not found"), "{local}");
        assert!(local.contains("next to the `aasm` executable"), "{local}");
        assert!(local.contains("$PATH") && local.contains("~/.cargo/bin"), "{local}");
        assert!(local.contains("cargo build -p aa-api --bin aa-api-server"), "{local}");
        let remote = not_found_error(ModeArg::Remote).to_string();
        assert!(
            remote.contains("`aa-gateway`") && remote.contains("cargo build -p aa-gateway"),
            "{remote}"
        );
    }

    #[test]
    fn a_matching_server_version_is_reported_without_a_warning() {
        let (line, warning) = server_identity(
            "aa-api-server",
            Some(Path::new("/opt/aa/bin/aa-api-server")),
            Some("0.0.1-rc.7"),
            "0.0.1-rc.7",
        );
        assert_eq!(
            line,
            "  Server:  aa-api-server 0.0.1-rc.7 from /opt/aa/bin/aa-api-server"
        );
        assert_eq!(warning, None);
    }

    #[test]
    fn a_stale_server_binary_is_named_with_both_versions_and_its_path() {
        let (line, warning) = server_identity(
            "aa-api-server",
            Some(Path::new("/opt/homebrew/bin/aa-api-server")),
            Some("0.0.1-rc.6"),
            "0.0.1-rc.7",
        );
        assert!(
            line.contains("0.0.1-rc.6") && line.contains("/opt/homebrew/bin/aa-api-server"),
            "{line}"
        );
        let warning = warning.expect("a version mismatch must warn");
        assert!(
            warning.contains("0.0.1-rc.6") && warning.contains("0.0.1-rc.7"),
            "{warning}"
        );
        assert!(warning.contains("/opt/homebrew/bin/aa-api-server"), "{warning}");
        assert!(warning.contains("$PATH") && warning.contains("shadow"), "{warning}");
    }

    #[test]
    fn an_unreported_server_version_is_said_so_and_never_warned_as_a_mismatch() {
        let (line, warning) = server_identity("aa-api-server", None, None, "0.0.1-rc.7");
        assert_eq!(
            line,
            "  Server:  aa-api-server (version not reported) from path unknown"
        );
        assert_eq!(warning, None);
    }

    #[test]
    fn redact_keys_hides_a_full_key_and_leaves_prefixes() {
        let full = format!("aa_{}", "0123456789abcdef".repeat(2));
        let text = format!("generated a random admin API key aa_2e8… and {full} too; aa_ alone");
        let out = redact_keys(&text);
        assert!(!out.contains(&full), "{out}");
        assert!(
            out.contains("aa_<redacted>") && out.contains("aa_2e8…") && out.ends_with("aa_ alone"),
            "{out}"
        );
    }

    #[test]
    fn log_tail_keeps_the_last_lines_and_redacts() {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("x.log");
        let body: String = (1..=30).map(|i| format!("line {i}\n")).collect();
        std::fs::write(&p, body).unwrap();
        let t = log_tail(&p, 3);
        assert_eq!(t, "line 28\nline 29\nline 30");
        assert_eq!(log_tail(&tmp.path().join("absent"), 3), "");
    }

    #[test]
    fn local_mode_spawns_aa_api_server_with_bind_env() {
        // AAASM-3382: local mode launches the combined SPA + REST entrypoint and
        // passes the bind address via AA_API_ADDR (the binary reads it from env).
        let addr: SocketAddr = "127.0.0.1:7391".parse().unwrap();
        let cmd = ProcessSpawner::new(ModeArg::Local).command(addr);
        assert_eq!(program_name(&cmd), "aa-api-server");
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
        assert_eq!(program_name(&cmd), "aa-gateway");
        let args: Vec<_> = cmd.get_args().collect();
        assert_eq!(args, vec!["--listen", "0.0.0.0:7391"]);
    }

    #[test]
    fn binary_name_names_launched_binary_per_mode() {
        // AAASM-4450: the spawn/exec failure messages interpolate
        // binary_name(mode), so it must name the binary command() actually
        // launches — otherwise a `--mode local` failure blames aa-gateway.
        let addr: SocketAddr = "127.0.0.1:7391".parse().unwrap();
        assert_eq!(binary_name(ModeArg::Local), "aa-api-server");
        assert_eq!(binary_name(ModeArg::Remote), "aa-gateway");
        assert_eq!(
            program_name(&ProcessSpawner::new(ModeArg::Local).command(addr)),
            binary_name(ModeArg::Local),
        );
        assert_eq!(
            program_name(&ProcessSpawner::new(ModeArg::Remote).command(addr)),
            binary_name(ModeArg::Remote),
        );
    }

    #[test]
    fn resolve_listen_addr_local_binds_loopback() {
        let addr = resolve_listen_addr(ModeArg::Local, None, 7391);
        assert_eq!(addr.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(addr.port(), 7391);
    }

    #[test]
    fn resolve_listen_addr_remote_binds_unspecified() {
        let addr = resolve_listen_addr(ModeArg::Remote, None, 7391);
        assert_eq!(addr.ip(), IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        assert_eq!(addr.port(), 7391);
    }

    // --- --host override (AAASM-6056) ---

    #[test]
    fn resolve_listen_addr_host_override_wins_over_local_default() {
        let addr = resolve_listen_addr(ModeArg::Local, Some(IpAddr::V4(Ipv4Addr::UNSPECIFIED)), 7391);
        assert_eq!(addr.ip(), IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        assert_eq!(addr.port(), 7391);
    }

    #[test]
    fn resolve_listen_addr_host_override_wins_over_remote_default() {
        let addr = resolve_listen_addr(ModeArg::Remote, Some(IpAddr::V4(Ipv4Addr::LOCALHOST)), 7391);
        assert_eq!(addr.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
    }

    #[test]
    fn start_args_host_defaults_to_none() {
        // No --host flag on the command line must not silently pick a
        // non-default bind — the opt-in has to be explicit.
        use clap::Parser;
        #[derive(clap::Parser)]
        struct Wrapper {
            #[command(flatten)]
            args: StartArgs,
        }
        let parsed = Wrapper::parse_from(["aasm-start"]);
        assert!(parsed.args.host.is_none());
    }

    #[test]
    fn format_started_banner_contains_mode_address_and_pid() {
        let addr: SocketAddr = "127.0.0.1:7391".parse().unwrap();
        let banner = format_started_banner(ModeArg::Local, addr, 12_345);
        assert!(banner.contains("✓ Agent Assembly gateway started"));
        assert!(banner.contains("Mode:    local"));
        assert!(banner.contains("Address: http://localhost:7391"));
        assert!(banner.contains("PID:     12345"));
    }

    #[test]
    fn format_started_banner_shows_non_loopback_host_verbatim() {
        // AAASM-6056: an explicit --host must be reflected in the banner,
        // not silently displayed as "localhost".
        let addr: SocketAddr = "0.0.0.0:7391".parse().unwrap();
        let banner = format_started_banner(ModeArg::Local, addr, 12_345);
        assert!(banner.contains("Address: http://0.0.0.0:7391"));
    }

    #[test]
    fn format_already_running_message_matches_story_contract() {
        let addr: SocketAddr = "127.0.0.1:7391".parse().unwrap();
        let msg = format_already_running_message(addr, 12_345);
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
            host: None,
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
        // AAASM-6385: the address it bound is recorded for operator commands.
        let recorded = std::fs::read_to_string(super::super::pidfile::url_file_path(&pid_file)).unwrap();
        assert_eq!(recorded.trim(), format!("http://localhost:{}", addr.port()));
    }

    #[test]
    fn client_url_reaches_an_unspecified_bind_through_localhost() {
        let v4: SocketAddr = "0.0.0.0:9000".parse().unwrap();
        let v6: SocketAddr = "[::]:9000".parse().unwrap();
        let lo: SocketAddr = "127.0.0.1:9000".parse().unwrap();
        let lan: SocketAddr = "192.168.1.5:9000".parse().unwrap();
        assert_eq!(client_url(v4), "http://localhost:9000");
        assert_eq!(client_url(v6), "http://localhost:9000");
        assert_eq!(client_url(lo), "http://localhost:9000");
        assert_eq!(client_url(lan), "http://192.168.1.5:9000");
    }

    #[test]
    fn default_port_is_the_documented_one() {
        assert_eq!(DEFAULT_PORT, 7391);
    }
}
