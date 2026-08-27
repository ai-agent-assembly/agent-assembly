//! `aasm gateway start` — spawn aa-gateway as a detached background process.

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, Instant};

use clap::Args;
#[cfg(unix)]
use std::os::unix::process::CommandExt;

use super::pid;

const DEFAULT_LISTEN: &str = "127.0.0.1:50051";
const READINESS_TIMEOUT: Duration = Duration::from_secs(10);
const READINESS_POLL: Duration = Duration::from_millis(200);

/// What to tell an operator when `aa-gateway` cannot be found.
///
/// A named constant rather than an inline literal so a test can assert that it
/// lists only lookups [`resolve_binary`] actually performs. The two drifted
/// before: the message advertised `./target/release/aa-gateway` for as long as
/// the fallback existed, and an error that names a lookup which no longer
/// happens is worse than terse — here it would have read as an instruction to
/// reinstate the AAASM-5937 vulnerability by hand.
const BINARY_NOT_FOUND_HELP: &str = "error: aa-gateway binary not found.\n\
     Tried: alongside aasm, $PATH, ~/.cargo/bin/aa-gateway\n\
     A path relative to the current directory is deliberately not tried (AAASM-5937);\n\
     install aa-gateway alongside aasm, or put it on $PATH.";

/// Arguments for `aasm gateway start`.
#[derive(Debug, Args)]
pub struct StartArgs {
    /// Path to the policy YAML file, or a directory of scoped `*.yaml`
    /// documents for the multi-document cascade (AAASM-3499). Overrides
    /// $AA_POLICY and the default locations.
    #[arg(long)]
    pub policy: Option<PathBuf>,

    /// TCP listen address (e.g. "127.0.0.1:50051").
    #[arg(long, default_value = DEFAULT_LISTEN)]
    pub listen: String,

    /// Unix domain socket path. When set, takes precedence over --listen.
    #[arg(long)]
    pub socket: Option<PathBuf>,

    /// Block the caller rather than detaching the gateway to the background.
    #[arg(long)]
    pub no_detach: bool,

    /// Log file path for aa-gateway stdout/stderr (default ~/.aasm/logs/gateway.log).
    #[arg(long)]
    pub log_file: Option<PathBuf>,
}

/// Dispatch `aasm gateway start`.
pub fn dispatch(args: StartArgs) -> ExitCode {
    let binary = match resolve_binary() {
        Some(b) => b,
        None => {
            eprintln!("{BINARY_NOT_FOUND_HELP}");
            return ExitCode::FAILURE;
        }
    };

    let policy = match resolve_policy(&args) {
        Some(p) => p,
        None => {
            eprintln!(
                "error: no policy file or directory found.\n\
                 Tried: $AA_POLICY, ~/.aasm/policy.yaml, ~/.aasm/policies/, \
                 /etc/aasm/policy.yaml, /etc/aasm/policies/\n\
                 Use --policy FILE or --policy DIR to specify a path."
            );
            return ExitCode::FAILURE;
        }
    };

    let log_file = resolve_log_file(&args);
    if let Some(parent) = log_file.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            eprintln!("warning: could not create log directory {}: {e}", parent.display());
        }
    }

    let log_fd = match std::fs::OpenOptions::new().create(true).append(true).open(&log_file) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("error: cannot open log file {}: {e}", log_file.display());
            return ExitCode::FAILURE;
        }
    };

    let stderr_fd = log_fd.try_clone().unwrap_or_else(|_| {
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_file)
            .expect("cannot re-open log file")
    });

    // Spawn aa-gateway with explicit args array — no shell involved.
    let mut cmd = std::process::Command::new(&binary);
    cmd.arg("--policy").arg(&policy);

    if let Some(ref socket) = args.socket {
        cmd.arg("--socket").arg(socket);
    } else {
        cmd.arg("--listen").arg(&args.listen);
    }

    cmd.stdin(std::process::Stdio::null()).stdout(log_fd).stderr(stderr_fd);

    if !args.no_detach {
        // setsid so the child survives shell exit (POSIX only).
        #[cfg(unix)]
        unsafe {
            cmd.pre_exec(|| {
                libc::setsid();
                Ok(())
            });
        }
    }

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: failed to spawn {}: {e}", binary.display());
            return ExitCode::FAILURE;
        }
    };

    let gateway_pid = child.id();
    let listen_display = args
        .socket
        .as_ref()
        .map_or(args.listen.clone(), |s| format!("unix:{}", s.display()));

    let now = chrono::Utc::now().to_rfc3339();
    if let Err(e) = pid::write_pid(gateway_pid, &listen_display, &now) {
        eprintln!("warning: could not write PID file: {e}");
    }

    // Readiness probe: poll TCP while confirming the spawned child is the
    // one that became ready (AAASM-5832 — a bare TCP connect cannot tell
    // "my child bound this" from "something else already was").
    if args.socket.is_none() {
        let addr = args.listen.clone();
        match wait_for_child_ready(&mut child, &addr, READINESS_TIMEOUT) {
            ReadinessOutcome::Ready => {}
            ReadinessOutcome::ChildExited => {
                eprintln!(
                    "error: aa-gateway (pid {gateway_pid}) exited before becoming ready — it did not bind {addr}"
                );
                eprintln!("       Check logs at {}", log_file.display());
                let _ = pid::remove_pid();
                return ExitCode::FAILURE;
            }
            ReadinessOutcome::Timeout => {
                eprintln!("error: gateway did not become ready within 10s on {addr}");
                eprintln!("       Check logs at {}", log_file.display());
                let _ = pid::remove_pid();
                return ExitCode::FAILURE;
            }
        }
    }

    println!("Gateway started on grpc://{listen_display}  (pid {gateway_pid})");
    println!("Logs: {}", log_file.display());
    ExitCode::SUCCESS
}

/// Resolve the `aa-gateway` binary path.
///
/// Search order: directory of the running `aasm` executable →
/// directories in `$PATH` → `~/.cargo/bin/aa-gateway`. Every candidate is an
/// absolute location derived from the *installation*, never from where the
/// process happens to have been started.
///
/// The exe-dir lookup is first so a release / Homebrew install — where
/// `aa-gateway` ships alongside `aasm` in the same directory (AAASM-2975) —
/// works even when that directory is not on `$PATH` (e.g. a tarball unpacked
/// to an arbitrary location). It is also what ADR 0030 §6.4 requires: `aasm`
/// and its children ship as one versioned unit, so a `$PATH` hit from some
/// other installation must not win over the sibling that was shipped with
/// this one.
///
/// # Why there is no `./target/...` fallback
///
/// This function used to end with `./target/release/aa-gateway` →
/// `./target/debug/aa-gateway`, which is the exact pattern AAASM-4020 removed
/// from the `aa-proxy` launcher on security grounds and which AAASM-5937
/// removed here. Resolving relative to the current working directory lets
/// whoever controls where `aasm` is invoked substitute an attacker-planted
/// `aa-gateway`, and `./target/` is the conventional Rust build output path, so
/// a planted file there looks unremarkable.
///
/// The population it exposed is the one least able to notice: the fallback is
/// only reached when `aa-gateway` is absent from the exe directory, `$PATH`
/// *and* `~/.cargo/bin`, which is precisely the state of a `cargo build`-only
/// checkout — a developer or CI job sitting in a repository root.
///
/// Nothing legitimate is lost. A `cargo build` puts `aasm` and `aa-gateway`
/// side by side in the same `target/<profile>/` directory, so the sibling
/// lookup above already finds it, and finds *the matching build* rather than
/// whichever `target/` the cwd happened to contain. The only case the fallback
/// uniquely served was an *installed* `aasm` picking a `target/` gateway out of
/// an unrelated repository, which is a version-mismatch hazard as much as a
/// substitution one.
pub fn resolve_binary() -> Option<PathBuf> {
    resolve_from(
        std::env::current_exe().ok().as_deref(),
        std::env::var("PATH").ok().as_deref(),
        dirs::home_dir().as_deref(),
    )
}

/// The search itself, over the three facts [`resolve_binary`] reads from the
/// environment.
///
/// Split out so the search order and the absence of a cwd-relative fallback can
/// both be asserted without mutating process-global state: a test names the exe
/// path, the `$PATH` string and the home directory it wants, and this function
/// has no other input. That is also the structural half of AAASM-5937 — a
/// function that is not given the current directory cannot resolve against it,
/// so the removed fallback cannot come back by accident. The behavioural half is
/// still pinned by a test that plants a binary under a temporary cwd.
///
/// # Why `$PATH` entries are filtered
///
/// Deleting the `./target/...` fallback is not on its own enough to make the
/// claim above true, because `$PATH` is a second door into the same room.
/// POSIX defines a **zero-length** `$PATH` entry as the current working
/// directory, so `PATH=":/usr/bin"`, `PATH="/usr/bin:"` and `PATH="/a::/b"` each
/// contribute one candidate that `PathBuf::join` renders as the bare relative
/// path `aa-gateway` — and `is_executable` resolves that against the cwd. A
/// non-empty but relative entry (`PATH="target/debug"`) does the same. Either
/// one reinstates exactly the attacker-substitution primitive AAASM-5937
/// removes, and an empty entry is not even malformed: it is a documented, if
/// discouraged, way to put `.` on `$PATH`, so it occurs on real hosts by
/// accident — a trailing `:` from a shell profile appending `$PATH` to an unset
/// variable is the usual origin.
///
/// So a candidate directory is used only if it is absolute. Non-absolute entries
/// are skipped, not rejected: an operator with a stray `:` in `$PATH` keeps every
/// other entry they wrote, and the only lookup they lose is the one that could
/// never have been safe.
fn resolve_from(exe: Option<&Path>, path_var: Option<&str>, home: Option<&Path>) -> Option<PathBuf> {
    if let Some(candidate) = exe.and_then(sibling_binary) {
        return Some(candidate);
    }
    if let Some(path_var) = path_var {
        for dir in path_var.split(':').map(Path::new).filter(|d| d.is_absolute()) {
            let candidate = dir.join("aa-gateway");
            if is_executable(&candidate) {
                return Some(candidate);
            }
        }
    }
    if let Some(home) = home {
        let candidate = home.join(".cargo").join("bin").join("aa-gateway");
        if is_executable(&candidate) {
            return Some(candidate);
        }
    }
    None
}

/// Return the `aa-gateway` binary sitting next to the given `aasm` executable
/// path, if it exists and is executable.
fn sibling_binary(exe: &std::path::Path) -> Option<PathBuf> {
    let candidate = exe.parent()?.join("aa-gateway");
    is_executable(&candidate).then_some(candidate)
}

#[cfg(unix)]
fn is_executable(path: &std::path::Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    path.metadata().is_ok_and(|m| m.permissions().mode() & 0o111 != 0)
}

#[cfg(not(unix))]
fn is_executable(path: &std::path::Path) -> bool {
    path.exists()
}

/// Resolve the policy path — a single file or a cascade directory.
///
/// Resolution order: `--policy` flag → `$AA_POLICY` → `~/.aasm/policy.yaml` →
/// `~/.aasm/policies/` → `/etc/aasm/policy.yaml` → `/etc/aasm/policies/`.
///
/// AAASM-3499 — the `--policy` flag and `$AA_POLICY` accept either a file or a
/// directory (forwarded verbatim to `aa-gateway --policy`, which routes a
/// directory to the multi-document cascade loader). The default `policies/`
/// directory locations let an operator drop scoped `*.yaml` documents into a
/// well-known path without any flag.
pub fn resolve_policy(args: &StartArgs) -> Option<PathBuf> {
    if let Some(ref p) = args.policy {
        return Some(p.clone());
    }
    if let Ok(env_path) = std::env::var("AA_POLICY") {
        if !env_path.is_empty() {
            let p = PathBuf::from(&env_path);
            if p.exists() {
                return Some(p);
            }
        }
    }
    if let Some(home) = dirs::home_dir() {
        let file = home.join(".aasm").join("policy.yaml");
        if file.exists() {
            return Some(file);
        }
        let dir = home.join(".aasm").join("policies");
        if dir.is_dir() {
            return Some(dir);
        }
    }
    let system_file = PathBuf::from("/etc/aasm/policy.yaml");
    if system_file.exists() {
        return Some(system_file);
    }
    let system_dir = PathBuf::from("/etc/aasm/policies");
    if system_dir.is_dir() {
        return Some(system_dir);
    }
    None
}

/// Resolve the log file path (--log-file flag or ~/.aasm/logs/gateway.log).
fn resolve_log_file(args: &StartArgs) -> PathBuf {
    if let Some(ref p) = args.log_file {
        return p.clone();
    }
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".aasm")
        .join("logs")
        .join("gateway.log")
}

/// Poll `addr` (TCP connect) until it accepts a connection or `timeout` elapses.
///
/// Uses `connect_timeout` with `READINESS_POLL` as the per-attempt bound so
/// filtered ports (no immediate ECONNREFUSED) cannot block longer than one
/// poll interval — critical for test determinism on Linux CI.
pub fn wait_for_tcp(addr: &str, timeout: Duration) -> bool {
    let Ok(socket_addr) = addr.parse() else {
        return false;
    };
    let deadline = Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return false;
        }
        if std::net::TcpStream::connect_timeout(&socket_addr, remaining.min(READINESS_POLL)).is_ok() {
            return true;
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return false;
        }
        std::thread::sleep(remaining.min(READINESS_POLL));
    }
}

/// Outcome of `wait_for_child_ready`.
#[derive(Debug, PartialEq, Eq)]
enum ReadinessOutcome {
    Ready,
    ChildExited,
    Timeout,
}

/// Poll `addr` for a TCP connection while confirming the spawned `child` is
/// still alive. A bare TCP connect (`wait_for_tcp`) cannot distinguish "my
/// child is now listening" from "someone else already was" — checking child
/// liveness at each poll, and again after a real `READINESS_POLL` grace
/// window both before the first check and before declaring success, closes
/// that gap: a same-tick check fires before the child has even been
/// scheduled, so only elapsed wall-clock time gives it a real chance to hit
/// its own bind()/panic path (e.g. AddrInUse) before a connect is trusted
/// (AAASM-5832).
fn wait_for_child_ready(child: &mut std::process::Child, addr: &str, timeout: Duration) -> ReadinessOutcome {
    let Ok(socket_addr) = addr.parse() else {
        return ReadinessOutcome::Timeout;
    };
    let deadline = Instant::now() + timeout;

    // Give the child a real chance to reach its own bind()/panic path
    // before trusting anything — a same-tick check right after spawn()
    // fires before the child has even been scheduled, so it can never
    // observe an AddrInUse crash that hasn't happened yet (AAASM-5832
    // review finding).
    std::thread::sleep(READINESS_POLL.min(timeout));

    loop {
        match child.try_wait() {
            Ok(Some(_status)) => return ReadinessOutcome::ChildExited,
            Ok(None) => {}
            // Can no longer observe the child's state — never fabricate success.
            Err(_) => return ReadinessOutcome::ChildExited,
        }

        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return ReadinessOutcome::Timeout;
        }
        if std::net::TcpStream::connect_timeout(&socket_addr, remaining.min(READINESS_POLL)).is_ok() {
            // Don't trust an immediate re-check — give the child one more
            // full poll interval of real elapsed time before confirming it
            // is still the one alive and bound, closing the TOCTOU window.
            let remaining = deadline.saturating_duration_since(Instant::now());
            std::thread::sleep(remaining.min(READINESS_POLL));
            return if matches!(child.try_wait(), Ok(None)) {
                ReadinessOutcome::Ready
            } else {
                ReadinessOutcome::ChildExited
            };
        }

        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return ReadinessOutcome::Timeout;
        }
        std::thread::sleep(remaining.min(READINESS_POLL));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::MutexGuard;

    struct PolicyEnvGuard {
        _lock: MutexGuard<'static, ()>,
        prior: Option<String>,
    }
    impl PolicyEnvGuard {
        fn set(value: &str) -> Self {
            let lock = crate::test_support::env_guard();
            let prior = std::env::var("AA_POLICY").ok();
            std::env::set_var("AA_POLICY", value);
            Self { _lock: lock, prior }
        }
    }
    impl Drop for PolicyEnvGuard {
        fn drop(&mut self) {
            match self.prior.take() {
                Some(v) => std::env::set_var("AA_POLICY", v),
                None => std::env::remove_var("AA_POLICY"),
            }
        }
    }

    #[test]
    fn resolve_policy_uses_flag_when_provided() {
        let args = StartArgs {
            policy: Some(PathBuf::from("/tmp/policy.yaml")),
            listen: DEFAULT_LISTEN.to_string(),
            socket: None,
            no_detach: false,
            log_file: None,
        };
        assert_eq!(resolve_policy(&args), Some(PathBuf::from("/tmp/policy.yaml")));
    }

    /// AAASM-3499 — `--policy` must accept a cascade *directory*, forwarded
    /// verbatim to `aa-gateway --policy` (which routes a directory to the
    /// multi-document cascade loader). Before the fix the dir was usable from
    /// Rust test code only; the operator path rejected it.
    #[test]
    fn resolve_policy_accepts_directory_via_flag() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().to_path_buf();
        let args = StartArgs {
            policy: Some(dir.clone()),
            listen: DEFAULT_LISTEN.to_string(),
            socket: None,
            no_detach: false,
            log_file: None,
        };
        let resolved = resolve_policy(&args).expect("a directory must resolve");
        assert_eq!(resolved, dir);
        assert!(resolved.is_dir(), "the resolved policy path is a directory");
    }

    /// `$AA_POLICY` pointing at a directory resolves too (the env-var path uses
    /// `.exists()`, which is true for directories).
    #[test]
    fn resolve_policy_accepts_directory_via_env() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().to_path_buf();
        let _guard = PolicyEnvGuard::set(dir.to_str().unwrap());

        let args = StartArgs {
            policy: None,
            listen: DEFAULT_LISTEN.to_string(),
            socket: None,
            no_detach: false,
            log_file: None,
        };
        assert_eq!(resolve_policy(&args), Some(dir));
    }

    #[test]
    fn resolve_policy_uses_env_when_no_flag_and_file_exists() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let path = tmp.path().to_path_buf();
        let _guard = PolicyEnvGuard::set(path.to_str().unwrap());

        let args = StartArgs {
            policy: None,
            listen: DEFAULT_LISTEN.to_string(),
            socket: None,
            no_detach: false,
            log_file: None,
        };
        let result = resolve_policy(&args);
        assert_eq!(result, Some(path));
    }

    #[test]
    fn resolve_policy_skips_env_when_path_does_not_exist() {
        let _guard = PolicyEnvGuard::set("/nonexistent/path/policy.yaml");

        let args = StartArgs {
            policy: None,
            listen: DEFAULT_LISTEN.to_string(),
            socket: None,
            no_detach: false,
            log_file: None,
        };
        let result = resolve_policy(&args);

        // Falls through to home/system paths; only None if those also don't exist.
        let has_default = dirs::home_dir().is_some_and(|h| h.join(".aasm").join("policy.yaml").exists())
            || PathBuf::from("/etc/aasm/policy.yaml").exists();
        if !has_default {
            assert!(result.is_none());
        }
    }

    #[test]
    fn wait_for_tcp_returns_false_on_closed_port() {
        assert!(!wait_for_tcp("127.0.0.1:1", Duration::from_millis(300)));
    }

    #[test]
    fn wait_for_tcp_returns_true_when_port_is_open() {
        use std::net::TcpListener;
        let _net = crate::test_support::net_guard();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let addr = format!("127.0.0.1:{port}");
        assert!(wait_for_tcp(&addr, Duration::from_secs(1)));
    }

    #[test]
    fn wait_for_child_ready_reports_child_exited_even_when_port_already_has_a_listener() {
        use std::net::TcpListener;
        let _net = crate::test_support::net_guard();
        // Something else is already listening on this port (the collision that
        // causes AddrInUse for our spawned child in the real scenario).
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let addr = format!("127.0.0.1:{port}");

        // Our "spawned child" exits almost immediately, as aa-gateway does on
        // AddrInUse.
        let mut child = std::process::Command::new("true")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("failed to spawn 'true'");

        let outcome = wait_for_child_ready(&mut child, &addr, Duration::from_secs(2));
        assert_eq!(outcome, ReadinessOutcome::ChildExited);
        drop(listener);
    }

    #[test]
    fn wait_for_child_ready_returns_ready_when_child_alive_and_port_open() {
        use std::net::TcpListener;
        let _net = crate::test_support::net_guard();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let addr = format!("127.0.0.1:{port}");

        // A long-lived "child" that does not exit during the poll window.
        let mut child = std::process::Command::new("sleep")
            .arg("5")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("failed to spawn 'sleep'");

        let outcome = wait_for_child_ready(&mut child, &addr, Duration::from_secs(2));
        assert_eq!(outcome, ReadinessOutcome::Ready);
        let _ = child.kill();
        let _ = child.wait();
        drop(listener);
    }

    /// Create an executable file at `path` (sets the user-exec bit on Unix).
    fn touch_executable(path: &std::path::Path) {
        std::fs::write(path, b"#!/bin/sh\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(path).unwrap().permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(path, perms).unwrap();
        }
    }

    #[test]
    fn sibling_binary_resolves_aa_gateway_next_to_exe() {
        let dir = tempfile::tempdir().unwrap();
        let exe = dir.path().join("aasm");
        touch_executable(&exe);
        let gateway = dir.path().join("aa-gateway");
        touch_executable(&gateway);

        assert_eq!(sibling_binary(&exe), Some(gateway));
    }

    #[test]
    fn sibling_binary_returns_none_when_gateway_absent() {
        let dir = tempfile::tempdir().unwrap();
        let exe = dir.path().join("aasm");
        touch_executable(&exe);
        // No aa-gateway alongside it.
        assert_eq!(sibling_binary(&exe), None);
    }

    #[cfg(unix)]
    #[test]
    fn sibling_binary_returns_none_when_gateway_not_executable() {
        let dir = tempfile::tempdir().unwrap();
        let exe = dir.path().join("aasm");
        touch_executable(&exe);
        // A non-executable file named aa-gateway must not be selected.
        std::fs::write(dir.path().join("aa-gateway"), b"not a binary").unwrap();
        assert_eq!(sibling_binary(&exe), None);
    }

    // ── AAASM-5937: no cwd-relative resolution ────────────────────────────

    /// An `aa-gateway` planted under the current directory must never be
    /// selected (AAASM-5937).
    ///
    /// This is the negative control for the removed
    /// `./target/{release,debug}/aa-gateway` fallback, and it is written as an
    /// end-to-end statement of the property rather than an assertion about the
    /// code's shape: it plants an executable at exactly the two paths the old
    /// implementation used, relative to a temporary cwd, with all three trusted
    /// lookups deliberately empty — the state the old fallback existed to
    /// serve — and requires `None`.
    ///
    /// Verified to fail against the previous implementation rather than assumed
    /// to: restoring the deleted `for rel in &["./target/release/aa-gateway",
    /// ...]` loop in `resolve_from` reddens this test with the planted
    /// `./target/release/aa-gateway`, and reddens nothing else in this module.
    ///
    /// `resolve_from` is called rather than `resolve_binary` so the exe path,
    /// `$PATH` and home directory are all named by the test. `resolve_binary`'s
    /// own exe path is `target/debug/deps/…`, whose sibling set is a build
    /// artefact this test must not depend on.
    #[cfg(unix)]
    #[test]
    fn resolve_from_ignores_a_gateway_planted_under_the_current_directory() {
        // Serialized against the other cwd/env-sensitive tests in this crate:
        // `set_current_dir` is process-global.
        let _lock = crate::test_support::env_guard();

        let cwd = tempfile::tempdir().unwrap();
        for profile in ["release", "debug"] {
            let dir = cwd.path().join("target").join(profile);
            std::fs::create_dir_all(&dir).unwrap();
            touch_executable(&dir.join("aa-gateway"));
        }

        // Empty, not absent: an empty `$PATH` and a home directory with no
        // `.cargo/bin` are the "three trusted lookups all miss" state.
        let empty_home = tempfile::tempdir().unwrap();
        let exe_dir = tempfile::tempdir().unwrap();
        let exe = exe_dir.path().join("aasm");
        touch_executable(&exe);

        let prior_cwd = std::env::current_dir().unwrap();
        std::env::set_current_dir(cwd.path()).unwrap();
        let resolved = resolve_from(Some(&exe), Some(""), Some(empty_home.path()));
        // Restored before asserting, so a failure does not leave every later
        // test in this binary running from a deleted temporary directory.
        std::env::set_current_dir(&prior_cwd).unwrap();

        assert_eq!(
            resolved, None,
            "resolved a gateway relative to the current directory — the AAASM-5937 fallback is back"
        );
    }

    /// The surviving search order is exe-dir → `$PATH` → `~/.cargo/bin`, and
    /// the exe-dir hit must win (ADR 0030 §6.4).
    ///
    /// Pinned because the ordering is the security property, not a preference:
    /// `aasm` and its children ship as one versioned unit, so a `$PATH` entry
    /// belonging to some other installation must not shadow the sibling that
    /// was shipped with this `aasm`. A refactor that reorders these three
    /// lookups is a silent downgrade, and this test is what makes it loud.
    #[cfg(unix)]
    #[test]
    fn resolve_from_prefers_the_exe_sibling_over_path_and_cargo_bin() {
        let exe_dir = tempfile::tempdir().unwrap();
        let path_dir = tempfile::tempdir().unwrap();
        let home = tempfile::tempdir().unwrap();

        let exe = exe_dir.path().join("aasm");
        touch_executable(&exe);
        let sibling = exe_dir.path().join("aa-gateway");
        touch_executable(&sibling);
        touch_executable(&path_dir.path().join("aa-gateway"));
        let cargo_bin = home.path().join(".cargo").join("bin");
        std::fs::create_dir_all(&cargo_bin).unwrap();
        touch_executable(&cargo_bin.join("aa-gateway"));

        // All three present: the sibling wins.
        assert_eq!(
            resolve_from(Some(&exe), Some(path_dir.path().to_str().unwrap()), Some(home.path())),
            Some(sibling)
        );

        // Sibling absent: `$PATH` wins over `~/.cargo/bin`.
        let bare_exe_dir = tempfile::tempdir().unwrap();
        let bare_exe = bare_exe_dir.path().join("aasm");
        touch_executable(&bare_exe);
        assert_eq!(
            resolve_from(
                Some(&bare_exe),
                Some(path_dir.path().to_str().unwrap()),
                Some(home.path())
            ),
            Some(path_dir.path().join("aa-gateway"))
        );

        // Sibling and `$PATH` absent: `~/.cargo/bin` is the last resort.
        assert_eq!(
            resolve_from(Some(&bare_exe), Some(""), Some(home.path())),
            Some(cargo_bin.join("aa-gateway"))
        );

        // Nothing anywhere: `None`, and no fourth lookup behind it.
        let empty_home = tempfile::tempdir().unwrap();
        assert_eq!(resolve_from(Some(&bare_exe), Some(""), Some(empty_home.path())), None);
    }

    /// The remediation message must name only lookups that still exist — an
    /// error telling an operator to check `./target/release/aa-gateway` would
    /// send them to reinstate the vulnerability by hand.
    #[test]
    fn binary_not_found_message_lists_only_the_lookups_that_still_happen() {
        assert!(
            !BINARY_NOT_FOUND_HELP.contains("./target/"),
            "the not-found remediation still points at a cwd-relative path:\n{BINARY_NOT_FOUND_HELP}"
        );
        for lookup in ["alongside aasm", "$PATH", "~/.cargo/bin/aa-gateway"] {
            assert!(
                BINARY_NOT_FOUND_HELP.contains(lookup),
                "remediation omits the {lookup} lookup, which resolve_binary does perform"
            );
        }
    }
}
