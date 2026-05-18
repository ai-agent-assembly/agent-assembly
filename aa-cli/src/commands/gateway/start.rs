//! `aasm gateway start` — spawn aa-gateway as a detached background process.

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use clap::Args;
#[cfg(unix)]
use std::os::unix::process::CommandExt;

use super::pid;

const DEFAULT_LISTEN: &str = "127.0.0.1:50051";
const READINESS_TIMEOUT: Duration = Duration::from_secs(10);
const READINESS_POLL: Duration = Duration::from_millis(200);

/// Arguments for `aasm gateway start`.
#[derive(Debug, Args)]
pub struct StartArgs {
    /// Path to the policy YAML file (overrides $AA_POLICY and default locations).
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
            eprintln!(
                "error: aa-gateway binary not found.\n\
                 Tried: $PATH, ~/.cargo/bin/aa-gateway, ./target/release/aa-gateway, ./target/debug/aa-gateway"
            );
            return ExitCode::FAILURE;
        }
    };

    let policy = match resolve_policy(&args) {
        Some(p) => p,
        None => {
            eprintln!(
                "error: no policy file found.\n\
                 Tried: $AA_POLICY, ~/.aasm/policy.yaml, /etc/aasm/policy.yaml\n\
                 Use --policy FILE to specify a path."
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

    let child = match cmd.spawn() {
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

    // Readiness probe: poll TCP until the gateway accepts connections.
    if args.socket.is_none() {
        let addr = args.listen.clone();
        if !wait_for_tcp(&addr, READINESS_TIMEOUT) {
            eprintln!("error: gateway did not become ready within 10s on {addr}");
            eprintln!("       Check logs at {}", log_file.display());
            let _ = pid::remove_pid();
            return ExitCode::FAILURE;
        }
    }

    println!("Gateway started on grpc://{listen_display}  (pid {gateway_pid})");
    println!("Logs: {}", log_file.display());
    ExitCode::SUCCESS
}

/// Resolve the `aa-gateway` binary path.
///
/// Search order: directories in `$PATH` → `~/.cargo/bin/aa-gateway` →
/// `./target/release/aa-gateway` → `./target/debug/aa-gateway`.
pub fn resolve_binary() -> Option<PathBuf> {
    if let Ok(path_var) = std::env::var("PATH") {
        for dir in path_var.split(':') {
            let candidate = PathBuf::from(dir).join("aa-gateway");
            if is_executable(&candidate) {
                return Some(candidate);
            }
        }
    }
    if let Some(home) = dirs::home_dir() {
        let candidate = home.join(".cargo").join("bin").join("aa-gateway");
        if is_executable(&candidate) {
            return Some(candidate);
        }
    }
    for rel in &["./target/release/aa-gateway", "./target/debug/aa-gateway"] {
        let candidate = PathBuf::from(rel);
        if is_executable(&candidate) {
            return Some(candidate);
        }
    }
    None
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

/// Resolve the policy file path.
///
/// Resolution order: `--policy` flag → `$AA_POLICY` → `~/.aasm/policy.yaml` →
/// `/etc/aasm/policy.yaml`.
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
        let p = home.join(".aasm").join("policy.yaml");
        if p.exists() {
            return Some(p);
        }
    }
    let system = PathBuf::from("/etc/aasm/policy.yaml");
    if system.exists() {
        return Some(system);
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
pub fn wait_for_tcp(addr: &str, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if std::net::TcpStream::connect(addr).is_ok() {
            return true;
        }
        std::thread::sleep(READINESS_POLL);
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn resolve_policy_uses_env_when_no_flag_and_file_exists() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let path = tmp.path().to_path_buf();

        let prior = std::env::var("AA_POLICY").ok();
        std::env::set_var("AA_POLICY", &path);

        let args = StartArgs {
            policy: None,
            listen: DEFAULT_LISTEN.to_string(),
            socket: None,
            no_detach: false,
            log_file: None,
        };
        let result = resolve_policy(&args);

        match prior {
            Some(v) => std::env::set_var("AA_POLICY", v),
            None => std::env::remove_var("AA_POLICY"),
        }

        assert_eq!(result, Some(path));
    }

    #[test]
    fn resolve_policy_skips_env_when_path_does_not_exist() {
        let prior = std::env::var("AA_POLICY").ok();
        std::env::set_var("AA_POLICY", "/nonexistent/path/policy.yaml");

        let args = StartArgs {
            policy: None,
            listen: DEFAULT_LISTEN.to_string(),
            socket: None,
            no_detach: false,
            log_file: None,
        };
        let result = resolve_policy(&args);

        match prior {
            Some(v) => std::env::set_var("AA_POLICY", v),
            None => std::env::remove_var("AA_POLICY"),
        }

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
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let addr = format!("127.0.0.1:{port}");
        assert!(wait_for_tcp(&addr, Duration::from_secs(1)));
    }
}
