//! `aasm proxy start` — spawn the aa-proxy sidecar as a background process.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::{ExitCode, Stdio};
use std::time::{Duration, Instant};

use clap::Args;

use super::pid;

/// Arguments for `aasm proxy start`.
#[derive(Debug, Args)]
pub struct StartArgs {
    /// Address the proxy should listen on.
    #[arg(long, default_value = "127.0.0.1:8899", env = "AA_PROXY_ADDR")]
    pub listen: String,
    /// Gateway URL to forward policy decisions to.
    #[arg(long, env = "AA_GATEWAY_URL")]
    pub gateway: Option<String>,
    /// Directory for CA certificate and key storage.
    #[arg(long, env = "AA_CA_DIR")]
    pub ca_dir: Option<PathBuf>,
    /// Run in the foreground instead of daemonizing.
    #[arg(long)]
    pub no_detach: bool,
    /// File to redirect proxy stdout/stderr to (background mode only).
    #[arg(long)]
    pub log_file: Option<PathBuf>,
}

fn default_log_path() -> PathBuf {
    dirs::data_local_dir()
        .expect("cannot determine local data directory")
        .join("aasm")
        .join("logs")
        .join("proxy.log")
}

/// Resolve the aa-proxy binary by trying, in order:
/// 1. `which aa-proxy` (checks PATH)
/// 2. `~/.cargo/bin/aa-proxy`
///
/// The former `./target/release/aa-proxy` cwd-relative fallback was dropped
/// (AAASM-4020): resolving a binary relative to the current working directory
/// lets whoever controls where `aasm` is invoked substitute an attacker-planted
/// `aa-proxy`. Only trusted, absolute locations (PATH, the cargo bin dir) are
/// honored.
pub fn resolve_binary() -> Option<PathBuf> {
    #[cfg(unix)]
    {
        if let Ok(out) = std::process::Command::new("which").arg("aa-proxy").output() {
            if out.status.success() {
                let p = PathBuf::from(String::from_utf8_lossy(&out.stdout).trim().to_string());
                if p.exists() {
                    return Some(p);
                }
            }
        }
    }

    if let Some(home) = dirs::home_dir() {
        let cargo_bin = home.join(".cargo").join("bin").join("aa-proxy");
        if cargo_bin.exists() {
            return Some(cargo_bin);
        }
    }

    None
}

/// Build the environment overrides applied to the spawned `aa-proxy` child.
///
/// AAASM-4127: the proxy reads its gateway endpoint from
/// `AA_PROXY_GATEWAY_ENDPOINT` — **not** `AA_GATEWAY_URL`, which it ignores — and
/// only performs MCP `tools/call` enforcement when that endpoint is set. A prior
/// version exported `AA_GATEWAY_URL`, so `aasm proxy start --gateway <url>` left
/// `gateway_endpoint = None` → raw passthrough with MCP enforcement silently OFF.
///
/// When a gateway is configured we also force `AA_PROXY_LLM_ONLY=false` so
/// non-LLM MCP hosts are intercepted and routed to the gateway's PolicyService
/// rather than transparently tunnelled before enforcement can run.
fn proxy_child_env(listen: &str, gateway: Option<&str>) -> Vec<(&'static str, String)> {
    let mut env = vec![("AA_PROXY_ADDR", listen.to_string())];
    if let Some(gw) = gateway {
        env.push(("AA_PROXY_GATEWAY_ENDPOINT", gw.to_string()));
        env.push(("AA_PROXY_LLM_ONLY", "false".to_string()));
    }
    env
}

/// Poll TCP connect on `addr` until the socket accepts or `timeout` elapses.
fn wait_for_port(addr: &str, timeout: Duration) -> bool {
    let Ok(sock_addr) = addr.parse::<SocketAddr>() else {
        return false;
    };
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if std::net::TcpStream::connect_timeout(&sock_addr, Duration::from_millis(100)).is_ok() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    false
}

/// Write the child process's PID and listen address to the shared PID file.
fn write_child_pid(child_pid: u32, listen_addr: &str) -> std::io::Result<()> {
    let path = pid::pid_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let content = format!("{}\n{}\n", child_pid, listen_addr);
    std::fs::write(&path, content)
}

pub fn dispatch(args: StartArgs) -> ExitCode {
    let Some(binary) = resolve_binary() else {
        eprintln!(
            "error: aa-proxy binary not found.\n\
             Install with `cargo install aa-proxy` or ensure it is on PATH \
             or in ~/.cargo/bin."
        );
        return ExitCode::FAILURE;
    };

    let mut cmd = std::process::Command::new(&binary);
    for (key, value) in proxy_child_env(&args.listen, args.gateway.as_deref()) {
        cmd.env(key, value);
    }
    if let Some(ref ca_dir) = args.ca_dir {
        cmd.env("AA_CA_DIR", ca_dir);
    }

    if args.no_detach {
        // Foreground: inherit stdio, block until the process exits.
        return match cmd.status() {
            Ok(s) if s.success() => ExitCode::SUCCESS,
            Ok(_) => ExitCode::FAILURE,
            Err(e) => {
                eprintln!("error: failed to run aa-proxy: {e}");
                ExitCode::FAILURE
            }
        };
    }

    // Background: redirect stdout/stderr to the log file.
    let log_file = args.log_file.unwrap_or_else(default_log_path);
    if let Some(parent) = log_file.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            eprintln!("warning: could not create log directory {}: {e}", parent.display());
        }
    }

    let log_out = match std::fs::OpenOptions::new().create(true).append(true).open(&log_file) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("error: could not open log file {}: {e}", log_file.display());
            return ExitCode::FAILURE;
        }
    };
    let log_err = match log_out.try_clone() {
        Ok(f) => f,
        Err(e) => {
            eprintln!("error: could not duplicate log file handle: {e}");
            return ExitCode::FAILURE;
        }
    };

    cmd.stdout(Stdio::from(log_out))
        .stderr(Stdio::from(log_err))
        .stdin(Stdio::null());

    // Create a new process group so the child isn't killed by the parent's SIGHUP.
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0);
    }

    let child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: failed to spawn aa-proxy from {}: {e}", binary.display());
            return ExitCode::FAILURE;
        }
    };

    let child_pid = child.id();

    if let Err(e) = write_child_pid(child_pid, &args.listen) {
        eprintln!("warning: could not write PID file: {e}");
    }

    println!("Starting aa-proxy on {} (PID {child_pid})...", args.listen);

    if wait_for_port(&args.listen, Duration::from_secs(5)) {
        println!("Proxy started on http://{}", args.listen);
        println!("Logs: {}", log_file.display());
        ExitCode::SUCCESS
    } else {
        eprintln!(
            "error: aa-proxy did not bind to {} within 5s.\nCheck logs: {}",
            args.listen,
            log_file.display()
        );
        let _ = pid::remove_pid();
        ExitCode::FAILURE
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Parser)]
    struct Wrapper {
        #[command(flatten)]
        inner: StartArgs,
    }

    #[test]
    fn start_args_default_listen_address() {
        let w = Wrapper::parse_from(["test"]);
        assert_eq!(w.inner.listen, "127.0.0.1:8899");
    }

    #[test]
    fn start_args_custom_listen_address() {
        let w = Wrapper::parse_from(["test", "--listen", "0.0.0.0:9000"]);
        assert_eq!(w.inner.listen, "0.0.0.0:9000");
    }

    #[test]
    fn start_args_gateway_is_optional() {
        let w = Wrapper::parse_from(["test"]);
        assert!(w.inner.gateway.is_none());
    }

    #[test]
    fn start_args_no_detach_defaults_false() {
        let w = Wrapper::parse_from(["test"]);
        assert!(!w.inner.no_detach);
    }

    #[test]
    fn start_args_no_detach_flag() {
        let w = Wrapper::parse_from(["test", "--no-detach"]);
        assert!(w.inner.no_detach);
    }

    #[test]
    fn proxy_child_env_gateway_uses_proxy_endpoint_var() {
        // AAASM-4127 regression guard: aa-proxy reads AA_PROXY_GATEWAY_ENDPOINT,
        // so `--gateway <url>` must export that exact name. A prior bug exported
        // AA_GATEWAY_URL (which aa-proxy ignores), leaving gateway_endpoint None
        // → raw passthrough with MCP enforcement silently OFF.
        let env = proxy_child_env("127.0.0.1:8899", Some("http://127.0.0.1:50051"));
        assert!(
            env.contains(&("AA_PROXY_GATEWAY_ENDPOINT", "http://127.0.0.1:50051".to_string())),
            "gateway must be exported as AA_PROXY_GATEWAY_ENDPOINT, got: {env:?}"
        );
        // llm_only disabled so non-LLM MCP hosts reach the gateway routing
        // instead of being transparently tunnelled before enforcement.
        assert!(env.contains(&("AA_PROXY_LLM_ONLY", "false".to_string())));
        // The old, ignored variable name must never be exported to the child.
        assert!(
            !env.iter().any(|(k, _)| *k == "AA_GATEWAY_URL"),
            "AA_GATEWAY_URL must not be exported (aa-proxy ignores it)"
        );
    }

    #[test]
    fn proxy_child_env_omits_gateway_vars_when_absent() {
        let env = proxy_child_env("127.0.0.1:8899", None);
        assert!(!env.iter().any(|(k, _)| *k == "AA_PROXY_GATEWAY_ENDPOINT"));
        assert!(!env.iter().any(|(k, _)| *k == "AA_PROXY_LLM_ONLY"));
        // The listen address is always exported.
        assert!(env.contains(&("AA_PROXY_ADDR", "127.0.0.1:8899".to_string())));
    }

    #[test]
    fn wait_for_port_returns_false_on_unbound_addr() {
        // Port 1 is privileged and never listening in test environments.
        assert!(!wait_for_port("127.0.0.1:1", Duration::from_millis(200)));
    }

    #[test]
    fn wait_for_port_returns_false_on_invalid_addr() {
        assert!(!wait_for_port("not-an-address", Duration::from_millis(100)));
    }
}
