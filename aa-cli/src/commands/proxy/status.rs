//! `aasm proxy status` — report whether the aa-proxy sidecar is running.

use std::net::SocketAddr;
use std::process::ExitCode;
use std::time::Duration;

use clap::Args;
use serde::Serialize;

use super::pid;

/// Arguments for `aasm proxy status`.
#[derive(Debug, Args)]
pub struct StatusArgs {
    /// Emit machine-readable JSON output.
    #[arg(long)]
    pub json: bool,
}

#[derive(Serialize)]
struct StatusOutput {
    running: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    listen: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    serving: Option<bool>,
}

/// Try a non-blocking TCP connect to confirm the proxy is actually serving.
fn is_serving(addr: &str) -> bool {
    let Ok(sock_addr) = addr.parse::<SocketAddr>() else {
        return false;
    };
    std::net::TcpStream::connect_timeout(&sock_addr, Duration::from_secs(1)).is_ok()
}

/// Returns `true` if the process with the given PID is alive (Unix: kill(pid, 0)).
fn is_alive(pid: u32) -> bool {
    #[cfg(unix)]
    {
        let ret = unsafe { libc::kill(pid as libc::pid_t, 0) };
        ret == 0
    }
    #[cfg(not(unix))]
    {
        let _ = pid;
        false
    }
}

pub fn dispatch(args: StatusArgs) -> ExitCode {
    let Some((proxy_pid, addr)) = pid::read_pid() else {
        if args.json {
            let out = serde_json::to_string(&StatusOutput {
                running: false,
                pid: None,
                listen: None,
                serving: None,
            })
            .unwrap_or_default();
            println!("{out}");
        } else {
            println!("not running");
        }
        return ExitCode::SUCCESS;
    };

    if !is_alive(proxy_pid) {
        // Stale PID file — clean it up.
        let _ = pid::remove_pid();
        if args.json {
            let out = serde_json::to_string(&StatusOutput {
                running: false,
                pid: None,
                listen: None,
                serving: None,
            })
            .unwrap_or_default();
            println!("{out}");
        } else {
            println!("not running (stale PID file cleaned up)");
        }
        return ExitCode::SUCCESS;
    }

    let serving = is_serving(&addr);

    if args.json {
        let out = serde_json::to_string(&StatusOutput {
            running: true,
            pid: Some(proxy_pid),
            listen: Some(addr.clone()),
            serving: Some(serving),
        })
        .unwrap_or_default();
        println!("{out}");
    } else {
        println!("running (PID {proxy_pid}, listening on {addr})");
        if !serving {
            eprintln!("warning: TCP connect to {addr} failed — proxy may still be starting");
        }
    }

    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Parser)]
    struct Wrapper {
        #[command(flatten)]
        inner: StatusArgs,
    }

    #[test]
    fn status_args_json_defaults_false() {
        let w = Wrapper::parse_from(["test"]);
        assert!(!w.inner.json);
    }

    #[test]
    fn status_args_json_flag() {
        let w = Wrapper::parse_from(["test", "--json"]);
        assert!(w.inner.json);
    }

    #[test]
    fn status_output_serialises_not_running() {
        let out = StatusOutput {
            running: false,
            pid: None,
            listen: None,
            serving: None,
        };
        let json = serde_json::to_string(&out).unwrap();
        assert_eq!(json, r#"{"running":false}"#);
    }

    #[test]
    fn status_output_serialises_running() {
        let out = StatusOutput {
            running: true,
            pid: Some(12345),
            listen: Some("127.0.0.1:8899".into()),
            serving: Some(true),
        };
        let json = serde_json::to_string(&out).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["running"], true);
        assert_eq!(parsed["pid"], 12345);
        assert_eq!(parsed["listen"], "127.0.0.1:8899");
        assert_eq!(parsed["serving"], true);
    }

    #[test]
    fn is_serving_returns_false_for_unbound_port() {
        assert!(!is_serving("127.0.0.1:1"));
    }

    #[test]
    fn is_serving_returns_false_for_invalid_addr() {
        assert!(!is_serving("not-an-addr"));
    }
}
