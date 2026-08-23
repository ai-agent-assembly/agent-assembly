//! `aasm gateway status` — report whether aa-gateway is running.

use std::process::ExitCode;
use std::time::Duration;

use clap::Args;
use serde::Serialize;

use super::pid;

const HEALTH_TIMEOUT: Duration = Duration::from_secs(2);

/// Arguments for `aasm gateway status`.
#[derive(Debug, Args)]
pub struct StatusArgs {
    /// Emit machine-readable JSON instead of human-readable text.
    #[arg(long)]
    pub json: bool,
}

/// Status snapshot passed to the output formatters.
#[derive(Debug, Serialize)]
pub struct GatewayStatus {
    pub running: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process_alive: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub listen: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uptime_seconds: Option<u64>,
    // Fields below require a gRPC status RPC that is not yet implemented in
    // aa-gateway; they are omitted until AAASM-1509 follow-up adds the RPC.
}

/// Dispatch `aasm gateway status`.
pub fn dispatch(args: StatusArgs) -> ExitCode {
    let status = collect_status();

    if args.json {
        match serde_json::to_string_pretty(&status) {
            Ok(s) => println!("{s}"),
            Err(e) => {
                eprintln!("error: could not serialise status: {e}");
                return ExitCode::FAILURE;
            }
        }
    } else {
        print_human(&status);
    }

    if status.running {
        ExitCode::SUCCESS
    } else {
        // Exit 1 when not running so scripts can test `aasm gateway status || start`.
        ExitCode::from(1)
    }
}

fn collect_status() -> GatewayStatus {
    let Some((gateway_pid, listen, started_at)) = pid::read_pid() else {
        return GatewayStatus {
            running: false,
            pid: None,
            process_alive: None,
            listen: None,
            uptime_seconds: None,
        };
    };

    if !pid::is_process_alive(gateway_pid) {
        return GatewayStatus {
            running: false,
            pid: Some(gateway_pid),
            process_alive: Some(false),
            listen: Some(listen),
            uptime_seconds: None,
        };
    }

    // Verify the gateway is actually serving (not just a hung process).
    let tcp_up = is_tcp_open(&listen);
    let uptime = parse_uptime(&started_at);

    GatewayStatus {
        running: tcp_up,
        pid: Some(gateway_pid),
        process_alive: Some(true),
        listen: Some(listen),
        uptime_seconds: uptime,
    }
}

fn print_human(s: &GatewayStatus) {
    if !s.running {
        match (s.pid, s.process_alive) {
            (Some(pid), Some(false)) => {
                println!("Gateway: not running  (stale PID file — process {pid} is no longer alive)");
            }
            (Some(pid), Some(true)) => {
                println!("Gateway: not responding  (pid {pid} is alive but port is unreachable)");
            }
            _ => {
                println!("Gateway: not running");
            }
        }
        return;
    }
    let pid = s.pid.map_or_else(|| "?".to_string(), |p| p.to_string());
    let listen = s.listen.as_deref().unwrap_or("?");
    print!("Gateway: running  pid={pid}  listen={listen}");
    if let Some(secs) = s.uptime_seconds {
        print!("  uptime={}", format_uptime(secs));
    }
    println!();
}

fn is_tcp_open(addr: &str) -> bool {
    std::net::TcpStream::connect_timeout(
        &addr.parse().unwrap_or_else(|_| "127.0.0.1:50051".parse().unwrap()),
        HEALTH_TIMEOUT,
    )
    .is_ok()
}

fn parse_uptime(started_at: &str) -> Option<u64> {
    let start = chrono::DateTime::parse_from_rfc3339(started_at).ok()?;
    let now = chrono::Utc::now();
    let secs = (now - start.with_timezone(&chrono::Utc)).num_seconds();
    if secs >= 0 {
        Some(secs as u64)
    } else {
        None
    }
}

fn format_uptime(secs: u64) -> String {
    if secs < 60 {
        format!("{secs}s")
    } else if secs < 3600 {
        format!("{}m{}s", secs / 60, secs % 60)
    } else {
        format!("{}h{}m", secs / 3600, (secs % 3600) / 60)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::MutexGuard;

    #[test]
    fn format_uptime_seconds() {
        assert_eq!(format_uptime(45), "45s");
    }

    #[test]
    fn format_uptime_minutes() {
        assert_eq!(format_uptime(125), "2m5s");
    }

    #[test]
    fn format_uptime_hours() {
        assert_eq!(format_uptime(3700), "1h1m");
    }

    #[test]
    fn parse_uptime_returns_none_for_garbage() {
        assert!(parse_uptime("not-a-timestamp").is_none());
    }

    #[test]
    fn parse_uptime_returns_some_for_valid_rfc3339() {
        // Use a timestamp well in the past so uptime is definitely positive.
        let ts = "2020-01-01T00:00:00Z";
        assert!(parse_uptime(ts).is_some_and(|s| s > 0));
    }

    #[test]
    fn gateway_status_serialises_to_json() {
        let s = GatewayStatus {
            running: true,
            pid: Some(1234),
            process_alive: Some(true),
            listen: Some("127.0.0.1:50051".to_string()),
            uptime_seconds: Some(600),
        };
        let json = serde_json::to_string(&s).unwrap();
        assert!(json.contains("\"running\":true"));
        assert!(json.contains("\"pid\":1234"));
    }

    #[test]
    fn gateway_status_omits_none_fields_in_json() {
        let s = GatewayStatus {
            running: false,
            pid: None,
            process_alive: None,
            listen: None,
            uptime_seconds: None,
        };
        let json = serde_json::to_string(&s).unwrap();
        assert!(!json.contains("\"pid\""));
        assert!(!json.contains("\"listen\""));
    }

    struct EnvGuard {
        _lock: MutexGuard<'static, ()>,
        prior: Option<String>,
    }
    impl EnvGuard {
        fn set(value: &str) -> Self {
            let lock = crate::test_support::env_guard();
            let prior = std::env::var("AA_DATA_DIR").ok();
            std::env::set_var("AA_DATA_DIR", value);
            Self { _lock: lock, prior }
        }
    }
    impl Drop for EnvGuard {
        fn drop(&mut self) {
            match self.prior.take() {
                Some(v) => std::env::set_var("AA_DATA_DIR", v),
                None => std::env::remove_var("AA_DATA_DIR"),
            }
        }
    }

    #[test]
    fn collect_status_distinguishes_dead_process_from_alive_unreachable() {
        let tmp = tempfile::tempdir().unwrap();
        let _guard = EnvGuard::set(tmp.path().to_str().unwrap());

        // Case 1: dead process (spawn, wait for exit, use its now-dead PID) —
        // this is the exact AAASM-5833 scenario: a PID file pointing at a
        // process that has actually died.
        let mut child = std::process::Command::new("true")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("failed to spawn 'true'");
        let dead_pid = child.id();
        child.wait().expect("wait failed");

        pid::write_pid(dead_pid, "127.0.0.1:1", "2020-01-01T00:00:00Z").unwrap();
        let status = collect_status();
        assert!(!status.running);
        assert_eq!(status.pid, Some(dead_pid));
        assert_eq!(
            status.process_alive,
            Some(false),
            "a dead PID must never be reported as alive"
        );

        // Independently cross-check against a direct liveness probe — the same
        // assertion the Jira ticket used (`kill -0` equivalent) to prove the
        // dead-PID claim was false.
        assert!(!pid::is_process_alive(dead_pid));
    }

    #[test]
    fn collect_status_reports_alive_process_with_unreachable_port_distinctly() {
        let tmp = tempfile::tempdir().unwrap();
        let _guard = EnvGuard::set(tmp.path().to_str().unwrap());

        // Case 2: a genuinely alive process (this test process itself) whose
        // "listen" address has nothing actually listening on it.
        let my_pid = std::process::id();
        pid::write_pid(my_pid, "127.0.0.1:1", "2020-01-01T00:00:00Z").unwrap();

        let status = collect_status();
        assert!(!status.running);
        assert_eq!(status.pid, Some(my_pid));
        assert_eq!(
            status.process_alive,
            Some(true),
            "a live process must never be reported as dead, even if its port is unreachable"
        );
    }
}
