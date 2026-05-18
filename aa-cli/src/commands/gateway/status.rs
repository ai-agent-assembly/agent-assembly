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
            listen: None,
            uptime_seconds: None,
        };
    };

    if !pid::is_process_alive(gateway_pid) {
        return GatewayStatus {
            running: false,
            pid: Some(gateway_pid),
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
        listen: Some(listen),
        uptime_seconds: uptime,
    }
}

fn print_human(s: &GatewayStatus) {
    if !s.running {
        if let Some(pid) = s.pid {
            println!("Gateway: not responding  (pid {pid} exists but port is unreachable)");
        } else {
            println!("Gateway: not running");
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
            listen: None,
            uptime_seconds: None,
        };
        let json = serde_json::to_string(&s).unwrap();
        assert!(!json.contains("\"pid\""));
        assert!(!json.contains("\"listen\""));
    }
}
