//! `aasm gateway` — governance daemon lifecycle management.
//!
//! Wraps the `aa-gateway` binary (gRPC policy server) with `start`, `stop`,
//! `status`, and `logs` subcommands, mirroring the pattern established by
//! `aasm dashboard start/stop/open`.

pub mod logs;
pub mod pid;
pub mod start;
pub mod status;
pub mod stop;

use std::process::ExitCode;

use clap::{Args, Subcommand};

/// Subcommands for `aasm gateway`.
#[derive(Debug, Subcommand)]
pub enum GatewayCommands {
    /// Spawn aa-gateway as a detached background process.
    Start(start::StartArgs),
    /// Terminate a running aa-gateway gracefully (SIGTERM → SIGKILL fallback).
    Stop,
    /// Report whether aa-gateway is running and serving gRPC.
    Status(status::StatusArgs),
    /// Tail the gateway log file.
    Logs(logs::LogsArgs),
}

/// Arguments for the `aasm gateway` subcommand group.
#[derive(Debug, Args)]
pub struct GatewayArgs {
    #[command(subcommand)]
    pub command: GatewayCommands,
}

/// Dispatch an `aasm gateway` subcommand.
pub fn dispatch(args: GatewayArgs) -> ExitCode {
    match args.command {
        GatewayCommands::Start(a) => start::dispatch(a),
        GatewayCommands::Stop => stop::dispatch(),
        GatewayCommands::Status(a) => status::dispatch(a),
        GatewayCommands::Logs(a) => logs::dispatch(a),
    }
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    #[derive(Parser)]
    #[command(name = "aasm")]
    struct TestCli {
        #[command(subcommand)]
        command: TestCommands,
    }

    #[derive(clap::Subcommand)]
    enum TestCommands {
        Gateway(super::GatewayArgs),
    }

    fn parse(args: &[&str]) -> super::GatewayArgs {
        let cli = TestCli::parse_from(args);
        match cli.command {
            TestCommands::Gateway(a) => a,
        }
    }

    #[test]
    fn parse_gateway_start_defaults() {
        let args = parse(&["aasm", "gateway", "start"]);
        match args.command {
            super::GatewayCommands::Start(a) => {
                assert!(a.policy.is_none());
                assert_eq!(a.listen, "127.0.0.1:50051");
                assert!(a.socket.is_none());
                assert!(!a.no_detach);
                assert!(a.log_file.is_none());
            }
            _ => panic!("expected Start"),
        }
    }

    #[test]
    fn parse_gateway_start_with_policy_and_listen() {
        let args = parse(&[
            "aasm",
            "gateway",
            "start",
            "--policy",
            "/etc/aasm/policy.yaml",
            "--listen",
            "0.0.0.0:50052",
        ]);
        match args.command {
            super::GatewayCommands::Start(a) => {
                assert_eq!(a.policy.unwrap().to_str().unwrap(), "/etc/aasm/policy.yaml");
                assert_eq!(a.listen, "0.0.0.0:50052");
            }
            _ => panic!("expected Start"),
        }
    }

    #[test]
    fn parse_gateway_stop() {
        let args = parse(&["aasm", "gateway", "stop"]);
        assert!(matches!(args.command, super::GatewayCommands::Stop));
    }

    #[test]
    fn parse_gateway_status_default() {
        let args = parse(&["aasm", "gateway", "status"]);
        match args.command {
            super::GatewayCommands::Status(a) => assert!(!a.json),
            _ => panic!("expected Status"),
        }
    }

    #[test]
    fn parse_gateway_status_json_flag() {
        let args = parse(&["aasm", "gateway", "status", "--json"]);
        match args.command {
            super::GatewayCommands::Status(a) => assert!(a.json),
            _ => panic!("expected Status"),
        }
    }

    #[test]
    fn parse_gateway_logs_defaults() {
        let args = parse(&["aasm", "gateway", "logs"]);
        match args.command {
            super::GatewayCommands::Logs(a) => {
                assert!(!a.follow);
                assert_eq!(a.lines, 50);
                assert!(a.level.is_none());
            }
            _ => panic!("expected Logs"),
        }
    }

    #[test]
    fn parse_gateway_logs_follow_short() {
        let args = parse(&["aasm", "gateway", "logs", "-f"]);
        match args.command {
            super::GatewayCommands::Logs(a) => assert!(a.follow),
            _ => panic!("expected Logs"),
        }
    }

    #[test]
    fn parse_gateway_logs_lines_and_level() {
        let args = parse(&["aasm", "gateway", "logs", "--lines", "100", "--level", "warn"]);
        match args.command {
            super::GatewayCommands::Logs(a) => {
                assert_eq!(a.lines, 100);
                assert!(matches!(a.level, Some(super::logs::LogLevel::Warn)));
            }
            _ => panic!("expected Logs"),
        }
    }
}
