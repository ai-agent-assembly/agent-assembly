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

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Args, Subcommand};

/// Where the gateway's log file lives.
///
/// `explicit` is the `--log-file` value, which is honoured unchanged and is not
/// affected by whether a home directory is resolvable.
///
/// # Why this is one function
///
/// `start` writes this file and `logs` reads it, and each used to carry its own
/// byte-identical copy of the rule. Fixing the cwd-relative fallback in one and
/// not the other would have produced a start-writes-here, logs-reads-there split
/// — a worse outcome than the defect. One rule cannot diverge from itself
/// (AAASM-5959 AC 3).
fn resolve_log_path(explicit: Option<&Path>) -> Option<PathBuf> {
    log_path_from(explicit.map(Path::to_path_buf), dirs::home_dir())
}

/// The resolution rule, with the environment passed in.
///
/// # Why there is no `.` fallback
///
/// Both copies ended in `unwrap_or_else(|| PathBuf::from("."))`, so on a host
/// where no home directory resolves, `gateway start` logged to
/// `./.aasm/logs/gateway.log` relative to the directory it was launched from and
/// `gateway logs`, run from anywhere else, reported that file as missing — for a
/// gateway that was running and logging normally. Of the four instances
/// AAASM-5959 covers these two are the least consequential, and they are still
/// worth closing because the divergence misleads about the gateway's state.
///
/// # Why the environment is an argument
///
/// A function not given the home directory cannot resolve against the process
/// working directory, so the removed fallback cannot return by accident — and the
/// rule stays assertable without any test mutating process-global state.
fn log_path_from(explicit: Option<PathBuf>, home: Option<PathBuf>) -> Option<PathBuf> {
    match explicit {
        Some(explicit) => Some(explicit),
        None => Some(home?.join(".aasm").join("logs").join("gateway.log")),
    }
}

/// What to tell an operator when no log-file location can be resolved.
const NO_LOG_PATH: &str = "error: no gateway log file location is known: no home directory could \
                           be resolved for the default ~/.aasm/logs/gateway.log.\n\
                           Use --log-file PATH to name the log file explicitly.";

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

    /// The log-path rule yields nothing rather than a relative path
    /// (AAASM-5959 AC 1/AC 5).
    ///
    /// Both `start` and `logs` now refuse on `None` instead of resolving
    /// `./.aasm/logs/gateway.log` against whatever directory they happened to be
    /// launched from — which is what produced the "no such log file" report for a
    /// gateway that was running and logging normally.
    ///
    /// Reverting `log_path_from` to `unwrap_or_else(|| PathBuf::from("."))`
    /// reddens exactly this test.
    #[test]
    fn no_log_path_is_synthesised_when_no_home_resolves() {
        assert_eq!(
            super::log_path_from(None, None),
            None,
            "with no --log-file and no home directory the rule must name no log file, not \
             ./.aasm/logs/gateway.log"
        );
    }

    /// `--log-file` is honoured verbatim and does not depend on a resolvable
    /// home directory (AAASM-5959 AC 2).
    ///
    /// This is the half that makes the refusal above safe to ship: an operator on
    /// a host where no home resolves is not locked out, because the explicit flag
    /// still works — and it must keep working on exactly that host, which is why
    /// the `home` argument is `None` here.
    #[test]
    fn an_explicit_log_file_needs_no_home_directory() {
        let named = std::path::PathBuf::from("/var/log/aasm-gateway.log");
        assert_eq!(super::log_path_from(Some(named.clone()), None), Some(named.clone()));
        assert_eq!(
            super::log_path_from(Some(named.clone()), Some(std::path::PathBuf::from("/h"))),
            Some(named),
            "an explicit path is never joined to, or overridden by, the home directory"
        );
    }

    /// The default layout is unchanged when a home directory resolves
    /// (AAASM-5959 AC 2 — no behaviour change).
    #[test]
    fn the_default_log_path_is_unchanged_when_a_home_resolves() {
        assert_eq!(
            super::log_path_from(None, Some(std::path::PathBuf::from("/h"))),
            Some(std::path::PathBuf::from("/h/.aasm/logs/gateway.log"))
        );
    }

    // AC 3 — that `start` and `logs` cannot disagree about where the file is —
    // is deliberately not asserted here. Both now call `super::resolve_log_path`
    // and their private copies are deleted, so the guarantee is structural: a
    // divergence would have to reintroduce a second function, which is visible in
    // review, not in a test run. A unit test could only compare this rule to
    // itself, which no change can make fail — it would read as proof of the
    // property while being causally incapable of detecting its loss.
}
