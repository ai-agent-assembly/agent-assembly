//! `aasm status` — kubectl-style tabular overview of governance state.

pub mod client;
pub mod fetch;
pub mod models;
pub mod render;
pub mod watch;

use std::process::ExitCode;

use clap::Args;

use crate::config::ResolvedContext;
use crate::output::OutputFormat;

/// Arguments for the `aasm status` subcommand.
#[derive(Debug, Args)]
pub struct StatusArgs {
    /// Auto-refresh the status display every 5 seconds.
    #[arg(long)]
    pub watch: bool,

    /// Print only the deployment-overview header as machine-readable JSON.
    ///
    /// Intended for scripting and CI integrations — the documented shape is
    /// the JSON contract published in the AAASM-1579 story description.
    /// Distinct from `--output json`, which serialises the full status snapshot.
    #[arg(long)]
    pub json: bool,
}

use models::StatusSnapshot;

/// Compute the process exit code from a status snapshot.
///
/// - `0` — all healthy
/// - `1` — gateway is unreachable (`deployment.health == "unreachable"`) OR at
///   least one agent has violations. Per the AAASM-1579 acceptance criteria,
///   unreachable now maps to exit code 1 instead of the legacy exit code 2 so
///   shell scripts can use a single non-zero check without distinguishing
///   between failure modes.
pub fn compute_exit_code(snapshot: &StatusSnapshot) -> ExitCode {
    if snapshot.deployment.health == "unreachable" {
        return ExitCode::from(1);
    }
    let has_violations = snapshot.agents.iter().any(|a| a.violations_today > 0);
    if has_violations {
        return ExitCode::from(1);
    }
    ExitCode::SUCCESS
}

/// Entry point for `aasm status`.
pub fn dispatch(args: StatusArgs, ctx: &ResolvedContext, output: OutputFormat) -> ExitCode {
    let rt = tokio::runtime::Runtime::new().expect("failed to create tokio runtime");
    rt.block_on(async {
        let api_client = client::StatusClient::new(&ctx.api_url);

        if args.watch {
            watch::run_watch_loop(&api_client, output).await;
            ExitCode::SUCCESS
        } else {
            let snapshot = fetch::fetch_all(&api_client).await;
            if args.json {
                match serde_json::to_string_pretty(&snapshot.deployment) {
                    Ok(json) => println!("{json}"),
                    Err(e) => eprintln!("error serializing deployment overview to JSON: {e}"),
                }
            } else {
                render::render_all(&snapshot, output);
            }
            if snapshot.deployment.health == "unreachable" {
                eprintln!("Error: gateway is not running. Start it with: aasm start");
            }
            compute_exit_code(&snapshot)
        }
    })
}

#[cfg(test)]
mod tests {
    use super::models::*;
    use super::*;

    fn healthy_snapshot() -> StatusSnapshot {
        StatusSnapshot {
            deployment: DeploymentOverview {
                mode: "local".to_string(),
                gateway_url: "http://localhost:7391".to_string(),
                storage_backend: "sqlite".to_string(),
                storage_path: Some("~/.aasm/local.db".to_string()),
                database_url_redacted: None,
                version: "0.0.1".to_string(),
                uptime_secs: 3600,
                health: "ok".to_string(),
            },
            runtime: RuntimeHealth {
                reachable: true,
                status: "ok".to_string(),
                uptime_secs: 3600,
                active_connections: 5,
                pipeline_lag_ms: 0,
            },
            agents: vec![AgentRow {
                id: "a1".to_string(),
                name: "agent".to_string(),
                framework: "langgraph".to_string(),
                status: "Running".to_string(),
                sessions: 0,
                violations_today: 0,
                last_event: "-".to_string(),
                layer: "-".to_string(),
            }],
            approvals: ApprovalsSummary {
                pending_count: 0,
                oldest_pending_age: None,
            },
            budget: BudgetRow {
                daily_spend_usd: "0.00".to_string(),
                monthly_spend_usd: None,
                daily_limit_usd: None,
                monthly_limit_usd: None,
                date: "2026-04-30".to_string(),
                per_agent: vec![],
            },
            storage_health: None,
        }
    }

    #[test]
    fn exit_code_0_when_healthy() {
        let snapshot = healthy_snapshot();
        assert_eq!(compute_exit_code(&snapshot), ExitCode::SUCCESS);
    }

    #[test]
    fn exit_code_1_when_violations() {
        let mut snapshot = healthy_snapshot();
        snapshot.agents[0].violations_today = 3;
        assert_eq!(compute_exit_code(&snapshot), ExitCode::from(1));
    }

    #[test]
    fn exit_code_1_when_deployment_unreachable() {
        let mut snapshot = healthy_snapshot();
        snapshot.deployment.health = "unreachable".to_string();
        assert_eq!(compute_exit_code(&snapshot), ExitCode::from(1));
    }

    #[test]
    fn json_flag_output_contains_documented_top_level_keys() {
        // The --json flag emits snapshot.deployment alone via
        // serde_json::to_string_pretty — verify the resulting shape matches
        // the AAASM-1579 documented contract.
        let snapshot = healthy_snapshot();
        let json: serde_json::Value =
            serde_json::from_str(&serde_json::to_string_pretty(&snapshot.deployment).expect("serialise deployment"))
                .expect("parse deployment JSON");
        for required_key in [
            "mode",
            "gateway_url",
            "storage_backend",
            "version",
            "uptime_secs",
            "health",
        ] {
            assert!(
                json.get(required_key).is_some(),
                "missing top-level key {required_key:?}"
            );
        }
        assert_eq!(json["mode"], "local");
        assert_eq!(json["gateway_url"], "http://localhost:7391");
        assert_eq!(json["storage_backend"], "sqlite");
        assert_eq!(json["health"], "ok");
    }

    #[test]
    fn exit_code_1_when_deployment_unreachable_with_violations() {
        let mut snapshot = healthy_snapshot();
        snapshot.deployment.health = "unreachable".to_string();
        snapshot.agents[0].violations_today = 5;
        assert_eq!(compute_exit_code(&snapshot), ExitCode::from(1));
    }
}
