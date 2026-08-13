//! `aasm alerts list` — list governance alerts.

use std::process::ExitCode;

use clap::Args;
use comfy_table::{Cell, Table};

use super::models::{AlertResponse, AlertSeverity, AlertStatusKind};
use crate::client;
use crate::commands::agent::PaginatedResponse;
use crate::config::ResolvedContext;
use crate::output::OutputFormat;
use crate::sanitize::sanitize_terminal;

/// Arguments for `aasm alerts list`.
#[derive(Args)]
pub struct ListArgs {
    /// Filter by agent ID.
    #[arg(long)]
    pub agent: Option<String>,

    /// Filter by severity (critical, warning, info).
    #[arg(long)]
    pub severity: Option<String>,

    /// Filter by status (unresolved, acknowledged, resolved). Default: unresolved.
    #[arg(long, default_value = "unresolved")]
    pub status: Option<String>,
}

/// Fetch alerts from the gateway API.
async fn fetch_alerts(ctx: &ResolvedContext) -> Result<Vec<AlertResponse>, crate::error::CliError> {
    let resp: PaginatedResponse<AlertResponse> = client::get_json(ctx, "/api/v1/alerts").await?;
    Ok(resp.items)
}

/// Apply client-side filters for --agent, --severity, --status.
pub fn apply_filters(alerts: Vec<AlertResponse>, args: &ListArgs) -> Vec<AlertResponse> {
    alerts
        .into_iter()
        .filter(|a| {
            if let Some(ref agent) = args.agent {
                match &a.agent_id {
                    Some(id) if id.eq_ignore_ascii_case(agent) => {}
                    _ => return false,
                }
            }
            if let Some(ref sev) = args.severity {
                if !a.severity.eq_ignore_ascii_case(sev) {
                    return false;
                }
            }
            if let Some(ref status) = args.status {
                if !a.status.eq_ignore_ascii_case(status) {
                    return false;
                }
            }
            true
        })
        .collect()
}

/// Render alerts as a color-coded table.
pub fn render_table(alerts: &[AlertResponse]) {
    let mut table = Table::new();
    table.set_header(vec![
        "ID",
        "AGENT",
        "SEVERITY",
        "TYPE",
        "MESSAGE",
        "STATUS",
        "CREATED_AT",
    ]);

    for alert in alerts {
        let agent = alert.agent_id.as_deref().unwrap_or("-");
        let sev = AlertSeverity::parse(&alert.severity);
        let status = AlertStatusKind::parse(&alert.status);

        // All fields are server-supplied; strip terminal escapes (severity/
        // status colours are still chosen from the raw, never-printed strings).
        table.add_row(vec![
            Cell::new(sanitize_terminal(&alert.id)),
            Cell::new(sanitize_terminal(agent)),
            Cell::new(sanitize_terminal(&alert.severity)).fg(sev.color()),
            Cell::new(sanitize_terminal(&alert.category)),
            Cell::new(sanitize_terminal(&alert.message)),
            Cell::new(sanitize_terminal(&alert.status)).fg(status.color()),
            Cell::new(sanitize_terminal(&alert.created_at)),
        ]);
    }

    println!("{table}");
}

/// Run the `aasm alerts list` command.
pub fn run(args: ListArgs, ctx: &ResolvedContext, output: OutputFormat) -> ExitCode {
    let rt = tokio::runtime::Runtime::new().expect("failed to create tokio runtime");

    let alerts = match rt.block_on(fetch_alerts(ctx)) {
        Ok(a) => apply_filters(a, &args),
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::FAILURE;
        }
    };

    if alerts.is_empty() {
        println!("No alerts found.");
    } else {
        match output {
            OutputFormat::Table => render_table(&alerts),
            OutputFormat::Json => match serde_json::to_string_pretty(&alerts) {
                Ok(json) => println!("{json}"),
                Err(e) => eprintln!("error serializing JSON: {e}"),
            },
            OutputFormat::Yaml => match serde_yaml::to_string(&alerts) {
                Ok(yaml) => print!("{yaml}"),
                Err(e) => eprintln!("error serializing YAML: {e}"),
            },
        }
    }

    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_alerts() -> Vec<AlertResponse> {
        vec![
            AlertResponse {
                id: "alert-001".to_string(),
                agent_id: Some("agent-abc".to_string()),
                severity: "critical".to_string(),
                category: "budget".to_string(),
                message: "Budget exceeded".to_string(),
                status: "unresolved".to_string(),
                created_at: "2026-04-30T10:00:00Z".to_string(),
                updated_at: None,
                context: None,
            },
            AlertResponse {
                id: "alert-002".to_string(),
                agent_id: Some("agent-def".to_string()),
                severity: "warning".to_string(),
                category: "anomaly".to_string(),
                message: "Unusual activity".to_string(),
                status: "acknowledged".to_string(),
                created_at: "2026-04-30T09:00:00Z".to_string(),
                updated_at: None,
                context: None,
            },
            AlertResponse {
                id: "alert-003".to_string(),
                agent_id: None,
                severity: "info".to_string(),
                category: "policy_violation".to_string(),
                message: "Policy updated".to_string(),
                status: "resolved".to_string(),
                created_at: "2026-04-30T08:00:00Z".to_string(),
                updated_at: None,
                context: None,
            },
        ]
    }

    #[test]
    fn filter_by_agent() {
        let alerts = sample_alerts();
        let args = ListArgs {
            agent: Some("agent-abc".to_string()),
            severity: None,
            status: None,
        };
        let filtered = apply_filters(alerts, &args);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].id, "alert-001");
    }

    #[test]
    fn filter_by_severity() {
        let alerts = sample_alerts();
        let args = ListArgs {
            agent: None,
            severity: Some("warning".to_string()),
            status: None,
        };
        let filtered = apply_filters(alerts, &args);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].id, "alert-002");
    }

    #[test]
    fn filter_by_status_default_unresolved() {
        let alerts = sample_alerts();
        let args = ListArgs {
            agent: None,
            severity: None,
            status: Some("unresolved".to_string()),
        };
        let filtered = apply_filters(alerts, &args);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].id, "alert-001");
    }

    #[test]
    fn filter_no_status_returns_all() {
        let alerts = sample_alerts();
        let args = ListArgs {
            agent: None,
            severity: None,
            status: None,
        };
        let filtered = apply_filters(alerts, &args);
        assert_eq!(filtered.len(), 3);
    }

    #[test]
    fn filter_agent_without_agent_id_excluded() {
        let alerts = sample_alerts();
        let args = ListArgs {
            agent: Some("agent-xyz".to_string()),
            severity: None,
            status: None,
        };
        let filtered = apply_filters(alerts, &args);
        assert!(filtered.is_empty());
    }

    #[test]
    fn render_table_does_not_panic() {
        let alerts = sample_alerts();
        render_table(&alerts);
    }

    #[test]
    fn render_table_empty_does_not_panic() {
        render_table(&[]);
    }

    #[test]
    fn json_output_is_valid() {
        let alerts = sample_alerts();
        let json = serde_json::to_string_pretty(&alerts).unwrap();
        let parsed: Vec<AlertResponse> = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.len(), 3);
    }
}
