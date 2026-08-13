//! `aasm alerts get` — show full alert detail.

use std::process::ExitCode;

use clap::Args;
use comfy_table::{Cell, Table};

use super::models::{AlertResponse, AlertSeverity, AlertStatusKind};
use crate::client;
use crate::config::ResolvedContext;
use crate::output::OutputFormat;
use crate::sanitize::sanitize_terminal;

/// Arguments for `aasm alerts get`.
#[derive(Args)]
pub struct GetArgs {
    /// Alert ID to inspect.
    pub alert_id: String,
}

/// Render a detailed key-value view of an alert.
pub fn render_detail(alert: &AlertResponse) {
    let mut table = Table::new();
    table.set_header(vec!["Field", "Value"]);

    // All free-text fields are server-supplied; strip terminal escapes
    // (severity/status colours come from the raw, never-printed strings).
    table.add_row(vec!["ID".to_string(), sanitize_terminal(&alert.id)]);

    let agent = alert.agent_id.as_deref().unwrap_or("-");
    table.add_row(vec!["Agent".to_string(), sanitize_terminal(agent)]);

    let sev = AlertSeverity::parse(&alert.severity);
    table.add_row(vec![
        Cell::new("Severity"),
        Cell::new(sanitize_terminal(&alert.severity)).fg(sev.color()),
    ]);

    table.add_row(vec!["Type".to_string(), sanitize_terminal(&alert.category)]);
    table.add_row(vec!["Message".to_string(), sanitize_terminal(&alert.message)]);

    let status = AlertStatusKind::parse(&alert.status);
    table.add_row(vec![
        Cell::new("Status"),
        Cell::new(sanitize_terminal(&alert.status)).fg(status.color()),
    ]);

    table.add_row(vec!["Created".to_string(), sanitize_terminal(&alert.created_at)]);

    let updated = alert.updated_at.as_deref().unwrap_or("-");
    table.add_row(vec!["Updated".to_string(), sanitize_terminal(updated)]);

    if let Some(ref ctx) = alert.context {
        let ctx_str = serde_json::to_string_pretty(ctx).unwrap_or_else(|_| ctx.to_string());
        table.add_row(vec!["Context".to_string(), ctx_str]);
    }

    println!("{table}");
}

/// Run the `aasm alerts get` command.
pub fn run(args: GetArgs, ctx: &ResolvedContext, output: OutputFormat) -> ExitCode {
    let rt = tokio::runtime::Runtime::new().expect("failed to create tokio runtime");

    let path = format!("/api/v1/alerts/{}", args.alert_id);
    let alert: AlertResponse = match rt.block_on(client::get_json(ctx, &path)) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::FAILURE;
        }
    };

    match output {
        OutputFormat::Table => render_detail(&alert),
        OutputFormat::Json => match serde_json::to_string_pretty(&alert) {
            Ok(json) => println!("{json}"),
            Err(e) => eprintln!("error serializing JSON: {e}"),
        },
        OutputFormat::Yaml => match serde_yaml::to_string(&alert) {
            Ok(yaml) => print!("{yaml}"),
            Err(e) => eprintln!("error serializing YAML: {e}"),
        },
    }

    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_alert() -> AlertResponse {
        AlertResponse {
            id: "alert-001".to_string(),
            agent_id: Some("agent-abc".to_string()),
            severity: "critical".to_string(),
            category: "budget".to_string(),
            message: "Budget exceeded".to_string(),
            status: "unresolved".to_string(),
            created_at: "2026-04-30T10:00:00Z".to_string(),
            updated_at: Some("2026-04-30T11:00:00Z".to_string()),
            context: Some(serde_json::json!({"tool": "shell_exec", "amount": 500})),
        }
    }

    #[test]
    fn render_detail_does_not_panic() {
        render_detail(&sample_alert());
    }

    #[test]
    fn render_detail_without_optional_fields() {
        let alert = AlertResponse {
            id: "alert-002".to_string(),
            agent_id: None,
            severity: "info".to_string(),
            category: "policy_violation".to_string(),
            message: "Minor issue".to_string(),
            status: "resolved".to_string(),
            created_at: "2026-04-30T08:00:00Z".to_string(),
            updated_at: None,
            context: None,
        };
        render_detail(&alert);
    }

    #[test]
    fn json_output_is_valid() {
        let alert = sample_alert();
        let json = serde_json::to_string_pretty(&alert).unwrap();
        let parsed: AlertResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.id, "alert-001");
        assert_eq!(parsed.context.unwrap()["tool"], "shell_exec");
    }
}
