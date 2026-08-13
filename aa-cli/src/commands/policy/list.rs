//! `aasm policy list` — list all policies deployed to the governance runtime.

use std::process::ExitCode;

use clap::Args;
use comfy_table::{Cell, Color, Table};
use serde::{Deserialize, Serialize};

use crate::client;
use crate::config::ResolvedContext;
use crate::output::OutputFormat;
use crate::sanitize::sanitize_terminal;

/// Arguments for `aasm policy list`.
#[derive(Args)]
pub struct ListArgs {}

/// API response item from `GET /api/v1/policies`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PolicyResponse {
    /// Policy name (SHA-256 prefix).
    pub name: String,
    /// Version timestamp string.
    pub version: String,
    /// Whether this is the currently active policy.
    pub active: bool,
    /// Number of rules in this policy.
    pub rule_count: usize,
}

/// Paginated API response wrapper for policies.
#[derive(Debug, Clone, Deserialize)]
pub struct PaginatedResponse {
    pub items: Vec<PolicyResponse>,
    #[allow(dead_code)]
    pub page: u32,
    #[allow(dead_code)]
    pub per_page: u32,
    #[allow(dead_code)]
    pub total: u64,
}

/// Fetch policies from the gateway API.
async fn fetch_policies(ctx: &ResolvedContext) -> Result<Vec<PolicyResponse>, crate::error::CliError> {
    let resp: PaginatedResponse = client::get_json(ctx, "/api/v1/policies").await?;
    Ok(resp.items)
}

/// Map a policy active flag to a display status string.
fn status_label(active: bool) -> &'static str {
    if active {
        "Active"
    } else {
        "Inactive"
    }
}

/// Map a policy active flag to a terminal color.
fn status_color(active: bool) -> Color {
    if active {
        Color::Green
    } else {
        Color::DarkGrey
    }
}

/// Render policies as a table using comfy-table.
fn render_table(policies: &[PolicyResponse]) {
    let mut table = Table::new();
    table.set_header(vec!["NAME", "STATUS", "UPDATED_AT", "RULES"]);

    for p in policies {
        // name/version are server-supplied; strip terminal escapes.
        table.add_row(vec![
            Cell::new(sanitize_terminal(&p.name)),
            Cell::new(status_label(p.active)).fg(status_color(p.active)),
            Cell::new(sanitize_terminal(&p.version)),
            Cell::new(p.rule_count),
        ]);
    }

    println!("{table}");
}

/// Render policies as JSON.
fn render_json(policies: &[PolicyResponse]) {
    match serde_json::to_string_pretty(policies) {
        Ok(json) => println!("{json}"),
        Err(e) => eprintln!("error serializing JSON: {e}"),
    }
}

/// Render policies as YAML.
fn render_yaml(policies: &[PolicyResponse]) {
    match serde_yaml::to_string(policies) {
        Ok(yaml) => print!("{yaml}"),
        Err(e) => eprintln!("error serializing YAML: {e}"),
    }
}

/// Render policies in the requested output format.
fn render(policies: &[PolicyResponse], output: OutputFormat) {
    match output {
        OutputFormat::Table => render_table(policies),
        OutputFormat::Json => render_json(policies),
        OutputFormat::Yaml => render_yaml(policies),
    }
}

/// Run the `aasm policy list` command.
pub fn run(args: ListArgs, ctx: &ResolvedContext, output: OutputFormat) -> ExitCode {
    let _ = args;
    let rt = tokio::runtime::Runtime::new().expect("failed to create tokio runtime");

    let policies = match rt.block_on(fetch_policies(ctx)) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::FAILURE;
        }
    };

    if policies.is_empty() {
        println!("No policies found. Use `aasm policy apply` to deploy one.");
    } else {
        render(&policies, output);
    }

    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_policies() -> Vec<PolicyResponse> {
        vec![
            PolicyResponse {
                name: "abc123def456".to_string(),
                version: "2026-04-30T10:00:00Z".to_string(),
                active: true,
                rule_count: 5,
            },
            PolicyResponse {
                name: "789012345678".to_string(),
                version: "2026-04-29T08:00:00Z".to_string(),
                active: false,
                rule_count: 3,
            },
        ]
    }

    #[test]
    fn status_label_active() {
        assert_eq!(status_label(true), "Active");
    }

    #[test]
    fn status_label_inactive() {
        assert_eq!(status_label(false), "Inactive");
    }

    #[test]
    fn status_color_active_is_green() {
        assert_eq!(status_color(true), Color::Green);
    }

    #[test]
    fn status_color_inactive_is_grey() {
        assert_eq!(status_color(false), Color::DarkGrey);
    }

    #[test]
    fn render_table_does_not_panic() {
        let policies = sample_policies();
        render_table(&policies);
    }

    #[test]
    fn render_table_empty_does_not_panic() {
        render_table(&[]);
    }

    #[test]
    fn json_output_is_valid() {
        let policies = sample_policies();
        let json = serde_json::to_string_pretty(&policies).unwrap();
        let parsed: Vec<PolicyResponse> = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].name, "abc123def456");
        assert!(parsed[0].active);
        assert_eq!(parsed[1].rule_count, 3);
    }

    #[test]
    fn yaml_output_is_valid() {
        let policies = sample_policies();
        let yaml = serde_yaml::to_string(&policies).unwrap();
        let parsed: Vec<PolicyResponse> = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(parsed.len(), 2);
    }

    #[test]
    fn deserialize_paginated_response() {
        let json = r#"{
            "items": [
                {"name": "abc123", "version": "2026-04-30T10:00:00Z", "active": true, "rule_count": 5}
            ],
            "page": 1,
            "per_page": 20,
            "total": 1
        }"#;
        let resp: PaginatedResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.items.len(), 1);
        assert_eq!(resp.items[0].name, "abc123");
        assert!(resp.items[0].active);
    }
}
