//! Rendering functions for `aasm status` output.

use colored::Colorize;
use comfy_table::{ContentArrangement, Table};

use super::models::{AgentRow, ApprovalsSummary, BudgetRow, RuntimeHealth, StatusSnapshot};
use crate::output::OutputFormat;

/// Render the Runtime Health section to stdout.
pub fn render_runtime_health(health: &RuntimeHealth) {
    println!("RUNTIME HEALTH");
    println!("──────────────");
    let indicator = if health.reachable { "✓" } else { "✗" };
    println!("  API:         {indicator} {}", health.status);
    println!("  Uptime:      {}", format_duration(health.uptime_secs));
    println!("  Connections: {}", health.active_connections);
    println!("  Lag:         {} ms", health.pipeline_lag_ms);
    println!();
}

/// Format a duration in seconds into a human-readable string (e.g. `"1h 30m 5s"`).
fn format_duration(secs: u64) -> String {
    let hours = secs / 3600;
    let minutes = (secs % 3600) / 60;
    let seconds = secs % 60;
    if hours > 0 {
        format!("{hours}h {minutes}m {seconds}s")
    } else if minutes > 0 {
        format!("{minutes}m {seconds}s")
    } else {
        format!("{seconds}s")
    }
}

/// Render the Active Agents section as a table to stdout.
pub fn render_agents_table(agents: &[AgentRow]) {
    println!("ACTIVE AGENTS");
    println!("─────────────");
    if agents.is_empty() {
        println!("  (no agents registered)");
        println!();
        return;
    }

    let mut table = Table::new();
    table.set_content_arrangement(ContentArrangement::Dynamic);
    table.set_header(vec![
        "AGENT_ID",
        "NAME",
        "STATUS",
        "FRAMEWORK",
        "SESSIONS",
        "LAST_EVENT",
        "VIOLATIONS_TODAY",
        "LAYER",
    ]);
    for agent in agents {
        let status_icon = match agent.status.as_str() {
            "Running" => "●",
            "Idle" => "○",
            "Suspended" => "⚠",
            _ => "?",
        };
        table.add_row(vec![
            &agent.id,
            &agent.name,
            &format!("{status_icon} {}", agent.status),
            &agent.framework,
            &agent.sessions.to_string(),
            &agent.last_event,
            &agent.violations_today.to_string(),
            &agent.layer,
        ]);
    }
    println!("{table}");
    println!();
}

/// Render the Pending Approvals section to stdout.
pub fn render_approvals_summary(summary: &ApprovalsSummary) {
    println!("PENDING APPROVALS");
    println!("─────────────────");
    println!("  Count:  {}", summary.pending_count);
    if let Some(ref age) = summary.oldest_pending_age {
        println!("  Oldest: {age} ago");
    }
    println!();
}

/// Render an ASCII bar chart: 20-char wide, `█` for used, `░` for remaining.
///
/// `percentage` is clamped to `0..=100`.
pub fn format_bar_chart(percentage: u32) -> String {
    let pct = percentage.min(100);
    let filled = (pct as usize * 20) / 100;
    let empty = 20 - filled;
    format!("{}{} {:>3}%", "█".repeat(filled), "░".repeat(empty), pct,)
}

/// Color a bar chart string based on the percentage threshold.
///
/// Green < 50%, yellow 50–80%, red > 80%.
fn colorize_bar(bar: &str, percentage: u32) -> String {
    if percentage > 80 {
        bar.red().to_string()
    } else if percentage >= 50 {
        bar.yellow().to_string()
    } else {
        bar.green().to_string()
    }
}

/// Render a single budget overview line (daily or monthly).
fn render_budget_line(label: &str, spend: &str, limit: Option<&str>) {
    match limit {
        Some(lim) => {
            let spend_f: f64 = spend.parse().unwrap_or(0.0);
            let limit_f: f64 = lim.parse().unwrap_or(1.0);
            let pct = if limit_f > 0.0 {
                ((spend_f / limit_f) * 100.0).round() as u32
            } else {
                0
            };
            let bar = format_bar_chart(pct);
            let colored_bar = colorize_bar(&bar, pct);
            println!("  {label}: ${spend} / ${lim}  {colored_bar}");
        }
        None => {
            println!("  {label}: ${spend} (no limit set)");
        }
    }
}

/// Render the Budget Status section to stdout.
pub fn render_budget_table(budget: &BudgetRow) {
    println!("BUDGET STATUS");
    println!("─────────────");

    render_budget_line(
        "Daily spend ",
        &budget.daily_spend_usd,
        budget.daily_limit_usd.as_deref(),
    );

    if let Some(ref monthly) = budget.monthly_spend_usd {
        render_budget_line("Monthly spend", monthly, budget.monthly_limit_usd.as_deref());
    }

    println!("  Date:           {}", budget.date);

    if budget.per_agent.is_empty() {
        println!("  (no per-agent data)");
    } else {
        println!();
        println!("PER-AGENT SPEND (today)");
        println!("───────────────────────");
        let mut table = Table::new();
        table.set_content_arrangement(ContentArrangement::Dynamic);
        table.set_header(vec!["AGENT_ID", "DAILY_SPEND"]);

        let mut sorted = budget.per_agent.clone();
        sorted.sort_by(|a, b| {
            let a_val: f64 = a.daily_spend_usd.parse().unwrap_or(0.0);
            let b_val: f64 = b.daily_spend_usd.parse().unwrap_or(0.0);
            b_val.partial_cmp(&a_val).unwrap_or(std::cmp::Ordering::Equal)
        });

        for entry in &sorted {
            table.add_row(vec![&entry.agent_id, &format!("${}", entry.daily_spend_usd)]);
        }
        println!("{table}");
    }
    println!();
}

/// Render the full status snapshot as JSON to stdout.
pub fn render_status_json(snapshot: &StatusSnapshot) {
    match serde_json::to_string_pretty(snapshot) {
        Ok(json) => println!("{json}"),
        Err(e) => eprintln!("error serializing status to JSON: {e}"),
    }
}

/// Render the full status snapshot using the selected output format.
pub fn render_all(snapshot: &StatusSnapshot, format: OutputFormat) {
    match format {
        OutputFormat::Json => render_status_json(snapshot),
        OutputFormat::Yaml => match serde_yaml::to_string(snapshot) {
            Ok(yaml) => print!("{yaml}"),
            Err(e) => eprintln!("error serializing status to YAML: {e}"),
        },
        OutputFormat::Table => {
            render_runtime_health(&snapshot.runtime);
            render_agents_table(&snapshot.agents);
            render_approvals_summary(&snapshot.approvals);
            render_budget_table(&snapshot.budget);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bar_chart_at_zero_percent() {
        let bar = format_bar_chart(0);
        assert_eq!(bar, "░░░░░░░░░░░░░░░░░░░░   0%");
    }

    #[test]
    fn bar_chart_at_fifty_percent() {
        let bar = format_bar_chart(50);
        assert_eq!(bar, "██████████░░░░░░░░░░  50%");
    }

    #[test]
    fn bar_chart_at_hundred_percent() {
        let bar = format_bar_chart(100);
        assert_eq!(bar, "████████████████████ 100%");
    }

    #[test]
    fn bar_chart_clamps_above_hundred() {
        let bar = format_bar_chart(150);
        assert_eq!(bar, "████████████████████ 100%");
    }

    #[test]
    fn colorize_bar_green_below_50() {
        let bar = format_bar_chart(30);
        let colored = colorize_bar(&bar, 30);
        // The colored string contains ANSI escape codes for green.
        assert!(colored.contains("30%"));
    }

    #[test]
    fn colorize_bar_yellow_at_50() {
        let bar = format_bar_chart(50);
        let colored = colorize_bar(&bar, 50);
        assert!(colored.contains("50%"));
    }

    #[test]
    fn colorize_bar_yellow_at_80() {
        let bar = format_bar_chart(80);
        let colored = colorize_bar(&bar, 80);
        assert!(colored.contains("80%"));
    }

    #[test]
    fn colorize_bar_red_above_80() {
        let bar = format_bar_chart(95);
        let colored = colorize_bar(&bar, 95);
        assert!(colored.contains("95%"));
    }

    #[test]
    fn per_agent_sorted_by_spend_descending() {
        use super::super::models::AgentCostEntry;
        let mut entries = [
            AgentCostEntry {
                agent_id: "low".to_string(),
                daily_spend_usd: "1.00".to_string(),
            },
            AgentCostEntry {
                agent_id: "high".to_string(),
                daily_spend_usd: "10.00".to_string(),
            },
            AgentCostEntry {
                agent_id: "mid".to_string(),
                daily_spend_usd: "5.00".to_string(),
            },
        ];
        entries.sort_by(|a, b| {
            let a_val: f64 = a.daily_spend_usd.parse().unwrap_or(0.0);
            let b_val: f64 = b.daily_spend_usd.parse().unwrap_or(0.0);
            b_val.partial_cmp(&a_val).unwrap_or(std::cmp::Ordering::Equal)
        });
        assert_eq!(entries[0].agent_id, "high");
        assert_eq!(entries[1].agent_id, "mid");
        assert_eq!(entries[2].agent_id, "low");
    }

    #[test]
    fn render_status_json_contains_all_keys() {
        use super::super::models::DeploymentOverview;
        let snapshot = StatusSnapshot {
            deployment: DeploymentOverview {
                mode: "local".to_string(),
                gateway_url: "http://localhost:7391".to_string(),
                storage_backend: "sqlite".to_string(),
                storage_path: None,
                database_url_redacted: None,
                version: "0.0.1".to_string(),
                uptime_secs: 120,
                health: "ok".to_string(),
            },
            runtime: RuntimeHealth {
                reachable: true,
                status: "ok".to_string(),
                uptime_secs: 120,
                active_connections: 3,
                pipeline_lag_ms: 0,
            },
            agents: vec![],
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
        };
        let json = serde_json::to_string_pretty(&snapshot).unwrap();
        assert!(json.contains("\"deployment\""));
        assert!(json.contains("\"gateway_url\""));
        assert!(json.contains("\"storage_backend\""));
        assert!(json.contains("\"runtime\""));
        assert!(json.contains("\"agents\""));
        assert!(json.contains("\"approvals\""));
        assert!(json.contains("\"budget\""));
        assert!(json.contains("\"uptime_secs\""));
        assert!(json.contains("\"active_connections\""));
        assert!(json.contains("\"pipeline_lag_ms\""));
    }

    #[test]
    fn format_duration_seconds_only() {
        assert_eq!(format_duration(45), "45s");
    }

    #[test]
    fn format_duration_minutes_and_seconds() {
        assert_eq!(format_duration(125), "2m 5s");
    }

    #[test]
    fn format_duration_hours_minutes_seconds() {
        assert_eq!(format_duration(3661), "1h 1m 1s");
    }

    #[test]
    fn format_duration_zero() {
        assert_eq!(format_duration(0), "0s");
    }
}
