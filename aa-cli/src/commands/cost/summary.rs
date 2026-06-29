//! `aasm cost summary` — display cost summary for the current period.

use std::process::ExitCode;

use clap::{Args, ValueEnum};
use comfy_table::Table;

use super::client;
use super::models::CostSummaryDisplay;
use crate::config::ResolvedContext;
use crate::output::OutputFormat;
use crate::sanitize::sanitize_terminal;

/// Time period for cost aggregation.
#[derive(Debug, Clone, Copy, Default, ValueEnum)]
pub enum Period {
    /// Today's spend only.
    #[default]
    Today,
    /// Current month's spend.
    Month,
}

/// Grouping dimension for cost summary.
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum GroupBy {
    /// Group by agent.
    Agent,
}

/// Arguments for `aasm cost summary`.
#[derive(Args)]
pub struct SummaryArgs {
    /// Time period to report on.
    #[arg(long, value_enum, default_value_t = Period::Today)]
    pub period: Period,

    /// Group spend by dimension.
    #[arg(long, value_enum)]
    pub group_by: Option<GroupBy>,
}

/// Run the `aasm cost summary` command.
pub fn run(args: SummaryArgs, ctx: &ResolvedContext, output: OutputFormat) -> ExitCode {
    let rt = tokio::runtime::Runtime::new().expect("failed to create tokio runtime");

    let resp = match rt.block_on(client::fetch_costs(ctx)) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::FAILURE;
        }
    };

    let display: CostSummaryDisplay = resp.into();
    render(&display, &args, output);
    ExitCode::SUCCESS
}

fn render(display: &CostSummaryDisplay, args: &SummaryArgs, output: OutputFormat) {
    match output {
        OutputFormat::Table => render_table(display, args),
        OutputFormat::Json => render_json(display),
        OutputFormat::Yaml => render_yaml(display),
    }
}

fn render_json(display: &CostSummaryDisplay) {
    match serde_json::to_string_pretty(display) {
        Ok(json) => println!("{json}"),
        Err(e) => eprintln!("error serializing JSON: {e}"),
    }
}

fn render_yaml(display: &CostSummaryDisplay) {
    match serde_yaml::to_string(display) {
        Ok(yaml) => print!("{yaml}"),
        Err(e) => eprintln!("error serializing YAML: {e}"),
    }
}

fn render_table(display: &CostSummaryDisplay, args: &SummaryArgs) {
    let spend_label = match args.period {
        Period::Today => "Daily",
        Period::Month => "Monthly",
    };

    let spend_value = match args.period {
        Period::Today => &display.daily_spend_usd,
        Period::Month => display.monthly_spend_usd.as_deref().unwrap_or("N/A"),
    };

    let limit = match args.period {
        Period::Today => display.daily_limit_usd.as_deref(),
        Period::Month => display.monthly_limit_usd.as_deref(),
    };

    // Per-agent table when --group-by agent is specified
    if matches!(args.group_by, Some(GroupBy::Agent)) && !display.per_agent.is_empty() {
        render_agent_table(display, args);
    }

    // Global summary
    println!("COST SUMMARY ({spend_label})");
    println!("──────────────────");
    // spend_value/limit_val/date are server-supplied; strip terminal escapes
    // (utilization is computed from the raw values, then itself is numeric).
    println!("  {spend_label} spend: ${}", sanitize_terminal(spend_value));
    if let Some(limit_val) = limit {
        let pct = compute_utilization_pct(spend_value, limit_val);
        println!("  Budget limit:  ${}", sanitize_terminal(limit_val));
        println!("  Utilization:   {pct}");
    }
    println!("  Date:          {}", sanitize_terminal(&display.date));
    println!();
}

fn render_agent_table(display: &CostSummaryDisplay, args: &SummaryArgs) {
    let mut table = Table::new();
    table.set_header(vec!["AGENT_ID", "DAILY_SPEND", "MONTHLY_SPEND"]);

    for agent in &display.per_agent {
        let spend = match args.period {
            Period::Today => format!("${}", agent.daily_spend_usd),
            Period::Month => agent
                .monthly_spend_usd
                .as_ref()
                .map_or("N/A".to_string(), |v| format!("${v}")),
        };
        // agent_id and the spend strings come from the server; sanitize them.
        table.add_row(vec![
            sanitize_terminal(&agent.agent_id),
            sanitize_terminal(&format!("${}", agent.daily_spend_usd)),
            sanitize_terminal(
                &agent
                    .monthly_spend_usd
                    .as_ref()
                    .map_or("N/A".to_string(), |v| format!("${v}")),
            ),
        ]);
        // Use spend to suppress unused warning in the match above
        let _ = spend;
    }

    println!("{table}");
    println!();
}

/// Compute utilization percentage string (e.g. "13.6%").
fn compute_utilization_pct(spend: &str, limit: &str) -> String {
    let spend_val: f64 = spend.parse().unwrap_or(0.0);
    let limit_val: f64 = limit.parse().unwrap_or(0.0);
    if limit_val <= 0.0 {
        return "N/A".to_string();
    }
    let pct = (spend_val / limit_val) * 100.0;
    format!("{pct:.1}%")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utilization_pct_normal() {
        assert_eq!(compute_utilization_pct("6.80", "50.00"), "13.6%");
    }

    #[test]
    fn utilization_pct_zero_limit() {
        assert_eq!(compute_utilization_pct("6.80", "0"), "N/A");
    }

    #[test]
    fn utilization_pct_zero_spend() {
        assert_eq!(compute_utilization_pct("0.00", "50.00"), "0.0%");
    }

    #[test]
    fn utilization_pct_over_budget() {
        assert_eq!(compute_utilization_pct("55.00", "50.00"), "110.0%");
    }

    #[test]
    fn cost_summary_display_serializes_to_json() {
        let display = CostSummaryDisplay {
            daily_spend_usd: "8.10".to_string(),
            monthly_spend_usd: Some("142.50".to_string()),
            date: "2026-04-30".to_string(),
            daily_limit_usd: Some("50.00".to_string()),
            monthly_limit_usd: None,
            per_agent: vec![],
        };
        let json = serde_json::to_string(&display).unwrap();
        assert!(json.contains("\"daily_spend_usd\":\"8.10\""));
        assert!(json.contains("\"daily_limit_usd\":\"50.00\""));
    }
}
