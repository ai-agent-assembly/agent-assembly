//! Shared client-side types and renderer for an agent's budget rollup
//! (AAASM-1051, F100).
//!
//! Consumed by `aasm policy show <agent_id> --show-budget`. The wire schema
//! matches `aa_api::routes::agents::BudgetRollupResponse`.

use serde::Deserialize;

use crate::client;
use crate::config::ResolvedContext;
use crate::error::CliError;
use crate::output::OutputFormat;

/// One row of the rollup, mirroring `aa_api::routes::agents::BudgetRowResponse`.
#[derive(Debug, Clone, Deserialize)]
pub struct BudgetRow {
    pub scope: String,
    pub period: String,
    pub spent_usd: String,
    #[serde(default)]
    pub limit_usd: Option<String>,
    #[serde(default)]
    pub remaining_usd: Option<String>,
    #[serde(default)]
    pub percent_used: Option<f64>,
}

/// Per-agent budget rollup (text / JSON renderable).
#[derive(Debug, Clone, Deserialize)]
pub struct BudgetRollup {
    pub rows: Vec<BudgetRow>,
}

/// Fetch `/api/v1/agents/{id}/budget` for the given agent.
pub async fn fetch_budget_rollup(ctx: &ResolvedContext, agent_id: &str) -> Result<BudgetRollup, CliError> {
    let path = format!("/api/v1/agents/{agent_id}/budget");
    client::get_json(ctx, &path).await
}

/// Render a `BudgetRollup` payload to stdout in the requested format.
///
/// Text format: one section per row with scope/period header and indented
/// `spent` / `limit` / `remaining` / `% used` fields. JSON / YAML formats
/// pretty-print the wire payload as-is.
pub fn render(rollup: &BudgetRollup, output: OutputFormat) {
    match output {
        OutputFormat::Json => render_json(rollup),
        OutputFormat::Yaml => render_yaml(rollup),
        OutputFormat::Table => render_text(rollup),
    }
}

fn as_serde_value(rollup: &BudgetRollup) -> serde_json::Value {
    // Read-side types don't derive Serialize, so build the wire shape inline.
    serde_json::json!({
        "rows": rollup.rows.iter().map(|r| {
            serde_json::json!({
                "scope": r.scope,
                "period": r.period,
                "spent_usd": r.spent_usd,
                "limit_usd": r.limit_usd,
                "remaining_usd": r.remaining_usd,
                "percent_used": r.percent_used,
            })
        }).collect::<Vec<_>>(),
    })
}

fn render_json(rollup: &BudgetRollup) {
    let value = as_serde_value(rollup);
    println!(
        "{}",
        serde_json::to_string_pretty(&value).expect("serialize budget rollup")
    );
}

fn render_yaml(rollup: &BudgetRollup) {
    let value = as_serde_value(rollup);
    print!(
        "{}",
        serde_yaml::to_string(&value).expect("serialize budget rollup to yaml")
    );
}

fn render_text(rollup: &BudgetRollup) {
    if rollup.rows.is_empty() {
        println!("No budget data recorded for this agent yet.");
        return;
    }

    for row in &rollup.rows {
        let header = format!("{} · {}", row.scope, row.period);
        println!("{header}");
        println!("  Spent:     {} USD", row.spent_usd);
        match &row.limit_usd {
            Some(limit) => println!("  Limit:     {limit} USD"),
            None => println!("  Limit:     (none)"),
        }
        match &row.remaining_usd {
            Some(remaining) => println!("  Remaining: {remaining} USD"),
            None => println!("  Remaining: (n/a — no limit)"),
        }
        match row.percent_used {
            Some(pct) => println!("  Used:      {pct:.1} %"),
            None => println!("  Used:      (n/a — no limit)"),
        }
        println!();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> BudgetRollup {
        BudgetRollup {
            rows: vec![
                BudgetRow {
                    scope: "agent".to_string(),
                    period: "daily".to_string(),
                    spent_usd: "12.50".to_string(),
                    limit_usd: Some("50.00".to_string()),
                    remaining_usd: Some("37.50".to_string()),
                    percent_used: Some(25.0),
                },
                BudgetRow {
                    scope: "team:eng-platform".to_string(),
                    period: "daily".to_string(),
                    spent_usd: "120.00".to_string(),
                    limit_usd: None,
                    remaining_usd: None,
                    percent_used: None,
                },
            ],
        }
    }

    #[test]
    fn deserialize_response_shape() {
        let json = serde_json::json!({
            "rows": [
                {
                    "scope": "agent",
                    "period": "daily",
                    "spent_usd": "1.25",
                    "limit_usd": "10.00",
                    "remaining_usd": "8.75",
                    "percent_used": 12.5,
                }
            ]
        });
        let parsed: BudgetRollup = serde_json::from_value(json).unwrap();
        assert_eq!(parsed.rows.len(), 1);
        assert_eq!(parsed.rows[0].scope, "agent");
        assert_eq!(parsed.rows[0].spent_usd, "1.25");
        assert_eq!(parsed.rows[0].percent_used, Some(12.5));
    }

    #[test]
    fn deserialize_omitted_limit_fields() {
        // Server omits limit/remaining/percent when no limit is configured.
        let json = serde_json::json!({
            "rows": [
                { "scope": "org", "period": "daily", "spent_usd": "0" }
            ]
        });
        let parsed: BudgetRollup = serde_json::from_value(json).unwrap();
        assert_eq!(parsed.rows[0].limit_usd, None);
        assert_eq!(parsed.rows[0].remaining_usd, None);
        assert_eq!(parsed.rows[0].percent_used, None);
    }

    #[test]
    fn empty_rollup_renders_explicit_no_data_message() {
        let empty = BudgetRollup { rows: vec![] };
        render_text(&empty);
    }

    #[test]
    fn sample_renders_each_row_section() {
        // Smoke: render every format without panic.
        render_text(&sample());
        render_json(&sample());
        render_yaml(&sample());
    }
}
