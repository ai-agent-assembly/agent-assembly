//! Shared client-side types and renderer for an agent's budget rollup
//! (AAASM-1051, F100).
//!
//! Consumed by `aasm policy show <agent_id> --show-budget`. The wire schema
//! matches `aa_api::routes::agents::BudgetRollupResponse`.

use comfy_table::{ContentArrangement, Table};
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
/// Text format (default): a `comfy-table` with one row per rollup row.
/// Columns are `Scope` / `Period` / `Spent` / `Limit` / `Remaining` / `Used %`.
/// USD amounts are formatted with a `$` prefix and thousands separators
/// (e.g. `$12,500.50`); the server already rounded to 2 decimals via
/// `Decimal::round_dp(2)`. JSON / YAML formats serialise the raw response.
pub fn render(rollup: &BudgetRollup, output: OutputFormat) {
    let mut stdout = std::io::stdout().lock();
    render_to(rollup, output, &mut stdout).expect("write budget rollup to stdout");
}

/// Render a `BudgetRollup` to an arbitrary writer.
///
/// Same output shape as [`render`]; exposed so integration tests can capture
/// and assert against the bytes without spawning a subprocess.
pub fn render_to<W: std::io::Write>(rollup: &BudgetRollup, output: OutputFormat, w: &mut W) -> std::io::Result<()> {
    match output {
        OutputFormat::Json => render_json(rollup, w),
        OutputFormat::Yaml => render_yaml(rollup, w),
        OutputFormat::Table => render_text(rollup, w),
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

fn render_json<W: std::io::Write>(rollup: &BudgetRollup, w: &mut W) -> std::io::Result<()> {
    let value = as_serde_value(rollup);
    let s = serde_json::to_string_pretty(&value).expect("serialize budget rollup");
    writeln!(w, "{s}")
}

fn render_yaml<W: std::io::Write>(rollup: &BudgetRollup, w: &mut W) -> std::io::Result<()> {
    let value = as_serde_value(rollup);
    let s = serde_yaml::to_string(&value).expect("serialize budget rollup to yaml");
    write!(w, "{s}")
}

fn render_text<W: std::io::Write>(rollup: &BudgetRollup, w: &mut W) -> std::io::Result<()> {
    if rollup.rows.is_empty() {
        return writeln!(w, "No budget data recorded for this agent yet.");
    }

    let mut table = Table::new();
    table
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(vec!["Scope", "Period", "Spent", "Limit", "Remaining", "Used %"]);

    for row in &rollup.rows {
        table.add_row(vec![
            row.scope.clone(),
            row.period.clone(),
            format_usd(&row.spent_usd),
            row.limit_usd
                .as_deref()
                .map(format_usd)
                .unwrap_or_else(|| "—".to_string()),
            row.remaining_usd
                .as_deref()
                .map(format_usd)
                .unwrap_or_else(|| "—".to_string()),
            row.percent_used
                .map(|p| format!("{p:.1}%"))
                .unwrap_or_else(|| "—".to_string()),
        ]);
    }

    writeln!(w, "{table}")
}

/// Render a server-rounded USD string with a `$` prefix and thousands
/// separators in the integer part. Closes AAASM-1051 AC bullet
/// "tokens with thousands separator".
///
/// Input is a canonical decimal string from the API (e.g. `"12500.50"` or
/// `"-3.00"`); the server guarantees exactly two decimals via
/// `Decimal::round_dp(2)`. Falls back to the raw input verbatim if the
/// string is malformed — robustness over precision for a presentation path.
fn format_usd(raw: &str) -> String {
    // Split into sign, integer part, fractional part. Anything we can't
    // parse falls back to the input wrapped in `$`.
    let (sign, rest) = if let Some(stripped) = raw.strip_prefix('-') {
        ("-", stripped)
    } else {
        ("", raw)
    };
    let (int_part, frac_part) = match rest.split_once('.') {
        Some((i, f)) => (i, f),
        None => (rest, "00"),
    };
    if int_part.is_empty() || !int_part.bytes().all(|b| b.is_ascii_digit()) {
        return format!("${raw}");
    }
    // Insert thousands separators.
    let mut grouped = String::with_capacity(int_part.len() + int_part.len() / 3);
    for (i, ch) in int_part.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 {
            grouped.push(',');
        }
        grouped.push(ch);
    }
    let int_with_commas: String = grouped.chars().rev().collect();
    format!("{sign}${int_with_commas}.{frac_part}")
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
                    spent_usd: "12500.00".to_string(),
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
        let mut buf = Vec::new();
        render_text(&empty, &mut buf).unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("No budget data"));
    }

    #[test]
    fn sample_renders_each_row_section() {
        // Smoke: render every format without panic.
        let mut buf = Vec::new();
        render_text(&sample(), &mut buf).unwrap();
        render_json(&sample(), &mut buf).unwrap();
        render_yaml(&sample(), &mut buf).unwrap();
    }

    #[test]
    fn format_usd_inserts_thousands_separators_and_dollar_sign() {
        assert_eq!(format_usd("12500.50"), "$12,500.50");
        assert_eq!(format_usd("1.25"), "$1.25");
        assert_eq!(format_usd("1234567.89"), "$1,234,567.89");
        assert_eq!(format_usd("0.00"), "$0.00");
    }

    #[test]
    fn format_usd_preserves_negative_sign_before_dollar() {
        assert_eq!(format_usd("-3.00"), "-$3.00");
        assert_eq!(format_usd("-12500.00"), "-$12,500.00");
    }

    #[test]
    fn format_usd_falls_back_to_raw_on_malformed_input() {
        // Anything we can't parse comes back wrapped — robustness for a
        // presentation path that should never panic.
        assert_eq!(format_usd("not-a-number"), "$not-a-number");
        assert_eq!(format_usd(""), "$");
    }
}
