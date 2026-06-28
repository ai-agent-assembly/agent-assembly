//! `aasm approvals list` — list pending approval requests.

use std::process::ExitCode;

use chrono::Utc;
use clap::{Args, ValueEnum};
use comfy_table::{Cell, Color, Table};

use crate::config::ResolvedContext;
use crate::output::OutputFormat;
use crate::sanitize::sanitize_terminal;

use super::client;

use super::models::{compute_timeout_color, format_countdown, ApprovalResponse, TimeoutColor};

/// Approval lifecycle status filter for `aasm approvals list --status` (AAASM-1477).
///
/// `Pending` is the default when `--status` is omitted. `Approved` /
/// `Rejected` query the resolved history (bounded; default cap 1000 entries
/// — older decisions may have been evicted on a busy gateway).
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum ApprovalStatusFilter {
    Pending,
    Approved,
    Rejected,
}

impl ApprovalStatusFilter {
    /// Lowercase wire-format value sent on the `?status=` query param.
    pub fn as_query_value(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Approved => "approved",
            Self::Rejected => "rejected",
        }
    }
}

/// Arguments for the `aasm approvals list` subcommand.
#[derive(Debug, Args)]
pub struct ListArgs {
    /// Output format override for this subcommand.
    #[arg(long, value_enum)]
    pub output: Option<OutputFormat>,
    /// Filter by approval status: `pending`, `approved`, or `rejected`.
    /// Omitted ⇒ pending only (matches pre-AAASM-1477 behavior).
    #[arg(long, value_enum)]
    pub status: Option<ApprovalStatusFilter>,
    /// Filter to approvals submitted by this agent id (exact match).
    #[arg(long)]
    pub agent: Option<String>,
}

/// Build the sanitized text columns for one approval row (everything except
/// the colour-coded TIMEOUT_IN cell).
///
/// `id`, `agent_id`, `action`, `reason`, and `created_at` are all
/// agent/server-controlled and reach the operator's terminal verbatim, so each
/// is run through [`sanitize_terminal`] to strip ANSI/OSC escapes and C0
/// control bytes (comfy_table does not strip them).
fn approval_row_text_cells(item: &ApprovalResponse) -> Vec<String> {
    vec![
        sanitize_terminal(&item.id),
        sanitize_terminal(&item.agent_id),
        sanitize_terminal(&item.action),
        sanitize_terminal(&item.reason),
        sanitize_terminal(&item.created_at),
    ]
}

/// Render a list of approval responses as a colored table to stdout.
///
/// Columns: ID, AGENT, ACTION, CONDITION, SUBMITTED_AT, TIMEOUT_IN.
/// The TIMEOUT_IN column is color-coded: red < 60s, yellow 60-180s, green > 180s.
pub fn render_approvals_table(items: &[ApprovalResponse], now_epoch: i64) {
    let mut table = Table::new();
    table.set_header(vec!["ID", "AGENT", "ACTION", "CONDITION", "SUBMITTED_AT", "TIMEOUT_IN"]);

    for item in items {
        let submitted_epoch = chrono::DateTime::parse_from_rfc3339(&item.created_at)
            .map(|dt| dt.timestamp())
            .unwrap_or(0);
        // The API does not expose timeout_secs directly; estimate as 300s default.
        let timeout_secs: i64 = 300;
        let remaining = (submitted_epoch + timeout_secs) - now_epoch;
        let color = match compute_timeout_color(remaining) {
            TimeoutColor::Red => Color::Red,
            TimeoutColor::Yellow => Color::Yellow,
            TimeoutColor::Green => Color::Green,
        };

        let mut cells: Vec<Cell> = approval_row_text_cells(item).into_iter().map(Cell::new).collect();
        cells.push(Cell::new(format_countdown(remaining)).fg(color));
        table.add_row(cells);
    }

    println!("{table}");
}

/// Execute the `aasm approvals list` subcommand.
pub fn run_list(args: ListArgs, ctx: &ResolvedContext, global_output: OutputFormat) -> ExitCode {
    let rt = tokio::runtime::Runtime::new().expect("failed to create tokio runtime");
    let status = args.status.map(|s| s.as_query_value());
    let result = rt.block_on(client::list_approvals(ctx, status, args.agent.as_deref()));

    match result {
        Ok(paginated) => {
            let format = args.output.unwrap_or(global_output);
            match format {
                OutputFormat::Json => {
                    println!("{}", serde_json::to_string_pretty(&paginated.items).unwrap_or_default());
                }
                OutputFormat::Yaml => {
                    println!("{}", serde_yaml::to_string(&paginated.items).unwrap_or_default());
                }
                OutputFormat::Table => {
                    let now = Utc::now().timestamp();
                    render_approvals_table(&paginated.items, now);
                    println!("\n{} pending approval(s)", paginated.total);
                }
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}
