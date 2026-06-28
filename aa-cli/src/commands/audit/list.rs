//! `aasm audit list` — query and display audit log entries.

use std::process::ExitCode;

use clap::Args;
use colored::Colorize;
use comfy_table::{ContentArrangement, Table};

use super::models::{AuditEntry, AuditResult, PaginatedAuditResponse};
use crate::commands::logs::format::{is_within_time_range, parse_since, parse_until};
use crate::config::ResolvedContext;
use crate::output::OutputFormat;
use crate::sanitize::sanitize_terminal;

/// Arguments for `aasm audit list`.
#[derive(Debug, Args)]
pub struct ListArgs {
    /// Filter by agent identifier.
    #[arg(long)]
    pub agent: Option<String>,

    /// Filter by action type (e.g. `ToolCallIntercepted`, `PolicyViolation`).
    #[arg(long)]
    pub action: Option<String>,

    /// Filter by policy decision result.
    #[arg(long, value_enum)]
    pub result: Option<AuditResult>,

    /// Show events after this duration or ISO 8601 timestamp (e.g. `30m`, `2h`, `2026-04-30T10:00:00Z`).
    #[arg(long)]
    pub since: Option<String>,

    /// Show events before this ISO 8601 timestamp.
    #[arg(long)]
    pub until: Option<String>,

    /// Maximum number of entries to return.
    #[arg(long, default_value_t = 50)]
    pub limit: u32,

    /// Show only sandbox / observe-mode shadow events — entries the gateway
    /// recorded with `dry_run: true` because policy was evaluated in observe
    /// mode (AAASM-1564). When this flag is OFF (the default), shadow events
    /// are hidden so operators see only live enforcement decisions.
    #[arg(long)]
    pub dry_run_only: bool,
}

/// Build the query URL for `GET /api/v1/logs` with filter parameters.
fn build_url(ctx: &ResolvedContext, args: &ListArgs) -> String {
    let mut url = format!("{}/api/v1/logs?per_page={}&page=1", ctx.api_url, args.limit);

    if let Some(ref agent) = args.agent {
        url.push_str(&format!("&agent_id={agent}"));
    }

    if let Some(ref action) = args.action {
        url.push_str(&format!("&event_type={action}"));
    }

    url
}

/// Extract a policy result string from the entry's payload JSON.
///
/// Looks for a `"result"` key in the payload. Returns `None` if the payload
/// is not valid JSON or does not contain the key.
pub fn extract_result(entry: &AuditEntry) -> Option<String> {
    serde_json::from_str::<serde_json::Value>(&entry.payload)
        .ok()
        .and_then(|v| v.get("result").and_then(|r| r.as_str()).map(String::from))
}

/// Extract a tool name from the entry's payload JSON.
pub fn extract_tool(entry: &AuditEntry) -> String {
    serde_json::from_str::<serde_json::Value>(&entry.payload)
        .ok()
        .and_then(|v| v.get("tool").and_then(|t| t.as_str()).map(String::from))
        .unwrap_or_else(|| "-".to_string())
}

/// Extract the `dry_run` flag from the entry's payload JSON.
///
/// Returns `true` when the gateway tagged this entry as an observe-mode
/// shadow event (AAASM-1564). Returns `false` for every other case —
/// missing key, non-bool value, payload that isn't valid JSON.
pub fn extract_dry_run(entry: &AuditEntry) -> bool {
    serde_json::from_str::<serde_json::Value>(&entry.payload)
        .ok()
        .and_then(|v| v.get("dry_run").and_then(|d| d.as_bool()))
        .unwrap_or(false)
}

/// Extract a policy name from the entry's payload JSON.
pub fn extract_policy(entry: &AuditEntry) -> String {
    serde_json::from_str::<serde_json::Value>(&entry.payload)
        .ok()
        .and_then(|v| v.get("policy").and_then(|p| p.as_str()).map(String::from))
        .unwrap_or_else(|| "-".to_string())
}

/// Check whether an entry matches the `--result` filter.
fn matches_result_filter(entry: &AuditEntry, filter: &AuditResult) -> bool {
    match extract_result(entry) {
        Some(result) => result == filter.as_filter_str(),
        None => false,
    }
}

/// Apply client-side filters (time range, result, dry-run) to entries.
///
/// `--dry-run-only` is an exclusive filter:
///
/// * OFF (default) → entries with `dry_run: true` are **hidden**, so the
///   default `aa audit list` view shows live enforcement decisions only and
///   doesn't get noisy as soon as anyone runs an agent under observe mode.
/// * ON → entries with `dry_run: true` are **the only ones kept**, so an
///   operator tuning a sandbox policy sees exactly the would-be violations.
pub fn apply_filters(entries: &[AuditEntry], args: &ListArgs) -> Vec<AuditEntry> {
    let since = args.since.as_deref().and_then(parse_since);
    let until = args.until.as_deref().and_then(parse_until);

    entries
        .iter()
        .filter(|e| is_within_time_range(&e.timestamp, since.as_ref(), until.as_ref()))
        .filter(|e| args.result.as_ref().map_or(true, |r| matches_result_filter(e, r)))
        .filter(|e| {
            if args.dry_run_only {
                extract_dry_run(e)
            } else {
                !extract_dry_run(e)
            }
        })
        .cloned()
        .collect()
}

/// Color-code the result string: allow=green, deny=red, pending=yellow.
fn colorize_result(result: &str) -> String {
    match result {
        "allow" => result.green().to_string(),
        "deny" => result.red().to_string(),
        "pending" => result.yellow().to_string(),
        other => other.to_string(),
    }
}

/// Render audit entries as a table to stdout.
pub fn render_table(entries: &[AuditEntry]) {
    if entries.is_empty() {
        println!("(no audit entries found)");
        return;
    }

    let mut table = Table::new();
    table.set_content_arrangement(ContentArrangement::Dynamic);
    table.set_header(vec!["TIMESTAMP", "AGENT", "ACTION", "TOOL", "RESULT", "POLICY"]);

    for entry in entries {
        let result_raw = extract_result(entry).unwrap_or_else(|| "-".to_string());
        // All fields originate from the server audit entry / its payload JSON;
        // strip terminal escapes (colour is applied after sanitization, and
        // colorize_result matches the sanitized exact values allow/deny/pending).
        let result_colored = colorize_result(&sanitize_terminal(&result_raw));
        let tool = sanitize_terminal(&extract_tool(entry));
        let policy = sanitize_terminal(&extract_policy(entry));

        table.add_row(vec![
            sanitize_terminal(&entry.timestamp),
            sanitize_terminal(&entry.agent_id),
            sanitize_terminal(&entry.event_type),
            tool,
            result_colored,
            policy,
        ]);
    }
    println!("{table}");
}

/// Render audit entries as JSON to stdout.
fn render_json(entries: &[AuditEntry]) {
    match serde_json::to_string_pretty(entries) {
        Ok(json) => println!("{json}"),
        Err(e) => eprintln!("error serializing audit entries to JSON: {e}"),
    }
}

/// Render audit entries as YAML to stdout.
fn render_yaml(entries: &[AuditEntry]) {
    match serde_yaml::to_string(entries) {
        Ok(yaml) => print!("{yaml}"),
        Err(e) => eprintln!("error serializing audit entries to YAML: {e}"),
    }
}

/// Execute `aasm audit list`.
pub fn run(args: ListArgs, ctx: &ResolvedContext, output: OutputFormat) -> ExitCode {
    let url = build_url(ctx, &args);

    let response = match reqwest::blocking::get(&url) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: failed to connect to {}: {e}", ctx.api_url);
            return ExitCode::FAILURE;
        }
    };

    if !response.status().is_success() {
        eprintln!("error: API returned status {}", response.status());
        return ExitCode::FAILURE;
    }

    let paginated: PaginatedAuditResponse = match response.json() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("error: failed to parse API response: {e}");
            return ExitCode::FAILURE;
        }
    };

    let filtered = apply_filters(&paginated.items, &args);

    match output {
        OutputFormat::Table => render_table(&filtered),
        OutputFormat::Json => render_json(&filtered),
        OutputFormat::Yaml => render_yaml(&filtered),
    }

    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_entry(event_type: &str, payload: &str) -> AuditEntry {
        AuditEntry {
            seq: 0,
            timestamp: "2026-04-30T10:00:00Z".to_string(),
            agent_id: "aa001".to_string(),
            session_id: "sess001".to_string(),
            event_type: event_type.to_string(),
            payload: payload.to_string(),
        }
    }

    #[test]
    fn extract_result_from_valid_payload() {
        let entry = sample_entry("PolicyViolation", r#"{"result":"deny","tool":"bash"}"#);
        assert_eq!(extract_result(&entry).as_deref(), Some("deny"));
    }

    #[test]
    fn extract_result_missing_key() {
        let entry = sample_entry("ToolCallIntercepted", r#"{"tool":"bash"}"#);
        assert_eq!(extract_result(&entry), None);
    }

    #[test]
    fn extract_result_invalid_json() {
        let entry = sample_entry("ToolCallIntercepted", "not json");
        assert_eq!(extract_result(&entry), None);
    }

    #[test]
    fn extract_tool_from_payload() {
        let entry = sample_entry("ToolCallIntercepted", r#"{"tool":"bash","result":"allow"}"#);
        assert_eq!(extract_tool(&entry), "bash");
    }

    #[test]
    fn extract_tool_missing_returns_dash() {
        let entry = sample_entry("ToolCallIntercepted", r#"{"result":"allow"}"#);
        assert_eq!(extract_tool(&entry), "-");
    }

    #[test]
    fn extract_policy_from_payload() {
        let entry = sample_entry("PolicyViolation", r#"{"policy":"deny-rm","result":"deny"}"#);
        assert_eq!(extract_policy(&entry), "deny-rm");
    }

    #[test]
    fn extract_policy_missing_returns_dash() {
        let entry = sample_entry("PolicyViolation", r#"{"result":"deny"}"#);
        assert_eq!(extract_policy(&entry), "-");
    }

    #[test]
    fn matches_result_filter_allow() {
        let entry = sample_entry("ToolCallIntercepted", r#"{"result":"allow"}"#);
        assert!(matches_result_filter(&entry, &AuditResult::Allow));
        assert!(!matches_result_filter(&entry, &AuditResult::Deny));
    }

    #[test]
    fn matches_result_filter_deny() {
        let entry = sample_entry("PolicyViolation", r#"{"result":"deny"}"#);
        assert!(matches_result_filter(&entry, &AuditResult::Deny));
        assert!(!matches_result_filter(&entry, &AuditResult::Allow));
    }

    #[test]
    fn matches_result_filter_no_result_in_payload() {
        let entry = sample_entry("BudgetLimitApproached", "{}");
        assert!(!matches_result_filter(&entry, &AuditResult::Allow));
    }

    #[test]
    fn apply_filters_no_filters() {
        let entries = vec![
            sample_entry("ToolCallIntercepted", r#"{"result":"allow"}"#),
            sample_entry("PolicyViolation", r#"{"result":"deny"}"#),
        ];
        let args = ListArgs {
            agent: None,
            action: None,
            result: None,
            since: None,
            until: None,
            limit: 50,
            dry_run_only: false,
        };
        let filtered = apply_filters(&entries, &args);
        assert_eq!(filtered.len(), 2);
    }

    #[test]
    fn apply_filters_by_result() {
        let entries = vec![
            sample_entry("ToolCallIntercepted", r#"{"result":"allow"}"#),
            sample_entry("PolicyViolation", r#"{"result":"deny"}"#),
            sample_entry("ApprovalRequested", r#"{"result":"pending"}"#),
        ];
        let args = ListArgs {
            agent: None,
            action: None,
            result: Some(AuditResult::Deny),
            since: None,
            until: None,
            limit: 50,
            dry_run_only: false,
        };
        let filtered = apply_filters(&entries, &args);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].event_type, "PolicyViolation");
    }

    #[test]
    fn apply_filters_by_time_range() {
        let mut e1 = sample_entry("ToolCallIntercepted", r#"{"result":"allow"}"#);
        e1.timestamp = "2026-04-30T08:00:00Z".to_string();
        let mut e2 = sample_entry("PolicyViolation", r#"{"result":"deny"}"#);
        e2.timestamp = "2026-04-30T12:00:00Z".to_string();

        let entries = vec![e1, e2];
        let args = ListArgs {
            agent: None,
            action: None,
            result: None,
            since: Some("2026-04-30T10:00:00Z".to_string()),
            until: None,
            limit: 50,
            dry_run_only: false,
        };
        let filtered = apply_filters(&entries, &args);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].timestamp, "2026-04-30T12:00:00Z");
    }

    #[test]
    fn build_url_no_filters() {
        let ctx = ResolvedContext {
            name: None,
            api_url: "http://localhost:8080".to_string(),
            api_key: None,
        };
        let args = ListArgs {
            agent: None,
            action: None,
            result: None,
            since: None,
            until: None,
            limit: 50,
            dry_run_only: false,
        };
        let url = build_url(&ctx, &args);
        assert_eq!(url, "http://localhost:8080/api/v1/logs?per_page=50&page=1");
    }

    #[test]
    fn build_url_with_agent_and_action() {
        let ctx = ResolvedContext {
            name: None,
            api_url: "http://localhost:8080".to_string(),
            api_key: None,
        };
        let args = ListArgs {
            agent: Some("aa001".to_string()),
            action: Some("PolicyViolation".to_string()),
            result: None,
            since: None,
            until: None,
            limit: 25,
            dry_run_only: false,
        };
        let url = build_url(&ctx, &args);
        assert!(url.contains("agent_id=aa001"));
        assert!(url.contains("event_type=PolicyViolation"));
        assert!(url.contains("per_page=25"));
    }

    // --- dry-run-only filter (AAASM-1559) ---

    #[test]
    fn extract_dry_run_reads_true_from_payload() {
        // Mirrors the JSON shape that aa-gateway/policy_service.rs::record_audit
        // produces when shadow events fire (see AAASM-1564).
        let entry = sample_entry(
            "ToolCallIntercepted",
            r#"{"decision":1,"dry_run":true,"shadow_decision":"deny"}"#,
        );
        assert!(extract_dry_run(&entry));
    }

    #[test]
    fn extract_dry_run_defaults_to_false_when_key_missing_or_wrong_type() {
        // Live (non-observe) entries don't carry the key. Malformed entries
        // must also report false rather than panic so a flaky producer
        // doesn't drop the whole listing.
        let live = sample_entry("PolicyViolation", r#"{"result":"deny"}"#);
        assert!(!extract_dry_run(&live));

        let wrong_type = sample_entry("ToolCallIntercepted", r#"{"dry_run":"true"}"#);
        assert!(!extract_dry_run(&wrong_type));

        let not_json = sample_entry("ToolCallIntercepted", "not even json");
        assert!(!extract_dry_run(&not_json));
    }

    fn observe_entry() -> AuditEntry {
        sample_entry(
            "ToolCallIntercepted",
            r#"{"decision":1,"dry_run":true,"shadow_decision":"deny","shadow_reason":"tool denied by policy"}"#,
        )
    }

    fn live_entry() -> AuditEntry {
        sample_entry("ToolCallIntercepted", r#"{"result":"allow"}"#)
    }

    #[test]
    fn default_apply_filters_hides_dry_run_entries() {
        // The whole point of making --dry-run-only an exclusive filter: the
        // operator running `aa audit list` without flags must not see
        // shadow events mixed in with their live enforcement decisions.
        let entries = vec![live_entry(), observe_entry()];
        let args = ListArgs {
            agent: None,
            action: None,
            result: None,
            since: None,
            until: None,
            limit: 50,
            dry_run_only: false,
        };
        let filtered = apply_filters(&entries, &args);
        assert_eq!(filtered.len(), 1);
        assert!(!extract_dry_run(&filtered[0]));
    }

    #[test]
    fn apply_filters_with_dry_run_only_keeps_only_shadow_entries() {
        // The complementary case: --dry-run-only drops the live entries and
        // surfaces just the would-be ones.
        let entries = vec![live_entry(), observe_entry(), live_entry(), observe_entry()];
        let args = ListArgs {
            agent: None,
            action: None,
            result: None,
            since: None,
            until: None,
            limit: 50,
            dry_run_only: true,
        };
        let filtered = apply_filters(&entries, &args);
        assert_eq!(filtered.len(), 2);
        assert!(filtered.iter().all(extract_dry_run));
    }

    #[test]
    fn dry_run_only_composes_with_since_filter() {
        // --dry-run-only + --since must compose: the time window cuts first,
        // then the dry-run filter, so a long-tail observe-mode audit log
        // returns only the recent shadow events.
        let mut old_shadow = observe_entry();
        old_shadow.timestamp = "2026-04-30T08:00:00Z".to_string();
        let mut recent_shadow = observe_entry();
        recent_shadow.timestamp = "2026-04-30T12:00:00Z".to_string();
        let mut recent_live = live_entry();
        recent_live.timestamp = "2026-04-30T12:30:00Z".to_string();

        let entries = vec![old_shadow, recent_shadow.clone(), recent_live];
        let args = ListArgs {
            agent: None,
            action: None,
            result: None,
            since: Some("2026-04-30T10:00:00Z".to_string()),
            until: None,
            limit: 50,
            dry_run_only: true,
        };
        let filtered = apply_filters(&entries, &args);
        assert_eq!(
            filtered.len(),
            1,
            "only the recent shadow entry should survive both filters"
        );
        assert_eq!(filtered[0].timestamp, recent_shadow.timestamp);
    }

    #[test]
    fn colorize_result_colors() {
        let allow = colorize_result("allow");
        assert!(allow.contains("allow"));
        let deny = colorize_result("deny");
        assert!(deny.contains("deny"));
        let pending = colorize_result("pending");
        assert!(pending.contains("pending"));
        let unknown = colorize_result("other");
        assert_eq!(unknown, "other");
    }
}
