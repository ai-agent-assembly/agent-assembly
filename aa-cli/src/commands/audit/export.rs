//! `aasm audit export` — export audit data in CSV or JSON format.

use std::io::Write;
use std::process::ExitCode;

use clap::Args;

use super::list::{apply_filters, extract_policy, extract_result, extract_tool, ListArgs};
use super::models::{AuditEntry, AuditResult, ComplianceFormat, ExportFormat, PaginatedAuditResponse};
use crate::config::ResolvedContext;

/// Arguments for `aasm audit export`.
#[derive(Debug, Args)]
pub struct ExportArgs {
    /// Export file format.
    #[arg(long, value_enum)]
    pub format: ExportFormat,

    /// Compliance report format (adds metadata headers).
    #[arg(long, value_enum)]
    pub compliance: Option<ComplianceFormat>,

    /// Write output to a file instead of stdout.
    ///
    /// Renamed from `--output` to `--output-file` to avoid a clap
    /// matches-store id collision with the top-level
    /// `Cli::output: OutputFormat` global flag — the duplicate id used
    /// to panic on downcast at every `aasm audit export` invocation
    /// (AAASM-1479).
    #[arg(long)]
    pub output_file: Option<String>,

    /// Filter by agent identifier.
    #[arg(long)]
    pub agent: Option<String>,

    /// Filter by action type.
    #[arg(long)]
    pub action: Option<String>,

    /// Filter by policy decision result.
    #[arg(long, value_enum)]
    pub result: Option<AuditResult>,

    /// Show events after this duration or ISO 8601 timestamp.
    #[arg(long)]
    pub since: Option<String>,

    /// Show events before this ISO 8601 timestamp.
    #[arg(long)]
    pub until: Option<String>,

    /// Maximum number of entries to fetch.
    #[arg(long, default_value_t = 1000)]
    pub limit: u32,
}

impl ExportArgs {
    /// Convert export filter flags into the shared `ListArgs` for reuse.
    fn as_list_args(&self) -> ListArgs {
        ListArgs {
            agent: self.agent.clone(),
            action: self.action.clone(),
            result: self.result,
            since: self.since.clone(),
            until: self.until.clone(),
            limit: self.limit,
        }
    }
}

/// Build the query URL for `GET /api/v1/logs` with filter parameters.
fn build_url(ctx: &ResolvedContext, args: &ExportArgs) -> String {
    let mut url = format!("{}/api/v1/logs?per_page={}&page=1", ctx.api_url, args.limit);

    if let Some(ref agent) = args.agent {
        url.push_str(&format!("&agent_id={agent}"));
    }

    if let Some(ref action) = args.action {
        url.push_str(&format!("&event_type={action}"));
    }

    url
}

/// Generate compliance metadata header block.
pub fn compliance_header(format: ComplianceFormat) -> String {
    let now = chrono::Utc::now().to_rfc3339();
    match format {
        ComplianceFormat::EuAiAct => {
            format!(
                "# EU AI Act Compliance Report\n\
                 # Generated: {now}\n\
                 # Framework: EU Artificial Intelligence Act (Regulation 2024/1689)\n\
                 # Category: High-risk AI system audit log\n\
                 #\n"
            )
        }
        ComplianceFormat::Soc2 => {
            format!(
                "# SOC 2 Type II Audit Report\n\
                 # Generated: {now}\n\
                 # Framework: AICPA SOC 2 Trust Services Criteria\n\
                 # Scope: AI governance decision log\n\
                 #\n"
            )
        }
    }
}

/// Write audit entries as CSV to the given writer.
pub fn write_csv<W: Write>(entries: &[AuditEntry], mut writer: W) -> Result<(), Box<dyn std::error::Error>> {
    let mut wtr = csv::Writer::from_writer(&mut writer);
    wtr.write_record([
        "timestamp",
        "agent_id",
        "session_id",
        "event_type",
        "tool",
        "result",
        "policy",
    ])?;

    for entry in entries {
        let result = extract_result(entry).unwrap_or_default();
        let tool = extract_tool(entry);
        let policy = extract_policy(entry);

        wtr.write_record([
            &entry.timestamp,
            &entry.agent_id,
            &entry.session_id,
            &entry.event_type,
            &tool,
            &result,
            &policy,
        ])?;
    }
    wtr.flush()?;
    Ok(())
}

/// Write audit entries as a JSON array to the given writer.
pub fn write_json<W: Write>(entries: &[AuditEntry], mut writer: W) -> Result<(), Box<dyn std::error::Error>> {
    let json = serde_json::to_string_pretty(entries)?;
    writer.write_all(json.as_bytes())?;
    writer.write_all(b"\n")?;
    Ok(())
}

/// Write compliance header (if any) and formatted entries to a writer.
fn write_to<W: Write>(
    entries: &[AuditEntry],
    args: &ExportArgs,
    writer: &mut W,
) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(compliance) = args.compliance {
        let header = compliance_header(compliance);
        writer.write_all(header.as_bytes())?;
    }
    match args.format {
        ExportFormat::Csv => write_csv(entries, writer),
        ExportFormat::Json => write_json(entries, writer),
    }
}

/// Execute `aasm audit export`.
pub fn run(args: ExportArgs, ctx: &ResolvedContext) -> ExitCode {
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

    let list_args = args.as_list_args();
    let filtered = apply_filters(&paginated.items, &list_args);

    // Determine output destination.
    let write_result: Result<(), Box<dyn std::error::Error>> = if let Some(ref path) = args.output_file {
        let file = match std::fs::File::create(path) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("error: cannot create file {path}: {e}");
                return ExitCode::FAILURE;
            }
        };
        let mut writer = std::io::BufWriter::new(file);
        write_to(&filtered, &args, &mut writer)
    } else {
        let stdout = std::io::stdout();
        let mut writer = stdout.lock();
        write_to(&filtered, &args, &mut writer)
    };

    match write_result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: export failed: {e}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_entries() -> Vec<AuditEntry> {
        vec![
            AuditEntry {
                seq: 0,
                timestamp: "2026-04-30T10:00:00Z".to_string(),
                agent_id: "aa001".to_string(),
                session_id: "sess001".to_string(),
                event_type: "ToolCallIntercepted".to_string(),
                payload: r#"{"tool":"bash","result":"allow","policy":"default"}"#.to_string(),
            },
            AuditEntry {
                seq: 1,
                timestamp: "2026-04-30T10:01:00Z".to_string(),
                agent_id: "aa002".to_string(),
                session_id: "sess002".to_string(),
                event_type: "PolicyViolation".to_string(),
                payload: r#"{"tool":"rm","result":"deny","policy":"deny-rm"}"#.to_string(),
            },
        ]
    }

    #[test]
    fn write_csv_produces_valid_output() {
        let entries = sample_entries();
        let mut buf = Vec::new();
        write_csv(&entries, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();

        let lines: Vec<&str> = output.lines().collect();
        assert_eq!(lines[0], "timestamp,agent_id,session_id,event_type,tool,result,policy");
        assert!(lines[1].contains("aa001"));
        assert!(lines[1].contains("allow"));
        assert!(lines[2].contains("aa002"));
        assert!(lines[2].contains("deny"));
    }

    #[test]
    fn write_csv_empty_entries() {
        let mut buf = Vec::new();
        write_csv(&[], &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        let lines: Vec<&str> = output.lines().collect();
        assert_eq!(lines.len(), 1); // header only
        assert!(lines[0].contains("timestamp"));
    }

    #[test]
    fn write_json_produces_valid_array() {
        let entries = sample_entries();
        let mut buf = Vec::new();
        write_json(&entries, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();

        let parsed: Vec<AuditEntry> = serde_json::from_str(&output).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].agent_id, "aa001");
        assert_eq!(parsed[1].agent_id, "aa002");
    }

    #[test]
    fn write_json_empty_entries() {
        let mut buf = Vec::new();
        write_json(&[], &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();

        let parsed: Vec<AuditEntry> = serde_json::from_str(&output).unwrap();
        assert!(parsed.is_empty());
    }

    #[test]
    fn compliance_header_eu_ai_act() {
        let header = compliance_header(ComplianceFormat::EuAiAct);
        assert!(header.contains("EU AI Act"));
        assert!(header.contains("Regulation 2024/1689"));
        assert!(header.contains("Generated:"));
    }

    #[test]
    fn compliance_header_soc2() {
        let header = compliance_header(ComplianceFormat::Soc2);
        assert!(header.contains("SOC 2"));
        assert!(header.contains("AICPA"));
        assert!(header.contains("Generated:"));
    }

    #[test]
    fn build_url_no_filters() {
        let ctx = ResolvedContext {
            name: None,
            api_url: "http://localhost:8080".to_string(),
            api_key: None,
        };
        let args = ExportArgs {
            format: ExportFormat::Csv,
            compliance: None,
            output_file: None,
            agent: None,
            action: None,
            result: None,
            since: None,
            until: None,
            limit: 1000,
        };
        let url = build_url(&ctx, &args);
        assert_eq!(url, "http://localhost:8080/api/v1/logs?per_page=1000&page=1");
    }

    #[test]
    fn build_url_with_filters() {
        let ctx = ResolvedContext {
            name: None,
            api_url: "http://localhost:8080".to_string(),
            api_key: None,
        };
        let args = ExportArgs {
            format: ExportFormat::Json,
            compliance: None,
            output_file: None,
            agent: Some("aa001".to_string()),
            action: Some("PolicyViolation".to_string()),
            result: None,
            since: None,
            until: None,
            limit: 500,
        };
        let url = build_url(&ctx, &args);
        assert!(url.contains("agent_id=aa001"));
        assert!(url.contains("event_type=PolicyViolation"));
    }

    #[test]
    fn export_args_as_list_args_preserves_filters() {
        let args = ExportArgs {
            format: ExportFormat::Csv,
            compliance: None,
            output_file: None,
            agent: Some("aa001".to_string()),
            action: Some("PolicyViolation".to_string()),
            result: Some(AuditResult::Deny),
            since: Some("30m".to_string()),
            until: Some("2026-04-30T12:00:00Z".to_string()),
            limit: 100,
        };
        let list_args = args.as_list_args();
        assert_eq!(list_args.agent.as_deref(), Some("aa001"));
        assert_eq!(list_args.action.as_deref(), Some("PolicyViolation"));
        assert_eq!(list_args.result, Some(AuditResult::Deny));
        assert_eq!(list_args.since.as_deref(), Some("30m"));
        assert_eq!(list_args.until.as_deref(), Some("2026-04-30T12:00:00Z"));
        assert_eq!(list_args.limit, 100);
    }
}
