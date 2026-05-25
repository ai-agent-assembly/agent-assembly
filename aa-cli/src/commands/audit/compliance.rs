//! `aasm audit compliance-export` — full-fidelity audit export for regulators
//! and SIEM consumers.
//!
//! Unlike `aasm audit export` (which reads the slim REST view served by
//! `GET /api/v1/logs`), this command reads per-session JSONL audit files
//! directly from disk so the hash chain (`previous_hash` / `entry_hash`),
//! credential findings, and delegation lineage carried by
//! [`aa_core::AuditEntry`] survive end-to-end.

use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use aa_core::AuditEntry;
use clap::Args;

use super::export::compliance_header;
use super::models::{ComplianceFormat, ComplianceRecord, ExportFormat};
use crate::commands::logs::format::{is_within_time_range, parse_since, parse_until};

/// Read one per-session audit JSONL file from disk into audit entries in file order.
///
/// Each line of the input must be a single JSON document produced by the
/// gateway's audit writer. Blank lines are skipped so a trailing newline does
/// not produce a parse error. A malformed line aborts the read with the
/// underlying I/O or serde error.
pub fn load_jsonl_file(path: &Path) -> Result<Vec<AuditEntry>, Box<dyn std::error::Error>> {
    let reader = BufReader::new(File::open(path)?);
    let mut entries = Vec::new();
    for line in reader.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let entry: AuditEntry = serde_json::from_str(&line)?;
        entries.push(entry);
    }
    Ok(entries)
}

/// Convert a full-fidelity on-disk [`AuditEntry`] into a [`ComplianceRecord`]
/// suitable for compliance export.
///
/// The mapping is intentionally lossless for the regulator-relevant fields:
///
/// * `timestamp_ns` (u64 nanoseconds since the Unix epoch) → ISO 8601 UTC
///   string. Returns an empty string when the nanosecond value cannot be
///   converted to a valid [`chrono::DateTime`] (this should not happen for
///   any entry the gateway writes today; the conversion is fail-soft so
///   one malformed entry does not abort an export of thousands).
/// * `agent_id` / `session_id` / `previous_hash` / `entry_hash` → hex-encoded
///   strings, matching the convention used by `aa-api/src/routes/logs.rs`
///   for `agent_id` and `session_id` and by `aasm audit verify-chain` for
///   the hash chain.
/// * `event_type` → its canonical `as_str()` label.
/// * `credential_findings` cloned through — each finding carries `kind`,
///   `offset`, and the redacted `[REDACTED:<Kind>]` label. The raw secret
///   value is not stored in the finding so the export never carries it.
/// * `redacted_payload`, lineage fields → cloned through verbatim.
pub fn map_audit_entry(entry: &AuditEntry) -> ComplianceRecord {
    let ts_secs = (entry.timestamp_ns() / 1_000_000_000) as i64;
    let ts_nanos = (entry.timestamp_ns() % 1_000_000_000) as u32;
    let timestamp = chrono::DateTime::from_timestamp(ts_secs, ts_nanos)
        .map(|dt| dt.to_rfc3339())
        .unwrap_or_default();

    ComplianceRecord {
        seq: entry.seq(),
        timestamp,
        event_type: entry.event_type().as_str().to_string(),
        agent_id: hex::encode(entry.agent_id().as_bytes()),
        session_id: hex::encode(entry.session_id().as_bytes()),
        payload: entry.payload().to_string(),
        previous_hash: hex::encode(entry.previous_hash()),
        entry_hash: hex::encode(entry.entry_hash()),
        credential_findings: entry.credential_findings().to_vec(),
        redacted_payload: entry.redacted_payload().map(|s| s.to_string()),
        root_agent_id: entry.root_agent_id().map(|a| hex::encode(a.as_bytes())),
        parent_agent_id: entry.parent_agent_id().map(|a| hex::encode(a.as_bytes())),
        team_id: entry.team_id().map(|s| s.to_string()),
        delegation_reason: entry.delegation_reason().map(|s| s.to_string()),
        spawned_by_tool: entry.spawned_by_tool().map(|s| s.to_string()),
        depth: entry.depth(),
    }
}

/// Write compliance records as newline-delimited JSON, one record per line.
///
/// The preferred output for SIEM ingestors, regulators, and archival systems.
/// Each line is a complete JSON document encoding a [`ComplianceRecord`].
pub fn write_records_jsonl<W: Write>(
    records: &[ComplianceRecord],
    mut writer: W,
) -> Result<(), Box<dyn std::error::Error>> {
    for record in records {
        let line = serde_json::to_string(record)?;
        writer.write_all(line.as_bytes())?;
        writer.write_all(b"\n")?;
    }
    Ok(())
}

/// Write compliance records as a pretty-printed JSON array.
///
/// Useful for human review of a small archive. Prefer JSONL for any
/// production export.
pub fn write_records_json<W: Write>(
    records: &[ComplianceRecord],
    mut writer: W,
) -> Result<(), Box<dyn std::error::Error>> {
    let json = serde_json::to_string_pretty(records)?;
    writer.write_all(json.as_bytes())?;
    writer.write_all(b"\n")?;
    Ok(())
}

/// Write compliance records as CSV with the regulator-relevant columns.
///
/// The CSV view drops the payload body and lineage to keep the file
/// approachable for spreadsheet review. It always includes the hash chain
/// anchors and the count of credential findings so an auditor can spot
/// scrubbed entries at a glance. Use JSONL for full fidelity.
pub fn write_records_csv<W: Write>(
    records: &[ComplianceRecord],
    mut writer: W,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut wtr = csv::Writer::from_writer(&mut writer);
    wtr.write_record([
        "seq",
        "timestamp",
        "event_type",
        "agent_id",
        "session_id",
        "previous_hash",
        "entry_hash",
        "credential_findings_count",
        "redacted",
    ])?;
    for record in records {
        wtr.write_record([
            record.seq.to_string().as_str(),
            record.timestamp.as_str(),
            record.event_type.as_str(),
            record.agent_id.as_str(),
            record.session_id.as_str(),
            record.previous_hash.as_str(),
            record.entry_hash.as_str(),
            record.credential_findings.len().to_string().as_str(),
            if record.redacted_payload.is_some() {
                "true"
            } else {
                "false"
            },
        ])?;
    }
    wtr.flush()?;
    Ok(())
}

/// Arguments for `aasm audit compliance-export`.
#[derive(Debug, Args)]
pub struct ComplianceExportArgs {
    /// Path to a per-session audit JSONL file produced by the gateway.
    #[arg(long)]
    pub input: PathBuf,

    /// Export file format. Defaults to JSONL for SIEM/regulator ingestion.
    #[arg(long, value_enum, default_value_t = ExportFormat::Jsonl)]
    pub format: ExportFormat,

    /// Compliance framework header to prepend (EU AI Act or SOC 2).
    #[arg(long, value_enum)]
    pub compliance: Option<ComplianceFormat>,

    /// Write output to a file instead of stdout.
    #[arg(long)]
    pub output_file: Option<PathBuf>,

    /// Filter by hex-encoded agent identifier (32 hex chars).
    #[arg(long)]
    pub agent: Option<String>,

    /// Filter by audit event type label (e.g. `PolicyViolation`).
    #[arg(long)]
    pub event_type: Option<String>,

    /// Include entries after this duration shorthand (`30m`, `2h`, `1d`) or
    /// ISO 8601 timestamp.
    #[arg(long)]
    pub since: Option<String>,

    /// Include entries before this ISO 8601 timestamp.
    #[arg(long)]
    pub until: Option<String>,
}

/// Filter mapped compliance records by the args' agent / event-type / time
/// window. Returns a fresh vector preserving original ordering.
pub fn filter_records(records: Vec<ComplianceRecord>, args: &ComplianceExportArgs) -> Vec<ComplianceRecord> {
    let since = args.since.as_deref().and_then(parse_since);
    let until = args.until.as_deref().and_then(parse_until);
    records
        .into_iter()
        .filter(|r| {
            if let Some(ref a) = args.agent {
                if !r.agent_id.eq_ignore_ascii_case(a) {
                    return false;
                }
            }
            if let Some(ref t) = args.event_type {
                if r.event_type != *t {
                    return false;
                }
            }
            is_within_time_range(&r.timestamp, since.as_ref(), until.as_ref())
        })
        .collect()
}

/// Dispatch records to the writer chosen by `args.format`, prepending the
/// optional compliance framework header.
fn write_records_to<W: Write>(
    records: &[ComplianceRecord],
    args: &ComplianceExportArgs,
    writer: &mut W,
) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(framework) = args.compliance {
        let header = compliance_header(framework);
        writer.write_all(header.as_bytes())?;
    }
    match args.format {
        ExportFormat::Csv => write_records_csv(records, writer),
        ExportFormat::Json => write_records_json(records, writer),
        ExportFormat::Jsonl => write_records_jsonl(records, writer),
    }
}

/// Execute `aasm audit compliance-export`.
pub fn run(args: ComplianceExportArgs) -> ExitCode {
    let entries = match load_jsonl_file(&args.input) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("error: failed to read {}: {e}", args.input.display());
            return ExitCode::FAILURE;
        }
    };

    let records: Vec<ComplianceRecord> = entries.iter().map(map_audit_entry).collect();
    let filtered = filter_records(records, &args);

    let write_result: Result<(), Box<dyn std::error::Error>> = if let Some(ref path) = args.output_file {
        let file = match File::create(path) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("error: cannot create file {}: {e}", path.display());
                return ExitCode::FAILURE;
            }
        };
        let mut w = std::io::BufWriter::new(file);
        write_records_to(&filtered, &args, &mut w)
    } else {
        let stdout = std::io::stdout();
        let mut w = stdout.lock();
        write_records_to(&filtered, &args, &mut w)
    };

    match write_result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: compliance export failed: {e}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use aa_core::identity::{AgentId, SessionId};
    use aa_core::{AuditEntry, AuditEventType};

    use super::*;

    fn fixed_agent() -> AgentId {
        AgentId::from_bytes([0xAA; 16])
    }

    fn fixed_session() -> SessionId {
        SessionId::from_bytes([0xBB; 16])
    }

    #[test]
    fn map_entry_hex_encodes_identity_and_hashes() {
        let entry = AuditEntry::new(
            7,
            1_700_000_000_000_000_000,
            AuditEventType::ToolCallIntercepted,
            fixed_agent(),
            fixed_session(),
            r#"{"tool":"bash","decision":"Allow"}"#.to_string(),
            [0u8; 32],
        );

        let record = map_audit_entry(&entry);

        assert_eq!(record.seq, 7);
        assert_eq!(record.event_type, "ToolCallIntercepted");
        assert_eq!(record.agent_id, "a".repeat(32));
        assert_eq!(record.session_id, "b".repeat(32));
        assert_eq!(record.previous_hash, "0".repeat(64));
        assert_eq!(record.entry_hash.len(), 64);
        assert!(record.entry_hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn map_entry_timestamp_renders_iso_8601_utc() {
        // 2023-11-14T22:13:20Z
        let entry = AuditEntry::new(
            0,
            1_700_000_000_000_000_000,
            AuditEventType::ToolCallIntercepted,
            fixed_agent(),
            fixed_session(),
            "{}".to_string(),
            [0u8; 32],
        );

        let record = map_audit_entry(&entry);
        assert!(record.timestamp.starts_with("2023-11-14T22:13:20"));
        assert!(record.timestamp.ends_with("+00:00"));
    }

    #[test]
    fn map_entry_preserves_payload_verbatim() {
        let payload = r#"{"tool":"read_file","args":{"path":"/etc/passwd"},"decision":"Deny"}"#;
        let entry = AuditEntry::new(
            1,
            1_700_000_000_000_000_000,
            AuditEventType::PolicyViolation,
            fixed_agent(),
            fixed_session(),
            payload.to_string(),
            [0u8; 32],
        );

        let record = map_audit_entry(&entry);
        assert_eq!(record.payload, payload);
    }

    #[test]
    fn load_jsonl_file_reads_chain_in_order() {
        use std::io::Write as _;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");

        let agent = fixed_agent();
        let session = fixed_session();
        let mut prev = [0u8; 32];
        let mut originals: Vec<AuditEntry> = Vec::new();
        for seq in 0..3 {
            let e = AuditEntry::new(
                seq,
                1_700_000_000_000_000_000 + seq,
                AuditEventType::ToolCallIntercepted,
                agent,
                session,
                format!("{{\"seq\":{seq}}}"),
                prev,
            );
            prev = *e.entry_hash();
            originals.push(e);
        }

        let mut f = File::create(&path).unwrap();
        for e in &originals {
            writeln!(f, "{}", serde_json::to_string(e).unwrap()).unwrap();
        }
        // Trailing blank line — must be skipped, not parsed.
        writeln!(f).unwrap();
        drop(f);

        let loaded = load_jsonl_file(&path).unwrap();
        assert_eq!(loaded.len(), 3);
        for (l, o) in loaded.iter().zip(originals.iter()) {
            assert_eq!(l.seq(), o.seq());
            assert_eq!(l.entry_hash(), o.entry_hash());
        }
    }

    #[test]
    fn map_entry_round_trip_through_serde() {
        let entry = AuditEntry::new(
            42,
            1_700_000_000_000_000_000,
            AuditEventType::ToolCallIntercepted,
            fixed_agent(),
            fixed_session(),
            r#"{"a":1}"#.to_string(),
            [0xFEu8; 32],
        );

        let record = map_audit_entry(&entry);
        let json = serde_json::to_string(&record).unwrap();
        let parsed: ComplianceRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, record);
    }

    fn sample_records(n: usize) -> Vec<ComplianceRecord> {
        let mut prev = [0u8; 32];
        (0..n)
            .map(|i| {
                let e = AuditEntry::new(
                    i as u64,
                    1_700_000_000_000_000_000 + i as u64,
                    AuditEventType::ToolCallIntercepted,
                    fixed_agent(),
                    fixed_session(),
                    format!("{{\"seq\":{i}}}"),
                    prev,
                );
                prev = *e.entry_hash();
                map_audit_entry(&e)
            })
            .collect()
    }

    #[test]
    fn write_records_jsonl_one_line_per_record() {
        let records = sample_records(3);
        let mut buf = Vec::new();
        write_records_jsonl(&records, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        let lines: Vec<&str> = output.lines().collect();
        assert_eq!(lines.len(), 3);
        for line in &lines {
            let parsed: ComplianceRecord = serde_json::from_str(line).unwrap();
            assert!(parsed.entry_hash.chars().all(|c| c.is_ascii_hexdigit()));
        }
    }

    #[test]
    fn write_records_json_yields_parseable_array() {
        let records = sample_records(2);
        let mut buf = Vec::new();
        write_records_json(&records, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        let parsed: Vec<ComplianceRecord> = serde_json::from_str(&output).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].seq, 0);
        assert_eq!(parsed[1].seq, 1);
    }

    fn default_args(input: PathBuf) -> ComplianceExportArgs {
        ComplianceExportArgs {
            input,
            format: ExportFormat::Jsonl,
            compliance: None,
            output_file: None,
            agent: None,
            event_type: None,
            since: None,
            until: None,
        }
    }

    #[test]
    fn filter_records_by_agent_id_case_insensitive() {
        let records = sample_records(2);
        let mut args = default_args(PathBuf::from("/tmp/none"));
        // sample_records uses [0xAA; 16] → "a" * 32 hex string.
        args.agent = Some("A".repeat(32));
        let kept = filter_records(records, &args);
        assert_eq!(kept.len(), 2, "uppercase agent filter must match hex value");
    }

    #[test]
    fn filter_records_by_event_type_drops_non_matching() {
        let records = sample_records(2);
        let mut args = default_args(PathBuf::from("/tmp/none"));
        args.event_type = Some("PolicyViolation".to_string());
        let kept = filter_records(records, &args);
        assert_eq!(kept.len(), 0, "no sample records match PolicyViolation");
    }

    #[test]
    fn filter_records_by_until_excludes_future_entries() {
        let records = sample_records(2);
        // sample timestamps are ~2023-11-14 — anything before 2023-01-01 should drop both.
        let mut args = default_args(PathBuf::from("/tmp/none"));
        args.until = Some("2023-01-01T00:00:00Z".to_string());
        let kept = filter_records(records, &args);
        assert_eq!(kept.len(), 0);
    }

    #[test]
    fn run_emits_one_jsonl_line_per_entry_to_output_file() {
        use std::io::Write as _;

        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("audit.jsonl");
        let output = dir.path().join("export.jsonl");

        let agent = fixed_agent();
        let session = fixed_session();
        let mut prev = [0u8; 32];
        let mut f = File::create(&input).unwrap();
        for seq in 0..4 {
            let e = AuditEntry::new(
                seq,
                1_700_000_000_000_000_000 + seq,
                AuditEventType::ToolCallIntercepted,
                agent,
                session,
                format!("{{\"seq\":{seq}}}"),
                prev,
            );
            prev = *e.entry_hash();
            writeln!(f, "{}", serde_json::to_string(&e).unwrap()).unwrap();
        }
        drop(f);

        let mut args = default_args(input);
        args.output_file = Some(output.clone());
        let code = run(args);
        assert_eq!(code, ExitCode::SUCCESS);

        let content = std::fs::read_to_string(&output).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 4);
        for line in lines {
            let parsed: ComplianceRecord = serde_json::from_str(line).unwrap();
            assert!(parsed.entry_hash.chars().all(|c| c.is_ascii_hexdigit()));
        }
    }

    #[test]
    fn run_prepends_compliance_header_when_requested() {
        use std::io::Write as _;

        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("audit.jsonl");
        let output = dir.path().join("export.jsonl");

        let e = AuditEntry::new(
            0,
            1_700_000_000_000_000_000,
            AuditEventType::ToolCallIntercepted,
            fixed_agent(),
            fixed_session(),
            "{}".to_string(),
            [0u8; 32],
        );
        let mut f = File::create(&input).unwrap();
        writeln!(f, "{}", serde_json::to_string(&e).unwrap()).unwrap();
        drop(f);

        let mut args = default_args(input);
        args.output_file = Some(output.clone());
        args.compliance = Some(ComplianceFormat::EuAiAct);
        assert_eq!(run(args), ExitCode::SUCCESS);

        let content = std::fs::read_to_string(&output).unwrap();
        assert!(content.starts_with("# EU AI Act Compliance Report"));
        assert!(content.contains("Regulation 2024/1689"));
    }

    #[test]
    fn write_records_csv_header_and_per_record_rows() {
        let records = sample_records(2);
        let mut buf = Vec::new();
        write_records_csv(&records, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        let lines: Vec<&str> = output.lines().collect();
        assert_eq!(lines.len(), 3); // header + 2 rows
        assert!(lines[0].starts_with("seq,timestamp,event_type,agent_id,session_id,previous_hash,entry_hash"));
        assert!(lines[1].contains("ToolCallIntercepted"));
        assert!(lines[1].contains("false")); // no redaction
    }
}
