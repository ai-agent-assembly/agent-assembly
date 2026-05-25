//! `aasm audit compliance-export` — full-fidelity audit export for regulators
//! and SIEM consumers.
//!
//! Unlike `aasm audit export` (which reads the slim REST view served by
//! `GET /api/v1/logs`), this command reads per-session JSONL audit files
//! directly from disk so the hash chain (`previous_hash` / `entry_hash`),
//! credential findings, and delegation lineage carried by
//! [`aa_core::AuditEntry`] survive end-to-end.

use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

use aa_core::AuditEntry;

use super::models::ComplianceRecord;

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
}
