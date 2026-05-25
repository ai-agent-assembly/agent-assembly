//! `aasm audit compliance-export` — full-fidelity audit export for regulators
//! and SIEM consumers.
//!
//! Unlike `aasm audit export` (which reads the slim REST view served by
//! `GET /api/v1/logs`), this command reads per-session JSONL audit files
//! directly from disk so the hash chain (`previous_hash` / `entry_hash`),
//! credential findings, and delegation lineage carried by
//! [`aa_core::AuditEntry`] survive end-to-end.

use aa_core::AuditEntry;

use super::models::ComplianceRecord;

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
