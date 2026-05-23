//! Conversion from the runtime [`AuditEntry`](aa_core::AuditEntry) to the
//! durable [`AuditEvent`](super::AuditEvent).
//!
//! The two records are different shapes by design (see
//! `aa-gateway/src/storage/audit.rs` and `aa-core/src/audit.rs`): the runtime
//! entry is a hash-chained, tamper-evident JSONL line; the storage event
//! mirrors the columns of the `audit_events` hypertable so the gateway can
//! answer "what happened in the last 24 hours" queries after a restart.
//!
//! Conversion runtime → storage is lossy: hash-chain metadata (`seq`,
//! `previous_hash`, `entry_hash`) is dropped because durability of the chain
//! itself stays the JSONL writer's job; `dry_run`, `shadow_decision`, and
//! `matched_rule_id` are not yet populated by the runtime audit pipeline and
//! default to `false` / `None`. The `payload` JSON string is parsed back
//! into a `serde_json::Value` where possible; a non-JSON payload is wrapped
//! as `Value::String(...)` so the row still inserts.
//!
//! Introduced by Epic 18 Story S-I.3 (AAASM-1867) — the audit-event sink
//! that makes the JSONL stream queryable through the StorageBackend.

use chrono::{DateTime, TimeZone, Utc};
use uuid::Uuid;

use aa_core::AuditEntry;

use super::audit::AuditEvent;

/// Build a deterministic UUID for a single [`AuditEntry`].
///
/// The storage primary key is `(ts, event_id)`; the JSONL hash chain is
/// already keyed by `(agent_id, session_id, seq)`, so we derive the event
/// UUID from that tuple via UUIDv5. This makes the conversion idempotent —
/// re-running the bridge on the same entry produces the same row, so the
/// write is safe to retry.
fn event_id_for_entry(entry: &AuditEntry) -> Uuid {
    // UUIDv5 namespace: a fixed v4 we generated for the audit-bridge module.
    // Stable across restarts so the same entry maps to the same row.
    const AUDIT_BRIDGE_NS: Uuid = Uuid::from_bytes([
        0xb1, 0x91, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x01,
    ]);
    let mut name = Vec::with_capacity(40);
    name.extend_from_slice(entry.agent_id().as_bytes());
    name.extend_from_slice(entry.session_id().as_bytes());
    name.extend_from_slice(&entry.seq().to_be_bytes());
    Uuid::new_v5(&AUDIT_BRIDGE_NS, &name)
}

/// Convert `timestamp_ns` (nanoseconds since the Unix epoch) into a
/// `DateTime<Utc>`. Falls back to the epoch on overflow — that's better than
/// dropping the row, and the bridge logs a warning so the operator notices.
fn ts_from_ns(ns: u64) -> DateTime<Utc> {
    let secs = (ns / 1_000_000_000) as i64;
    let nanos = (ns % 1_000_000_000) as u32;
    match Utc.timestamp_opt(secs, nanos).single() {
        Some(ts) => ts,
        None => {
            tracing::warn!(
                timestamp_ns = ns,
                "audit_bridge: timestamp_ns overflow, falling back to epoch"
            );
            DateTime::<Utc>::from_timestamp_nanos(0)
        }
    }
}

/// Build a storage [`AuditEvent`] from a runtime [`AuditEntry`].
///
/// Lossy — see the module doc for the list of fields the bridge drops or
/// defaults. The returned event uses `entry.event_type().as_str()` for
/// both `action` and `decision` until the runtime pipeline grows separate
/// fields (the spec calls these out as separate columns; until then, the
/// event type is the only signal we have).
pub fn audit_entry_to_storage_event(entry: &AuditEntry) -> AuditEvent {
    let payload_str = entry.payload();
    let payload = if payload_str.is_empty() {
        None
    } else {
        match serde_json::from_str::<serde_json::Value>(payload_str) {
            Ok(value) => Some(value),
            Err(_) => Some(serde_json::Value::String(payload_str.to_string())),
        }
    };

    AuditEvent {
        ts: ts_from_ns(entry.timestamp_ns()),
        event_id: event_id_for_entry(entry),
        agent_id: entry.agent_id(),
        team_id: entry.team_id().map(str::to_string),
        action: entry.event_type().as_str().to_string(),
        decision: entry.event_type().as_str().to_string(),
        dry_run: false,
        shadow_decision: None,
        matched_rule_id: None,
        payload,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aa_core::{AgentId, AuditEventType, SessionId};

    fn make_entry(seq: u64, agent_id: [u8; 16], payload: &str) -> AuditEntry {
        AuditEntry::new(
            seq,
            1_700_000_000_000_000_000,
            AuditEventType::PolicyViolation,
            AgentId::from_bytes(agent_id),
            SessionId::from_bytes([2u8; 16]),
            payload.to_string(),
            [0u8; 32],
        )
    }

    #[test]
    fn bridge_preserves_agent_id_and_action() {
        let entry = make_entry(0, [9u8; 16], r#"{"k":"v"}"#);
        let event = audit_entry_to_storage_event(&entry);
        assert_eq!(event.agent_id, AgentId::from_bytes([9u8; 16]));
        assert_eq!(event.action, "PolicyViolation");
        assert_eq!(event.decision, "PolicyViolation");
        assert!(!event.dry_run);
    }

    #[test]
    fn bridge_parses_json_payload_into_value() {
        let entry = make_entry(1, [1u8; 16], r#"{"answer":42}"#);
        let event = audit_entry_to_storage_event(&entry);
        let payload = event.payload.expect("payload Some for JSON");
        assert_eq!(payload["answer"], serde_json::json!(42));
    }

    #[test]
    fn bridge_wraps_non_json_payload_as_string() {
        let entry = make_entry(2, [3u8; 16], "not-json");
        let event = audit_entry_to_storage_event(&entry);
        assert_eq!(
            event.payload.expect("payload Some for plain text"),
            serde_json::Value::String("not-json".to_string())
        );
    }

    #[test]
    fn bridge_event_id_is_deterministic_for_same_entry() {
        let entry = make_entry(7, [4u8; 16], r#"{"x":1}"#);
        let id_a = audit_entry_to_storage_event(&entry).event_id;
        let id_b = audit_entry_to_storage_event(&entry).event_id;
        assert_eq!(
            id_a, id_b,
            "same entry must map to same UUID — supports safe write retries"
        );
    }

    #[test]
    fn bridge_event_id_differs_across_seq_values() {
        let entry_a = make_entry(0, [5u8; 16], "");
        let entry_b = make_entry(1, [5u8; 16], "");
        assert_ne!(
            audit_entry_to_storage_event(&entry_a).event_id,
            audit_entry_to_storage_event(&entry_b).event_id,
            "different seq within the same session must produce different UUIDs"
        );
    }
}
