//! AAASM-1519 / F116 ST-G — E2E audit log integrity tests.
//!
//! Verifies that every intercepted call produces a JSONL audit entry and that
//! the hash chain remains valid and tamper-evident.
//!
//! ## Test status
//!
//! | # | Name | Status |
//! |---|------|--------|
//! | 1 | `audit_sdk_tool_call_writes_jsonl_entry` | `#[ignore]` — pending AAASM-237 |
//! | 2 | `audit_sdk_all_intercepted_calls_appear_in_log` | `#[ignore]` — pending AAASM-237 |
//! | 3 | `audit_entry_schema_matches_documented_fields` | enabled |
//! | 4 | `audit_entries_are_in_chronological_order` | enabled |
//! | 5 | `audit_hash_chain_validates_against_known_good` | enabled |
//! | 6 | `audit_chain_break_detected_when_entry_modified` | enabled |
//! | 7 | `audit_chain_survives_gateway_restart` | `#[ignore]` — requires binary spawn |
//!
//! Tests 1-2 are scaffolded with `#[ignore]` pending AAASM-237 (the HTTP path
//! in `aa-api` does not yet wire `AuditWriter` into handlers). Test 7 requires
//! a binary gateway spawn + SIGTERM/restart fixture not yet available.

mod common;

use std::io::Write as _;
use std::path::Path;

use aa_core::audit::AuditEventType;
use aa_core::identity::SessionId;
use aa_core::{AgentId, AuditEntry};
use aa_gateway::audit::AuditWriter;
use tempfile::tempdir;

// =============================================================================
// Helpers shared across the enabled tests
// =============================================================================

/// Build a valid hash-linked `AuditEntry` chain of `n` entries rooted at the
/// `[0u8; 32]` genesis hash.
fn make_chain(n: u64) -> Vec<AuditEntry> {
    let agent = AgentId::from_bytes([0xe1; 16]);
    let session = SessionId::from_bytes([0xe2; 16]);
    let mut entries = Vec::with_capacity(n as usize);
    let mut prev_hash = [0u8; 32];
    for seq in 0..n {
        let entry = AuditEntry::new(
            seq,
            1_700_000_000_000_000_000 + seq * 1_000_000_000,
            AuditEventType::ToolCallIntercepted,
            agent,
            session,
            format!(r#"{{"tool":"bash","result":"allow","seq":{seq}}}"#),
            prev_hash,
        );
        prev_hash = *entry.entry_hash();
        entries.push(entry);
    }
    entries
}

/// Serialize `entries` one-per-line as JSONL to `path`.
fn write_jsonl(path: &Path, entries: &[AuditEntry]) {
    let mut f = std::fs::File::create(path).expect("create jsonl");
    for e in entries {
        writeln!(f, "{}", serde_json::to_string(e).expect("serialize entry")).expect("write line");
    }
}

// =============================================================================
// Tests 1-2 — SDK-driven write path (blocked on AAASM-237)
// =============================================================================

/// SDK-driven: one tool call via the Python SDK should produce one JSONL audit
/// entry in the audit directory.
///
/// Blocked: `aa-api` HTTP handlers do not yet call `AuditWriter` (AAASM-237).
/// Remove `#[ignore]` once AAASM-237 lands and wire `audit_driver.py` here.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "blocked on AAASM-237: HTTP path does not yet write audit entries"]
async fn audit_sdk_tool_call_writes_jsonl_entry() {
    let env = common::TopologyTestEnv::start().await.expect("harness should start");
    let audit_dir = env.audit_dir.clone();

    let files_before = std::fs::read_dir(&audit_dir).map(|d| d.count()).unwrap_or(0);
    // TODO(AAASM-237): spawn audit_driver.py --calls 1, wait for exit 0.
    let files_after = std::fs::read_dir(&audit_dir).map(|d| d.count()).unwrap_or(0);
    assert!(
        files_after > files_before,
        "audit_dir should gain at least one JSONL file after a tool call"
    );
}

/// SDK-driven: N tool calls → exactly N audit entries across the audit files.
///
/// Blocked: same as `audit_sdk_tool_call_writes_jsonl_entry` — AAASM-237.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "blocked on AAASM-237: HTTP path does not yet write audit entries"]
async fn audit_sdk_all_intercepted_calls_appear_in_log() {
    const CALL_COUNT: u64 = 3;
    let env = common::TopologyTestEnv::start().await.expect("harness should start");
    let _audit_dir = env.audit_dir.clone();
    // TODO(AAASM-237): spawn audit_driver.py --calls 3, count total JSONL lines.
    let _ = CALL_COUNT;
}

// =============================================================================
// Test 3 — AuditEntry wire schema
// =============================================================================

/// A serialized `AuditEntry` must contain the eight fields mandated by the
/// documented wire schema: `seq`, `timestamp_ns`, `event_type`, `agent_id`,
/// `session_id`, `payload`, `previous_hash`, `entry_hash`.
#[tokio::test(flavor = "multi_thread")]
async fn audit_entry_schema_matches_documented_fields() {
    let entry = AuditEntry::new(
        0,
        1_700_000_000_000_000_000,
        AuditEventType::ToolCallIntercepted,
        AgentId::from_bytes([0xab; 16]),
        SessionId::from_bytes([0xcd; 16]),
        r#"{"tool":"bash","result":"allow"}"#.to_string(),
        [0u8; 32],
    );

    let json_str = serde_json::to_string(&entry).expect("AuditEntry should serialize");
    let obj: serde_json::Value = serde_json::from_str(&json_str).expect("round-trip parse");

    for field in &[
        "seq",
        "timestamp_ns",
        "event_type",
        "agent_id",
        "session_id",
        "payload",
        "previous_hash",
        "entry_hash",
    ] {
        assert!(
            obj.get(field).is_some(),
            "serialized AuditEntry must contain field '{field}'; got:\n{json_str}"
        );
    }
    assert_eq!(obj["seq"], 0u64, "seq should be 0");
    assert_eq!(
        obj["event_type"].as_str().unwrap_or(""),
        "ToolCallIntercepted",
        "event_type should serialize as its string label"
    );
}

// =============================================================================
// Test 4 — chronological ordering
// =============================================================================

/// Entries in a constructed chain must be in strict timestamp order.
#[tokio::test(flavor = "multi_thread")]
async fn audit_entries_are_in_chronological_order() {
    let entries = make_chain(8);
    for window in entries.windows(2) {
        let (prev, curr) = (&window[0], &window[1]);
        assert!(
            curr.timestamp_ns() > prev.timestamp_ns(),
            "entry seq={} (ts={}) must have a greater timestamp than seq={} (ts={})",
            curr.seq(),
            curr.timestamp_ns(),
            prev.seq(),
            prev.timestamp_ns(),
        );
    }
}

// =============================================================================
// Test 5 — hash chain round-trip
// =============================================================================

/// `AuditWriter::verify_chain` must return `is_valid = true` and
/// `entries_checked == N` for a correctly-constructed N-entry chain.
#[tokio::test(flavor = "multi_thread")]
async fn audit_hash_chain_validates_against_known_good() {
    const N: u64 = 10;
    let dir = tempdir().expect("tempdir");
    let path = dir.path().join("chain.jsonl");
    write_jsonl(&path, &make_chain(N));

    let result = AuditWriter::verify_chain(&path)
        .await
        .expect("verify_chain should not error on a well-formed file");

    assert!(result.is_valid, "known-good chain must report is_valid = true");
    assert_eq!(result.entries_checked, N, "entries_checked should equal N");
    assert_eq!(result.first_invalid, None, "first_invalid must be None");
}

// =============================================================================
// Test 6 — tamper detection (security-critical)
// =============================================================================

/// Mutating any field of a chain entry must cause `verify_chain` to report
/// `is_valid = false` and identify the first broken entry index.
///
/// Security property: this test exercises the tamper-evidence guarantee that
/// makes the audit log trustworthy for forensic review. Any modification to
/// a committed entry breaks the hash linkage and is detectable.
#[tokio::test(flavor = "multi_thread")]
async fn audit_chain_break_detected_when_entry_modified() {
    let dir = tempdir().expect("tempdir");
    let path = dir.path().join("tampered.jsonl");

    let entries = make_chain(4);
    // Forge entry[1]: keep seq / timestamp / previous_hash intact so entry[1]
    // itself passes its own integrity check, but change event_type + payload so
    // entry[1]'s entry_hash diverges. Entry[2]'s previous_hash then mismatches,
    // causing verify_chain to fail at index 2.
    let forged = AuditEntry::new(
        entries[1].seq(),
        entries[1].timestamp_ns(),
        AuditEventType::PolicyViolation, // mutated
        entries[1].agent_id(),
        entries[1].session_id(),
        "TAMPERED".to_string(), // mutated
        *entries[1].previous_hash(),
    );

    let mut f = std::fs::File::create(&path).expect("create tampered.jsonl");
    writeln!(f, "{}", serde_json::to_string(&entries[0]).unwrap()).unwrap();
    writeln!(f, "{}", serde_json::to_string(&forged).unwrap()).unwrap();
    writeln!(f, "{}", serde_json::to_string(&entries[2]).unwrap()).unwrap();
    writeln!(f, "{}", serde_json::to_string(&entries[3]).unwrap()).unwrap();
    drop(f);

    let result = AuditWriter::verify_chain(&path)
        .await
        .expect("verify_chain should not I/O error on a tampered file");

    assert!(!result.is_valid, "tampered chain must report is_valid = false");
    assert_eq!(
        result.first_invalid,
        Some(2),
        "chain break should be detected at index 2 (first entry whose \
         previous_hash no longer matches the forged entry's hash)"
    );
}

// =============================================================================
// Test 7 — restart persistence (blocked)
// =============================================================================

/// After a gateway restart the chain must still validate: `AuditWriter`
/// resumes from `read_last_hash` so the chain links across the restart
/// boundary without a gap.
///
/// Blocked: requires spawning the `aa-gateway` binary, sending SIGTERM, and
/// restarting — infrastructure not yet available in the integration harness.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "blocked on AAASM-1601: binary gateway spawn + SIGTERM/restart test infrastructure not yet available"]
async fn audit_chain_survives_gateway_restart() {
    todo!("implement once binary-spawn harness is available")
}
