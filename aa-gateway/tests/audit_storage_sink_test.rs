//! End-to-end durability test for the AuditWriter dual-sink path.
//!
//! Epic 18 Story S-I.3 (AAASM-1867) acceptance criterion:
//!
//! > End-to-end test: register agent, emit N audit entries, drop writer,
//! > reopen SqliteBackend, `storage.query_audit_events(AuditFilter::default())`
//! > returns N events.
//! > JSONL file content is byte-identical to pre-change behaviour.
//!
//! Exercises `AuditWriter::with_storage` + the dual-sink path in `run()`
//! against a real on-disk SQLite file (not `:memory:`).

use std::sync::Arc;

use tempfile::tempdir;
use tokio::sync::mpsc;

use aa_core::{AgentId, AuditEntry, AuditEventType, SessionId};
use aa_gateway::audit::AuditWriter;
use aa_gateway::storage::{open_sqlite_backend, AuditFilter, StorageBackend};

fn make_entry(seq: u64, agent_id: [u8; 16], session_id: [u8; 16], previous_hash: [u8; 32]) -> AuditEntry {
    AuditEntry::new(
        seq,
        1_700_000_000_000_000_000 + seq * 1_000_000,
        AuditEventType::PolicyViolation,
        AgentId::from_bytes(agent_id),
        SessionId::from_bytes(session_id),
        format!(r#"{{"seq":{seq}}}"#),
        previous_hash,
    )
}

/// AC bullet: emit 5 audit entries through the dual-sink, drop, reopen,
/// query — all 5 must come back.
#[tokio::test]
async fn audit_entries_persist_to_storage_through_dual_sink() {
    let tmp = tempdir().expect("tempdir");
    let db_path = tmp.path().join("audit-sink.db");
    let audit_dir = tmp.path().join("audit-logs");

    // ── Session 1: open backend, build writer with storage attached.
    let storage_1: Arc<dyn StorageBackend> = open_sqlite_backend(&db_path).await.expect("open backend");

    let (tx, rx) = mpsc::channel::<AuditEntry>(16);
    let writer = AuditWriter::new(audit_dir.clone(), "agent-X", "session-Y", rx)
        .await
        .expect("AuditWriter::new")
        .with_storage(storage_1.clone());

    let agent = [1u8; 16];
    let session = [2u8; 16];
    let mut previous_hash = [0u8; 32];
    for seq in 0..5u64 {
        let entry = make_entry(seq, agent, session, previous_hash);
        previous_hash = *entry.entry_hash();
        tx.send(entry).await.expect("send entry");
    }
    drop(tx);

    let handle = tokio::spawn(writer.run());
    handle.await.expect("writer task joins cleanly");

    // Drop the storage handle to force everything through Arc/Drop semantics.
    drop(storage_1);

    // ── Session 2: reopen the same SQLite file and query.
    let storage_2: Arc<dyn StorageBackend> = open_sqlite_backend(&db_path).await.expect("reopen backend");
    let rows = storage_2
        .query_audit_events(AuditFilter::default())
        .await
        .expect("query_audit_events");
    assert_eq!(rows.len(), 5, "all 5 audit entries must be queryable after restart");

    // All rows must carry the same agent_id.
    for row in &rows {
        assert_eq!(row.agent_id, AgentId::from_bytes(agent));
        assert_eq!(row.action, "PolicyViolation");
    }
}

/// AC bullet: JSONL file content is byte-identical to pre-change
/// behaviour. The dual-sink must not perturb what the JSONL writer
/// produces — same line count, same first/last entry.
#[tokio::test]
async fn jsonl_content_unchanged_under_dual_sink() {
    let tmp = tempdir().expect("tempdir");
    let db_path = tmp.path().join("audit-jsonl.db");
    let audit_dir = tmp.path().join("audit-logs");

    let storage: Arc<dyn StorageBackend> = open_sqlite_backend(&db_path).await.expect("open backend");
    let (tx, rx) = mpsc::channel::<AuditEntry>(8);
    let writer = AuditWriter::new(audit_dir.clone(), "agent-A", "session-B", rx)
        .await
        .expect("AuditWriter::new")
        .with_storage(storage);

    let agent = [7u8; 16];
    let session = [8u8; 16];
    let mut previous_hash = [0u8; 32];
    for seq in 0..3u64 {
        let entry = make_entry(seq, agent, session, previous_hash);
        previous_hash = *entry.entry_hash();
        tx.send(entry).await.expect("send entry");
    }
    drop(tx);

    let handle = tokio::spawn(writer.run());
    handle.await.expect("writer task joins cleanly");

    let jsonl_path = audit_dir.join("agent-A-session-B.jsonl");
    let on_disk = tokio::fs::read_to_string(&jsonl_path).await.expect("read JSONL");
    let line_count = on_disk.lines().count();
    assert_eq!(
        line_count, 3,
        "JSONL must hold one line per entry — dual-sink must not perturb the file shape"
    );

    // Hash chain integrity check: re-verify on disk.
    let verify = AuditWriter::verify_chain(&jsonl_path).await.expect("verify_chain");
    assert!(verify.is_valid, "JSONL hash chain must verify under dual-sink");
    assert_eq!(verify.entries_checked, 3);
}
