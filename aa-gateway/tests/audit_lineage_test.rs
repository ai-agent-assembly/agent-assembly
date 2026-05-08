//! Integration + regression tests for AAASM-934: AuditEntry lineage fields.

use aa_core::identity::{AgentId, SessionId};
use aa_core::{AuditEntry, AuditEventType, Lineage};

const AGENT: AgentId = AgentId::from_bytes([1u8; 16]);
const SESSION: SessionId = SessionId::from_bytes([2u8; 16]);
const ROOT: AgentId = AgentId::from_bytes([7u8; 16]);
const PARENT: AgentId = AgentId::from_bytes([9u8; 16]);

fn make_entry_with_lineage(seq: u64, previous_hash: [u8; 32], lineage: Lineage) -> AuditEntry {
    AuditEntry::new_with_lineage(
        seq,
        1_700_000_000_000_000_000 + seq,
        AuditEventType::ToolCallIntercepted,
        AGENT,
        SESSION,
        format!("{{\"seq\":{seq}}}"),
        previous_hash,
        lineage,
    )
}

fn depth2_lineage() -> Lineage {
    Lineage {
        root_agent_id: Some(ROOT),
        parent_agent_id: Some(PARENT),
        team_id: Some("team-alpha".into()),
        delegation_reason: Some("summarise results".into()),
        spawned_by_tool: Some("langgraph.subgraph".into()),
        depth: Some(2),
    }
}

// ── Integration tests: depth-2 agent ─────────────────────────────────────

#[test]
fn depth2_agent_all_lineage_fields_populated() {
    let entry = make_entry_with_lineage(0, [0u8; 32], depth2_lineage());
    assert_eq!(entry.root_agent_id(), Some(ROOT));
    assert_eq!(entry.parent_agent_id(), Some(PARENT));
    assert_eq!(entry.team_id(), Some("team-alpha"));
    assert_eq!(entry.delegation_reason(), Some("summarise results"));
    assert_eq!(entry.spawned_by_tool(), Some("langgraph.subgraph"));
    assert_eq!(entry.depth(), Some(2));
}

#[test]
fn depth2_entry_passes_verify_integrity() {
    let entry = make_entry_with_lineage(0, [0u8; 32], depth2_lineage());
    assert!(entry.verify_integrity(), "depth-2 entry must verify its own hash");
}

#[test]
fn multi_entry_chain_with_lineage_is_valid() {
    let mut log = aa_core::AuditLog::new(AGENT, SESSION);
    let ts = 1_700_000_000_000_000_000u64;

    log.next_entry_with_lineage(
        AuditEventType::ToolCallIntercepted,
        ts,
        r#"{"tool":"web_search"}"#.into(),
        depth2_lineage(),
    );
    log.next_entry_with_lineage(
        AuditEventType::PolicyViolation,
        ts + 1,
        r#"{"tool":"bash"}"#.into(),
        depth2_lineage(),
    );
    log.next_entry(AuditEventType::ApprovalRequested, ts + 2, r#"{"tool":"bash"}"#.into());

    assert!(log.verify_chain(), "mixed lineage/no-lineage chain must verify");
    assert_eq!(log.len(), 3);
}

// ── Integration tests: JSONL write + verify_chain ─────────────────────────

#[tokio::test]
async fn depth2_chain_written_to_jsonl_verifies_ok() {
    use aa_gateway::audit::AuditWriter;
    use tokio::sync::mpsc;

    let dir = tempfile::tempdir().unwrap();
    let (tx, rx) = mpsc::channel(64);

    let writer = AuditWriter::new(dir.path().to_path_buf(), "agent-l", "sess-l", rx)
        .await
        .unwrap();
    tokio::spawn(writer.run());

    let mut prev_hash = [0u8; 32];
    for seq in 0..4u64 {
        let entry = make_entry_with_lineage(seq, prev_hash, depth2_lineage());
        prev_hash = *entry.entry_hash();
        tx.send(entry).await.unwrap();
    }
    drop(tx);
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let path = dir.path().join("agent-l-sess-l.jsonl");
    let result = AuditWriter::verify_chain(&path).await.unwrap();
    assert!(result.is_valid, "depth-2 chain must verify");
    assert_eq!(result.entries_checked, 4);
    assert!(result.first_invalid.is_none());
}

// ── Regression tests: legacy JSONL rows ──────────────────────────────────

#[tokio::test]
async fn legacy_entries_without_lineage_still_verify() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("legacy.jsonl");

    let mut prev_hash = [0u8; 32];
    let mut lines = Vec::new();
    for seq in 0..3u64 {
        let entry = AuditEntry::new(
            seq,
            1_700_000_000_000_000_000 + seq,
            AuditEventType::ToolCallIntercepted,
            AGENT,
            SESSION,
            format!("{{\"seq\":{seq}}}"),
            prev_hash,
        );
        prev_hash = *entry.entry_hash();
        lines.push(serde_json::to_string(&entry).unwrap());
    }

    // None lineage fields must not appear in JSONL (skip_serializing_if = None).
    assert!(
        !lines[0].contains("root_agent_id"),
        "None lineage must not appear in JSONL"
    );
    assert!(!lines[0].contains("\"depth\""), "None lineage must not appear in JSONL");

    tokio::fs::write(&path, lines.join("\n") + "\n").await.unwrap();

    let result = aa_gateway::audit::AuditWriter::verify_chain(&path).await.unwrap();
    assert!(result.is_valid, "legacy entries must still verify");
    assert_eq!(result.entries_checked, 3);
}

#[tokio::test]
async fn mixed_legacy_and_lineage_chain_verifies() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("mixed.jsonl");

    let mut prev_hash = [0u8; 32];
    let mut lines = Vec::new();

    // Entry 0: no lineage (legacy).
    let e0 = AuditEntry::new(
        0,
        1_000_000,
        AuditEventType::ToolCallIntercepted,
        AGENT,
        SESSION,
        "{}".into(),
        prev_hash,
    );
    prev_hash = *e0.entry_hash();
    lines.push(serde_json::to_string(&e0).unwrap());

    // Entry 1: with lineage.
    let e1 = make_entry_with_lineage(1, prev_hash, depth2_lineage());
    prev_hash = *e1.entry_hash();
    lines.push(serde_json::to_string(&e1).unwrap());

    // Entry 2: no lineage again.
    let e2 = AuditEntry::new(
        2,
        1_000_002,
        AuditEventType::PolicyViolation,
        AGENT,
        SESSION,
        "{}".into(),
        prev_hash,
    );
    lines.push(serde_json::to_string(&e2).unwrap());

    tokio::fs::write(&path, lines.join("\n") + "\n").await.unwrap();

    let result = aa_gateway::audit::AuditWriter::verify_chain(&path).await.unwrap();
    assert!(result.is_valid, "mixed chain must verify");
    assert_eq!(result.entries_checked, 3);
}
