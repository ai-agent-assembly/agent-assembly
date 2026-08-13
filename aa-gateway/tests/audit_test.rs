//! Unit tests for `AuditWriter` — append, verify_chain, read_last_hash.

use aa_core::identity::{AgentId, SessionId};
use aa_core::{AuditEntry, AuditEventType};
use aa_gateway::audit::{AuditWriter, VerifyResult};
use tokio::sync::mpsc;

const AGENT: AgentId = AgentId::from_bytes([1u8; 16]);
const SESSION: SessionId = SessionId::from_bytes([2u8; 16]);

fn make_entry(seq: u64, previous_hash: [u8; 32]) -> AuditEntry {
    AuditEntry::new(
        seq,
        1_700_000_000_000_000_000 + seq,
        AuditEventType::ToolCallIntercepted,
        AGENT,
        SESSION,
        format!("{{\"seq\":{seq}}}"),
        previous_hash,
    )
}

fn make_chain(count: u64) -> Vec<AuditEntry> {
    let mut entries = Vec::new();
    let mut prev_hash = [0u8; 32];
    for seq in 0..count {
        let entry = make_entry(seq, prev_hash);
        prev_hash = *entry.entry_hash();
        entries.push(entry);
    }
    entries
}

#[tokio::test]
async fn append_writes_valid_jsonl() {
    let dir = tempfile::tempdir().unwrap();
    let (tx, rx) = mpsc::channel(64);
    let writer = AuditWriter::new(dir.path().to_path_buf(), "agent-1", "sess-1", rx)
        .await
        .unwrap();

    tokio::spawn(writer.run());

    let entries = make_chain(3);
    for entry in &entries {
        tx.send(entry.clone()).await.unwrap();
    }
    drop(tx); // close channel, writer flushes and exits

    // Give the writer task time to process.
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let path = dir.path().join("agent-1-sess-1.jsonl");
    assert!(path.exists(), "JSONL file should be created");

    // Read back and verify line count.
    let content = tokio::fs::read_to_string(&path).await.unwrap();
    let lines: Vec<&str> = content.lines().collect();
    assert_eq!(lines.len(), 3, "should have 3 JSON lines");

    // Each line should deserialize to an AuditEntry.
    for (i, line) in lines.iter().enumerate() {
        let entry: AuditEntry = serde_json::from_str(line).unwrap_or_else(|e| panic!("line {i} failed to parse: {e}"));
        assert_eq!(entry.seq(), i as u64);
    }
}

#[tokio::test]
async fn verify_chain_valid() {
    let dir = tempfile::tempdir().unwrap();
    let (tx, rx) = mpsc::channel(64);
    let writer = AuditWriter::new(dir.path().to_path_buf(), "agent-v", "sess-v", rx)
        .await
        .unwrap();

    tokio::spawn(writer.run());

    let entries = make_chain(5);
    for entry in &entries {
        tx.send(entry.clone()).await.unwrap();
    }
    drop(tx);
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let path = dir.path().join("agent-v-sess-v.jsonl");
    let result = AuditWriter::verify_chain(&path).await.unwrap();
    assert_eq!(
        result,
        VerifyResult {
            is_valid: true,
            entries_checked: 5,
            first_invalid: None,
        }
    );
}

#[tokio::test]
async fn verify_chain_detects_tampering() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tampered.jsonl");

    // Write a valid chain, then tamper with the second entry.
    let entries = make_chain(3);
    let mut lines: Vec<String> = entries.iter().map(|e| serde_json::to_string(e).unwrap()).collect();

    // Tamper: replace the payload in line 1 (breaks its hash).
    let _original: AuditEntry = serde_json::from_str(&lines[1]).unwrap();
    // We can't mutate AuditEntry directly (fields are private), so we re-create
    // with a different payload but the same previous_hash — this breaks the stored hash.
    let bad_entry = AuditEntry::new(
        1,
        entries[1].timestamp_ns(),
        entries[1].event_type(),
        entries[1].agent_id(),
        entries[1].session_id(),
        "TAMPERED".to_string(),
        *entries[1].previous_hash(),
    );
    // Write the original first entry + tampered second entry (different hash) + third entry
    // The third entry's previous_hash will no longer match the tampered entry's hash.
    lines[1] = serde_json::to_string(&bad_entry).unwrap();
    // Note: line[1] itself is internally consistent (new hash matches its own fields),
    // but line[2]'s previous_hash still points to the ORIGINAL line[1]'s hash.

    let content = lines.join("\n") + "\n";
    tokio::fs::write(&path, content).await.unwrap();

    let result = AuditWriter::verify_chain(&path).await.unwrap();
    assert!(!result.is_valid);
    // The break is at entry 2 (index 2) because its previous_hash doesn't match
    // the tampered entry 1's new hash.
    assert_eq!(result.first_invalid, Some(2));
}

#[tokio::test]
async fn read_last_hash_returns_correct_hash() {
    let dir = tempfile::tempdir().unwrap();
    let (tx, rx) = mpsc::channel(64);
    let writer = AuditWriter::new(dir.path().to_path_buf(), "agent-h", "sess-h", rx)
        .await
        .unwrap();

    tokio::spawn(writer.run());

    let entries = make_chain(3);
    let expected_hash = *entries.last().unwrap().entry_hash();
    for entry in &entries {
        tx.send(entry.clone()).await.unwrap();
    }
    drop(tx);
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let path = dir.path().join("agent-h-sess-h.jsonl");
    let hash = AuditWriter::read_last_hash(&path).await.unwrap();
    assert_eq!(hash, Some(expected_hash));
}

#[tokio::test]
async fn read_last_hash_returns_none_for_missing_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("nonexistent.jsonl");
    let hash = AuditWriter::read_last_hash(&path).await.unwrap();
    assert_eq!(hash, None);
}

// AAASM-3356: the service must recover the last seq across restarts so the
// monotonic sequence counter does not restart at 0 (which would emit duplicate
// sequence numbers in the WORM log).
#[tokio::test]
async fn read_last_seq_returns_last_entry_seq() {
    let dir = tempfile::tempdir().unwrap();
    let (tx, rx) = mpsc::channel(64);
    let writer = AuditWriter::new(dir.path().to_path_buf(), "agent-s", "sess-s", rx)
        .await
        .unwrap();

    tokio::spawn(writer.run());

    // Chain of 5 entries → seqs 0..=4, so the last seq is 4.
    let entries = make_chain(5);
    for entry in &entries {
        tx.send(entry.clone()).await.unwrap();
    }
    drop(tx);
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let path = dir.path().join("agent-s-sess-s.jsonl");
    let seq = AuditWriter::read_last_seq(&path).await.unwrap();
    assert_eq!(seq, Some(4));
}

#[tokio::test]
async fn read_last_seq_returns_none_for_missing_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("nonexistent.jsonl");
    let seq = AuditWriter::read_last_seq(&path).await.unwrap();
    assert_eq!(seq, None);
}
