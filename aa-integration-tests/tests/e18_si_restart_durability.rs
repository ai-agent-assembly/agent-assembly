//! Story-level end-to-end restart durability test for Epic 18 Story S-I
//! (AAASM-1590). Exercises all three durability planes (agent registry,
//! audit event sink, retention engine boot) in a single boot cycle
//! against a real on-disk SQLite file (not `:memory:`), shuts the
//! gateway state down, reopens, and asserts every piece reappears.
//!
//! The per-Subtask integration tests pin each plane in isolation:
//!
//! - `aa-gateway/tests/registry_storage_persistence_test.rs` — S-I.2
//! - `aa-gateway/tests/audit_storage_sink_test.rs` — S-I.3
//! - `aa-gateway/src/storage/retention_boot::tests` — S-I.4
//! - `aa-cli/tests/admin_run_retention.rs` — S-I.5
//!
//! This file is the Story-level verification asked for by Sub-task
//! AAASM-1873: one boot cycle that proves all three planes coexist
//! correctly through the same surfaces production uses.

use std::collections::{BTreeMap, VecDeque};
use std::sync::Arc;

use chrono::Utc;
use tempfile::tempdir;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use aa_core::config::{ColdAction as CoreColdAction, RetentionConfig as CoreRetentionConfig};
use aa_core::{AgentId, AuditEntry, AuditEventType, GovernanceLevel, SessionId};
use aa_gateway::audit::AuditWriter;
use aa_gateway::registry::store::{AgentRecord, AgentRegistry};
use aa_gateway::registry::AgentStatus;
use aa_gateway::storage::{open_sqlite_backend, spawn_retention_engine, AuditFilter, StorageBackend};

fn make_agent(id: [u8; 16], name: &str, team: &str) -> AgentRecord {
    AgentRecord {
        agent_id: id,
        name: name.to_string(),
        framework: "e18-si-verify".to_string(),
        version: "0.0.0".to_string(),
        risk_tier: 0,
        tool_names: Vec::new(),
        public_key: String::new(),
        credential_token: String::new(),
        metadata: BTreeMap::new(),
        registered_at: Utc::now(),
        last_heartbeat: Utc::now(),
        status: AgentStatus::Active,
        pid: None,
        session_count: 0,
        last_event: None,
        policy_violations_count: 0,
        active_sessions: Vec::new(),
        recent_events: VecDeque::new(),
        recent_traces: Vec::new(),
        layer: None,
        governance_level: GovernanceLevel::L0Discover,
        parent_agent_id: None,
        team_id: Some(team.to_string()),
        depth: 0,
        delegation_reason: None,
        spawned_by_tool: None,
        root_agent_id: Some(id),
        children: Vec::new(),
        parent_key: None,
        enforcement_mode: None,
    }
}

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

/// Story-level e2e: exercise all three durability planes in one boot
/// cycle, then shut down, reopen, and assert every plane survives.
///
/// This validates the parent Story AAASM-1590's two foundational
/// acceptance criteria together:
/// - "Audit events written during a gateway session are still
///   queryable after a gateway restart."
/// - "Agents registered during a gateway session are still in the
///   registry after a gateway restart."
///
/// Plus the AAASM-1588 follow-up #1 wiring (RetentionEngine spawn
/// returns a live JoinHandle that responds to a cancellation token).
#[tokio::test]
async fn e18_si_full_stack_survives_restart() {
    let tmp = tempdir().expect("tempdir");
    let db_path = tmp.path().join("e18-si-verify.db");
    let audit_dir = tmp.path().join("audit-logs");

    // ─── Session 1: full S-I stack up ────────────────────────────
    let storage_1: Arc<dyn StorageBackend> = open_sqlite_backend(&db_path).await.expect("open backend");

    // S-I.2 — write-through registry.
    let registry_1 = AgentRegistry::new().with_storage(storage_1.clone());
    registry_1
        .register_persisted(make_agent([1u8; 16], "alpha", "teamA"))
        .await
        .expect("register alpha");
    registry_1
        .register_persisted(make_agent([2u8; 16], "beta", "teamB"))
        .await
        .expect("register beta");

    // S-I.3 — dual-sink audit pipeline (JSONL + storage).
    let (tx, rx) = mpsc::channel::<AuditEntry>(8);
    let writer = AuditWriter::new(audit_dir.clone(), "agent-e18si", "session-e18si", rx)
        .await
        .expect("AuditWriter::new")
        .with_storage(storage_1.clone());
    let mut previous_hash = [0u8; 32];
    for seq in 0..3u64 {
        let entry = make_entry(seq, [1u8; 16], [9u8; 16], previous_hash);
        previous_hash = *entry.entry_hash();
        tx.send(entry).await.expect("send entry");
    }
    drop(tx);
    let writer_task = tokio::spawn(writer.run());
    writer_task.await.expect("writer drains");

    // S-I.4 — retention engine spawn (using a 6-field cron so the
    // validator accepts it; default aa-core schedule is 5-field which
    // the cron crate rejects — graceful-failure path is documented
    // in main.rs).
    let retention_cfg = CoreRetentionConfig {
        schedule: "0 0 3 * * *".to_string(),
        cold_action: CoreColdAction::Drop,
        archive_url: None,
        ..CoreRetentionConfig::default()
    };
    let retention_token = CancellationToken::new();
    let (engine, retention_handle) = spawn_retention_engine(storage_1.clone(), &retention_cfg, retention_token.clone())
        .expect("retention engine spawns");
    assert!(
        !retention_handle.is_finished(),
        "retention engine must stay alive until shutdown is signalled"
    );

    // Tear down session 1 cleanly: cancel the retention loop, drop
    // the registry, drop the storage Arc. Mirrors the shape of a
    // graceful gateway shutdown.
    retention_token.cancel();
    tokio::time::timeout(std::time::Duration::from_secs(2), retention_handle)
        .await
        .expect("retention engine resolves within 2 s of cancel")
        .expect("retention engine task joins cleanly");
    drop(engine);
    drop(registry_1);
    drop(storage_1);

    // ─── Session 2: reopen and assert every plane survives ────────
    let storage_2: Arc<dyn StorageBackend> = open_sqlite_backend(&db_path).await.expect("reopen backend");

    // Agents rehydrate.
    let registry_2 = AgentRegistry::new().with_storage(storage_2.clone());
    let restored = registry_2.rehydrate_from_storage().await.expect("rehydrate");
    assert_eq!(restored, 2, "both agents must rehydrate after restart");
    assert!(registry_2.get(&[1u8; 16]).is_some(), "alpha agent must rehydrate");
    assert!(registry_2.get(&[2u8; 16]).is_some(), "beta agent must rehydrate");

    // Audit events queryable.
    let events = storage_2
        .query_audit_events(AuditFilter::default())
        .await
        .expect("query audit events");
    assert_eq!(events.len(), 3, "all 3 audit events must be queryable after restart");
    for event in &events {
        assert_eq!(event.agent_id, AgentId::from_bytes([1u8; 16]));
        assert_eq!(event.action, "PolicyViolation");
    }

    // Retention engine can be re-spawned against the same storage,
    // and re-canceled cleanly — proves the boot helper is re-entrant
    // and the storage backend has not been corrupted by session 1.
    let token_2 = CancellationToken::new();
    let (_engine_2, handle_2) = spawn_retention_engine(storage_2, &retention_cfg, token_2.clone())
        .expect("retention engine respawns against reopened storage");
    token_2.cancel();
    tokio::time::timeout(std::time::Duration::from_secs(2), handle_2)
        .await
        .expect("retention engine resolves within 2 s of cancel (session 2)")
        .expect("retention engine task joins cleanly (session 2)");
}
