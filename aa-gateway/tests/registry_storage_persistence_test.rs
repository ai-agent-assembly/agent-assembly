//! End-to-end durability test for the `AgentRegistry` write-through path.
//!
//! Epic 18 Story S-I.2 (AAASM-1864) acceptance criterion:
//!
//! > Restart test: register N agents → drop registry → reopen SqliteBackend
//! > → rehydrate → all agents present with original team_id, registered_at, name.
//!
//! Exercises `AgentRegistry::with_storage` + `register_persisted` +
//! `rehydrate_from_storage` against a real on-disk SQLite file (not
//! `:memory:`) so the test fails if a future change accidentally turns
//! the storage write into a no-op or persists to a transient location.

use std::collections::{BTreeMap, VecDeque};
use std::sync::Arc;

use chrono::Utc;
use tempfile::tempdir;

use aa_core::GovernanceLevel;
use aa_gateway::registry::store::{AgentRecord, AgentRegistry};
use aa_gateway::registry::{AgentStatus, OrphanMode};
use aa_gateway::storage::{open_sqlite_backend, StorageBackend};

/// Build a minimal `AgentRecord` for testing — enough fields to register
/// successfully without exercising lineage validation.
fn record(id: [u8; 16], name: &str, team_id: Option<&str>) -> AgentRecord {
    AgentRecord {
        agent_id: id,
        name: name.to_string(),
        framework: "test".to_string(),
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
        team_id: team_id.map(str::to_string),
        depth: 0,
        delegation_reason: None,
        spawned_by_tool: None,
        root_agent_id: Some(id),
        children: Vec::new(),
        parent_key: None,
        enforcement_mode: None,
    }
}

/// AC bullet: registered agents survive a registry restart.
///
/// Pattern: open a tempdir SQLite file, register three agents via the
/// persisted path, drop the registry and backend, reopen the same file,
/// rehydrate, and assert all three are back with the original
/// `agent_id`, `name`, and `team_id`.
#[tokio::test]
async fn agents_registered_persisted_survive_registry_restart() {
    let tmp = tempdir().expect("tempdir");
    let db_path = tmp.path().join("registry-persistence.db");

    // ── Session 1: open storage, build registry, register 3 agents.
    let storage_1: Arc<dyn StorageBackend> = open_sqlite_backend(&db_path).await.expect("open backend");
    let registry_1 = AgentRegistry::new().with_storage(storage_1.clone());
    registry_1
        .register_persisted(record([1u8; 16], "alpha", Some("teamA")))
        .await
        .expect("register alpha");
    registry_1
        .register_persisted(record([2u8; 16], "beta", Some("teamB")))
        .await
        .expect("register beta");
    registry_1
        .register_persisted(record([3u8; 16], "gamma", None))
        .await
        .expect("register gamma");

    // Drop registry + storage handles to simulate a gateway shutdown.
    drop(registry_1);
    drop(storage_1);

    // ── Session 2: open the same SQLite file, build a fresh registry,
    // rehydrate, assert the three agents reappear.
    let storage_2: Arc<dyn StorageBackend> = open_sqlite_backend(&db_path).await.expect("reopen backend");
    let registry_2 = AgentRegistry::new().with_storage(storage_2);
    let restored = registry_2.rehydrate_from_storage().await.expect("rehydrate");
    assert_eq!(restored, 3, "all three persisted agents must rehydrate");

    let alpha = registry_2.get(&[1u8; 16]).expect("alpha restored");
    assert_eq!(alpha.name, "alpha");
    assert_eq!(alpha.team_id.as_deref(), Some("teamA"));

    let beta = registry_2.get(&[2u8; 16]).expect("beta restored");
    assert_eq!(beta.name, "beta");
    assert_eq!(beta.team_id.as_deref(), Some("teamB"));

    let gamma = registry_2.get(&[3u8; 16]).expect("gamma restored");
    assert_eq!(gamma.name, "gamma");
    assert_eq!(gamma.team_id, None);
}

/// Deregister_persisted must clear the durable row, so a subsequent
/// restart does NOT bring the agent back.
#[tokio::test]
async fn deregister_persisted_clears_storage_so_restart_skips_agent() {
    let tmp = tempdir().expect("tempdir");
    let db_path = tmp.path().join("registry-deregister.db");

    // ── Session 1: register two agents, deregister one.
    let storage_1: Arc<dyn StorageBackend> = open_sqlite_backend(&db_path).await.expect("open backend");
    let registry_1 = AgentRegistry::new().with_storage(storage_1.clone());
    registry_1
        .register_persisted(record([4u8; 16], "keep-me", Some("teamA")))
        .await
        .expect("register keep-me");
    registry_1
        .register_persisted(record([5u8; 16], "drop-me", Some("teamA")))
        .await
        .expect("register drop-me");
    registry_1
        .deregister_persisted(&[5u8; 16], OrphanMode::Suspend)
        .await
        .expect("deregister drop-me");

    drop(registry_1);
    drop(storage_1);

    // ── Session 2: rehydrate, expect only keep-me back.
    let storage_2: Arc<dyn StorageBackend> = open_sqlite_backend(&db_path).await.expect("reopen backend");
    let registry_2 = AgentRegistry::new().with_storage(storage_2);
    let restored = registry_2.rehydrate_from_storage().await.expect("rehydrate");
    assert_eq!(restored, 1, "only one agent must remain after deregister_persisted");

    assert!(registry_2.get(&[4u8; 16]).is_some(), "keep-me must rehydrate");
    assert!(registry_2.get(&[5u8; 16]).is_none(), "drop-me must NOT rehydrate");
}
