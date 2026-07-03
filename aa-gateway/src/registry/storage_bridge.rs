//! Conversion between the runtime `AgentRecord`
//! and the durable [`storage::AgentRecord`](crate::storage::AgentRecord).
//!
//! The two records are intentionally different shapes (see
//! `aa-gateway/src/storage/agent.rs` for the rationale): the registry layer
//! owns liveness, heartbeats, and credential tokens; the storage layer
//! persists only the durable identity / configuration fields. This module
//! is the only place that knows how to translate between the two.
//!
//! Conversion runtime → storage is lossy by design: runtime-only fields
//! (`recent_events`, `active_sessions`, `credential_token`, lineage links,
//! …) are dropped because they are either ephemeral, security-sensitive,
//! or reconstructible at the next agent connect. On rehydrate the inverse
//! direction synthesises defaults for the missing runtime fields so the
//! agent reappears in the registry as a root-level entry with status
//! [`AgentStatus::Active`].
//!
//! Introduced by Epic 18 Story S-I.2 (AAASM-1864) — the registry
//! write-through wiring that makes agent registrations durable across
//! gateway restarts.

use std::collections::VecDeque;

use aa_core::identity::AgentId;
use aa_core::GovernanceLevel;

use crate::registry::AgentStatus;
use crate::storage::AgentRecord as StorageAgentRecord;

use super::store::AgentRecord as RuntimeAgentRecord;

/// Metadata key used to round-trip the runtime `enforcement_mode`-equivalent
/// flag through `storage::AgentRecord::enforcement_mode`. The runtime record
/// has no first-class field for this today, so the storage column defaults to
/// `"enforce"` on conversion; later Sub-tasks of Epic 18 may surface it
/// directly on the runtime record.
const DEFAULT_ENFORCEMENT_MODE: &str = "enforce";

/// Metadata key used to carry the agent's friendly name through storage so
/// the runtime field can be restored on rehydrate. The runtime record's
/// `name` field has no direct column in `agent_registry`; piggy-backing on
/// `metadata["name"]` keeps the storage schema flat.
const METADATA_KEY_NAME: &str = "name";

/// Convert a runtime `AgentRecord` into its durable storage equivalent.
///
/// Lossy — runtime-only fields are dropped. `name` is round-tripped through
/// `metadata["name"]` so rehydrate can restore it.
pub fn runtime_to_storage(record: &RuntimeAgentRecord) -> StorageAgentRecord {
    let mut metadata = record.metadata.clone();
    metadata.insert(METADATA_KEY_NAME.to_string(), record.name.clone());
    StorageAgentRecord {
        agent_id: AgentId::from_bytes(record.agent_id),
        team_id: record.team_id.clone(),
        // The runtime record has no org_id field today; storage carries
        // None until later Sub-tasks add an explicit field or the value
        // gets piggy-backed through metadata.
        org_id: None,
        metadata,
        registered_at: record.registered_at,
        last_seen_at: record.last_heartbeat,
        enforcement_mode: DEFAULT_ENFORCEMENT_MODE.to_string(),
    }
}

/// Synthesise a runtime `AgentRecord` from its storage row.
///
/// Used at boot-time rehydrate (see
/// `AgentRegistry::rehydrate_from_storage`). Fills the runtime-only fields
/// with defaults — restored agents reappear as root-level entries with
/// [`AgentStatus::Active`]; their credential tokens, lineage links, and
/// recent-event buffers do not survive a restart and are reconstructed at
/// the next agent connect.
pub fn storage_to_runtime(stored: StorageAgentRecord) -> RuntimeAgentRecord {
    let StorageAgentRecord {
        agent_id,
        team_id,
        org_id: _,
        mut metadata,
        registered_at,
        last_seen_at,
        enforcement_mode: _,
    } = stored;

    let name = metadata.remove(METADATA_KEY_NAME).unwrap_or_default();

    RuntimeAgentRecord {
        agent_id: *agent_id.as_bytes(),
        name,
        // Framework / version / public_key are not persisted today — left
        // empty so rehydrated entries are flagged for the next connect to
        // refresh.
        framework: String::new(),
        version: String::new(),
        risk_tier: 0,
        tool_names: Vec::new(),
        public_key: String::new(),
        credential_token: String::new(),
        metadata,
        registered_at,
        last_heartbeat: last_seen_at,
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
        team_id,
        depth: 0,
        delegation_reason: None,
        spawned_by_tool: None,
        // Restored agents reappear as roots — lineage is not persisted in
        // this Sub-task's storage schema.
        root_agent_id: Some(*agent_id.as_bytes()),
        children: Vec::new(),
        parent_key: None,
        enforcement_mode: None,
        // AAASM-2008 — org_id is not persisted in the current storage
        // schema either; populated as None until the storage layer carries
        // it through (follow-up).
        org_id: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use std::collections::BTreeMap;

    fn sample_runtime(agent_id: [u8; 16]) -> RuntimeAgentRecord {
        let mut metadata = BTreeMap::new();
        metadata.insert("env".to_string(), "staging".to_string());
        RuntimeAgentRecord {
            agent_id,
            name: "demo-agent".to_string(),
            framework: "langgraph".to_string(),
            version: "0.1.0".to_string(),
            risk_tier: 2,
            tool_names: vec!["search".to_string()],
            public_key: "pk".to_string(),
            credential_token: "token".to_string(),
            metadata,
            registered_at: Utc::now(),
            last_heartbeat: Utc::now(),
            status: AgentStatus::Active,
            pid: Some(1234),
            session_count: 0,
            last_event: None,
            policy_violations_count: 0,
            active_sessions: Vec::new(),
            recent_events: VecDeque::new(),
            recent_traces: Vec::new(),
            layer: Some("enforced".to_string()),
            governance_level: GovernanceLevel::L1Observe,
            parent_agent_id: None,
            team_id: Some("teamA".to_string()),
            depth: 0,
            delegation_reason: None,
            spawned_by_tool: None,
            root_agent_id: Some(agent_id),
            children: Vec::new(),
            parent_key: None,
            enforcement_mode: None,
            org_id: None,
        }
    }

    #[test]
    fn runtime_to_storage_preserves_durable_fields() {
        let id = [9u8; 16];
        let rec = sample_runtime(id);
        let stored = runtime_to_storage(&rec);
        assert_eq!(stored.agent_id, AgentId::from_bytes(id));
        assert_eq!(stored.team_id.as_deref(), Some("teamA"));
        assert_eq!(stored.metadata.get("env").map(String::as_str), Some("staging"));
        // `name` is round-tripped via metadata so rehydrate can restore it.
        assert_eq!(
            stored.metadata.get(METADATA_KEY_NAME).map(String::as_str),
            Some("demo-agent")
        );
        assert_eq!(stored.enforcement_mode, DEFAULT_ENFORCEMENT_MODE);
    }

    #[test]
    fn storage_to_runtime_restores_name_and_team() {
        let id = [7u8; 16];
        let rec = sample_runtime(id);
        let stored = runtime_to_storage(&rec);
        let restored = storage_to_runtime(stored);
        assert_eq!(restored.agent_id, id);
        assert_eq!(restored.name, "demo-agent");
        assert_eq!(restored.team_id.as_deref(), Some("teamA"));
        // Rehydrate strips the synthetic `name` key from metadata.
        assert!(!restored.metadata.contains_key(METADATA_KEY_NAME));
        // Restored entries are roots with status Active.
        assert!(matches!(restored.status, AgentStatus::Active));
        assert_eq!(restored.parent_key, None);
        assert_eq!(restored.root_agent_id, Some(id));
    }
}
