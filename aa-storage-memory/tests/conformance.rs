//! Trait-conformance suite: the shared `aa-storage` harnesses run against every
//! memory backend through a `&dyn` reference, exercising object-safety too.

use aa_core::{AuditEventType, EnforcementMode};
use aa_storage::conformance::{
    assert_audit_sink_conformance, assert_credential_store_conformance, assert_policy_store_conformance,
    assert_session_store_conformance,
};
use aa_storage::{AgentId, AuditEntry, PolicyDocument, SessionId, SessionRecord};
use aa_storage_memory::{MemoryAuditSink, MemoryCredentialStore, MemoryPolicyStore, MemorySessionStore};

fn sample_policy() -> PolicyDocument {
    PolicyDocument {
        version: 1,
        name: "conformance".to_owned(),
        rules: Vec::new(),
        enforcement_mode: EnforcementMode::default(),
    }
}

fn sample_audit_entry() -> AuditEntry {
    AuditEntry::new(
        0,
        0,
        AuditEventType::ToolCallIntercepted,
        AgentId::from_bytes([1; 16]),
        SessionId::from_bytes([9; 16]),
        "{}".to_owned(),
        [0u8; 32],
    )
}

#[tokio::test]
async fn policy_store_conformance() {
    let present = AgentId::from_bytes([1; 16]);
    let absent = AgentId::from_bytes([2; 16]);
    let store = MemoryPolicyStore::new();
    store.insert(&present, sample_policy());
    assert_policy_store_conformance(&store, &present, &absent).await;
}

#[tokio::test]
async fn audit_sink_conformance() {
    let sink = MemoryAuditSink::new();
    assert_audit_sink_conformance(&sink, sample_audit_entry()).await;
    assert_eq!(sink.len(), 1, "emitted entry should be buffered");
}

#[tokio::test]
async fn session_store_conformance() {
    let store = MemorySessionStore::new();
    let record = SessionRecord {
        session_id: SessionId::from_bytes([3; 16]),
        agent_id: AgentId::from_bytes([1; 16]),
        started_at_ns: 42,
    };
    assert_session_store_conformance(&store, record).await;
}

#[tokio::test]
async fn credential_store_conformance() {
    let store = MemoryCredentialStore::new();
    assert_credential_store_conformance(&store, "openai/api_key", b"sk-secret".to_vec()).await;
}
