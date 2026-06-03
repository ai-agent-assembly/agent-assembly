//! All-memory end-to-end check: drive the memory backends together the way an
//! all-`"memory"` deployment would — lifecycle, policy lookup, and audit.

use aa_core::{AuditEventType, EnforcementMode};
use aa_storage::{AgentId, AuditEntry, AuditSink, LifecycleStore, PolicyDocument, PolicyStore, SessionId};
use aa_storage_memory::{MemoryAuditSink, MemoryLifecycleStore, MemoryPolicyStore};

#[tokio::test]
async fn all_memory_lifecycle_policy_and_audit_round_trip() {
    let agent = AgentId::from_bytes([7; 16]);
    let session = SessionId::from_bytes([8; 16]);

    // Lifecycle: register the agent and heartbeat it.
    let lifecycle = MemoryLifecycleStore::new();
    lifecycle.register(&agent).await.expect("register should succeed");
    lifecycle.heartbeat(&agent).await.expect("heartbeat should succeed");

    // Policy lookup: seed and resolve the agent's effective policy.
    let policies = MemoryPolicyStore::new();
    policies.insert(
        &agent,
        PolicyDocument {
            version: 1,
            name: "all-memory".to_owned(),
            rules: Vec::new(),
            enforcement_mode: EnforcementMode::default(),
        },
    );
    let resolved = policies.get_policy(&agent).await.expect("policy should resolve");
    assert_eq!(resolved.name, "all-memory");

    // Audit: emit an event and drain it back.
    let audit = MemoryAuditSink::new();
    audit
        .emit(AuditEntry::new(
            0,
            0,
            AuditEventType::PolicyViolation,
            agent,
            session,
            "{}".to_owned(),
            [0u8; 32],
        ))
        .await
        .expect("emit should succeed");
    let drained = audit.drain();
    assert_eq!(drained.len(), 1, "one entry should have been emitted");
    assert_eq!(drained[0].event_type(), AuditEventType::PolicyViolation);
    assert!(audit.is_empty(), "drain should empty the buffer");
}
