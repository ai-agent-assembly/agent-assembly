//! Integration test proving the conformance harness runs against a real
//! `PolicyStore` implementation, driven through a `dyn` reference.

use std::collections::HashMap;

use aa_core::EnforcementMode;
use aa_storage::conformance::assert_policy_store_conformance;
use aa_storage::{AgentId, PolicyDocument, PolicyStore, Result, StorageError};
use async_trait::async_trait;

/// Minimal in-memory `PolicyStore` used only to exercise the conformance harness.
struct MemoryPolicyStore {
    policies: HashMap<[u8; 16], PolicyDocument>,
}

#[async_trait]
impl PolicyStore for MemoryPolicyStore {
    async fn get_policy(&self, agent_id: &AgentId) -> Result<PolicyDocument> {
        self.policies
            .get(agent_id.as_bytes())
            .cloned()
            .ok_or_else(|| StorageError::NotFound(format!("{:?}", agent_id.as_bytes())))
    }

    async fn invalidate(&self, _agent_id: &AgentId) -> Result<()> {
        Ok(())
    }
}

#[tokio::test]
async fn memory_policy_store_satisfies_conformance() {
    let present = AgentId::from_bytes([1; 16]);
    let absent = AgentId::from_bytes([2; 16]);

    let mut policies = HashMap::new();
    policies.insert(
        *present.as_bytes(),
        PolicyDocument {
            version: 1,
            name: "test".to_owned(),
            rules: Vec::new(),
            enforcement_mode: EnforcementMode::default(),
        },
    );

    let store = MemoryPolicyStore { policies };

    // Coerces to `&dyn PolicyStore` at the call site, exercising object-safety.
    assert_policy_store_conformance(&store, &present, &absent).await;
}
