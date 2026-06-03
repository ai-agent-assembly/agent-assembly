//! Trait-conformance suite: the shared `aa-storage` harnesses run against every
//! memory backend through a `&dyn` reference, exercising object-safety too.

use aa_core::EnforcementMode;
use aa_storage::conformance::assert_policy_store_conformance;
use aa_storage::{AgentId, PolicyDocument};
use aa_storage_memory::MemoryPolicyStore;

fn sample_policy() -> PolicyDocument {
    PolicyDocument {
        version: 1,
        name: "conformance".to_owned(),
        rules: Vec::new(),
        enforcement_mode: EnforcementMode::default(),
    }
}

#[tokio::test]
async fn policy_store_conformance() {
    let present = AgentId::from_bytes([1; 16]);
    let absent = AgentId::from_bytes([2; 16]);
    let store = MemoryPolicyStore::new();
    store.insert(&present, sample_policy());
    assert_policy_store_conformance(&store, &present, &absent).await;
}
