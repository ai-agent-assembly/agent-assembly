//! In-memory [`PolicyStore`] backed by a `DashMap`.

use std::sync::Arc;

use aa_storage::{AgentId, PolicyDocument, PolicyStore, Result, StorageError};
use async_trait::async_trait;
use dashmap::DashMap;

/// A `DashMap`-backed [`PolicyStore`] for tests and local development.
///
/// The store is authoritative — it holds the policies directly rather than
/// caching a remote source — so [`invalidate`](PolicyStore::invalidate) is a
/// no-op (there is no upstream to reload from). Cloning shares the same
/// underlying map.
#[derive(Clone, Default)]
pub struct MemoryPolicyStore {
    policies: Arc<DashMap<[u8; 16], PolicyDocument>>,
}

impl MemoryPolicyStore {
    /// Create an empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert or replace the policy associated with `agent_id`.
    ///
    /// A seed helper for tests and boot wiring; not part of the trait contract.
    pub fn insert(&self, agent_id: &AgentId, policy: PolicyDocument) {
        self.policies.insert(*agent_id.as_bytes(), policy);
    }
}

#[async_trait]
impl PolicyStore for MemoryPolicyStore {
    async fn get_policy(&self, agent_id: &AgentId) -> Result<PolicyDocument> {
        self.policies
            .get(agent_id.as_bytes())
            .map(|entry| entry.value().clone())
            .ok_or_else(|| StorageError::NotFound(format!("policy for agent {:?}", agent_id.as_bytes())))
    }

    async fn invalidate(&self, _agent_id: &AgentId) -> Result<()> {
        // Authoritative store: nothing is cached, so there is nothing to drop.
        Ok(())
    }
}
