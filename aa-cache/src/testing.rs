//! In-memory test/bench doubles for the storage traits.
//!
//! Gated behind the `test-utils` feature (and always available under `cfg(test)`)
//! so production builds never pull the scaffolding.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use aa_core::policy::EnforcementMode;
use aa_core::storage::{AgentId, PolicyDocument, PolicyStore, Result, StorageError};
use async_trait::async_trait;

/// Build a throwaway [`PolicyDocument`] with the given schema version.
#[must_use]
pub fn sample_policy(version: u32) -> PolicyDocument {
    PolicyDocument {
        version,
        name: "sample".to_owned(),
        rules: Vec::new(),
        enforcement_mode: EnforcementMode::default(),
    }
}

/// An in-memory [`PolicyStore`] for tests and benchmarks.
///
/// Counts `get_policy` calls (so stampede tests can assert "exactly one inner
/// call") and supports an artificial per-call delay (to widen the stampede
/// window deterministically).
#[derive(Default)]
pub struct MemoryPolicyStore {
    policies: HashMap<[u8; 16], PolicyDocument>,
    calls: AtomicUsize,
    delay: Option<Duration>,
}

impl MemoryPolicyStore {
    /// An empty store with no policies and no artificial delay.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A store seeded with a single `agent_id -> policy` mapping.
    #[must_use]
    pub fn with_policy(agent_id: AgentId, policy: PolicyDocument) -> Self {
        let mut store = Self::new();
        store.insert(agent_id, policy);
        store
    }

    /// Seed or overwrite the policy for `agent_id`.
    pub fn insert(&mut self, agent_id: AgentId, policy: PolicyDocument) {
        self.policies.insert(*agent_id.as_bytes(), policy);
    }

    /// Make every `get_policy` sleep `delay` before returning, widening the
    /// window in which concurrent callers pile up behind the cache leader.
    #[must_use]
    pub fn with_delay(mut self, delay: Duration) -> Self {
        self.delay = Some(delay);
        self
    }

    /// Number of `get_policy` calls served so far.
    #[must_use]
    pub fn call_count(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl PolicyStore for MemoryPolicyStore {
    async fn get_policy(&self, agent_id: &AgentId) -> Result<PolicyDocument> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if let Some(delay) = self.delay {
            tokio::time::sleep(delay).await;
        }
        self.policies
            .get(agent_id.as_bytes())
            .cloned()
            .ok_or_else(|| StorageError::NotFound(format!("{:?}", agent_id.as_bytes())))
    }

    async fn invalidate(&self, _agent_id: &AgentId) -> Result<()> {
        Ok(())
    }
}
