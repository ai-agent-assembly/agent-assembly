//! In-memory [`LifecycleStore`] backed by a `DashMap`.

use std::sync::Arc;
use std::time::Instant;

use aa_storage::{AgentId, LifecycleStore, Result, StorageError};
use async_trait::async_trait;
use dashmap::DashMap;

/// A `DashMap`-backed [`LifecycleStore`] mapping a registered agent to the
/// instant of its last heartbeat. Cloning shares the same underlying map.
#[derive(Clone, Default)]
pub struct MemoryLifecycleStore {
    agents: Arc<DashMap<[u8; 16], Instant>>,
}

impl MemoryLifecycleStore {
    /// Create an empty store.
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl LifecycleStore for MemoryLifecycleStore {
    async fn register(&self, agent_id: &AgentId) -> Result<()> {
        self.agents.insert(*agent_id.as_bytes(), Instant::now());
        Ok(())
    }

    async fn heartbeat(&self, agent_id: &AgentId) -> Result<()> {
        match self.agents.get_mut(agent_id.as_bytes()) {
            Some(mut entry) => {
                *entry = Instant::now();
                Ok(())
            }
            None => Err(StorageError::NotFound(format!("agent {:?}", agent_id.as_bytes()))),
        }
    }

    async fn deregister(&self, agent_id: &AgentId) -> Result<()> {
        self.agents.remove(agent_id.as_bytes());
        Ok(())
    }
}
