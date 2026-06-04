//! In-memory [`SessionStore`] backed by a `DashMap`.

use std::sync::Arc;

use aa_storage::{Result, SessionId, SessionRecord, SessionStore, StorageError};
use async_trait::async_trait;
use dashmap::DashMap;

/// A `DashMap`-backed [`SessionStore`] keyed by session id. Cloning shares the
/// same underlying map.
#[derive(Clone, Default)]
pub struct MemorySessionStore {
    sessions: Arc<DashMap<[u8; 16], SessionRecord>>,
}

impl MemorySessionStore {
    /// Create an empty store.
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl SessionStore for MemorySessionStore {
    async fn save(&self, session: SessionRecord) -> Result<()> {
        self.sessions.insert(*session.session_id.as_bytes(), session);
        Ok(())
    }

    async fn load(&self, session_id: &SessionId) -> Result<SessionRecord> {
        self.sessions
            .get(session_id.as_bytes())
            .map(|entry| entry.value().clone())
            .ok_or_else(|| StorageError::NotFound(format!("session {:?}", session_id.as_bytes())))
    }

    async fn delete(&self, session_id: &SessionId) -> Result<()> {
        self.sessions.remove(session_id.as_bytes());
        Ok(())
    }
}
