//! [`SessionStore`] — persistence for per-execution session records.

use crate::{AgentId, Result, SessionId};
use async_trait::async_trait;

/// A persisted record of a single agent execution session.
///
/// One record is created per execution run and ties together all governance
/// events within that run. Backends key the record by its
/// [`session_id`](SessionRecord::session_id).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionRecord {
    /// Stable identifier for this execution run.
    pub session_id: SessionId,
    /// The agent that owns this session.
    pub agent_id: AgentId,
    /// Wall-clock start time of the session, in nanoseconds since the Unix epoch.
    pub started_at_ns: u64,
}

/// Persists, loads, and deletes [`SessionRecord`]s.
///
/// The runtime saves a record when a session starts, loads it to resume
/// governance context, and deletes it when the session ends.
///
/// # Example
///
/// ```
/// use aa_storage::{Result, SessionRecord, SessionStore, StorageError};
/// use aa_storage::SessionId;
/// use async_trait::async_trait;
///
/// /// A store that holds no sessions.
/// struct EmptySessionStore;
///
/// #[async_trait]
/// impl SessionStore for EmptySessionStore {
///     async fn save(&self, _session: SessionRecord) -> Result<()> {
///         Ok(())
///     }
///
///     async fn load(&self, session_id: &SessionId) -> Result<SessionRecord> {
///         Err(StorageError::NotFound(format!("{:?}", session_id.as_bytes())))
///     }
///
///     async fn delete(&self, _session_id: &SessionId) -> Result<()> {
///         Ok(())
///     }
/// }
/// ```
#[async_trait]
pub trait SessionStore: Send + Sync {
    /// Persist `session`, overwriting any record with the same session id.
    async fn save(&self, session: SessionRecord) -> Result<()>;

    /// Load the record for `session_id`.
    ///
    /// Returns [`StorageError::NotFound`](crate::StorageError::NotFound) when no
    /// record exists for the id.
    async fn load(&self, session_id: &SessionId) -> Result<SessionRecord>;

    /// Delete the record for `session_id`.
    ///
    /// Idempotent: deleting an absent session succeeds.
    async fn delete(&self, session_id: &SessionId) -> Result<()>;
}
