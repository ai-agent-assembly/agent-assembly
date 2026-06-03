//! [`LifecycleStore`] — agent register / heartbeat / deregister bookkeeping.

use crate::{AgentId, Result};
use async_trait::async_trait;

/// Tracks agent liveness through register, heartbeat, and deregister.
///
/// The runtime [`register`](LifecycleStore::register)s an agent when it comes
/// online, sends periodic [`heartbeat`](LifecycleStore::heartbeat)s while it runs,
/// and [`deregister`](LifecycleStore::deregister)s it on clean shutdown. Backends
/// use the heartbeat timestamp to expire agents that stopped reporting.
///
/// # Example
///
/// ```
/// use aa_storage::{AgentId, LifecycleStore, Result};
/// use async_trait::async_trait;
///
/// /// A store that accepts all lifecycle transitions and persists nothing.
/// struct NullLifecycleStore;
///
/// #[async_trait]
/// impl LifecycleStore for NullLifecycleStore {
///     async fn register(&self, _agent_id: &AgentId) -> Result<()> {
///         Ok(())
///     }
///
///     async fn heartbeat(&self, _agent_id: &AgentId) -> Result<()> {
///         Ok(())
///     }
///
///     async fn deregister(&self, _agent_id: &AgentId) -> Result<()> {
///         Ok(())
///     }
/// }
/// ```
#[async_trait]
pub trait LifecycleStore: Send + Sync {
    /// Record that `agent_id` is now online.
    ///
    /// Overwrites any stale registration for the same agent.
    async fn register(&self, agent_id: &AgentId) -> Result<()>;

    /// Refresh the liveness timestamp for `agent_id`.
    ///
    /// Returns [`StorageError::NotFound`](crate::StorageError::NotFound) when the
    /// agent is not currently registered.
    async fn heartbeat(&self, agent_id: &AgentId) -> Result<()>;

    /// Record that `agent_id` has gone offline.
    ///
    /// Idempotent: deregistering an agent that is not registered succeeds.
    async fn deregister(&self, agent_id: &AgentId) -> Result<()>;
}
