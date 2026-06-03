//! [`PolicyStore`] — read-side access to an agent's effective policy.

use crate::{AgentId, PolicyDocument, Result};
use async_trait::async_trait;

/// Fetches and invalidates the effective [`PolicyDocument`] for an agent.
///
/// The runtime calls [`get_policy`](PolicyStore::get_policy) on the hot path
/// before evaluating an action, so backends are expected to serve from a fast
/// store (or a cache wrapper layered on top — see Epic C). When a policy changes,
/// [`invalidate`](PolicyStore::invalidate) drops any cached copy so the next read
/// reloads from the source of truth.
///
/// # Example
///
/// ```
/// use aa_storage::{AgentId, PolicyDocument, PolicyStore, Result, StorageError};
/// use async_trait::async_trait;
///
/// /// A backend that has no policy for any agent.
/// struct EmptyPolicyStore;
///
/// #[async_trait]
/// impl PolicyStore for EmptyPolicyStore {
///     async fn get_policy(&self, agent_id: &AgentId) -> Result<PolicyDocument> {
///         Err(StorageError::NotFound(format!("{:?}", agent_id.as_bytes())))
///     }
///
///     async fn invalidate(&self, _agent_id: &AgentId) -> Result<()> {
///         Ok(())
///     }
/// }
/// ```
#[async_trait]
pub trait PolicyStore: Send + Sync {
    /// Return the effective policy for `agent_id`.
    ///
    /// Returns [`StorageError::NotFound`](crate::StorageError::NotFound) when the
    /// agent has no policy on record.
    async fn get_policy(&self, agent_id: &AgentId) -> Result<PolicyDocument>;

    /// Drop any cached policy for `agent_id` so the next read reloads it.
    ///
    /// Idempotent: invalidating an agent with no cached entry succeeds.
    async fn invalidate(&self, agent_id: &AgentId) -> Result<()>;
}
