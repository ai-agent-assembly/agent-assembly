//! [`CacheSource`] — the store an [`L1Cache`](crate::L1Cache) loads from on a miss.

use std::hash::Hash;

use aa_core::storage::{AgentId, PolicyDocument, PolicyStore, Result};
use async_trait::async_trait;

/// The backing store an [`L1Cache`](crate::L1Cache) fronts.
///
/// Abstracts "load the value for a key" so the cache is generic over any store —
/// `PolicyStore`, `SessionStore`, `CredentialStore`, … — without depending on a
/// concrete one. The associated [`Key`](CacheSource::Key) and
/// [`Value`](CacheSource::Value) become the cache's key and cached value types.
#[async_trait]
pub trait CacheSource: Send + Sync {
    /// The key the source is addressed by; also the cache key.
    type Key: Eq + Hash + Clone + Send + Sync;

    /// The value the source returns; cloned out of the cache on a hit.
    type Value: Clone + Send + Sync;

    /// Load the value for `key` from the underlying store.
    async fn load(&self, key: &Self::Key) -> Result<Self::Value>;
}

/// Every [`PolicyStore`] is a [`CacheSource`] keyed by [`AgentId`] returning a
/// [`PolicyDocument`], so `L1Cache<P>` fronts any policy backend directly.
#[async_trait]
impl<P: PolicyStore> CacheSource for P {
    type Key = AgentId;
    type Value = PolicyDocument;

    async fn load(&self, key: &AgentId) -> Result<PolicyDocument> {
        self.get_policy(key).await
    }
}
