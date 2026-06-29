//! [`PolicyStore`] read-through cache backed by Redis JSON values.

use aa_storage::{AgentId, PolicyDocument, PolicyStore, Result, StorageError};
use async_trait::async_trait;
use deadpool_redis::Pool;

use crate::error::backend;
use crate::util::hex16;

/// Suggested default TTL, in seconds, for a cached policy entry.
///
/// Passed to [`RedisPolicyStore::cache_policy`] by callers that do not have a
/// policy-specific TTL of their own.
pub const DEFAULT_POLICY_CACHE_TTL_SECS: u64 = 300;

/// Redis-backed read-through [`PolicyStore`].
///
/// [`get_policy`](PolicyStore::get_policy) reads a JSON [`PolicyDocument`] from
/// `aa:policy:<agent_id>` and returns
/// [`NotFound`](aa_storage::StorageError::NotFound) on a cache miss — callers
/// fall through to the authoritative store and then repopulate the cache with
/// [`cache_policy`](Self::cache_policy).
/// [`invalidate`](PolicyStore::invalidate) deletes the cached key. Cheap to
/// [`Clone`] — clones share the underlying [`Pool`].
#[derive(Clone)]
pub struct RedisPolicyStore {
    pool: Pool,
}

impl RedisPolicyStore {
    /// Create a store over an existing connection pool.
    pub fn new(pool: Pool) -> Self {
        Self { pool }
    }

    /// Populate the cache for `agent_id` with `policy`, expiring after
    /// `ttl_secs` seconds (`SET ... EX`).
    ///
    /// This is the write half of the read-through cache: callers invoke it
    /// after loading a policy from the authoritative store on a
    /// [`get_policy`](PolicyStore::get_policy) miss. See
    /// [`DEFAULT_POLICY_CACHE_TTL_SECS`] for the suggested default TTL.
    pub async fn cache_policy(&self, agent_id: &AgentId, policy: &PolicyDocument, ttl_secs: u64) -> Result<()> {
        let mut conn = self.pool.get().await.map_err(backend)?;
        let payload = serde_json::to_string(policy).map_err(|e| StorageError::Serialization(e.to_string()))?;
        let _: () = redis::cmd("SET")
            .arg(policy_key(agent_id))
            .arg(payload)
            .arg("EX")
            .arg(ttl_secs)
            .query_async(&mut conn)
            .await
            .map_err(backend)?;
        Ok(())
    }
}

// TODO(AAASM-3919): namespace this key by the verified tenant/org id
// (e.g. `aa:policy:<org_id>:<agent_id>`) once org context is threaded into the
// PolicyStore path. The shared L2 cache currently has no tenant boundary; agent
// ids are globally unique so there is no collision today, but also no isolation.
// Deferred here because PolicyStore::get_policy/invalidate carry only an agent
// id — adding a prefix without the org id would break lookups.
fn policy_key(agent_id: &AgentId) -> String {
    format!("aa:policy:{}", hex16(agent_id.as_bytes()))
}

#[async_trait]
impl PolicyStore for RedisPolicyStore {
    async fn get_policy(&self, agent_id: &AgentId) -> Result<PolicyDocument> {
        let mut conn = self.pool.get().await.map_err(backend)?;
        let raw: Option<String> = redis::cmd("GET")
            .arg(policy_key(agent_id))
            .query_async(&mut conn)
            .await
            .map_err(backend)?;
        let raw =
            raw.ok_or_else(|| StorageError::NotFound(format!("policy for agent {}", hex16(agent_id.as_bytes()))))?;
        serde_json::from_str(&raw).map_err(|e| StorageError::Serialization(e.to_string()))
    }

    async fn invalidate(&self, agent_id: &AgentId) -> Result<()> {
        let mut conn = self.pool.get().await.map_err(backend)?;
        let _: () = redis::cmd("DEL")
            .arg(policy_key(agent_id))
            .query_async(&mut conn)
            .await
            .map_err(backend)?;
        Ok(())
    }
}
