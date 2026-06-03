//! [`PgPolicyStore`] — read-side policy access against Postgres.

use aa_storage::{AgentId, PolicyDocument, PolicyStore, Result, StorageError};
use async_trait::async_trait;

use crate::pool::PostgresPool;
use crate::support::{agent_id_to_text, backend_err};

/// Postgres-backed [`PolicyStore`]. Reads the highest-versioned policy row for
/// an agent and deserializes its JSONB `body` into a [`PolicyDocument`].
#[derive(Clone)]
pub struct PgPolicyStore {
    pool: PostgresPool,
}

impl PgPolicyStore {
    /// Build a policy store over an existing pool.
    pub fn new(pool: PostgresPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl PolicyStore for PgPolicyStore {
    async fn get_policy(&self, agent_id: &AgentId) -> Result<PolicyDocument> {
        let id = agent_id_to_text(agent_id);
        let row: Option<(serde_json::Value,)> = sqlx::query_as(
            "SELECT body FROM policies WHERE agent_id = $1 \
             ORDER BY policy_version DESC LIMIT 1",
        )
        .bind(&id)
        .fetch_optional(self.pool.pool())
        .await
        .map_err(backend_err)?;

        let (body,) = row.ok_or(StorageError::NotFound(id))?;
        serde_json::from_value(body).map_err(|e| StorageError::Serialization(e.to_string()))
    }

    async fn invalidate(&self, _agent_id: &AgentId) -> Result<()> {
        // No-op: this driver holds no in-process cache, so reads already hit the
        // source of truth. The L2 cache layer (Epic C) owns invalidation.
        Ok(())
    }
}
