//! [`PgPolicyStore`] — read-side policy access against Postgres.

use aa_storage::{AgentId, PolicyDocument, PolicyStore, Result, StorageError};
use async_trait::async_trait;
use uuid::Uuid;

use crate::pool::PostgresPool;
use crate::support::{agent_id_to_text, backend_err, SYSTEM_ORG};

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

    /// Read the highest-versioned policy for `agent_id` under the verified
    /// tenant `org_id`, running through an RLS-scoped connection.
    ///
    /// `org_id` must be the verified caller's tenant (never client input). The
    /// `tenant_isolation` policy already confines rows to `org_id`, so this is
    /// the DB-backstopped read: even with the `WHERE org_id` predicate dropped,
    /// RLS returns only this tenant's rows.
    pub async fn get_policy_for_tenant(&self, org_id: Uuid, agent_id: &AgentId) -> Result<PolicyDocument> {
        let id = agent_id_to_text(agent_id);
        let mut tx = self.pool.begin_for_tenant(org_id).await.map_err(backend_err)?;
        let row: Option<(serde_json::Value,)> = sqlx::query_as(
            "SELECT body FROM policies WHERE agent_id = $1 \
             ORDER BY policy_version DESC LIMIT 1",
        )
        .bind(&id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(backend_err)?;
        tx.commit().await.map_err(backend_err)?;

        let (body,) = row.ok_or(StorageError::NotFound(id))?;
        serde_json::from_value(body).map_err(|e| StorageError::Serialization(e.to_string()))
    }
}

#[async_trait]
impl PolicyStore for PgPolicyStore {
    async fn get_policy(&self, agent_id: &AgentId) -> Result<PolicyDocument> {
        // The org-less trait method scopes to the reserved system org; callers
        // that carry a verified tenant use `get_policy_for_tenant`. Under FORCE
        // RLS an unscoped read would see zero rows, so this routes through the
        // system-org GUC rather than the bare pool.
        self.get_policy_for_tenant(SYSTEM_ORG, agent_id).await
    }

    async fn invalidate(&self, _agent_id: &AgentId) -> Result<()> {
        // No-op: this driver holds no in-process cache, so reads already hit the
        // source of truth. The L2 cache layer (Epic C) owns invalidation.
        Ok(())
    }
}
