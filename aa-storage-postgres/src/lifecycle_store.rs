//! [`PgLifecycleStore`] — agent register / heartbeat / deregister against Postgres.

use aa_storage::{AgentId, LifecycleStore, Result, StorageError};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::pool::PostgresPool;
use crate::support::{agent_id_to_text, backend_err, SYSTEM_ORG};

/// Postgres-backed [`LifecycleStore`]. Liveness is tracked in the `agents`
/// table's `status` and `last_heartbeat` columns.
#[derive(Clone)]
pub struct PgLifecycleStore {
    pool: PostgresPool,
}

impl PgLifecycleStore {
    /// Build a lifecycle store over an existing pool.
    pub fn new(pool: PostgresPool) -> Self {
        Self { pool }
    }

    /// Register an agent under the verified tenant `org_id`, stamping its row
    /// with that tenant so RLS confines it.
    ///
    /// `org_id` must be the verified caller's tenant (never client input). The
    /// RLS `WITH CHECK` rejects an attempt to register an agent into a different
    /// tenant than the connection's GUC.
    pub async fn register_for_tenant(&self, org_id: Uuid, agent_id: &AgentId) -> Result<()> {
        let mut tx = self.pool.begin_for_tenant(org_id).await.map_err(backend_err)?;
        sqlx::query(
            "INSERT INTO agents (id, org_id, status, registered_at, last_heartbeat) \
             VALUES ($1, $2, 'registered', now(), now()) \
             ON CONFLICT (id) DO UPDATE SET org_id = EXCLUDED.org_id, status = 'registered', last_heartbeat = now()",
        )
        .bind(agent_id_to_text(agent_id))
        .bind(org_id)
        .execute(&mut *tx)
        .await
        .map_err(backend_err)?;
        tx.commit().await.map_err(backend_err)?;
        Ok(())
    }

    /// Record a heartbeat "last seen" for a raw agent-id string without
    /// requiring the agent row to exist.
    ///
    /// The async audit consumer (AAASM-2388) collapses heartbeat events into
    /// this call. Unlike [`LifecycleStore::heartbeat`], an unknown `agent_id`
    /// is a no-op (zero rows) rather than a [`StorageError::NotFound`] — a
    /// heartbeat must never fail the consumer's ack path. `ts` falls back to
    /// `now()` when the event carried no timestamp.
    pub async fn touch_last_heartbeat(&self, agent_id: &str, ts: Option<DateTime<Utc>>) -> Result<()> {
        let mut tx = self.pool.begin_for_tenant(SYSTEM_ORG).await.map_err(backend_err)?;
        sqlx::query("UPDATE agents SET last_heartbeat = COALESCE($2, now()) WHERE id = $1")
            .bind(agent_id)
            .bind(ts)
            .execute(&mut *tx)
            .await
            .map_err(backend_err)?;
        tx.commit().await.map_err(backend_err)?;
        Ok(())
    }
}

#[async_trait]
impl LifecycleStore for PgLifecycleStore {
    async fn register(&self, agent_id: &AgentId) -> Result<()> {
        // The org-less trait register carries no org context (org_id stays NULL,
        // which the agents RLS policy COALESCEs to the system org); tenant
        // callers use `register_for_tenant`. Scoped through the system-org GUC so
        // the write passes FORCE RLS.
        let mut tx = self.pool.begin_for_tenant(SYSTEM_ORG).await.map_err(backend_err)?;
        sqlx::query(
            "INSERT INTO agents (id, status, registered_at, last_heartbeat) \
             VALUES ($1, 'registered', now(), now()) \
             ON CONFLICT (id) DO UPDATE SET status = 'registered', last_heartbeat = now()",
        )
        .bind(agent_id_to_text(agent_id))
        .execute(&mut *tx)
        .await
        .map_err(backend_err)?;
        tx.commit().await.map_err(backend_err)?;
        Ok(())
    }

    async fn heartbeat(&self, agent_id: &AgentId) -> Result<()> {
        let id = agent_id_to_text(agent_id);
        let mut tx = self.pool.begin_for_tenant(SYSTEM_ORG).await.map_err(backend_err)?;
        let result = sqlx::query("UPDATE agents SET last_heartbeat = now() WHERE id = $1")
            .bind(&id)
            .execute(&mut *tx)
            .await
            .map_err(backend_err)?;
        tx.commit().await.map_err(backend_err)?;

        if result.rows_affected() == 0 {
            return Err(StorageError::NotFound(id));
        }
        Ok(())
    }

    async fn deregister(&self, agent_id: &AgentId) -> Result<()> {
        // Idempotent: marking an absent agent offline affects zero rows and
        // still succeeds. Scoped through the system-org GUC under FORCE RLS.
        let mut tx = self.pool.begin_for_tenant(SYSTEM_ORG).await.map_err(backend_err)?;
        sqlx::query("UPDATE agents SET status = 'deregistered' WHERE id = $1")
            .bind(agent_id_to_text(agent_id))
            .execute(&mut *tx)
            .await
            .map_err(backend_err)?;
        tx.commit().await.map_err(backend_err)?;
        Ok(())
    }
}
