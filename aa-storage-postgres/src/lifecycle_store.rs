//! [`PgLifecycleStore`] — agent register / heartbeat / deregister against Postgres.

use aa_storage::{AgentId, LifecycleStore, Result, StorageError};
use async_trait::async_trait;

use crate::pool::PostgresPool;
use crate::support::{agent_id_to_text, backend_err};

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
}

#[async_trait]
impl LifecycleStore for PgLifecycleStore {
    async fn register(&self, agent_id: &AgentId) -> Result<()> {
        // Upsert so a re-registration overwrites a stale row's status/heartbeat.
        sqlx::query(
            "INSERT INTO agents (id, status, registered_at, last_heartbeat) \
             VALUES ($1, 'registered', now(), now()) \
             ON CONFLICT (id) DO UPDATE SET status = 'registered', last_heartbeat = now()",
        )
        .bind(agent_id_to_text(agent_id))
        .execute(self.pool.pool())
        .await
        .map_err(backend_err)?;
        Ok(())
    }

    async fn heartbeat(&self, agent_id: &AgentId) -> Result<()> {
        let id = agent_id_to_text(agent_id);
        let result = sqlx::query("UPDATE agents SET last_heartbeat = now() WHERE id = $1")
            .bind(&id)
            .execute(self.pool.pool())
            .await
            .map_err(backend_err)?;

        if result.rows_affected() == 0 {
            return Err(StorageError::NotFound(id));
        }
        Ok(())
    }

    async fn deregister(&self, agent_id: &AgentId) -> Result<()> {
        // Idempotent: marking an absent agent offline affects zero rows and
        // still succeeds.
        sqlx::query("UPDATE agents SET status = 'deregistered' WHERE id = $1")
            .bind(agent_id_to_text(agent_id))
            .execute(self.pool.pool())
            .await
            .map_err(backend_err)?;
        Ok(())
    }
}
