//! [`PgCredentialStore`] — opaque secret storage against Postgres.

use aa_storage::{CredentialStore, Result, StorageError};
use async_trait::async_trait;
use uuid::Uuid;

use crate::pool::PostgresPool;
use crate::support::{backend_err, SYSTEM_ORG};

/// Postgres-backed [`CredentialStore`]. Secrets are stored verbatim as opaque
/// ciphertext in the `credentials.ciphertext` column; the driver never sees or
/// stores plaintext.
#[derive(Clone)]
pub struct PgCredentialStore {
    pool: PostgresPool,
}

impl PgCredentialStore {
    /// Build a credential store over an existing pool.
    pub fn new(pool: PostgresPool) -> Self {
        Self { pool }
    }

    /// Fetch a secret for `key` under the verified tenant `org_id`, via an
    /// RLS-scoped connection. A key owned by another tenant is RLS-invisible and
    /// reads as [`StorageError::NotFound`].
    pub async fn get_secret_for_tenant(&self, org_id: Uuid, key: &str) -> Result<Vec<u8>> {
        let mut tx = self.pool.begin_for_tenant(org_id).await.map_err(backend_err)?;
        let row: Option<(Vec<u8>,)> = sqlx::query_as("SELECT ciphertext FROM credentials WHERE key = $1")
            .bind(key)
            .fetch_optional(&mut *tx)
            .await
            .map_err(backend_err)?;
        tx.commit().await.map_err(backend_err)?;

        let (ciphertext,) = row.ok_or_else(|| StorageError::NotFound(key.to_owned()))?;
        Ok(ciphertext)
    }

    /// Store a secret for `key` under the verified tenant `org_id`, stamping the
    /// row with that tenant. The RLS `WITH CHECK` rejects any attempt to write a
    /// row for a different tenant than the connection's GUC.
    pub async fn put_secret_for_tenant(&self, org_id: Uuid, key: &str, value: Vec<u8>) -> Result<()> {
        let mut tx = self.pool.begin_for_tenant(org_id).await.map_err(backend_err)?;
        sqlx::query(
            "INSERT INTO credentials (key, ciphertext, org_id, updated_at) \
             VALUES ($1, $2, $3, now()) \
             ON CONFLICT (key) DO UPDATE SET ciphertext = EXCLUDED.ciphertext, updated_at = now()",
        )
        .bind(key)
        .bind(value)
        .bind(org_id)
        .execute(&mut *tx)
        .await
        .map_err(backend_err)?;
        tx.commit().await.map_err(backend_err)?;
        Ok(())
    }
}

#[async_trait]
impl CredentialStore for PgCredentialStore {
    async fn get_secret(&self, key: &str) -> Result<Vec<u8>> {
        // Org-less trait read scopes to the reserved system org; tenant callers
        // use `get_secret_for_tenant`.
        self.get_secret_for_tenant(SYSTEM_ORG, key).await
    }

    async fn put_secret(&self, key: &str, value: Vec<u8>) -> Result<()> {
        // Org-less trait write scopes to the reserved system org; tenant callers
        // use `put_secret_for_tenant`.
        self.put_secret_for_tenant(SYSTEM_ORG, key, value).await
    }

    async fn delete_secret(&self, key: &str) -> Result<()> {
        // Idempotent: deleting an absent (or RLS-invisible) key affects zero rows
        // and still succeeds. Scoped to the reserved system org under FORCE RLS.
        let mut tx = self.pool.begin_for_tenant(SYSTEM_ORG).await.map_err(backend_err)?;
        sqlx::query("DELETE FROM credentials WHERE key = $1")
            .bind(key)
            .execute(&mut *tx)
            .await
            .map_err(backend_err)?;
        tx.commit().await.map_err(backend_err)?;
        Ok(())
    }
}
