//! [`PgCredentialStore`] — opaque secret storage against Postgres.

use aa_storage::{CredentialStore, Result, StorageError};
use async_trait::async_trait;

use crate::pool::PostgresPool;
use crate::support::backend_err;

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
}

#[async_trait]
impl CredentialStore for PgCredentialStore {
    async fn get_secret(&self, key: &str) -> Result<Vec<u8>> {
        let row: Option<(Vec<u8>,)> = sqlx::query_as("SELECT ciphertext FROM credentials WHERE key = $1")
            .bind(key)
            .fetch_optional(self.pool.pool())
            .await
            .map_err(backend_err)?;

        let (ciphertext,) = row.ok_or_else(|| StorageError::NotFound(key.to_owned()))?;
        Ok(ciphertext)
    }

    async fn put_secret(&self, key: &str, value: Vec<u8>) -> Result<()> {
        sqlx::query(
            "INSERT INTO credentials (key, ciphertext, updated_at) \
             VALUES ($1, $2, now()) \
             ON CONFLICT (key) DO UPDATE SET ciphertext = EXCLUDED.ciphertext, updated_at = now()",
        )
        .bind(key)
        .bind(value)
        .execute(self.pool.pool())
        .await
        .map_err(backend_err)?;
        Ok(())
    }

    async fn delete_secret(&self, key: &str) -> Result<()> {
        // Idempotent: deleting an absent key affects zero rows and still succeeds.
        sqlx::query("DELETE FROM credentials WHERE key = $1")
            .bind(key)
            .execute(self.pool.pool())
            .await
            .map_err(backend_err)?;
        Ok(())
    }
}
