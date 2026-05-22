//! PostgreSQL-backed implementation of [`StorageBackend`](super::backend::StorageBackend).
//!
//! Only the constructor lands in this sub-task (Epic 18 S-C #1). The
//! [`StorageBackend`](super::backend::StorageBackend) trait impl is built up
//! incrementally across sub-tasks #2 – #7.

use std::time::Duration;

use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;

use super::error::{StorageError, StorageResult};
use super::postgres_config::PostgresConfig;

/// PostgreSQL-backed control-plane storage.
///
/// Created via [`PostgresBackend::connect`]. The trait surface (audit /
/// registry / policy / metrics / lifecycle methods) is filled in by the
/// later Epic-18 S-C sub-tasks.
pub struct PostgresBackend {
    pool: PgPool,
}

impl PostgresBackend {
    /// Open a connection pool against `config`.
    ///
    /// Returns [`StorageError::ConnectionFailed`] when `database_url` is
    /// unset or the pool cannot be opened. The error message explicitly
    /// names `AAASM_DATABASE_URL` so operators see the missing-env path
    /// without having to dig through stack traces.
    pub async fn connect(config: &PostgresConfig) -> StorageResult<Self> {
        let database_url = config.database_url.as_deref().ok_or_else(|| {
            StorageError::ConnectionFailed(
                "AAASM_DATABASE_URL is not set and storage.postgres.database_url is not configured".into(),
            )
        })?;

        let pool = PgPoolOptions::new()
            .max_connections(config.max_connections)
            .min_connections(config.min_connections)
            .acquire_timeout(Duration::from_secs(config.connect_timeout_secs))
            .connect(database_url)
            .await
            .map_err(|e| StorageError::ConnectionFailed(e.to_string()))?;

        Ok(Self { pool })
    }

    /// Apply the embedded `migrations/postgres/*.sql` migrations.
    ///
    /// Idempotent — sqlx records applied versions in `_sqlx_migrations`,
    /// so calling this against an already-migrated database is a no-op.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError::MigrationFailed`] when any migration fails
    /// to apply or sqlx cannot verify previously-applied versions.
    pub async fn migrate(&self) -> StorageResult<()> {
        sqlx::migrate!("./migrations/postgres")
            .run(&self.pool)
            .await
            .map_err(|e| StorageError::MigrationFailed(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Returns a connected backend when `AAASM_DATABASE_URL` is set, or `None`
    /// after printing a skip notice when the env var is absent. This lets the
    /// suite stay green on developer machines without a local PostgreSQL while
    /// still exercising the real driver in CI.
    async fn pg_backend_or_skip() -> Option<PostgresBackend> {
        let url = match std::env::var("AAASM_DATABASE_URL") {
            Ok(v) => v,
            Err(_) => {
                eprintln!(
                    "skipping postgres test: AAASM_DATABASE_URL not set (CI provides this via services: postgres)"
                );
                return None;
            }
        };
        let config = PostgresConfig {
            database_url: Some(url),
            ..PostgresConfig::default()
        };
        Some(
            PostgresBackend::connect(&config)
                .await
                .expect("connect to AAASM_DATABASE_URL"),
        )
    }

    #[tokio::test]
    async fn connect_rejects_missing_database_url() {
        let config = PostgresConfig::default();
        let result = PostgresBackend::connect(&config).await;
        match result {
            Err(StorageError::ConnectionFailed(msg)) => {
                assert!(
                    msg.contains("AAASM_DATABASE_URL"),
                    "missing-URL error must mention AAASM_DATABASE_URL, got: {msg}"
                );
            }
            Err(other) => panic!("expected ConnectionFailed, got {other:?}"),
            Ok(_) => panic!("expected error when database_url is None"),
        }
    }

    #[tokio::test]
    async fn migrate_creates_expected_tables() {
        let Some(backend) = pg_backend_or_skip().await else {
            return;
        };
        backend.migrate().await.expect("migrate");

        for table in ["agent_registry", "policy_versions", "audit_events", "metrics"] {
            let exists: bool =
                sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_tables WHERE tablename = $1)")
                    .bind(table)
                    .fetch_one(&backend.pool)
                    .await
                    .expect("query pg_tables");
            assert!(exists, "table {table} should exist after migrate()");
        }
    }

    #[tokio::test]
    async fn migrate_is_idempotent() {
        let Some(backend) = pg_backend_or_skip().await else {
            return;
        };
        backend.migrate().await.expect("first migrate");
        backend.migrate().await.expect("second migrate should be a no-op");
    }
}
