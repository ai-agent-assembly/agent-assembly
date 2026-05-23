//! Storage backend bootstrap helpers.
//!
//! Centralises the open-then-migrate sequence each deployment mode
//! runs at startup. Local mode opens a SQLite file at the configured
//! path; remote mode connects to PostgreSQL. In both cases the helper
//! returns the backend already type-erased as `Arc<dyn StorageBackend>`
//! so call sites never depend on the concrete driver type.
//!
//! Introduced by Epic 18 Story S-I.1 (AAASM-1859); consumed by the
//! Local/Remote boot paths in subsequent commits of the same Story.

use std::path::Path;
use std::sync::Arc;

use super::{PostgresBackend, PostgresConfig, SqliteBackend, SqliteConfig, StorageBackend, StorageResult};

/// Open a SQLite-backed [`StorageBackend`] at `path` and apply pending
/// schema migrations.
///
/// `path`'s parent directories are assumed to exist — local mode
/// guarantees this via `ensure_storage_parent` before calling here.
///
/// Returns the backend already wrapped in `Arc<dyn StorageBackend>` so
/// the caller can hand it straight to [`crate::AppState::new`].
///
/// # Errors
///
/// Surfaces any [`StorageError`](super::StorageError) raised by the
/// underlying `SqliteBackend::open` or `migrate` calls — typically
/// `ConnectionFailed` (bad path / permissions) or `MigrationFailed`
/// (schema apply error).
pub async fn open_sqlite_backend(path: &Path) -> StorageResult<Arc<dyn StorageBackend>> {
    let backend = SqliteBackend::open(&SqliteConfig {
        path: path.to_path_buf(),
    })
    .await?;
    backend.migrate().await?;
    Ok(Arc::new(backend))
}

/// Connect to a PostgreSQL-backed [`StorageBackend`] from `config`
/// and apply pending schema migrations.
///
/// Returns the backend already wrapped in `Arc<dyn StorageBackend>`
/// for the same reason as [`open_sqlite_backend`].
///
/// # Errors
///
/// Surfaces `ConnectionFailed` when the database is unreachable and
/// `MigrationFailed` when the schema cannot be brought up to date.
pub async fn open_postgres_backend(config: &PostgresConfig) -> StorageResult<Arc<dyn StorageBackend>> {
    let backend = PostgresBackend::connect(config).await?;
    backend.migrate().await?;
    Ok(Arc::new(backend))
}
