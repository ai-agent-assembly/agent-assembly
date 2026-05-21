//! Schema migration runner for the storage layer.
//!
//! Wraps [`sqlx::migrate!`] so the gateway's startup path can apply pending
//! migrations against any `sqlx` pool — SQLite (local mode) or PostgreSQL
//! (production). Migration files live in `aa-gateway/migrations/` and are
//! embedded into the binary at compile time. Re-running an already-applied
//! migration is a no-op (idempotent), and a failed migration surfaces as
//! [`StorageError::MigrationFailed`].
//!
//! The wiring of [`run_migrations`] into `local_mode.rs` / `remote_mode.rs`
//! is owned by Epic 18 Story S-I (AAASM-1590); when an instance of
//! [`StorageBackend`](super::StorageBackend) exposes a `pool()` accessor,
//! callers invoke this once before serving requests.

use std::ops::Deref;

use sqlx::migrate::{Migrate, Migrator};
use sqlx::Acquire;

use super::error::{StorageError, StorageResult};

/// Compile-time-embedded migrator pointing at `aa-gateway/migrations/`.
static MIGRATOR: Migrator = sqlx::migrate!("./migrations");

/// Apply `migrator` against `conn`, mapping any driver error to
/// [`StorageError::MigrationFailed`].
///
/// Kept `pub(crate)` so tests can drive the runner with fixture migrators
/// (good and bad) without leaking `sqlx` types onto the public surface.
///
/// # Errors
///
/// Returns [`StorageError::MigrationFailed`] when a migration fails to
/// apply, the checksum verification fails, or the connection cannot be
/// acquired.
pub(crate) async fn apply<'a, A>(migrator: &Migrator, conn: A) -> StorageResult<()>
where
    A: Acquire<'a> + Send,
    <A::Connection as Deref>::Target: Migrate,
{
    migrator
        .run(conn)
        .await
        .map_err(|e| StorageError::MigrationFailed(e.to_string()))
}

/// Run every pending schema migration against `conn`.
///
/// Idempotent — already-applied migrations are skipped via the
/// `_sqlx_migrations` tracking table that `sqlx` maintains automatically.
/// Callers (gateway startup) invoke this once after constructing the pool
/// and before serving requests.
///
/// # Errors
///
/// Returns [`StorageError::MigrationFailed`] when any migration fails to
/// apply or verify.
pub async fn run_migrations<'a, A>(conn: A) -> StorageResult<()>
where
    A: Acquire<'a> + Send,
    <A::Connection as Deref>::Target: Migrate,
{
    apply(&MIGRATOR, conn).await
}
