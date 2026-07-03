//! Schema migration runner for the storage layer.
//!
//! Wraps [`sqlx::migrate!`] so the gateway's startup path can apply pending
//! migrations against any `sqlx` pool — SQLite (local mode) or PostgreSQL
//! (production). Migration files live in `aa-gateway/migrations/` and are
//! embedded into the binary at compile time. Re-running an already-applied
//! migration is a no-op (idempotent), and a failed migration surfaces as
//! `StorageError`.
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
/// `StorageError`.
///
/// Kept `pub(crate)` so tests can drive the runner with fixture migrators
/// (good and bad) without leaking `sqlx` types onto the public surface.
///
/// # Errors
///
/// Returns `StorageError` when a migration fails to
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
/// Returns `StorageError` when any migration fails to
/// apply or verify.
pub async fn run_migrations<'a, A>(conn: A) -> StorageResult<()>
where
    A: Acquire<'a> + Send,
    <A::Connection as Deref>::Target: Migrate,
{
    apply(&MIGRATOR, conn).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::sqlite::SqlitePoolOptions;
    use sqlx::SqlitePool;

    /// Fixture migrator containing a single cross-database-compatible
    /// `CREATE TABLE` statement.
    static GOOD_MIGRATOR: Migrator = sqlx::migrate!("./src/storage/test_fixtures/migrations/good");

    /// Fixture migrator with intentionally invalid SQL — exercises the
    /// runner's failure path.
    static BAD_MIGRATOR: Migrator = sqlx::migrate!("./src/storage/test_fixtures/migrations/bad");

    async fn fresh_sqlite_pool() -> SqlitePool {
        SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .expect("sqlite in-memory pool")
    }

    #[tokio::test]
    async fn apply_good_succeeds_on_fresh_sqlite() {
        let pool = fresh_sqlite_pool().await;
        apply(&GOOD_MIGRATOR, &pool)
            .await
            .expect("apply must succeed on a fresh SQLite database");
    }

    #[tokio::test]
    async fn apply_is_idempotent_on_sqlite() {
        let pool = fresh_sqlite_pool().await;
        apply(&GOOD_MIGRATOR, &pool).await.expect("first apply ok");
        apply(&GOOD_MIGRATOR, &pool)
            .await
            .expect("re-applying the same migrator must be a no-op");
    }

    #[tokio::test]
    async fn apply_creates_sqlx_migrations_tracking_table_on_sqlite() {
        let pool = fresh_sqlite_pool().await;
        apply(&GOOD_MIGRATOR, &pool).await.expect("apply ok");
        let applied: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM _sqlx_migrations")
            .fetch_one(&pool)
            .await
            .expect("_sqlx_migrations table must exist and be queryable");
        assert!(applied >= 1, "expected at least one tracked migration, got {applied}");
    }

    #[tokio::test]
    async fn apply_bad_returns_migration_failed_on_sqlite() {
        let pool = fresh_sqlite_pool().await;
        let err = apply(&BAD_MIGRATOR, &pool)
            .await
            .expect_err("apply must fail when a migration file contains invalid SQL");
        assert!(
            matches!(err, StorageError::MigrationFailed(_)),
            "expected StorageError::MigrationFailed, got: {err:?}"
        );
    }

    /// Smoke-tests the public `run_migrations` wrapper against the
    /// production `./migrations` directory using a fresh SQLite pool.
    /// Guards against regressions where the embedded migration files
    /// become invalid SQLite SQL.
    #[tokio::test]
    async fn run_migrations_against_production_dir_succeeds_on_sqlite() {
        let pool = fresh_sqlite_pool().await;
        run_migrations(&pool)
            .await
            .expect("production migrator must apply cleanly on a fresh SQLite DB");
    }

    /// PostgreSQL integration test driven by `testcontainers-modules`. Boots
    /// a real Postgres container, points the runner at it, and asserts that
    /// the good fixture migrator applies cleanly and is idempotent.
    ///
    /// Requires Docker on the host. Skipped automatically by CI hosts that
    /// do not expose a Docker socket because container start will error;
    /// running the suite with `cargo nextest` on a Docker-enabled machine
    /// exercises the PostgreSQL code path.
    #[tokio::test]
    async fn apply_good_succeeds_and_is_idempotent_on_postgres() {
        use sqlx::postgres::PgPoolOptions;
        use testcontainers_modules::postgres::Postgres;
        use testcontainers_modules::testcontainers::runners::AsyncRunner;

        let container = Postgres::default()
            .start()
            .await
            .expect("failed to start postgres testcontainer (is Docker running?)");

        let host = container.get_host().await.expect("container host");
        let port = container.get_host_port_ipv4(5432).await.expect("container port");
        let url = format!("postgres://postgres:postgres@{host}:{port}/postgres");

        let pool = PgPoolOptions::new()
            .max_connections(2)
            .connect(&url)
            .await
            .expect("connect to postgres container");

        apply(&GOOD_MIGRATOR, &pool)
            .await
            .expect("apply must succeed on a fresh PostgreSQL database");
        apply(&GOOD_MIGRATOR, &pool)
            .await
            .expect("re-applying the same migrator must be a no-op on PostgreSQL");

        let applied: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM _sqlx_migrations")
            .fetch_one(&pool)
            .await
            .expect("_sqlx_migrations table must exist on PostgreSQL");
        assert!(
            applied >= 1,
            "expected at least one tracked migration on PostgreSQL, got {applied}"
        );
    }
}
