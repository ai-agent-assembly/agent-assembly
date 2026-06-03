//! Connection-pool wrapper that owns a [`sqlx::PgPool`] and carries the driver's
//! embedded migrations.

use sqlx::migrate::Migrator;
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;

use crate::config::PostgresPoolConfig;

/// The four MVP-table migrations (`orgs`, `agents`, `policies`, `audit_logs`),
/// embedded into the binary at compile time.
pub static MIGRATOR: Migrator = sqlx::migrate!("./migrations");

/// A connected Postgres pool for the storage driver.
///
/// Construct one with [`PostgresPool::connect`], then call
/// [`migrate`](PostgresPool::migrate) once on startup to bring the schema up to
/// date. The trait implementations borrow [`pool`](PostgresPool::pool) to run
/// their queries.
#[derive(Clone)]
pub struct PostgresPool {
    pool: PgPool,
}

impl PostgresPool {
    /// Open a pool against `config.url`, honoring the configured pool size and
    /// per-statement timeout.
    ///
    /// When `statement_timeout_ms` is non-zero, every pooled connection runs
    /// `SET statement_timeout` on establishment so a runaway query is bounded.
    pub async fn connect(config: &PostgresPoolConfig) -> Result<Self, sqlx::Error> {
        let mut options = PgPoolOptions::new().max_connections(config.max_connections);

        let statement_timeout_ms = config.statement_timeout_ms;
        if statement_timeout_ms > 0 {
            options = options.after_connect(move |conn, _meta| {
                Box::pin(async move {
                    sqlx::query(&format!("SET statement_timeout = {statement_timeout_ms}"))
                        .execute(conn)
                        .await?;
                    Ok(())
                })
            });
        }

        let pool = options.connect(&config.url).await?;
        Ok(Self { pool })
    }

    /// Borrow the underlying pool for query execution.
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Apply every embedded migration. Idempotent: already-applied migrations
    /// are skipped, so it is safe to call on every startup.
    pub async fn migrate(&self) -> Result<(), sqlx::migrate::MigrateError> {
        MIGRATOR.run(&self.pool).await
    }
}
