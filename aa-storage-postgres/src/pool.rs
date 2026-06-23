//! Connection-pool wrapper that owns a [`sqlx::PgPool`] and carries the driver's
//! embedded migrations.

use sqlx::migrate::Migrator;
use sqlx::pool::PoolConnection;
use sqlx::postgres::PgPoolOptions;
use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

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

    /// Acquire a connection bound to `org_id` for the duration of a transaction,
    /// returning that open transaction.
    ///
    /// The tenant is bound by `SET LOCAL app.tenant_id` (via `set_config(…, true)`),
    /// which the `tenant_isolation` RLS policy (migration 0007) reads to confine
    /// every row to this tenant. `is_local = true` ties the GUC to *this*
    /// transaction, so when the connection returns to the pool the setting is
    /// rolled back and cannot bleed into the next tenant's checkout — the
    /// connection-pool cross-tenant leak vector RLS designs must guard against.
    ///
    /// `org_id` MUST be the verified caller's tenant (the JWT `org_id` claim via
    /// [`crate`]'s gateway seam), never a client-supplied value. Run the store
    /// query through the returned transaction and commit it; on drop without
    /// commit the work — and the GUC — are discarded.
    pub async fn begin_for_tenant(&self, org_id: Uuid) -> Result<Transaction<'static, Postgres>, sqlx::Error> {
        // `pool.begin()` returns a transaction that owns its pooled connection for
        // its lifetime, so the GUC and the checkout share a scope.
        let mut tx = self.pool.begin().await?;
        set_tenant_guc(&mut tx, org_id).await?;
        Ok(tx)
    }

    /// Acquire a raw pooled connection with no tenant GUC set.
    ///
    /// Under FORCE RLS a connection with no `app.tenant_id` sees zero tenant rows
    /// (fail-closed). Used only by privileged/admin paths that intentionally run
    /// without a tenant scope.
    pub async fn acquire(&self) -> Result<PoolConnection<Postgres>, sqlx::Error> {
        self.pool.acquire().await
    }

    /// Apply every embedded migration. Idempotent: already-applied migrations
    /// are skipped, so it is safe to call on every startup.
    pub async fn migrate(&self) -> Result<(), sqlx::migrate::MigrateError> {
        MIGRATOR.run(&self.pool).await
    }
}

/// Bind the open transaction to `org_id` via the transaction-local
/// `app.tenant_id` GUC the `tenant_isolation` RLS policy filters on.
///
/// `set_config(name, value, is_local = true)` scopes the setting to the
/// surrounding transaction, so it never survives the connection's return to the
/// pool. The UUID is rendered to its canonical string and re-parsed by the
/// policy's `::uuid` cast.
async fn set_tenant_guc(tx: &mut Transaction<'static, Postgres>, org_id: Uuid) -> Result<(), sqlx::Error> {
    sqlx::query("SELECT set_config('app.tenant_id', $1, true)")
        .bind(org_id.to_string())
        .execute(&mut **tx)
        .await?;
    Ok(())
}
