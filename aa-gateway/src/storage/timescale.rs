//! TimescaleDB observability and capability detection for the gateway's
//! PostgreSQL backend.
//!
//! The TimescaleDB extension is **optional**: the gateway runs against
//! vanilla PostgreSQL as well. This module owns the small surface that
//! lets the rest of the storage layer answer two questions at runtime:
//!
//! 1. "Is the TimescaleDB extension installed on the connected cluster?"
//!    → [`has_timescaledb_extension`] (Epic 18 S-D #3 — `PostgresBackend::apply_timescaledb_setup`)
//! 2. "If yes, what's the current hypertable + compression state?"
//!    → [`TimescaleStats`] returned from `healthcheck()` (Epic 18 S-D #4)
//!
//! The module **deliberately does not** create or drop hypertables — that
//! DDL lives in the `0002_timescaledb_hypertables.sql` migration (S-D #1).
//! Keeping schema mutation in migrations and observability in Rust keeps
//! the two concerns independently versioned.
//!
//! # CI contract
//!
//! Tests that require the extension to be loaded gate themselves on the
//! `TIMESCALEDB_AVAILABLE` env var being set to `"1"`. The dedicated
//! `timescaledb-tests` CI job (defined in `.github/workflows/ci.yml`,
//! AAASM-1858) sets the var and spins up a
//! `timescale/timescaledb:latest-pg17` service container. The regular
//! `Test` job leaves the var unset and runs against vanilla
//! `postgres:18-alpine`, so the same tests skip cleanly there.

use serde::{Deserialize, Serialize};
use sqlx::PgPool;

use super::error::{StorageError, StorageResult};

/// Returns `true` when the TimescaleDB extension is installed on the
/// PostgreSQL cluster behind `pool`, `false` otherwise.
///
/// The check is a single round-trip against `pg_extension` and is safe
/// to call on any PostgreSQL cluster — vanilla PG returns `false`,
/// TimescaleDB-enabled PG returns `true`. Callers in
/// `PostgresBackend::apply_timescaledb_setup` (S-D #3) and
/// `PostgresBackend::healthcheck` (S-D #4) use this to branch between
/// the plain-table and hypertable code paths.
///
/// # Errors
///
/// Returns `StorageError` when the query against
/// `pg_extension` cannot execute (transport failure, permission denied,
/// etc.). Treat the failure as "extension status unknown" — the caller
/// typically downgrades to the no-TimescaleDB code path.
pub async fn has_timescaledb_extension(pool: &PgPool) -> StorageResult<bool> {
    sqlx::query_scalar::<_, bool>("SELECT EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'timescaledb')")
        .fetch_one(pool)
        .await
        .map_err(|e| StorageError::QueryFailed(format!("pg_extension probe: {e}")))
}

/// Snapshot of TimescaleDB chunk and compression state for the gateway's
/// hypertables (`audit_events` + `metrics`), surfaced through
/// [`StorageHealth::timescale`](super::health::StorageHealth) when the
/// extension is active. `None` on plain PostgreSQL.
///
/// All fields are aggregated across both hypertables; per-table breakdown
/// is intentionally out of scope for v1 — the dashboard's storage panel
/// only needs the rollup.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TimescaleStats {
    /// Total number of chunks across the gateway's hypertables.
    pub total_chunks: u32,
    /// Subset of `total_chunks` that have been compressed by the
    /// auto-compression policy.
    pub compressed_chunks: u32,
    /// Aggregate `uncompressed_bytes / compressed_bytes` ratio expressed
    /// in tenths of a unit (e.g. `124` = 12.4× size reduction).
    ///
    /// Stored as an integer to keep the type `Eq + Hash`; readers
    /// reconstruct the float with `compression_ratio_tenths as f32 / 10.0`.
    pub compression_ratio_tenths: u32,
    /// Age in days of the oldest chunk across both hypertables. `0` when
    /// no chunks exist yet.
    pub oldest_chunk_age_days: u32,
}

/// Roll up chunk counts and oldest-chunk age across the gateway's
/// hypertables (`audit_events` + `metrics`) and return a
/// [`TimescaleStats`] snapshot.
///
/// Single round-trip against `timescaledb_information.chunks`. Caller
/// must verify the extension is present first (via
/// [`has_timescaledb_extension`]) — querying the schema on a vanilla
/// PostgreSQL cluster raises an undefined-table error.
///
/// `compression_ratio_tenths` is left at `0` for the v1 implementation.
/// Pulling the actual ratio requires per-hypertable
/// `hypertable_compression_stats('<table>')` calls, which differ across
/// TimescaleDB minor versions; the SD-K dashboard ticket can layer a
/// version-aware fetcher on top when the storage panel needs it.
///
/// # Errors
///
/// Returns `StorageError` when the chunks rollup query
/// fails (transport / permission / extension uninstalled).
pub(crate) async fn query_timescale_stats(pool: &PgPool) -> StorageResult<TimescaleStats> {
    let (total, compressed, oldest_age_days): (i64, i64, i32) = sqlx::query_as(
        "SELECT \
             COUNT(*)::bigint, \
             COUNT(*) FILTER (WHERE is_compressed)::bigint, \
             COALESCE(EXTRACT(DAY FROM NOW() - MIN(range_start))::int, 0) \
         FROM timescaledb_information.chunks \
         WHERE hypertable_name IN ('audit_events', 'metrics')",
    )
    .fetch_one(pool)
    .await
    .map_err(|e| StorageError::QueryFailed(format!("timescale chunks rollup: {e}")))?;

    Ok(TimescaleStats {
        total_chunks: u32::try_from(total).unwrap_or(u32::MAX),
        compressed_chunks: u32::try_from(compressed).unwrap_or(u32::MAX),
        compression_ratio_tenths: 0,
        oldest_chunk_age_days: u32::try_from(oldest_age_days).unwrap_or(0),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::postgres::PgPoolOptions;

    /// Build a pool against `AAASM_DATABASE_URL`, or return `None` after
    /// printing a skip notice. Mirrors `postgres::tests::pg_backend_or_skip`
    /// but works directly with a `PgPool` since the probe helper does not
    /// need a full `PostgresBackend`.
    async fn pool_or_skip() -> Option<PgPool> {
        let url = match std::env::var("AAASM_DATABASE_URL") {
            Ok(v) => v,
            Err(_) => {
                eprintln!(
                    "skipping postgres test: AAASM_DATABASE_URL not set (CI provides this via services: postgres)"
                );
                return None;
            }
        };
        Some(
            PgPoolOptions::new()
                .max_connections(2)
                .connect(&url)
                .await
                .expect("connect to AAASM_DATABASE_URL"),
        )
    }

    /// `has_timescaledb_extension` must return `false` against a plain
    /// PostgreSQL cluster — `pg_extension` has no `timescaledb` row.
    /// Exercises the false branch via the existing `Test` CI job
    /// (postgres:18-alpine service).
    #[tokio::test]
    async fn probe_returns_false_on_plain_postgres() {
        if std::env::var("TIMESCALEDB_AVAILABLE").as_deref() == Ok("1") {
            eprintln!(
                "skipping plain-postgres probe test: TIMESCALEDB_AVAILABLE=1 (see probe_returns_true_on_timescaledb)"
            );
            return;
        }
        let Some(pool) = pool_or_skip().await else {
            return;
        };
        let present = has_timescaledb_extension(&pool)
            .await
            .expect("probe must succeed on plain PostgreSQL");
        assert!(
            !present,
            "expected probe to report false on plain PostgreSQL; if your CI installed TimescaleDB, set TIMESCALEDB_AVAILABLE=1"
        );
    }

    /// `has_timescaledb_extension` must return `true` against a
    /// TimescaleDB-enabled cluster. Env-gated on `TIMESCALEDB_AVAILABLE=1`;
    /// the CI `timescaledb-tests` job (AAASM-1858 / SD-5) wires this
    /// against the `timescale/timescaledb:latest-pg17` service container.
    #[tokio::test]
    async fn probe_returns_true_on_timescaledb() {
        if std::env::var("TIMESCALEDB_AVAILABLE").as_deref() != Ok("1") {
            eprintln!(
                "skipping timescaledb probe test: TIMESCALEDB_AVAILABLE != 1 (set it to 1 when AAASM_DATABASE_URL points at a TimescaleDB-enabled instance)"
            );
            return;
        }
        let Some(pool) = pool_or_skip().await else {
            return;
        };
        let present = has_timescaledb_extension(&pool)
            .await
            .expect("probe must succeed on a TimescaleDB-enabled PostgreSQL");
        assert!(
            present,
            "TIMESCALEDB_AVAILABLE=1 was set but the extension is not installed; \
             check the docker image is timescale/timescaledb:latest-pg17"
        );
    }
}
