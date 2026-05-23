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

use serde::{Deserialize, Serialize};

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
