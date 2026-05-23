//! Storage health-report value types returned by
//! [`StorageBackend::healthcheck`](super::StorageBackend::healthcheck).

use super::timescale::TimescaleStats;

/// Coarse health state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HealthStatus {
    /// Backend is reachable and responsive within expected latency.
    Ok,
    /// Backend is reachable but degraded — slow queries or partial features.
    Degraded,
    /// Backend is unreachable or returning errors.
    Unavailable,
}

/// Row-count snapshot across top-level storage entities.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RowCounts {
    /// Total number of audit events stored across all tiers.
    pub audit_events: u64,
    /// Number of registered agents.
    pub agents: u64,
    /// Number of stored policy versions across all policy names.
    pub policy_versions: u64,
}

/// Aggregate health report.
#[derive(Debug, Clone)]
pub struct StorageHealth {
    /// Overall status.
    pub status: HealthStatus,
    /// Static backend identifier — e.g. `"sqlite"`, `"postgres"`.
    pub backend: &'static str,
    /// Latency of the healthcheck probe in milliseconds.
    pub latency_ms: u32,
    /// Row-count snapshot taken during the probe.
    pub row_counts: RowCounts,
    /// TimescaleDB chunk + compression rollup for `audit_events` + `metrics`,
    /// populated only when the PostgreSQL backend is connected to a cluster
    /// with the `timescaledb` extension installed. `None` on SQLite and on
    /// plain PostgreSQL deployments (Epic 18 S-D #4).
    pub timescale: Option<TimescaleStats>,
}
