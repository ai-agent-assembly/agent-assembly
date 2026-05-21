//! Connection settings consumed by [`PostgresBackend::connect`](super::postgres::PostgresBackend::connect).
//!
//! Lives inside `aa-gateway::storage` so the PostgreSQL backend can be wired
//! end-to-end before Epic 18 S-H lands the unified [`StorageConfig`]. Once
//! S-H ships, the canonical type moves to `aa-core::config` and this module
//! is expected to re-export it.

/// PostgreSQL connection settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PostgresConfig {
    /// Database URL (e.g. `postgres://user:pass@host:5432/db`).
    ///
    /// `None` means the operator did not provide one; [`PostgresBackend::connect`]
    /// surfaces a [`StorageError::ConnectionFailed`] mentioning
    /// `AAASM_DATABASE_URL` so the missing-config path is obvious.
    pub database_url: Option<String>,
    /// Upper bound on connection-pool size.
    pub max_connections: u32,
    /// Minimum number of warm connections kept in the pool.
    pub min_connections: u32,
    /// Seconds before `acquire` from the pool times out.
    pub connect_timeout_secs: u64,
}

impl Default for PostgresConfig {
    fn default() -> Self {
        Self {
            database_url: None,
            max_connections: 20,
            min_connections: 2,
            connect_timeout_secs: 10,
        }
    }
}
