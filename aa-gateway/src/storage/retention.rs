//! Retention-policy descriptor + applied-result statistics.

use chrono::{DateTime, Utc};

/// Action taken on cold-tier rows once they exceed `warm_days`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ColdAction {
    /// Archive rows to an external store (e.g. S3).
    Archive,
    /// Drop rows permanently.
    Drop,
}

/// Operator-configurable retention policy applied by
/// [`StorageBackend::apply_retention`](super::StorageBackend::apply_retention).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetentionPolicy {
    /// Number of days a row stays indexed and queryable in hot tier.
    pub hot_days: u32,
    /// Number of days a row stays in warm tier (compressed) before cold action.
    pub warm_days: u32,
    /// Action to take on rows older than `warm_days`.
    pub cold_action: ColdAction,
    /// Archive URL (e.g. `s3://bucket/path`) — required when
    /// `cold_action == ColdAction::Archive`.
    pub archive_url: Option<String>,
    /// When true, log the work that would be performed without taking action.
    pub dry_run: bool,
}

/// Outcome of a single
/// [`apply_retention`](super::StorageBackend::apply_retention) invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetentionStats {
    /// Rows in hot tier after the run.
    pub hot_rows: u64,
    /// Rows compressed into warm tier during the run.
    pub compressed_rows: u64,
    /// Rows archived during the run.
    pub archived_rows: u64,
    /// Rows dropped during the run.
    pub dropped_rows: u64,
    /// Bytes freed from primary storage as a result of compression / drop.
    pub freed_bytes: u64,
    /// Timestamp at which the run completed.
    pub ran_at: DateTime<Utc>,
}
