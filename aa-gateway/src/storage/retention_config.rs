//! Runtime configuration for the retention background task.

use super::retention::ColdAction;

/// Operator-configurable retention engine settings parsed from the
/// `storage.retention` section of the gateway YAML (Story S-H wires the
/// YAML parser; S-F owns the type itself).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetentionConfig {
    /// Cron schedule (UTC) on which the background task fires.
    pub schedule: String,
    /// Days a row stays indexed and queryable in the hot tier.
    pub hot_days: u32,
    /// Days a row stays in the warm tier (compressed when supported)
    /// before the cold action runs.
    pub warm_days: u32,
    /// Action applied to rows older than `warm_days`.
    pub cold_action: ColdAction,
    /// Archive destination (e.g. `s3://bucket/path`) — required when
    /// `cold_action == ColdAction::Archive`.
    pub archive_url: Option<String>,
    /// When true, log the work that would be performed without taking action.
    pub dry_run: bool,
}

impl Default for RetentionConfig {
    /// Compliance-friendly defaults: hot=30d, warm=90d, cold=Drop,
    /// schedule="0 3 * * *" (3am UTC daily), dry_run=false.
    fn default() -> Self {
        Self {
            schedule: "0 3 * * *".to_string(),
            hot_days: 30,
            warm_days: 90,
            cold_action: ColdAction::Drop,
            archive_url: None,
            dry_run: false,
        }
    }
}
