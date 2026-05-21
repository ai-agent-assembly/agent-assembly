//! Runtime configuration for the retention background task.

use super::retention::{ColdAction, RetentionPolicy};

/// Reasons a [`RetentionConfig`] can be invalid at startup time.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RetentionConfigError {
    /// `cold_action == Archive` was set but no `archive_url` was provided.
    #[error("cold_action=archive requires archive_url to be set")]
    MissingArchiveUrl,
}

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

impl RetentionConfig {
    /// Build the [`RetentionPolicy`] descriptor the backend's
    /// `apply_retention` expects.
    pub fn to_policy(&self) -> RetentionPolicy {
        RetentionPolicy {
            hot_days: self.hot_days,
            warm_days: self.warm_days,
            cold_action: self.cold_action,
            archive_url: self.archive_url.clone(),
            dry_run: self.dry_run,
        }
    }
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
