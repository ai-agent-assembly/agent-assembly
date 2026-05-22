//! Runtime configuration for the retention background task.

use super::retention::{ColdAction, RetentionPolicy};

/// Reasons a [`RetentionConfig`] can be invalid at startup time.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RetentionConfigError {
    /// `cold_action == Archive` was set but no `archive_url` was provided.
    #[error("cold_action=archive requires archive_url to be set")]
    MissingArchiveUrl,
    /// `schedule` is not a valid cron expression.
    #[error("invalid cron schedule {schedule:?}: {reason}")]
    InvalidSchedule {
        /// The offending schedule string verbatim from config.
        schedule: String,
        /// Underlying cron-parse error rendered as a string.
        reason: String,
    },
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
    /// Reject configurations that are internally inconsistent at startup
    /// (fail-fast preferred over a silent surprise at the first cron tick).
    ///
    /// # Errors
    ///
    /// - [`RetentionConfigError::MissingArchiveUrl`] when `cold_action`
    ///   is [`ColdAction::Archive`] but `archive_url` is `None`.
    pub fn validate(&self) -> Result<(), RetentionConfigError> {
        if self.cold_action == ColdAction::Archive && self.archive_url.is_none() {
            return Err(RetentionConfigError::MissingArchiveUrl);
        }
        Ok(())
    }

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_uses_compliance_friendly_30_90_drop_3am() {
        let cfg = RetentionConfig::default();
        assert_eq!(cfg.schedule, "0 3 * * *");
        assert_eq!(cfg.hot_days, 30);
        assert_eq!(cfg.warm_days, 90);
        assert_eq!(cfg.cold_action, ColdAction::Drop);
        assert_eq!(cfg.archive_url, None);
        assert!(!cfg.dry_run);
    }

    #[test]
    fn validate_accepts_default_config() {
        assert!(RetentionConfig::default().validate().is_ok());
    }

    #[test]
    fn validate_rejects_archive_action_without_url() {
        let cfg = RetentionConfig {
            cold_action: ColdAction::Archive,
            archive_url: None,
            ..RetentionConfig::default()
        };
        assert_eq!(cfg.validate(), Err(RetentionConfigError::MissingArchiveUrl));
    }

    #[test]
    fn validate_accepts_archive_action_with_url() {
        let cfg = RetentionConfig {
            cold_action: ColdAction::Archive,
            archive_url: Some("s3://example/path/".to_string()),
            ..RetentionConfig::default()
        };
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn to_policy_forwards_all_runtime_fields() {
        let cfg = RetentionConfig {
            schedule: "0 4 * * *".to_string(),
            hot_days: 7,
            warm_days: 30,
            cold_action: ColdAction::Archive,
            archive_url: Some("s3://bucket/aasm/".to_string()),
            dry_run: true,
        };
        let policy = cfg.to_policy();
        assert_eq!(policy.hot_days, 7);
        assert_eq!(policy.warm_days, 30);
        assert_eq!(policy.cold_action, ColdAction::Archive);
        assert_eq!(policy.archive_url.as_deref(), Some("s3://bucket/aasm/"));
        assert!(policy.dry_run);
    }
}
