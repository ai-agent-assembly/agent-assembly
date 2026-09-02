//! Retention-policy descriptor + applied-result statistics.

use chrono::{DateTime, Duration, Utc};

use super::error::StorageError;

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
    /// Number of days the warm tier spans *following* the hot window —
    /// not an absolute age. A row's total age when cold action fires is
    /// `hot_days + warm_days` (e.g. 30 + 90 = 120 days at the shipped
    /// defaults), not `warm_days` alone. See
    /// [`cold_cutoff`](RetentionPolicy::cold_cutoff) /
    /// [`cold_cutoff_days`](RetentionPolicy::cold_cutoff_days).
    pub warm_days: u32,
    /// Action to take on rows older than `warm_days`.
    pub cold_action: ColdAction,
    /// Archive URL (e.g. `s3://bucket/path`) — required when
    /// `cold_action == ColdAction::Archive`.
    pub archive_url: Option<String>,
    /// When true, log the work that would be performed without taking action.
    pub dry_run: bool,
}

impl RetentionPolicy {
    /// Total row age, in days, at which cold action fires — `hot_days +
    /// warm_days`. Widens to `i64` before adding so two `u32::MAX` inputs
    /// cannot overflow/panic.
    pub fn cold_cutoff_days(&self) -> i64 {
        i64::from(self.hot_days) + i64::from(self.warm_days)
    }

    /// Timestamp below which a row is a cold-action candidate:
    /// `now - cold_cutoff_days()`.
    ///
    /// Saturates to `DateTime::<Utc>::MIN_UTC` when the subtraction
    /// would overflow `chrono`'s representable range, so a pathological
    /// policy (e.g. `hot_days = warm_days = u32::MAX`) deletes **nothing**
    /// rather than everything — the predicate callers apply is `ts <
    /// cutoff`, and a cutoff pinned at the minimum representable instant
    /// can never be greater than a real row's timestamp.
    pub fn cold_cutoff(&self, now: DateTime<Utc>) -> DateTime<Utc> {
        Duration::try_days(self.cold_cutoff_days())
            .and_then(|d| now.checked_sub_signed(d))
            .unwrap_or(DateTime::<Utc>::MIN_UTC)
    }

    /// Timestamp below which a row has left the hot tier: `now -
    /// hot_days`. Same saturation behavior as
    /// [`cold_cutoff`](Self::cold_cutoff).
    pub fn hot_cutoff(&self, now: DateTime<Utc>) -> DateTime<Utc> {
        Duration::try_days(i64::from(self.hot_days))
            .and_then(|d| now.checked_sub_signed(d))
            .unwrap_or(DateTime::<Utc>::MIN_UTC)
    }

    /// Reject cold actions no backend implements yet.
    ///
    /// # Errors
    ///
    /// - [`StorageError::RetentionError`] when `cold_action ==
    ///   `[`ColdAction::Archive`] — archival is not implemented on any
    ///   backend (AAASM-5774); callers must call this **before** taking
    ///   any destructive action so a refused policy modifies no rows.
    pub fn ensure_cold_action_supported(&self) -> Result<(), StorageError> {
        if matches!(self.cold_action, ColdAction::Archive) {
            return Err(StorageError::RetentionError(format!(
                "cold_action=archive is not implemented — refusing to run; no rows were modified (archive_url = {:?})",
                self.archive_url
            )));
        }
        Ok(())
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(hot_days: u32, warm_days: u32, cold_action: ColdAction) -> RetentionPolicy {
        RetentionPolicy {
            hot_days,
            warm_days,
            cold_action,
            archive_url: None,
            dry_run: false,
        }
    }

    #[test]
    fn cold_cutoff_days_sums_hot_and_warm() {
        assert_eq!(policy(30, 90, ColdAction::Drop).cold_cutoff_days(), 120);
    }

    #[test]
    fn cold_cutoff_days_does_not_panic_on_max_values() {
        let p = policy(u32::MAX, u32::MAX, ColdAction::Drop);
        // Must not overflow/panic; the widening to i64 guarantees this.
        let days = p.cold_cutoff_days();
        assert_eq!(days, i64::from(u32::MAX) * 2);
    }

    #[test]
    fn cold_cutoff_saturates_to_min_instead_of_panicking_or_wrapping() {
        let p = policy(u32::MAX, u32::MAX, ColdAction::Drop);
        let now = Utc::now();
        let cutoff = p.cold_cutoff(now);
        assert_eq!(
            cutoff,
            DateTime::<Utc>::MIN_UTC,
            "an overflowing cutoff must saturate toward deleting nothing, not toward now/wrapping"
        );
        assert!(
            cutoff < now,
            "saturated cutoff must still be far in the past, not near `now`"
        );
    }

    #[test]
    fn hot_cutoff_saturates_to_min_on_overflow() {
        let p = policy(u32::MAX, 0, ColdAction::Drop);
        let now = Utc::now();
        assert_eq!(p.hot_cutoff(now), DateTime::<Utc>::MIN_UTC);
    }

    #[test]
    fn ensure_cold_action_supported_rejects_archive() {
        let p = policy(30, 90, ColdAction::Archive);
        let err = p.ensure_cold_action_supported().expect_err("Archive must be rejected");
        match err {
            StorageError::RetentionError(msg) => {
                assert!(msg.contains("cold_action=archive is not implemented"));
            }
            other => panic!("expected RetentionError, got {other:?}"),
        }
    }

    #[test]
    fn ensure_cold_action_supported_accepts_drop() {
        let p = policy(30, 90, ColdAction::Drop);
        assert!(p.ensure_cold_action_supported().is_ok());
    }
}
