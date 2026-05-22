//! Background retention engine — orchestrates periodic invocations of
//! [`StorageBackend::apply_retention`](super::StorageBackend::apply_retention).
//!
//! Story S-F. The engine itself is a thin orchestrator; backend-specific
//! semantics (TimescaleDB compression, S3 archive, plain DELETE) live in
//! each [`StorageBackend`] implementation.

use std::sync::Arc;

use chrono::Utc;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use super::backend::StorageBackend;
use super::error::StorageResult;
use super::retention::RetentionStats;
use super::retention_config::{RetentionConfig, RetentionConfigError};

/// Owns the periodic retention task lifecycle.
pub struct RetentionEngine {
    backend: Arc<dyn StorageBackend>,
    config: RetentionConfig,
}

impl RetentionEngine {
    /// Build an engine that, when driven, calls
    /// [`apply_retention`](StorageBackend::apply_retention) on `backend`
    /// using the policy derived from `config`.
    pub fn new(backend: Arc<dyn StorageBackend>, config: RetentionConfig) -> Self {
        Self { backend, config }
    }

    /// Run one retention pass: build the [`RetentionPolicy`](super::RetentionPolicy)
    /// from `self.config`, hand it to the backend, and return the
    /// resulting [`RetentionStats`].
    ///
    /// The cron-driven background loop (next commit) invokes this once per
    /// scheduled tick; operators can also invoke it manually via
    /// `aasm admin run-retention`.
    ///
    /// # Errors
    ///
    /// Surfaces any [`StorageError`](super::StorageError) returned by
    /// [`apply_retention`](StorageBackend::apply_retention).
    pub async fn run_once(&self) -> StorageResult<RetentionStats> {
        let policy = self.config.to_policy();
        let stats = self.backend.apply_retention(&policy).await?;
        tracing::info!(
            dry_run = policy.dry_run,
            hot_rows = stats.hot_rows,
            compressed_rows = stats.compressed_rows,
            archived_rows = stats.archived_rows,
            dropped_rows = stats.dropped_rows,
            freed_bytes = stats.freed_bytes,
            ran_at = %stats.ran_at,
            "retention run complete",
        );
        Ok(stats)
    }

    /// Spawn the background retention task. Returns a [`JoinHandle`] for
    /// the spawned tokio task.
    ///
    /// The task loops until `shutdown` is cancelled: on each iteration it
    /// waits until the next scheduled instant, invokes
    /// [`run_once`](Self::run_once), logs any error and continues (one
    /// transient failure does not kill the loop).
    ///
    /// # Errors
    ///
    /// - [`RetentionConfigError::InvalidSchedule`] when the configured
    ///   cron expression cannot be parsed. The task is not spawned in
    ///   this case — fail-fast at startup rather than panic at the first
    ///   tick.
    pub fn start(self: Arc<Self>, shutdown: CancellationToken) -> Result<JoinHandle<()>, RetentionConfigError> {
        let schedule = self.config.parsed_schedule()?;
        Ok(tokio::spawn(async move {
            loop {
                let Some(next) = schedule.upcoming(Utc).next() else {
                    tracing::warn!("retention schedule has no future occurrences, exiting loop");
                    return;
                };
                let delay = (next - Utc::now()).to_std().unwrap_or_default();
                tokio::select! {
                    _ = tokio::time::sleep(delay) => {
                        if let Err(e) = self.run_once().await {
                            tracing::error!(error = %e, "retention run failed; loop continues");
                        }
                    }
                    _ = shutdown.cancelled() => {
                        tracing::info!("retention engine shutdown requested, exiting loop");
                        return;
                    }
                }
            }
        }))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use async_trait::async_trait;
    use chrono::{TimeZone, Utc};

    use super::*;
    use crate::storage::{
        AgentFilter, AgentRecord, AuditEvent, AuditFilter, ColdAction, Metric, MetricPoint, MetricQuery,
        PolicyDocument, PolicyMeta, PolicyVersion, RetentionPolicy, StorageError, StorageHealth,
    };
    use aa_core::identity::AgentId;

    /// `StorageBackend` test double that records the
    /// [`RetentionPolicy`] handed to `apply_retention` and returns either
    /// canned [`RetentionStats`] or a configured error. Every other trait
    /// method is unreachable in this module's tests and panics if called.
    struct FakeBackend {
        outcome: Mutex<Option<StorageResult<RetentionStats>>>,
        captured: Mutex<Option<RetentionPolicy>>,
    }

    impl FakeBackend {
        fn new(canned: RetentionStats) -> Self {
            Self {
                outcome: Mutex::new(Some(Ok(canned))),
                captured: Mutex::new(None),
            }
        }

        fn failing(error: StorageError) -> Self {
            Self {
                outcome: Mutex::new(Some(Err(error))),
                captured: Mutex::new(None),
            }
        }

        fn captured_policy(&self) -> Option<RetentionPolicy> {
            self.captured.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl StorageBackend for FakeBackend {
        async fn apply_retention(&self, policy: &RetentionPolicy) -> StorageResult<RetentionStats> {
            *self.captured.lock().unwrap() = Some(policy.clone());
            self.outcome
                .lock()
                .unwrap()
                .take()
                .expect("FakeBackend::apply_retention fired more than once in a single test")
        }
        async fn append_audit_event(&self, _: &AuditEvent) -> StorageResult<()> {
            unreachable!()
        }
        async fn query_audit_events(&self, _: AuditFilter) -> StorageResult<Vec<AuditEvent>> {
            unreachable!()
        }
        async fn count_audit_events(&self, _: AuditFilter) -> StorageResult<u64> {
            unreachable!()
        }
        async fn upsert_agent(&self, _: AgentRecord) -> StorageResult<()> {
            unreachable!()
        }
        async fn get_agent(&self, _: &AgentId) -> StorageResult<Option<AgentRecord>> {
            unreachable!()
        }
        async fn list_agents(&self, _: AgentFilter) -> StorageResult<Vec<AgentRecord>> {
            unreachable!()
        }
        async fn delete_agent(&self, _: &AgentId) -> StorageResult<()> {
            unreachable!()
        }
        async fn save_policy(&self, _: PolicyDocument) -> StorageResult<PolicyVersion> {
            unreachable!()
        }
        async fn get_active_policy(&self, _: &str) -> StorageResult<Option<PolicyDocument>> {
            unreachable!()
        }
        async fn list_policy_versions(&self, _: &str) -> StorageResult<Vec<PolicyMeta>> {
            unreachable!()
        }
        async fn rollback_policy(&self, _: &str, _: u32) -> StorageResult<()> {
            unreachable!()
        }
        async fn record_metric(&self, _: Metric) -> StorageResult<()> {
            unreachable!()
        }
        async fn query_metrics(&self, _: MetricQuery) -> StorageResult<Vec<MetricPoint>> {
            unreachable!()
        }
        async fn migrate(&self) -> StorageResult<()> {
            unreachable!()
        }
        async fn healthcheck(&self) -> StorageResult<StorageHealth> {
            unreachable!()
        }
    }

    fn canned_stats() -> RetentionStats {
        RetentionStats {
            hot_rows: 100,
            compressed_rows: 50,
            archived_rows: 20,
            dropped_rows: 10,
            freed_bytes: 4096,
            ran_at: Utc.with_ymd_and_hms(2026, 5, 22, 3, 0, 0).unwrap(),
        }
    }

    #[tokio::test]
    async fn run_once_invokes_apply_retention_with_policy_from_config() {
        let backend = Arc::new(FakeBackend::new(canned_stats()));
        let config = RetentionConfig {
            hot_days: 7,
            warm_days: 30,
            cold_action: ColdAction::Archive,
            archive_url: Some("s3://b/".to_string()),
            dry_run: true,
            ..RetentionConfig::default()
        };
        let engine = RetentionEngine::new(backend.clone(), config.clone());

        engine.run_once().await.expect("run_once should succeed");

        let captured = backend
            .captured_policy()
            .expect("apply_retention should have been called");
        assert_eq!(captured, config.to_policy());
    }

    #[tokio::test]
    async fn run_once_propagates_dry_run_flag_to_policy() {
        let backend = Arc::new(FakeBackend::new(canned_stats()));
        let config = RetentionConfig {
            dry_run: true,
            ..RetentionConfig::default()
        };
        let engine = RetentionEngine::new(backend.clone(), config);

        engine.run_once().await.expect("run_once should succeed");

        let captured = backend.captured_policy().unwrap();
        assert!(
            captured.dry_run,
            "dry_run must round-trip from RetentionConfig through to_policy and into the backend"
        );
    }

    #[tokio::test]
    async fn run_once_returns_stats_from_backend_unchanged() {
        let canned = canned_stats();
        let backend = Arc::new(FakeBackend::new(canned.clone()));
        let engine = RetentionEngine::new(backend, RetentionConfig::default());

        let stats = engine.run_once().await.expect("run_once should succeed");

        assert_eq!(stats, canned);
    }

    #[tokio::test]
    async fn run_once_surfaces_backend_error() {
        let backend = Arc::new(FakeBackend::failing(StorageError::RetentionError(
            "simulated S3 archive timeout".to_string(),
        )));
        let engine = RetentionEngine::new(backend, RetentionConfig::default());

        let err = engine.run_once().await.expect_err("backend error must surface");
        assert!(matches!(err, StorageError::RetentionError(ref msg) if msg.contains("S3 archive timeout")));
    }
}
