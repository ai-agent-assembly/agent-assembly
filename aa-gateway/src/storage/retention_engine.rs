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
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    use async_trait::async_trait;
    use chrono::{TimeZone, Utc};

    use super::*;
    use crate::storage::{
        AgentFilter, AgentRecord, AuditEvent, AuditFilter, ColdAction, Metric, MetricPoint, MetricQuery,
        PolicyDocument, PolicyMeta, PolicyVersion, RetentionPolicy, StorageError, StorageHealth,
    };
    use aa_core::identity::AgentId;

    /// `StorageBackend` test double that records every
    /// [`RetentionPolicy`] handed to `apply_retention` and returns a
    /// per-call outcome built by a closure. Multi-fire safe so a cron
    /// loop can drive it across multiple ticks. Every other trait method
    /// is unreachable in this module's tests and panics if called.
    struct FakeBackend {
        factory: Box<dyn Fn() -> StorageResult<RetentionStats> + Send + Sync>,
        captured: Mutex<Vec<RetentionPolicy>>,
        call_count: AtomicUsize,
    }

    impl FakeBackend {
        fn new(canned: RetentionStats) -> Self {
            Self {
                factory: Box::new(move || Ok(canned.clone())),
                captured: Mutex::new(Vec::new()),
                call_count: AtomicUsize::new(0),
            }
        }

        fn failing(error_message: &'static str) -> Self {
            Self {
                factory: Box::new(move || Err(StorageError::RetentionError(error_message.to_string()))),
                captured: Mutex::new(Vec::new()),
                call_count: AtomicUsize::new(0),
            }
        }

        fn captured_policy(&self) -> Option<RetentionPolicy> {
            self.captured.lock().unwrap().last().cloned()
        }

        fn call_count(&self) -> usize {
            self.call_count.load(Ordering::SeqCst)
        }
    }

    #[async_trait]
    impl StorageBackend for FakeBackend {
        async fn apply_retention(&self, policy: &RetentionPolicy) -> StorageResult<RetentionStats> {
            self.captured.lock().unwrap().push(policy.clone());
            self.call_count.fetch_add(1, Ordering::SeqCst);
            (self.factory)()
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
        let backend = Arc::new(FakeBackend::failing("simulated S3 archive timeout"));
        let engine = RetentionEngine::new(backend, RetentionConfig::default());

        let err = engine.run_once().await.expect_err("backend error must surface");
        assert!(matches!(err, StorageError::RetentionError(ref msg) if msg.contains("S3 archive timeout")));
    }

    #[tokio::test]
    async fn start_fires_run_once_on_short_schedule_and_stops_on_cancellation() {
        // "* * * * * *" — every second
        let backend = Arc::new(FakeBackend::new(canned_stats()));
        let config = RetentionConfig {
            schedule: "* * * * * *".to_string(),
            ..RetentionConfig::default()
        };
        let engine = Arc::new(RetentionEngine::new(backend.clone(), config));
        let shutdown = CancellationToken::new();

        let handle = engine.start(shutdown.clone()).expect("valid schedule must spawn");

        // Two seconds should yield at least one tick on a "* * * * * *" schedule.
        tokio::time::sleep(std::time::Duration::from_millis(2_100)).await;
        shutdown.cancel();
        handle.await.expect("background task must finish cleanly on shutdown");

        let calls = backend.call_count();
        assert!(
            calls >= 1,
            "cron loop should have fired apply_retention at least once in 2s, got {calls}"
        );
    }

    #[tokio::test]
    async fn start_loop_survives_failed_run_once() {
        let backend = Arc::new(FakeBackend::failing("intermittent backend failure"));
        let config = RetentionConfig {
            schedule: "* * * * * *".to_string(),
            ..RetentionConfig::default()
        };
        let engine = Arc::new(RetentionEngine::new(backend.clone(), config));
        let shutdown = CancellationToken::new();

        let handle = engine.start(shutdown.clone()).expect("valid schedule must spawn");

        // Three seconds — long enough for at least two failed run_once calls
        // if the loop correctly continues past the first error.
        tokio::time::sleep(std::time::Duration::from_millis(3_100)).await;
        shutdown.cancel();
        handle.await.expect("background task must finish cleanly on shutdown");

        let calls = backend.call_count();
        assert!(
            calls >= 2,
            "loop must keep ticking after a failed run_once, got {calls} call(s)"
        );
    }

    #[tokio::test]
    async fn start_rejects_invalid_schedule_before_spawning() {
        let backend = Arc::new(FakeBackend::new(canned_stats()));
        let config = RetentionConfig {
            schedule: "not a cron expression".to_string(),
            ..RetentionConfig::default()
        };
        let engine = Arc::new(RetentionEngine::new(backend, config));

        let err = engine
            .start(CancellationToken::new())
            .expect_err("invalid schedule must return Err, not panic");
        assert!(matches!(err, RetentionConfigError::InvalidSchedule { .. }));
    }
}
