//! Background retention engine — orchestrates periodic invocations of
//! [`StorageBackend::apply_retention`](super::StorageBackend::apply_retention).
//!
//! Story S-F. The engine itself is a thin orchestrator; backend-specific
//! semantics (TimescaleDB compression, S3 archive, plain DELETE) live in
//! each [`StorageBackend`] implementation.

use std::sync::Arc;

use super::backend::StorageBackend;
use super::error::StorageResult;
use super::retention::RetentionStats;
use super::retention_config::RetentionConfig;

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
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use async_trait::async_trait;
    use chrono::{TimeZone, Utc};

    use super::*;
    use crate::storage::{
        AgentFilter, AgentRecord, AuditEvent, AuditFilter, ColdAction, Metric, MetricPoint, MetricQuery,
        PolicyDocument, PolicyMeta, PolicyVersion, RetentionPolicy, StorageHealth,
    };
    use aa_core::identity::AgentId;

    /// `StorageBackend` test double that records the
    /// [`RetentionPolicy`] handed to `apply_retention` and returns canned
    /// [`RetentionStats`]. Every other trait method is unreachable in this
    /// module's tests and panics if called.
    struct FakeBackend {
        canned: RetentionStats,
        captured: Mutex<Option<RetentionPolicy>>,
    }

    impl FakeBackend {
        fn new(canned: RetentionStats) -> Self {
            Self {
                canned,
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
            Ok(self.canned.clone())
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
}
