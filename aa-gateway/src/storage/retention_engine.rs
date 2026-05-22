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
        self.backend.apply_retention(&policy).await
    }
}
