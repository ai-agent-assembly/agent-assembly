//! Background retention engine — orchestrates periodic invocations of
//! [`StorageBackend::apply_retention`](super::StorageBackend::apply_retention).
//!
//! Story S-F. The engine itself is a thin orchestrator; backend-specific
//! semantics (TimescaleDB compression, S3 archive, plain DELETE) live in
//! each [`StorageBackend`] implementation.

use std::sync::Arc;

use super::backend::StorageBackend;
use super::retention_config::RetentionConfig;

/// Owns the periodic retention task lifecycle.
#[allow(dead_code)] // fields read by run_once landing in the next commit
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
}
