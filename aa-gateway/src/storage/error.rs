//! Failure modes returned by every [`StorageBackend`](super::StorageBackend) operation.

/// Result alias used across the storage layer.
pub type StorageResult<T> = Result<T, StorageError>;

/// Errors any storage backend may return.
///
/// Variants are intentionally broad so concrete backends (`sqlx`, `rusqlite`, …)
/// can map their driver-specific errors into one of these without leaking
/// driver types into the trait surface.
#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    /// Backend connection could not be established or was lost mid-operation.
    #[error("connection failed: {0}")]
    ConnectionFailed(String),
    /// Query execution failed at the backend.
    #[error("query failed: {0}")]
    QueryFailed(String),
    /// Schema migration failed to apply or verify.
    #[error("migration failed: {0}")]
    MigrationFailed(String),
    /// Requested record does not exist.
    #[error("record not found: {0}")]
    NotFound(String),
    /// Uniqueness, version, or optimistic-concurrency conflict.
    #[error("conflict: {0}")]
    Conflict(String),
    /// Retention-policy enforcement encountered a non-fatal error.
    #[error("retention error: {0}")]
    RetentionError(String),
}
