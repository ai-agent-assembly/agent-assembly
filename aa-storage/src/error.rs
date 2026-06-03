//! Error type shared by every storage trait.

use std::string::String;

/// Failure modes common to all storage backends.
///
/// Backends map their native errors (a `sqlx::Error`, a `redis::RedisError`, a
/// `tonic::Status`, …) onto these variants so callers never depend on a concrete
/// backend's error type. The string payloads carry backend-specific detail for
/// logging without leaking the backend's types into this crate's public API.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum StorageError {
    /// The requested entity does not exist in the backend.
    #[error("storage entity not found: {0}")]
    NotFound(String),

    /// The backend is unreachable or returned a transport/connection failure.
    #[error("storage backend unavailable: {0}")]
    Backend(String),

    /// Stored bytes could not be encoded to or decoded from the domain type.
    #[error("storage serialization error: {0}")]
    Serialization(String),

    /// The write conflicts with existing state (optimistic-concurrency or
    /// uniqueness violation).
    #[error("storage conflict: {0}")]
    Conflict(String),
}

/// Convenience alias for results returned by storage trait methods.
pub type Result<T> = core::result::Result<T, StorageError>;
