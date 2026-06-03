//! Shared helpers for the trait implementations: id encoding and error mapping.

use aa_storage::{AgentId, StorageError};

/// Encode an [`AgentId`] for a `TEXT` agent-id column as its canonical
/// hyphenated UUID string (the same encoding the gateway driver uses).
pub fn agent_id_to_text(id: &AgentId) -> String {
    uuid::Uuid::from_bytes(*id.as_bytes()).to_string()
}

/// Map an sqlx error to [`StorageError::Backend`] — the catch-all for a backend
/// that was reachable but failed the operation.
pub fn backend_err(err: sqlx::Error) -> StorageError {
    StorageError::Backend(err.to_string())
}
