//! [`AuditSink`] — append-only emission of audit entries.

use super::{AuditEntry, Result};
use async_trait::async_trait;

/// Append-only sink for governance [`AuditEntry`] records.
///
/// Every governance decision produces one entry. The sink is write-only from the
/// runtime's perspective: it persists entries in order so the hash-chained audit
/// log stays verifiable. Backends may batch or buffer internally, but
/// [`emit`](AuditSink::emit) must not reorder entries relative to the calls.
///
/// # Example
///
/// ```
/// use aa_core::storage::{AuditEntry, AuditSink, Result};
/// use async_trait::async_trait;
///
/// /// A sink that discards every entry (useful as a test double).
/// struct NullAuditSink;
///
/// #[async_trait]
/// impl AuditSink for NullAuditSink {
///     async fn emit(&self, _event: AuditEntry) -> Result<()> {
///         Ok(())
///     }
/// }
/// ```
#[async_trait]
pub trait AuditSink: Send + Sync {
    /// Persist a single audit entry.
    ///
    /// Takes ownership of `event` because the sink is the entry's final
    /// destination. Returns [`StorageError::Backend`](super::StorageError::Backend)
    /// when the entry could not be durably recorded.
    async fn emit(&self, event: AuditEntry) -> Result<()>;
}
