//! In-memory [`AuditSink`] backed by a `parking_lot::Mutex<Vec<_>>`.

use std::sync::Arc;

use aa_storage::{AuditEntry, AuditSink, Result};
use async_trait::async_trait;
use parking_lot::Mutex;

/// An [`AuditSink`] that appends entries to an in-memory, unbounded buffer.
///
/// Intended for tests that need to assert on emitted entries. Cloning shares
/// the same underlying buffer. The buffer is unbounded — there is no
/// backpressure — which is acceptable for the ephemeral memory driver.
#[derive(Clone, Default)]
pub struct MemoryAuditSink {
    entries: Arc<Mutex<Vec<AuditEntry>>>,
}

impl MemoryAuditSink {
    /// Create an empty sink.
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of entries currently buffered.
    pub fn len(&self) -> usize {
        self.entries.lock().len()
    }

    /// Whether the buffer holds no entries.
    pub fn is_empty(&self) -> bool {
        self.entries.lock().is_empty()
    }

    /// Remove and return all buffered entries in emit order.
    pub fn drain(&self) -> Vec<AuditEntry> {
        std::mem::take(&mut *self.entries.lock())
    }
}

#[async_trait]
impl AuditSink for MemoryAuditSink {
    async fn emit(&self, event: AuditEntry) -> Result<()> {
        self.entries.lock().push(event);
        Ok(())
    }
}
