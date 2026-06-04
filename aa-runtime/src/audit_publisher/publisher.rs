//! The fire-and-forget [`AuditPublisher`] with offline buffering.

use std::sync::Arc;

use aa_core::storage::{AuditEntry, AuditSink, Result};
use aa_storage_sqlite_buffer::EventBuffer;

use super::{METRIC_BUFFERED, METRIC_PUBLISHED, METRIC_PUBLISH_ERRORS};

/// Publishes audit events to a NATS [`AuditSink`] and, when that sink fails,
/// diverts them to a local SQLite [`EventBuffer`] instead of blocking the agent.
///
/// The sink is held behind a trait object so the publisher can be exercised
/// with an in-memory fake in unit tests and a real
/// [`NatsAuditSink`](super::NatsAuditSink) in production.
pub struct AuditPublisher {
    sink: Arc<dyn AuditSink>,
    buffer: Arc<EventBuffer>,
}

impl AuditPublisher {
    /// Build a publisher over an audit `sink` and the SQLite fallback `buffer`.
    #[must_use]
    pub fn new(sink: Arc<dyn AuditSink>, buffer: Arc<EventBuffer>) -> Self {
        Self { sink, buffer }
    }

    /// Publish `entry`, fire-and-forget.
    ///
    /// Tries the sink first; on any sink error the entry is appended to the
    /// buffer. This never returns an error to the caller, so the agent's
    /// critical path is never blocked by audit production. Each outcome bumps
    /// the matching `aa_audit_*` counter.
    pub async fn publish(&self, entry: AuditEntry) {
        match self.sink.emit(entry.clone()).await {
            Ok(()) => {
                metrics::counter!(METRIC_PUBLISHED).increment(1);
            }
            Err(_) => {
                metrics::counter!(METRIC_PUBLISH_ERRORS).increment(1);
                if self.buffer.enqueue(&entry).is_ok() {
                    metrics::counter!(METRIC_BUFFERED).increment(1);
                }
            }
        }
    }

    /// Number of events currently held in the fallback buffer.
    ///
    /// # Errors
    ///
    /// Propagates any error from the underlying buffer query.
    pub fn buffered_len(&self) -> Result<usize> {
        self.buffer.len()
    }
}
