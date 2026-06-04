//! The fire-and-forget [`AuditPublisher`] with offline buffering.

use std::sync::Arc;
use std::time::Duration;

use aa_core::storage::{AuditEntry, AuditSink, Result};
use aa_storage_sqlite_buffer::EventBuffer;
use tokio::task::JoinHandle;

use super::{METRIC_BUFFERED, METRIC_FLUSHED, METRIC_PUBLISHED, METRIC_PUBLISH_ERRORS};

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

    /// Replay any buffered events to the sink in FIFO order, returning the count
    /// flushed.
    ///
    /// Draining stops at the first sink failure (the connection is treated as
    /// still down), leaving the remainder buffered for a later attempt. Each
    /// replayed event bumps `aa_audit_flushed_total`.
    ///
    /// # Errors
    ///
    /// Propagates buffer read/decode errors; a sink failure is not an error
    /// here — it simply ends the drain early.
    pub async fn flush_pending(&self) -> Result<usize> {
        if self.buffer.is_empty()? {
            return Ok(0);
        }
        let flushed = self.buffer.drain_and_send(&*self.sink).await?;
        if flushed > 0 {
            metrics::counter!(METRIC_FLUSHED).increment(flushed as u64);
        }
        Ok(flushed)
    }

    /// Spawn a background task that periodically flushes the buffer, draining it
    /// once the NATS connection recovers.
    ///
    /// The task ticks every `interval` and calls [`flush_pending`](Self::flush_pending);
    /// abort the returned [`JoinHandle`] to stop it.
    #[must_use]
    pub fn spawn_reconnect_flush_loop(self: Arc<Self>, interval: Duration) -> JoinHandle<()> {
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            loop {
                ticker.tick().await;
                if let Err(err) = self.flush_pending().await {
                    tracing::warn!(error = %err, "audit buffer flush failed");
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Mutex;

    use aa_core::audit::{AuditEntry, AuditEventType};
    use aa_core::storage::StorageError;
    use aa_core::{AgentId, SessionId};
    use async_trait::async_trait;
    use tempfile::TempDir;

    /// An in-memory [`AuditSink`] whose connectivity can be toggled. It records
    /// every accepted entry so tests can assert FIFO replay order.
    struct FakeSink {
        up: AtomicBool,
        captured: Mutex<Vec<AuditEntry>>,
    }

    impl FakeSink {
        fn new(up: bool) -> Self {
            Self {
                up: AtomicBool::new(up),
                captured: Mutex::new(Vec::new()),
            }
        }

        fn captured_seqs(&self) -> Vec<u64> {
            self.captured.lock().unwrap().iter().map(AuditEntry::seq).collect()
        }
    }

    #[async_trait]
    impl AuditSink for FakeSink {
        async fn emit(&self, event: AuditEntry) -> Result<()> {
            if !self.up.load(Ordering::SeqCst) {
                return Err(StorageError::Backend("fake sink down".to_string()));
            }
            self.captured.lock().unwrap().push(event);
            Ok(())
        }
    }

    /// Build a distinct audit entry tagged with `seq`.
    fn entry(seq: u64) -> AuditEntry {
        AuditEntry::new(
            seq,
            seq,
            AuditEventType::ToolCallIntercepted,
            AgentId::from_bytes([0u8; 16]),
            SessionId::from_bytes([0u8; 16]),
            format!("{{\"seq\":{seq}}}"),
            [0u8; 32],
        )
    }

    /// Create a fresh on-disk buffer in a temp dir (returned so it outlives the buffer).
    fn new_buffer() -> (TempDir, Arc<EventBuffer>) {
        let dir = TempDir::new().expect("temp dir");
        let buffer = EventBuffer::new(dir.path().join("buffer.db"), 10_000).expect("open buffer");
        (dir, Arc::new(buffer))
    }

    #[tokio::test]
    async fn publish_succeeds_when_sink_up() {
        let (_dir, buffer) = new_buffer();
        let sink = Arc::new(FakeSink::new(true));
        let publisher = AuditPublisher::new(sink.clone(), buffer.clone());

        publisher.publish(entry(1)).await;

        assert_eq!(sink.captured_seqs(), vec![1]);
        assert_eq!(publisher.buffered_len().unwrap(), 0, "nothing should be buffered");
    }

    #[tokio::test]
    async fn buffers_when_sink_down() {
        let (_dir, buffer) = new_buffer();
        let sink = Arc::new(FakeSink::new(false));
        let publisher = AuditPublisher::new(sink.clone(), buffer.clone());

        publisher.publish(entry(1)).await;
        publisher.publish(entry(2)).await;

        assert!(sink.captured_seqs().is_empty(), "sink is down, nothing delivered");
        assert_eq!(publisher.buffered_len().unwrap(), 2, "both events buffered");
    }
}
