//! Local in-process SQLite **event buffer** for Agent Assembly.
//!
//! When the upstream NATS/gateway is briefly unreachable, Assembly keeps
//! emitting governance [`AuditEntry`] records into this buffer instead of
//! dropping them. Once the connection recovers, the buffer flushes its backlog
//! — in insertion order — through the upstream [`AuditSink`]. This gives
//! Assembly **partial
//! autonomy** so a transient outage never silently loses audit-trail data.
//!
//! The buffer is a single SQLite file opened in WAL mode, so a buffered event
//! survives a process restart and is replayed on the next reconnect.
//!
//! ```no_run
//! use aa_storage_sqlite_buffer::EventBuffer;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Open (or create) a buffer holding at most 10_000 events.
//! let buffer = EventBuffer::new("/var/lib/agent-assembly/buffer.db", 10_000)?;
//! # let _ = buffer;
//! # Ok(())
//! # }
//! ```

#![warn(missing_docs)]

mod buffer;
mod config;

pub use buffer::EventBuffer;
pub use config::{default_path, SqliteBufferConfig, DEFAULT_CAP};

// Re-export the storage-contract types that appear in this crate's public API
// so callers reach the buffer and its event/sink types from a single path.
pub use aa_core::storage::{AuditEntry, AuditSink, Result, StorageError};

/// Counter incremented once per event accepted into the buffer.
pub const METRIC_EVENTS_BUFFERED: &str = "aa_events_buffered";

/// Counter incremented when the cap is exceeded and an oldest event is evicted.
pub const METRIC_EVENTS_DROPPED: &str = "aa_events_dropped_total";

/// Counter incremented once per event successfully flushed to the sink.
pub const METRIC_EVENTS_FLUSHED: &str = "aa_events_flushed_total";
