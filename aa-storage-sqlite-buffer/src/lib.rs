//! Local in-process SQLite **event buffer** for Agent Assembly.
//!
//! When the upstream NATS/gateway is briefly unreachable, Assembly keeps
//! emitting governance [`AuditEntry`](aa_core::storage::AuditEntry) records into
//! this buffer instead of dropping them. Once the connection recovers, the
//! buffer flushes its backlog — in insertion order — through the upstream
//! [`AuditSink`](aa_core::storage::AuditSink). This gives Assembly **partial
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
