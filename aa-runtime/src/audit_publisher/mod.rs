//! Assembly-side audit-event publisher.
//!
//! The [`AuditPublisher`] fires governance [`AuditEntry`](aa_core::storage::AuditEntry)
//! records at a NATS subject and returns control to the agent immediately, so
//! the tool-call critical path never blocks on the gateway's database writes
//! (spec line 7349). When the NATS connection is down, events spill into the
//! local SQLite [`EventBuffer`](aa_storage_sqlite_buffer::EventBuffer) instead
//! of being dropped, and a background loop flushes the backlog in FIFO order
//! once the connection recovers.
//!
//! NATS is the Phase 1 backend (spec line 7457); the publisher is the only
//! Assembly-side component that knows about it, so swapping in Kafka later does
//! not touch the agent-facing API.

mod config;
mod sink;
mod subject;

pub use config::{NatsConfig, NatsTlsConfig, DEFAULT_MAX_INFLIGHT, DEFAULT_URL};
pub use sink::NatsAuditSink;
pub use subject::subject_for;

/// Counter incremented once per event accepted by the NATS sink.
pub const METRIC_PUBLISHED: &str = "aa_audit_published_total";

/// Counter incremented once per failed publish attempt (the event is then
/// routed to the buffer).
pub const METRIC_PUBLISH_ERRORS: &str = "aa_audit_publish_errors_total";

/// Counter incremented once per event diverted to the SQLite fallback buffer.
pub const METRIC_BUFFERED: &str = "aa_audit_buffered_total";

/// Counter incremented once per buffered event replayed to NATS on reconnect.
pub const METRIC_FLUSHED: &str = "aa_audit_flushed_total";
