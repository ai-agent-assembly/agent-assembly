//! Audit event sink abstraction used by the approval router.

use aa_core::AuditEventType;

/// Receives audit events emitted by the approval router.
pub trait AuditEventSink: Send + Sync {
    fn emit(&self, event_type: AuditEventType, payload: String);
}

/// Sink that discards all events; used in unit tests.
pub struct NoopAuditSink;

impl AuditEventSink for NoopAuditSink {
    fn emit(&self, _event_type: AuditEventType, _payload: String) {}
}
