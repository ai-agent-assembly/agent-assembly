//! Newtypes that mark the trust boundary between raw inbound audit events and
//! the sanitized form the storage layer is allowed to persist.

// Accessors are consumed once `sanitize` is wired up; introduced here with the
// types they belong to.
#![allow(dead_code)]

use serde_json::Value;

/// An audit event exactly as received off the wire (NATS subject
/// `assembly.audit.>`), before any field-drop rules are applied.
///
/// Carries whatever an upstream SDK or proxy chose to emit — including fields
/// we must never persist. The only way to turn one into something the storage
/// layer accepts is [`sanitize`](super::sanitize).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawAuditEvent(Value);

impl RawAuditEvent {
    /// Wraps a decoded JSON value as a raw, untrusted audit event.
    pub fn new(value: Value) -> Self {
        Self(value)
    }

    /// Consumes the wrapper, yielding the underlying JSON value.
    pub(crate) fn into_value(self) -> Value {
        self.0
    }
}

impl From<Value> for RawAuditEvent {
    fn from(value: Value) -> Self {
        Self::new(value)
    }
}
