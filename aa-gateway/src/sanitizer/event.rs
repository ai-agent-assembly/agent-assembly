//! Newtypes that mark the trust boundary between raw inbound audit events and
//! the sanitized form the storage layer is allowed to persist.

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

/// An audit event that has passed the write-boundary sanitizer: guaranteed to
/// contain none of the banned keys at any depth and only vetted top-level
/// metadata.
///
/// The inner value is private and the constructor is crate-private, so the
/// **only** way to obtain one is [`sanitize`](super::sanitize). Postgres
/// handlers accept this type and nothing else, which makes "raw events never
/// get INSERTed" a compile-time guarantee rather than a convention.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SanitizedAuditEvent(Value);

impl SanitizedAuditEvent {
    /// Mints the sanitized wrapper. Crate-private on purpose: only the
    /// sanitizer may vouch that a value is safe to persist.
    pub(crate) fn new(value: Value) -> Self {
        Self(value)
    }

    /// Borrows the sanitized JSON value for persistence.
    pub fn as_value(&self) -> &Value {
        &self.0
    }

    /// Consumes the wrapper, yielding the sanitized JSON value.
    pub fn into_value(self) -> Value {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn raw_audit_event_from_value_wraps_without_mutation() {
        // The `From<Value>` ergonomic constructor must wrap the value verbatim:
        // wrapping is a trust-boundary marker only — it performs no sanitization,
        // so the inner value is byte-for-byte the untrusted input.
        let value = json!({ "event": "tool_call", "secret_field": "leak-me" });
        let raw: RawAuditEvent = value.clone().into();
        assert_eq!(raw.into_value(), value);
    }

    #[test]
    fn raw_audit_event_new_and_from_are_equivalent() {
        let value = json!({ "k": 1 });
        assert_eq!(RawAuditEvent::from(value.clone()), RawAuditEvent::new(value));
    }
}

/// A collapsed heartbeat. Per-beat records are never stored; instead a
/// heartbeat event becomes a single "last seen at" update on the agent row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeartbeatUpdate {
    /// Agent the heartbeat belongs to (empty when the event omitted it).
    pub agent_id: String,
    /// Heartbeat timestamp as carried by the event, left as the raw JSON
    /// scalar (`Null` when absent) so the storage layer owns parsing and may
    /// fall back to `now()`.
    pub last_heartbeat_at: Value,
}

/// The result of sanitizing a raw audit event — either an audit row to INSERT
/// or a heartbeat to collapse into an agent "last seen" update.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SanitizeOutcome {
    /// A normal event: write this sanitized row to `audit_logs`.
    Audit(SanitizedAuditEvent),
    /// A heartbeat: update `agents.last_heartbeat` instead of inserting a row.
    Heartbeat(HeartbeatUpdate),
}
