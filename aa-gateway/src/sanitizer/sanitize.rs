//! The write-boundary sanitizer entrypoint and its field-drop helpers.

use serde_json::Value;

use super::event::{HeartbeatUpdate, RawAuditEvent, SanitizeOutcome, SanitizedAuditEvent};
use super::rules;

/// The `kind` discriminant that marks a heartbeat event.
const HEARTBEAT_KIND: &str = "heartbeat";

/// Recursively removes every [`rules::BANNED_KEYS`] entry from a JSON value,
/// descending into nested objects and array elements. Mutates in place.
fn strip_banned_keys(value: &mut Value) {
    match value {
        Value::Object(map) => {
            map.retain(|key, _| !rules::is_banned(key));
            for child in map.values_mut() {
                strip_banned_keys(child);
            }
        }
        Value::Array(items) => {
            for item in items {
                strip_banned_keys(item);
            }
        }
        _ => {}
    }
}

/// Drops any top-level key that is not vetted metadata, emitting
/// `aa_audit_dropped_unknown_field_total{field=<name>}` once per dropped key.
///
/// Must run *after* [`strip_banned_keys`] so that known-bad keys are already
/// gone and the counter only fires for genuinely unexpected fields — the
/// signal that a sender has started emitting something new.
fn drop_unknown_top_level(map: &mut serde_json::Map<String, Value>) {
    let unknown: Vec<String> = map
        .keys()
        .filter(|key| !rules::is_allowed_top_level(key))
        .cloned()
        .collect();
    for field in unknown {
        map.remove(&field);
        metrics::counter!("aa_audit_dropped_unknown_field_total", "field" => field).increment(1);
    }
}

/// Returns `true` when the event's top-level `kind` is `"heartbeat"`.
fn is_heartbeat(value: &Value) -> bool {
    value.get("kind").and_then(Value::as_str) == Some(HEARTBEAT_KIND)
}

/// Collapses a heartbeat event into a single agent "last seen" update.
///
/// Missing fields degrade gracefully: an absent agent id becomes the empty
/// string and an absent timestamp becomes `Value::Null`, leaving the storage
/// layer free to default to `now()`.
fn collapse_heartbeat(value: &Value) -> HeartbeatUpdate {
    let agent_id = value
        .get("agent_id")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let last_heartbeat_at = value
        .get("ts")
        .or_else(|| value.get("timestamp"))
        .cloned()
        .unwrap_or(Value::Null);
    HeartbeatUpdate {
        agent_id,
        last_heartbeat_at,
    }
}

/// Sanitizes a raw inbound audit event at the Gateway write boundary.
///
/// Heartbeats collapse to a [`HeartbeatUpdate`]; every other event has its
/// banned keys stripped recursively and its unknown top-level fields dropped,
/// then is wrapped as a [`SanitizedAuditEvent`] ready to INSERT. This is the
/// single entrypoint the consumer (AAASM-2388) calls before persisting.
pub fn sanitize(raw: RawAuditEvent) -> SanitizeOutcome {
    let mut value = raw.into_value();

    // Heartbeats never become audit rows — collapse to a last-seen update.
    if is_heartbeat(&value) {
        return SanitizeOutcome::Heartbeat(collapse_heartbeat(&value));
    }

    // Defense-in-depth: drop never-store keys at every depth first, so the
    // unknown-field accounting only sees genuinely unexpected keys.
    strip_banned_keys(&mut value);
    if let Value::Object(map) = &mut value {
        drop_unknown_top_level(map);
    }

    SanitizeOutcome::Audit(SanitizedAuditEvent::new(value))
}

#[cfg(test)]
mod tests {
    use super::sanitize;
    use crate::sanitizer::{RawAuditEvent, SanitizeOutcome};
    use serde_json::{json, Value};

    /// Recursively reports whether `key` appears anywhere in the JSON tree.
    fn contains_key_recursive(value: &Value, key: &str) -> bool {
        match value {
            Value::Object(map) => map.contains_key(key) || map.values().any(|v| contains_key_recursive(v, key)),
            Value::Array(items) => items.iter().any(|v| contains_key_recursive(v, key)),
            _ => false,
        }
    }

    /// Sanitizes `raw`, asserting it produced an audit row, and returns the
    /// sanitized JSON for inspection.
    fn audit_value(raw: RawAuditEvent) -> Value {
        match sanitize(raw) {
            SanitizeOutcome::Audit(ev) => ev.into_value(),
            other => panic!("expected Audit outcome, got {other:?}"),
        }
    }

    #[test]
    fn drops_prompt_field() {
        let raw = RawAuditEvent::new(json!({
            "kind": "tool_call",
            "agent_id": "acme/bot",
            "prompt": "the raw system prompt",
        }));
        assert!(!contains_key_recursive(&audit_value(raw), "prompt"));
    }

    #[test]
    fn drops_completion_field() {
        let raw = RawAuditEvent::new(json!({
            "kind": "tool_call",
            "agent_id": "acme/bot",
            "completion": "the model completion text",
        }));
        assert!(!contains_key_recursive(&audit_value(raw), "completion"));
    }

    #[test]
    fn drops_llm_input_field() {
        let raw = RawAuditEvent::new(json!({
            "kind": "tool_call",
            "agent_id": "acme/bot",
            "llm_input": "raw llm input prompt",
        }));
        assert!(!contains_key_recursive(&audit_value(raw), "llm_input"));
    }

    #[test]
    fn drops_llm_output_field() {
        let raw = RawAuditEvent::new(json!({
            "kind": "tool_call",
            "agent_id": "acme/bot",
            "llm_output": "raw llm output text",
        }));
        assert!(!contains_key_recursive(&audit_value(raw), "llm_output"));
    }

    #[test]
    fn drops_tool_payload_field() {
        let raw = RawAuditEvent::new(json!({
            "kind": "tool_call",
            "agent_id": "acme/bot",
            "tool_payload": { "args": { "path": "/etc/passwd" } },
        }));
        assert!(!contains_key_recursive(&audit_value(raw), "tool_payload"));
    }

    #[test]
    fn drops_tool_response_field() {
        let raw = RawAuditEvent::new(json!({
            "kind": "tool_call",
            "agent_id": "acme/bot",
            "tool_response": { "body": "tool stdout bytes" },
        }));
        assert!(!contains_key_recursive(&audit_value(raw), "tool_response"));
    }

    #[test]
    fn drops_tool_args_field() {
        let raw = RawAuditEvent::new(json!({
            "kind": "tool_call",
            "agent_id": "acme/bot",
            "tool_args": ["--token", "sekret"],
        }));
        assert!(!contains_key_recursive(&audit_value(raw), "tool_args"));
    }

    #[test]
    fn drops_tool_result_field() {
        let raw = RawAuditEvent::new(json!({
            "kind": "tool_call",
            "agent_id": "acme/bot",
            "tool_result": { "stdout": "result bytes" },
        }));
        assert!(!contains_key_recursive(&audit_value(raw), "tool_result"));
    }

    #[test]
    fn drops_packet_body_field() {
        let raw = RawAuditEvent::new(json!({
            "kind": "tool_call",
            "agent_id": "acme/bot",
            "packet_body": "QkFTRTY0UEFDS0VU",
        }));
        assert!(!contains_key_recursive(&audit_value(raw), "packet_body"));
    }

    #[test]
    fn drops_packet_payload_field() {
        let raw = RawAuditEvent::new(json!({
            "kind": "tool_call",
            "agent_id": "acme/bot",
            "packet_payload": "raw-packet-bytes",
        }));
        assert!(!contains_key_recursive(&audit_value(raw), "packet_payload"));
    }
}
