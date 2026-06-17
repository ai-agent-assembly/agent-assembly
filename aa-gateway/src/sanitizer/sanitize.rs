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
    use proptest::prelude::*;
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

    #[test]
    fn drops_heartbeat_seq_field() {
        let raw = RawAuditEvent::new(json!({
            "kind": "tool_call",
            "agent_id": "acme/bot",
            "heartbeat_seq": 42,
        }));
        assert!(!contains_key_recursive(&audit_value(raw), "heartbeat_seq"));
    }

    #[test]
    fn drops_banned_keys_regardless_of_case() {
        // AAASM-3136: a case-variant of a banned key must still be stripped,
        // at the top level and nested inside the opaque payload container.
        let raw = RawAuditEvent::new(json!({
            "kind": "tool_call",
            "agent_id": "acme/bot",
            "Prompt": "top-level mixed case secret",
            "payload": {
                "TOOL_PAYLOAD": { "args": "nested upper-case secret" },
                "steps": [{ "Completion": "deep mixed-case completion" }],
            },
        }));
        let out = audit_value(raw);
        assert!(!contains_key_recursive(&out, "Prompt"));
        assert!(!contains_key_recursive(&out, "TOOL_PAYLOAD"));
        assert!(!contains_key_recursive(&out, "Completion"));
        // The vetted payload container itself survives.
        assert!(contains_key_recursive(&out, "payload"));
    }

    #[test]
    fn drops_banned_keys_nested_in_payload() {
        let raw = RawAuditEvent::new(json!({
            "kind": "tool_call",
            "agent_id": "acme/bot",
            "payload": {
                "tool_call": { "prompt": "nested secret prompt" },
                "steps": [{ "completion": "deep completion" }],
            },
        }));
        let out = audit_value(raw);
        // The vetted `payload` container survives...
        assert!(contains_key_recursive(&out, "payload"));
        // ...but banned keys nested anywhere inside it are gone.
        assert!(!contains_key_recursive(&out, "prompt"));
        assert!(!contains_key_recursive(&out, "completion"));
    }

    #[test]
    fn heartbeat_routes_to_last_seen_update() {
        let raw = RawAuditEvent::new(json!({
            "kind": "heartbeat",
            "agent_id": "acme/bot",
            "ts": "2026-06-03T00:00:00Z",
            "heartbeat_seq": 7,
        }));
        match sanitize(raw) {
            SanitizeOutcome::Heartbeat(hb) => {
                assert_eq!(hb.agent_id, "acme/bot");
                assert_eq!(hb.last_heartbeat_at, json!("2026-06-03T00:00:00Z"));
            }
            SanitizeOutcome::Audit(_) => panic!("heartbeat must not become an audit row"),
        }
    }

    #[test]
    fn drops_unknown_top_level_field() {
        let raw = RawAuditEvent::new(json!({
            "kind": "tool_call",
            "agent_id": "acme/bot",
            "mystery_field": "who put this here",
        }));
        let out = audit_value(raw);
        // The unvetted key is dropped (and counted via the metric)...
        assert!(!contains_key_recursive(&out, "mystery_field"));
        // ...while vetted metadata is retained.
        assert!(contains_key_recursive(&out, "agent_id"));
    }

    /// Generates object keys, biased toward the banned set so the invariant is
    /// actually exercised rather than almost never hitting a banned key.
    fn key_strategy() -> impl Strategy<Value = String> {
        prop_oneof![
            proptest::sample::select(crate::sanitizer::rules::BANNED_KEYS).prop_map(String::from),
            "[a-z_]{1,12}",
        ]
    }

    /// Generates an arbitrary, possibly deeply-nested `serde_json::Value`.
    fn arb_json() -> impl Strategy<Value = Value> {
        let leaf = prop_oneof![
            Just(Value::Null),
            any::<bool>().prop_map(Value::Bool),
            any::<i64>().prop_map(|n| Value::Number(n.into())),
            ".*".prop_map(Value::String),
        ];
        leaf.prop_recursive(4, 64, 8, |inner| {
            prop_oneof![
                prop::collection::vec(inner.clone(), 0..8).prop_map(Value::Array),
                prop::collection::vec((key_strategy(), inner), 0..8)
                    .prop_map(|pairs| Value::Object(pairs.into_iter().collect())),
            ]
        })
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(1000))]

        /// The core invariant: no banned key survives anywhere in the tree of a
        /// sanitized audit event, for any random input.
        #[test]
        fn proptest_no_banned_keys(value in arb_json()) {
            if let SanitizeOutcome::Audit(ev) = sanitize(RawAuditEvent::new(value)) {
                for banned in crate::sanitizer::rules::BANNED_KEYS {
                    prop_assert!(!contains_key_recursive(ev.as_value(), banned));
                }
            }
        }
    }
}
