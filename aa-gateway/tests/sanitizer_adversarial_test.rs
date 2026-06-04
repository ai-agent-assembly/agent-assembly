//! Adversarial verification for the write-boundary sanitizer
//! (Story AAASM-2390, verification subtask AAASM-2398).
//!
//! Treats the sanitizer as a black box at its public boundary: feeds a
//! maliciously-crafted event that stuffs every banned key into every nesting
//! position, then asserts the sanitized output a handler would persist
//! contains none of them — the boundary-level equivalent of "publish a
//! crafted event and assert the resulting DB row has no banned field". The
//! end-to-end NATS→Postgres path lands with the consumer (AAASM-2388).

use aa_gateway::sanitizer::{sanitize, RawAuditEvent, SanitizeOutcome};
use serde_json::{json, Value};

/// Every key the sanitizer must strip, per AAASM-2390 / AAASM-2397.
const BANNED_KEYS: &[&str] = &[
    "prompt",
    "completion",
    "llm_input",
    "llm_output",
    "tool_payload",
    "tool_response",
    "tool_args",
    "tool_result",
    "packet_body",
    "packet_payload",
    "heartbeat_seq",
];

/// Recursively reports whether `key` appears anywhere in the JSON tree.
fn contains_key_recursive(value: &Value, key: &str) -> bool {
    match value {
        Value::Object(map) => map.contains_key(key) || map.values().any(|v| contains_key_recursive(v, key)),
        Value::Array(items) => items.iter().any(|v| contains_key_recursive(v, key)),
        _ => false,
    }
}

#[test]
fn maliciously_crafted_event_yields_no_banned_keys() {
    // Every banned key, placed top-level AND nested inside payload, an array,
    // and a deeply-nested object — plus an unknown field for good measure.
    let raw = RawAuditEvent::new(json!({
        "kind": "tool_call",
        "agent_id": "acme/bot",
        "prompt": "top-level prompt",
        "completion": "top-level completion",
        "llm_input": "x",
        "llm_output": "y",
        "tool_payload": { "tool_args": ["--secret"], "nested": { "prompt": "deep" } },
        "tool_response": { "tool_result": { "packet_body": "QkFTRTY0" } },
        "packet_payload": "raw",
        "heartbeat_seq": 9,
        "payload": {
            "events": [
                { "prompt": "in-array prompt", "completion": "in-array completion" },
                { "tool_payload": { "packet_payload": "deep-bytes" } }
            ],
            "meta": { "llm_input": "nested", "heartbeat_seq": 1 }
        },
        "exfiltration_attempt": "unknown field"
    }));

    let SanitizeOutcome::Audit(ev) = sanitize(raw) else {
        panic!("a non-heartbeat event must produce an audit row");
    };
    let sanitized = ev.into_value();

    for banned in BANNED_KEYS {
        assert!(
            !contains_key_recursive(&sanitized, banned),
            "banned key `{banned}` survived sanitization: {sanitized:#}"
        );
    }
    // The unknown top-level field is dropped as well.
    assert!(!contains_key_recursive(&sanitized, "exfiltration_attempt"));
}

#[test]
fn malicious_heartbeat_never_becomes_audit_row() {
    // A heartbeat that smuggles a prompt must still route to a last-seen
    // update, never an audit row.
    let raw = RawAuditEvent::new(json!({
        "kind": "heartbeat",
        "agent_id": "acme/bot",
        "ts": "2026-06-03T12:00:00Z",
        "prompt": "smuggled prompt on a heartbeat",
        "heartbeat_seq": 123,
    }));
    match sanitize(raw) {
        SanitizeOutcome::Heartbeat(hb) => assert_eq!(hb.agent_id, "acme/bot"),
        SanitizeOutcome::Audit(_) => panic!("a heartbeat must not produce an audit row"),
    }
}
