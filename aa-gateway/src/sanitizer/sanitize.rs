//! The write-boundary sanitizer entrypoint and its field-drop helpers.

// Helpers are wired together by `sanitize` in this same module; each is
// introduced just ahead of its caller.
#![allow(dead_code)]

use serde_json::Value;

use super::rules;

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
