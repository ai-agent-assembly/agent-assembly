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
