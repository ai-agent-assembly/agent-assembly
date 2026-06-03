//! Field-classification rule sets for the write-boundary sanitizer.

// Consumed by `sanitize` once the entrypoint is wired up; until then the rule
// sets are introduced ahead of their first caller.
#![allow(dead_code)]

/// Keys whose values are **never** persisted. Stripped recursively at every
/// depth of the event tree before an audit row is constructed.
///
/// This is the union of the spec's "確定不用存" (must NOT store) list
/// (spec lines 7551–7572) and the expanded observability-payload keys called
/// out in AAASM-2397: raw LLM prompt / completion, full tool-call payloads,
/// eBPF packet bodies, and the per-heartbeat sequence counter. A superset is
/// deliberate — defense-in-depth means erring toward dropping.
pub(crate) const BANNED_KEYS: &[&str] = &[
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

/// Returns `true` if `key` is on the recursive banned list.
pub(crate) fn is_banned(key: &str) -> bool {
    BANNED_KEYS.contains(&key)
}
