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

/// Top-level metadata keys the sanitizer keeps. Mirrors the `audit_events`
/// columns plus the event-routing fields a sender may set (`kind`,
/// `event_type`, `session_id`, `org_id`, `timestamp`, `policy_version`). The
/// `payload` container is kept — its dangerous contents are removed by the
/// recursive [`BANNED_KEYS`] pass, not by dropping the whole object.
///
/// Anything else at the top level is dropped and counted via
/// `aa_audit_dropped_unknown_field_total`, so we notice when a sender starts
/// emitting a field we have not vetted.
pub(crate) const ALLOWED_TOP_LEVEL_KEYS: &[&str] = &[
    "event_id",
    "ts",
    "timestamp",
    "agent_id",
    "team_id",
    "org_id",
    "session_id",
    "kind",
    "event_type",
    "action",
    "decision",
    "dry_run",
    "shadow_decision",
    "matched_rule_id",
    "policy_version",
    "payload",
];

/// Returns `true` if `key` is on the recursive banned list.
pub(crate) fn is_banned(key: &str) -> bool {
    BANNED_KEYS.contains(&key)
}

/// Returns `true` if `key` is an allowed top-level metadata key.
pub(crate) fn is_allowed_top_level(key: &str) -> bool {
    ALLOWED_TOP_LEVEL_KEYS.contains(&key)
}
