//! Wire-mirror types for the `GET /api/v1/traces/:session_id` response
//! (AAASM-1475).
//!
//! `aa-api` returns `TraceResponse { session_id, agent_id, spans }` where
//! each span is a flat record with `parent_span_id` linking. The CLI
//! consumes a richer hierarchical [`SessionTrace`] (see
//! [`super::models`]). These types let us deserialize the wire shape
//! without forcing `aa-cli` to depend on `aa-api`; the
//! [`From<WireTraceResponse> for SessionTrace`] impl folds the flat
//! span list into the tree the CLI renderer expects.

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::Deserialize;

use super::models::{SessionTrace, TraceEvent, TraceEventKind};

/// Wire shape of `TraceResponse` from `aa-api`.
#[derive(Debug, Clone, Deserialize)]
pub struct WireTraceResponse {
    pub session_id: String,
    #[serde(default)]
    pub agent_id: String,
    #[serde(default)]
    pub spans: Vec<WireTraceSpan>,
}

/// Wire shape of one `TraceSpan` from `aa-api`.
#[derive(Debug, Clone, Deserialize)]
pub struct WireTraceSpan {
    pub span_id: String,
    #[serde(default)]
    pub parent_span_id: Option<String>,
    pub operation: String,
    #[serde(default)]
    pub decision: Option<String>,
    pub start_time: DateTime<Utc>,
    #[serde(default)]
    pub end_time: Option<DateTime<Utc>>,
}

impl From<WireTraceResponse> for SessionTrace {
    /// Fold the flat span list into a hierarchical [`SessionTrace`].
    ///
    /// Spans are matched parent → child via `parent_span_id` /
    /// `span_id`. Top-level events are those whose `parent_span_id` is
    /// `None` **or** points at a span that isn't in the response
    /// (orphaned children are promoted to roots so no data is lost).
    /// Siblings at every level are sorted by `start_time`.
    fn from(wire: WireTraceResponse) -> Self {
        // Map child parent_span_id → list of child indices.
        let mut children_of: HashMap<Option<String>, Vec<usize>> = HashMap::new();
        let known_ids: std::collections::HashSet<&str> = wire.spans.iter().map(|s| s.span_id.as_str()).collect();

        for (idx, span) in wire.spans.iter().enumerate() {
            // Promote orphans (parent_span_id present but not in the
            // response) to top-level so they still render.
            let bucket_key = match &span.parent_span_id {
                Some(p) if known_ids.contains(p.as_str()) => Some(p.clone()),
                _ => None,
            };
            children_of.entry(bucket_key).or_default().push(idx);
        }

        // Sort each bucket by start_time so the rendered tree is
        // chronologically ordered.
        for indices in children_of.values_mut() {
            indices.sort_by_key(|&i| wire.spans[i].start_time);
        }

        let events = build_events(None, &wire.spans, &children_of);

        SessionTrace {
            session_id: wire.session_id,
            events,
        }
    }
}

/// Recursively build the [`TraceEvent`] subtree rooted under `parent_id`.
fn build_events(
    parent_id: Option<String>,
    spans: &[WireTraceSpan],
    children_of: &HashMap<Option<String>, Vec<usize>>,
) -> Vec<TraceEvent> {
    let Some(indices) = children_of.get(&parent_id) else {
        return Vec::new();
    };
    indices
        .iter()
        .map(|&i| {
            let span = &spans[i];
            TraceEvent {
                kind: kind_from_span(&span.operation, span.decision.as_deref()),
                label: span.operation.clone(),
                duration_ms: duration_ms_from(span.start_time, span.end_time),
                children: build_events(Some(span.span_id.clone()), spans, children_of),
                violation_reason: None,
            }
        })
        .collect()
}

/// Compute milliseconds elapsed between `start` and `end`. Returns `0`
/// if `end` is missing (span still in progress) or if `end < start`
/// (clock skew — we never report negative durations).
pub fn duration_ms_from(start: DateTime<Utc>, end: Option<DateTime<Utc>>) -> u64 {
    let Some(end) = end else { return 0 };
    let delta = end.signed_duration_since(start).num_milliseconds();
    if delta <= 0 {
        0
    } else {
        delta as u64
    }
}

/// Derive a [`TraceEventKind`] for a span from its `operation` name and
/// `decision`. The CLI renderer uses kinds to pick icons / colors; the
/// API only exposes the operation string + optional decision, so this
/// is a best-effort mapping:
///
/// * `decision == "deny"` → [`TraceEventKind::PolicyDeny`]
/// * operation contains `tool_call` → [`TraceEventKind::ToolCall`]
/// * operation contains `tool_result` → [`TraceEventKind::ToolResult`]
/// * operation contains `llm` → [`TraceEventKind::Llm`]
/// * otherwise → [`TraceEventKind::PolicyAllow`] (default — every span
///   the gateway records has at least an implicit allow decision)
pub fn kind_from_span(operation: &str, decision: Option<&str>) -> TraceEventKind {
    if matches!(decision, Some(d) if d.eq_ignore_ascii_case("deny")) {
        return TraceEventKind::PolicyDeny;
    }
    let op = operation.to_ascii_lowercase();
    if op.contains("tool_result") {
        TraceEventKind::ToolResult
    } else if op.contains("tool_call") || op.contains("tool") {
        TraceEventKind::ToolCall
    } else if op.contains("llm") {
        TraceEventKind::Llm
    } else {
        TraceEventKind::PolicyAllow
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deny_decision_wins_over_operation() {
        assert_eq!(kind_from_span("llm_call", Some("deny")), TraceEventKind::PolicyDeny,);
        assert_eq!(kind_from_span("tool_call", Some("DENY")), TraceEventKind::PolicyDeny,);
    }

    #[test]
    fn llm_operation_maps_to_llm() {
        assert_eq!(kind_from_span("llm_call", Some("allow")), TraceEventKind::Llm,);
        assert_eq!(kind_from_span("LLM-Inference", None), TraceEventKind::Llm);
    }

    #[test]
    fn tool_call_and_result_are_distinct() {
        assert_eq!(kind_from_span("tool_call", None), TraceEventKind::ToolCall,);
        assert_eq!(kind_from_span("tool_result", None), TraceEventKind::ToolResult,);
    }

    #[test]
    fn unknown_operation_defaults_to_policy_allow() {
        assert_eq!(kind_from_span("op-42", Some("allow")), TraceEventKind::PolicyAllow,);
        assert_eq!(kind_from_span("misc", None), TraceEventKind::PolicyAllow);
    }

    #[test]
    fn duration_ms_returns_zero_when_end_missing() {
        let start = Utc::now();
        assert_eq!(duration_ms_from(start, None), 0);
    }

    #[test]
    fn duration_ms_computes_positive_delta() {
        let start = chrono::TimeZone::with_ymd_and_hms(&Utc, 2026, 1, 1, 0, 0, 0).unwrap();
        let end = start + chrono::Duration::milliseconds(250);
        assert_eq!(duration_ms_from(start, Some(end)), 250);
    }

    #[test]
    fn duration_ms_clamps_negative_to_zero() {
        let start = chrono::TimeZone::with_ymd_and_hms(&Utc, 2026, 1, 1, 0, 0, 0).unwrap();
        let end = start - chrono::Duration::milliseconds(100);
        assert_eq!(duration_ms_from(start, Some(end)), 0);
    }

    fn span(span_id: &str, parent: Option<&str>, op: &str, seconds_offset: i64) -> WireTraceSpan {
        let base = chrono::TimeZone::with_ymd_and_hms(&Utc, 2026, 1, 1, 0, 0, 0).unwrap();
        let start = base + chrono::Duration::seconds(seconds_offset);
        WireTraceSpan {
            span_id: span_id.to_string(),
            parent_span_id: parent.map(String::from),
            operation: op.to_string(),
            decision: Some("allow".to_string()),
            start_time: start,
            end_time: Some(start + chrono::Duration::milliseconds(100)),
        }
    }

    #[test]
    fn translate_flat_spans_become_top_level_events() {
        let wire = WireTraceResponse {
            session_id: "sess".into(),
            agent_id: String::new(),
            spans: vec![span("a", None, "llm_call", 0), span("b", None, "tool_call", 1)],
        };
        let trace: SessionTrace = wire.into();
        assert_eq!(trace.session_id, "sess");
        assert_eq!(trace.events.len(), 2);
        assert_eq!(trace.events[0].label, "llm_call");
        assert_eq!(trace.events[1].label, "tool_call");
        assert!(trace.events.iter().all(|e| e.children.is_empty()));
    }

    #[test]
    fn translate_builds_parent_child_tree() {
        let wire = WireTraceResponse {
            session_id: "sess".into(),
            agent_id: String::new(),
            spans: vec![
                span("root", None, "llm_call", 0),
                span("child1", Some("root"), "tool_call", 1),
                span("child2", Some("root"), "tool_result", 2),
            ],
        };
        let trace: SessionTrace = wire.into();
        assert_eq!(trace.events.len(), 1);
        assert_eq!(trace.events[0].label, "llm_call");
        assert_eq!(trace.events[0].children.len(), 2);
        assert_eq!(trace.events[0].children[0].label, "tool_call");
        assert_eq!(trace.events[0].children[1].label, "tool_result");
    }

    #[test]
    fn translate_sorts_siblings_by_start_time() {
        let wire = WireTraceResponse {
            session_id: "sess".into(),
            agent_id: String::new(),
            spans: vec![span("late", None, "op-3", 5), span("early", None, "op-1", 1)],
        };
        let trace: SessionTrace = wire.into();
        assert_eq!(trace.events[0].label, "op-1");
        assert_eq!(trace.events[1].label, "op-3");
    }

    #[test]
    fn translate_promotes_orphans_to_top_level() {
        // parent_span_id refers to a span not in the response —
        // surface the orphan as a top-level event rather than dropping it.
        let wire = WireTraceResponse {
            session_id: "sess".into(),
            agent_id: String::new(),
            spans: vec![span("orphan", Some("missing-parent"), "tool_call", 0)],
        };
        let trace: SessionTrace = wire.into();
        assert_eq!(trace.events.len(), 1);
        assert_eq!(trace.events[0].label, "tool_call");
    }
}
