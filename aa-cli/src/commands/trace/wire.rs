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

use chrono::{DateTime, Utc};
use serde::Deserialize;

use super::models::TraceEventKind;

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
}
