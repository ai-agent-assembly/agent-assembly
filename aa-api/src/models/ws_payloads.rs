//! OpenAPI schemas for WebSocket event payloads.
//!
//! These types document the JSON structure of `GovernanceEvent.payload`
//! for each [`EventType`] variant.  They mirror the internal runtime
//! and gateway types (`PipelineEvent`, `ApprovalRequest`, `BudgetAlert`)
//! without pulling `utoipa` into those crates.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// One node in the hierarchical call stack rendered beneath an
/// expanded Live Ops row in the dashboard.
///
/// Mirrors the proto `assembly.audit.v1.CallStackNode` message and the
/// dashboard `LiveOperation.callStack[]` TS type.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
#[schema(no_recursion)]
pub struct CallStackNode {
    /// Stable identifier for this node within the call stack.
    pub id: String,
    /// Node category — one of `"llm"`, `"tool"`, or `"result"`. String-typed
    /// (not an enum) to keep this open-ended for downstream renderers.
    pub kind: String,
    /// Human-readable label rendered in the dashboard.
    pub label: String,
    /// Step-local latency in milliseconds. Omitted when the producer did
    /// not record a duration for this node.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latency_ms: Option<i64>,
    /// Recursive descent — nested calls produced by this step. Omitted
    /// when the node has no children.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub children: Option<Vec<CallStackNode>>,
}

/// Payload for `event_type: "violation"` events.
///
/// Represents a governance audit event from the pipeline — either an
/// action that violated policy or an interception layer degradation.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ViolationPayload {
    /// A governance audit event enriched with runtime metadata.
    Audit {
        /// Source that delivered the event: `"sdk"`, `"ebpf"`, or `"proxy"`.
        source: String,
        /// Unix milliseconds when the pipeline received the event.
        received_at_ms: i64,
        /// Monotonic sequence number assigned by the pipeline.
        sequence_number: u64,
        /// Operation kind from the underlying `AuditEvent.action_type` — one of
        /// `"llm_call"`, `"tool_call"`, `"file_op"`, `"network"`, `"process"`,
        /// `"spawn"`, or `"unknown"` when unspecified. Drives the Live Ops
        /// dashboard's per-row "op type" column.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        op_type: Option<String>,
        /// Target resource derived from the action's `detail` variant — e.g.
        /// `LLMCallDetail.model_name`, `ToolCallDetail.tool_name`,
        /// `FileOpDetail.path`. Drives the Live Ops "resource" column.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        resource: Option<String>,
        /// Operation lifecycle status mapped from the proto `Decision`:
        /// `"running"` (allow / redact), `"blocked"` (deny), `"pending"`
        /// (awaiting human approval).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        status: Option<String>,
        /// Observed latency in milliseconds. Optional today — populated once
        /// the audit pipeline tracks per-action duration end-to-end.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        latency_ms: Option<u64>,
        /// Team identifier from the agent's lineage context. Empty for
        /// legacy events and root agents without a team set.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        team: Option<String>,
        /// Hierarchical call stack for the operation (LLM / tool / result
        /// steps). Omitted when the producer did not record a stack.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        call_stack: Option<Vec<CallStackNode>>,
    },
    /// An interception layer became unavailable.
    LayerDegradation {
        /// Name of the degraded layer (e.g. `"ebpf"`, `"proxy"`).
        layer: String,
        /// Human-readable reason for the degradation.
        reason: String,
        /// Remaining active layers after degradation.
        remaining_layers: Vec<String>,
    },
}

/// Payload for `event_type: "approval"` events.
///
/// Represents either a freshly-submitted human-in-the-loop approval
/// request or a status-change notification (e.g. auto-expiration). The
/// `status` field discriminates: `"pending"` for new requests,
/// `"expired"` for auto-expirations (AAASM-1453).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ApprovalPayload {
    /// Unique ID for the approval request (UUID v4).
    pub request_id: String,
    /// Human-readable description of the action awaiting approval.
    pub action: String,
    /// Policy condition that triggered this request.
    pub condition_triggered: String,
    /// Unix epoch timestamp (seconds) when the request was submitted.
    pub submitted_at: u64,
    /// Seconds before the request times out.
    pub timeout_secs: u64,
    /// Unix epoch timestamp (seconds) at which the request expires
    /// (`submitted_at + timeout_secs`). Provided as a pre-computed
    /// absolute timestamp so dashboard consumers can render the
    /// auto-expire countdown without local-clock drift.
    pub expires_at: u64,
    /// Lifecycle status — `"pending"` for newly-submitted requests
    /// (the original event semantics) or `"expired"` when the
    /// per-request timeout has elapsed without a human decision
    /// (AAASM-1453). Defaults to `"pending"` for legacy producers
    /// pre-AAASM-1453 that haven't been updated.
    #[serde(default = "default_pending_status")]
    pub status: String,
}

fn default_pending_status() -> String {
    "pending".to_string()
}

/// Payload for `event_type: "budget"` events.
///
/// Emitted when an agent's spend crosses a configured daily threshold
/// (80 % or 95 % of the daily limit).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct BudgetAlertPayload {
    /// Threshold percentage that was crossed (e.g. `80` or `95`).
    pub threshold_pct: u8,
    /// Current total spend in USD at the time of the alert.
    pub spent_usd: f64,
    /// Configured daily limit in USD.
    pub limit_usd: f64,
}

/// Payload for `event_type: "ops_change"` events.
///
/// Emitted on every transition of an in-flight operation in the
/// gateway-side [`aa_gateway::ops::OpsRegistry`] (AAASM-1422 PR-B).
/// The dashboard's `useLiveOpsStream` hook correlates rows by `op_id`
/// (composed from `trace_id:span_id`) and updates the matching row in
/// place, so a `pause` followed by the confirming `paused` event
/// auto-clears any optimistic override.
///
/// Actual emission on registry transitions ships in PR-H. PR-B only
/// defines the payload shape so PR-C (dashboard rework) and PR-H
/// (gateway emission) can build against a stable schema in parallel.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct OpsChangePayload {
    /// Stable operation identifier — `"{trace_id}:{span_id}"` composed
    /// in the gateway. The dashboard keys its row map by this value so
    /// successive `ops_change` events for the same op merge into one
    /// row instead of stacking.
    pub op_id: String,
    /// New lifecycle state after the transition. Mirrors the
    /// `aa_gateway::ops::OpState` enum (snake_case wire format:
    /// `pending` / `running` / `paused` / `completing` / `terminated`).
    #[schema(value_type = String, example = "running")]
    pub state: aa_gateway::ops::OpState,
    /// RFC 3339 UTC timestamp of the transition. Same value as the
    /// matching `OpRecord.updated_at` returned by the registry.
    pub updated_at: String,
    /// Agent that owns the operation. Mirrors `GovernanceEvent.agent_id`
    /// so a single agent's live-ops can be filtered without joining
    /// against the audit channel.
    pub agent_id: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_serializes_with_op_fields() {
        let payload = ViolationPayload::Audit {
            source: "sdk".into(),
            received_at_ms: 1_700_000_000_000,
            sequence_number: 42,
            op_type: Some("tool_call".into()),
            resource: Some("gmail.send".into()),
            status: Some("running".into()),
            latency_ms: Some(834),
            team: Some("support".into()),
            call_stack: None,
        };
        let json = serde_json::to_value(&payload).unwrap();
        assert_eq!(json["kind"], "audit");
        assert_eq!(json["op_type"], "tool_call");
        assert_eq!(json["resource"], "gmail.send");
        assert_eq!(json["status"], "running");
        assert_eq!(json["latency_ms"], 834);
        assert_eq!(json["team"], "support");
    }

    #[test]
    fn audit_round_trips_through_serde() {
        let original = ViolationPayload::Audit {
            source: "sdk".into(),
            received_at_ms: 1_700_000_000_000,
            sequence_number: 42,
            op_type: Some("llm_call".into()),
            resource: Some("gpt-4o".into()),
            status: Some("running".into()),
            latency_ms: Some(600),
            team: None,
            call_stack: None,
        };
        let json = serde_json::to_string(&original).unwrap();
        let decoded: ViolationPayload = serde_json::from_str(&json).unwrap();
        let ViolationPayload::Audit {
            op_type,
            resource,
            status,
            latency_ms,
            team,
            ..
        } = decoded
        else {
            panic!("expected Audit variant");
        };
        assert_eq!(op_type.as_deref(), Some("llm_call"));
        assert_eq!(resource.as_deref(), Some("gpt-4o"));
        assert_eq!(status.as_deref(), Some("running"));
        assert_eq!(latency_ms, Some(600));
        assert_eq!(team, None);
    }

    #[test]
    fn audit_omits_none_fields_from_json() {
        // Mirrors the back-compat path: an event constructed without op
        // metadata should serialize like the pre-1418 shape so legacy
        // consumers don't see unexpected null fields.
        let payload = ViolationPayload::Audit {
            source: "sdk".into(),
            received_at_ms: 1_700_000_000_000,
            sequence_number: 1,
            op_type: None,
            resource: None,
            status: None,
            latency_ms: None,
            team: None,
            call_stack: None,
        };
        let json = serde_json::to_value(&payload).unwrap();
        let obj = json.as_object().unwrap();
        assert!(!obj.contains_key("op_type"));
        assert!(!obj.contains_key("resource"));
        assert!(!obj.contains_key("status"));
        assert!(!obj.contains_key("latency_ms"));
        assert!(!obj.contains_key("team"));
        assert!(!obj.contains_key("call_stack"));
    }

    #[test]
    fn audit_serializes_call_stack_as_snake_case_array() {
        let payload = ViolationPayload::Audit {
            source: "sdk".into(),
            received_at_ms: 1_700_000_000_000,
            sequence_number: 7,
            op_type: Some("tool_call".into()),
            resource: Some("gmail.send".into()),
            status: Some("running".into()),
            latency_ms: Some(500),
            team: None,
            call_stack: Some(vec![CallStackNode {
                id: "n0".into(),
                kind: "llm".into(),
                label: "gpt-4o".into(),
                latency_ms: Some(300),
                children: Some(vec![CallStackNode {
                    id: "n1".into(),
                    kind: "tool".into(),
                    label: "gmail.send".into(),
                    latency_ms: Some(120),
                    children: None,
                }]),
            }]),
        };
        let json = serde_json::to_value(&payload).unwrap();
        let stack = json["call_stack"].as_array().expect("call_stack array");
        assert_eq!(stack.len(), 1);
        assert_eq!(stack[0]["id"], "n0");
        assert_eq!(stack[0]["kind"], "llm");
        assert_eq!(stack[0]["latency_ms"], 300);
        let children = stack[0]["children"].as_array().expect("children array");
        assert_eq!(children[0]["label"], "gmail.send");
        // No `latencyMs` camelCase leak — the dashboard mapEvent layer
        // does that translation on the consumer side.
        assert!(stack[0].as_object().unwrap().contains_key("latency_ms"));
    }

    #[test]
    fn audit_call_stack_omits_optional_fields_when_none() {
        let node = CallStackNode {
            id: "n0".into(),
            kind: "result".into(),
            label: "done".into(),
            latency_ms: None,
            children: None,
        };
        let json = serde_json::to_value(&node).unwrap();
        let obj = json.as_object().unwrap();
        assert!(!obj.contains_key("latency_ms"));
        assert!(!obj.contains_key("children"));
    }

    #[test]
    fn audit_decodes_legacy_json_without_op_fields() {
        // Pre-1418 payload shape — no op fields. Must still decode cleanly.
        let legacy = serde_json::json!({
            "kind": "audit",
            "source": "sdk",
            "received_at_ms": 1700000000000_i64,
            "sequence_number": 1
        });
        let decoded: ViolationPayload = serde_json::from_value(legacy).unwrap();
        let ViolationPayload::Audit { op_type, .. } = decoded else {
            panic!("expected Audit variant");
        };
        assert_eq!(op_type, None);
    }
}

/// Discriminated union of all possible `GovernanceEvent.payload` shapes.
///
/// The concrete variant is determined by the sibling `event_type` field:
/// - `"violation"` → [`ViolationPayload`]
/// - `"approval"` → [`ApprovalPayload`]
/// - `"budget"` → [`BudgetAlertPayload`]
/// - `"ops_change"` → [`OpsChangePayload`]
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(untagged)]
pub enum EventPayload {
    /// Pipeline / violation event payload.
    Violation(ViolationPayload),
    /// Approval request event payload.
    Approval(ApprovalPayload),
    /// Budget threshold alert payload.
    Budget(BudgetAlertPayload),
    /// In-flight ops registry state-transition payload (AAASM-1422 PR-B).
    OpsChange(OpsChangePayload),
}
