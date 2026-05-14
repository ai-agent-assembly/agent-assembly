//! OpenAPI schemas for WebSocket event payloads.
//!
//! These types document the JSON structure of `GovernanceEvent.payload`
//! for each [`EventType`] variant.  They mirror the internal runtime
//! and gateway types (`PipelineEvent`, `ApprovalRequest`, `BudgetAlert`)
//! without pulling `utoipa` into those crates.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

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
/// Represents a human-in-the-loop approval request submitted by the
/// policy engine when an action requires explicit authorisation.
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
        };
        let json = serde_json::to_value(&payload).unwrap();
        let obj = json.as_object().unwrap();
        assert!(!obj.contains_key("op_type"));
        assert!(!obj.contains_key("resource"));
        assert!(!obj.contains_key("status"));
        assert!(!obj.contains_key("latency_ms"));
        assert!(!obj.contains_key("team"));
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
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(untagged)]
pub enum EventPayload {
    /// Pipeline / violation event payload.
    Violation(ViolationPayload),
    /// Approval request event payload.
    Approval(ApprovalPayload),
    /// Budget threshold alert payload.
    Budget(BudgetAlertPayload),
}
