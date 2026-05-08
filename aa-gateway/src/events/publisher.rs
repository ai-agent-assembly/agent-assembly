//! Converts runtime events into JSON-serializable webhook payloads.
//!
//! Proto-generated types lack `serde::Serialize`, so this module manually
//! constructs a [`serde_json::Value`] representation of each
//! [`EnvelopedEvent`](aa_proto::assembly::event::v1::EnvelopedEvent) payload.

use aa_runtime::approval::ApprovalRequest;
use serde_json::{json, Value};
use uuid::Uuid;

use crate::budget::BudgetAlert;

/// Event type routing keys used in the envelope's `event_type` field.
pub const EVENT_TYPE_APPROVAL_REQUESTED: &str = "approval.requested";
pub const EVENT_TYPE_BUDGET_THRESHOLD: &str = "budget.threshold_hit";

/// Convert a runtime [`ApprovalRequest`] into a JSON envelope for webhook delivery.
pub fn approval_to_envelope(request: &ApprovalRequest) -> Value {
    let event_id = Uuid::now_v7().to_string();
    let now_ms = chrono::Utc::now().timestamp_millis();

    json!({
        "event_id": event_id,
        "event_type": EVENT_TYPE_APPROVAL_REQUESTED,
        "published_at": { "unix_ms": now_ms },
        "source": "aa-gateway",
        "payload": {
            "approval_request": {
                "approval_id": request.request_id.to_string(),
                "agent_id": request.agent_id,
                "action_summary": request.action,
                "condition_triggered": request.condition_triggered,
                "submitted_at": request.submitted_at,
                "timeout_secs": request.timeout_secs,
            }
        }
    })
}

/// Convert a [`BudgetAlert`] into a JSON envelope for webhook delivery.
pub fn budget_alert_to_envelope(alert: &BudgetAlert) -> Value {
    let event_id = Uuid::now_v7().to_string();
    let now_ms = chrono::Utc::now().timestamp_millis();
    let agent_bytes = alert.agent_id.as_bytes();
    let agent_uuid = Uuid::from_bytes(*agent_bytes);

    json!({
        "event_id": event_id,
        "event_type": EVENT_TYPE_BUDGET_THRESHOLD,
        "published_at": { "unix_ms": now_ms },
        "source": "aa-gateway",
        "payload": {
            "budget_alert": {
                "agent_id": agent_uuid.to_string(),
                "current_spend": alert.spent_usd,
                "budget_limit": alert.limit_usd,
                "percent_used": alert.threshold_pct,
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use aa_core::AgentId;

    fn sample_approval_request() -> ApprovalRequest {
        ApprovalRequest {
            request_id: uuid::Uuid::new_v4(),
            agent_id: "agent-1".to_string(),
            action: "delete production database".to_string(),
            condition_triggered: "destructive-action".to_string(),
            submitted_at: 1_700_000_000,
            timeout_secs: 60,
            fallback: aa_core::PolicyResult::Deny {
                reason: "timed out".to_string(),
            },
            team_id: None,
        }
    }

    #[test]
    fn approval_envelope_has_correct_event_type() {
        let request = sample_approval_request();
        let envelope = approval_to_envelope(&request);

        assert_eq!(envelope["event_type"], "approval.requested");
        assert_eq!(envelope["source"], "aa-gateway");
        assert_eq!(envelope["payload"]["approval_request"]["agent_id"], "agent-1");
        assert_eq!(
            envelope["payload"]["approval_request"]["action_summary"],
            "delete production database"
        );
        assert_eq!(
            envelope["payload"]["approval_request"]["condition_triggered"],
            "destructive-action"
        );
    }

    #[test]
    fn approval_envelope_has_uuid_v7_event_id() {
        let request = sample_approval_request();
        let envelope = approval_to_envelope(&request);

        let id_str = envelope["event_id"].as_str().unwrap();
        let parsed = Uuid::parse_str(id_str).expect("valid UUID");
        assert_eq!(parsed.get_version_num(), 7);
    }

    #[test]
    fn approval_envelope_contains_approval_id() {
        let request = sample_approval_request();
        let expected_id = request.request_id.to_string();
        let envelope = approval_to_envelope(&request);

        assert_eq!(envelope["payload"]["approval_request"]["approval_id"], expected_id);
    }

    #[test]
    fn budget_alert_envelope_has_correct_fields() {
        let alert = BudgetAlert {
            agent_id: AgentId::from_bytes([1; 16]),
            team_id: None,
            threshold_pct: 80,
            spent_usd: 80.0,
            limit_usd: 100.0,
        };

        let envelope = budget_alert_to_envelope(&alert);
        assert_eq!(envelope["event_type"], "budget.threshold_hit");
        assert_eq!(envelope["source"], "aa-gateway");
        assert_eq!(envelope["payload"]["budget_alert"]["current_spend"], 80.0);
        assert_eq!(envelope["payload"]["budget_alert"]["budget_limit"], 100.0);
        assert_eq!(envelope["payload"]["budget_alert"]["percent_used"], 80);
    }

    #[test]
    fn budget_alert_envelope_has_uuid_v7_event_id() {
        let alert = BudgetAlert {
            agent_id: AgentId::from_bytes([2; 16]),
            team_id: None,
            threshold_pct: 95,
            spent_usd: 95.0,
            limit_usd: 100.0,
        };

        let envelope = budget_alert_to_envelope(&alert);
        let id_str = envelope["event_id"].as_str().unwrap();
        let parsed = Uuid::parse_str(id_str).expect("valid UUID");
        assert_eq!(parsed.get_version_num(), 7);
    }
}
