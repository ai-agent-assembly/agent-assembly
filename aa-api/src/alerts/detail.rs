//! Rich detail types backing the `GET /api/v1/alerts/{id}` response.
//!
//! These types describe the rule-based alert payload from the AAASM-1385
//! spec — rule snapshot at fire time, routing-log entries written by the
//! connector framework, and active silence records.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// One delivery attempt by the connector framework for a routed alert.
///
/// Each entry records the outcome of fanning an alert out to a configured
/// destination — Slack, PagerDuty, webhook, etc. The framework appends a
/// new entry per attempt; dedup-suppressed re-fires must NOT add entries.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, ToSchema)]
pub struct RoutingLogEntry {
    /// Identifier of the destination the alert was routed to.
    pub destination_id: String,
    /// ISO 8601 timestamp at which the connector framework completed
    /// the delivery attempt.
    pub delivered_at: String,
    /// Outcome label — typically `"ok"`, `"error"`, or a connector-
    /// specific status string.
    pub status: String,
}

/// Active silence record attached to an alert.
///
/// Present when an operator has acknowledged the alert and asked the
/// notification framework to suppress further routing until `expires_at`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, ToSchema)]
pub struct Silence {
    /// Stable identifier of the silence record.
    pub id: String,
    /// ISO 8601 timestamp at which the silence expires.
    pub expires_at: String,
    /// Optional free-text reason captured at silence creation time.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub reason: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn routing_log_entry_round_trips() {
        let entry = RoutingLogEntry {
            destination_id: "slack-ops".to_string(),
            delivered_at: "2026-05-13T09:12:01Z".to_string(),
            status: "ok".to_string(),
        };
        let json = serde_json::to_string(&entry).unwrap();
        let parsed: RoutingLogEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, entry);
    }

    #[test]
    fn silence_round_trips_with_reason() {
        let silence = Silence {
            id: "sil-001".to_string(),
            expires_at: "2026-05-20T10:00:00Z".to_string(),
            reason: Some("planned maintenance".to_string()),
        };
        let json = serde_json::to_string(&silence).unwrap();
        let parsed: Silence = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, silence);
    }

    #[test]
    fn silence_omits_reason_when_none() {
        let silence = Silence {
            id: "sil-002".to_string(),
            expires_at: "2026-05-20T10:00:00Z".to_string(),
            reason: None,
        };
        let json = serde_json::to_string(&silence).unwrap();
        assert!(!json.contains("reason"), "reason field must be omitted when None");
        let parsed: Silence = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.reason, None);
    }
}
