//! Server → Client frame schema for `GET /api/v1/alerts/ws`
//! (AAASM-1389).
//!
//! Each frame is a single JSON object discriminated by the `type`
//! field. The `alert` payload reuses the existing [`AlertResponse`]
//! shape from `GET /api/v1/alerts/{id}` so dashboard code can share
//! the type with the REST list/get endpoints.

use serde::Serialize;
use utoipa::ToSchema;

use crate::routes::alerts::AlertResponse;

/// Lifecycle frame pushed to clients over the alerts WebSocket.
///
/// Server-only — `AlertResponse` does not currently derive
/// `Deserialize`, so this enum is `Serialize`-only. Client-side
/// parsing happens through `serde_json::Value` in tests.
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(tag = "type")]
pub enum AlertWsFrame {
    /// A new alert was just captured into the store.
    #[serde(rename = "alert.fire")]
    Fire {
        /// ISO 8601 timestamp at which the server emitted this frame.
        ts: String,
        /// Full alert payload — same shape as `GET /api/v1/alerts/{id}`.
        alert: AlertResponse,
    },
    /// An existing alert was acknowledged via the resolve endpoint.
    /// `alert.status` is `"resolved"`.
    #[serde(rename = "alert.resolve")]
    Resolve { ts: String, alert: AlertResponse },
    /// An existing alert was suppressed by an active silence. Reserved
    /// for the future suppression feature — no production code emits
    /// this variant today; the schema is published so clients can
    /// already round-trip frames once a producer exists.
    #[serde(rename = "alert.silence")]
    Silence {
        ts: String,
        alert: AlertResponse,
        /// Silence metadata — left as a free-form object so the
        /// concrete `Silence` schema can land in a follow-up without
        /// breaking the WS contract.
        silence: serde_json::Value,
    },
    /// Keep-alive frame emitted every 30 s when no other frame was
    /// sent in that window (AC).
    #[serde(rename = "heartbeat")]
    Heartbeat { ts: String },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_alert() -> AlertResponse {
        AlertResponse {
            id: "1".to_string(),
            severity: "critical".to_string(),
            category: "budget".to_string(),
            message: "test alert".to_string(),
            timestamp: "2026-05-20T00:00:00Z".to_string(),
            agent_id: Some("agent-1".to_string()),
            team_id: None,
            status: "unresolved".to_string(),
            updated_at: None,
            detected_pattern_type: None,
            redacted_value: None,
        }
    }

    #[test]
    fn fire_frame_serialises_with_alert_fire_tag() {
        let frame = AlertWsFrame::Fire {
            ts: "2026-05-13T09:12:00Z".to_string(),
            alert: sample_alert(),
        };
        let json = serde_json::to_value(&frame).unwrap();
        assert_eq!(json["type"], "alert.fire");
        assert_eq!(json["ts"], "2026-05-13T09:12:00Z");
        assert_eq!(json["alert"]["id"], "1");
        assert_eq!(json["alert"]["severity"], "critical");
    }

    #[test]
    fn resolve_frame_serialises_with_alert_resolve_tag() {
        let frame = AlertWsFrame::Resolve {
            ts: "2026-05-13T10:00:00Z".to_string(),
            alert: sample_alert(),
        };
        let json = serde_json::to_value(&frame).unwrap();
        assert_eq!(json["type"], "alert.resolve");
    }

    #[test]
    fn silence_frame_carries_free_form_silence_object() {
        let frame = AlertWsFrame::Silence {
            ts: "2026-05-13T11:00:00Z".to_string(),
            alert: sample_alert(),
            silence: serde_json::json!({"id": "sil-1", "reason": "maintenance"}),
        };
        let json = serde_json::to_value(&frame).unwrap();
        assert_eq!(json["type"], "alert.silence");
        assert_eq!(json["silence"]["id"], "sil-1");
    }

    #[test]
    fn heartbeat_frame_has_only_type_and_ts() {
        let frame = AlertWsFrame::Heartbeat {
            ts: "2026-05-13T09:12:30Z".to_string(),
        };
        let json = serde_json::to_value(&frame).unwrap();
        assert_eq!(json["type"], "heartbeat");
        assert_eq!(json["ts"], "2026-05-13T09:12:30Z");
        assert!(json.get("alert").is_none(), "heartbeat must not carry alert payload");
    }
}
