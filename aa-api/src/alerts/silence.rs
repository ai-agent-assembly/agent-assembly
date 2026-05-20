//! Silence record domain type for the `POST /api/v1/alerts/silence` endpoint.
//!
//! `SilenceRecord` is the in-memory representation kept by `SilenceStore`
//! and returned in the 201 response body. The slimmer
//! [`super::detail::Silence`] embedded view (id + expires_at + reason)
//! is projected from this record when an alert detail payload includes
//! its active silence.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::detail;

/// Full silence record kept in `SilenceStore` and returned by
/// `POST /api/v1/alerts/silence`.
///
/// The struct is exposed via `utoipa::ToSchema` so the OpenAPI spec can
/// reference it as the 201 response body for the silence endpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct SilenceRecord {
    /// ULID identifier of the silence record itself (26 chars).
    pub id: String,
    /// ULID of the alert this silence is attached to.
    pub alert_id: String,
    /// ISO 8601 timestamp at which the silence took effect (typically
    /// when the operator submitted the request).
    pub starts_at: String,
    /// ISO 8601 timestamp at which the silence expires. After this,
    /// the alert is restored to its prior status by the expiry watcher.
    pub expires_at: String,
    /// Optional free-text reason captured at silence creation time
    /// (max 500 chars enforced by the route handler).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub reason: Option<String>,
    /// Stable identifier of the principal that created the silence —
    /// resolved from the API key / JWT auth context by the handler.
    pub created_by: String,
}

impl From<&SilenceRecord> for detail::Silence {
    /// Project a full silence record into the slim embedded view used by
    /// `RuleContext.silence` in `GET /api/v1/alerts/{id}`.
    fn from(record: &SilenceRecord) -> Self {
        detail::Silence {
            id: record.id.clone(),
            expires_at: record.expires_at.clone(),
            reason: record.reason.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_record() -> SilenceRecord {
        SilenceRecord {
            id: "01KS1HQA40000000000000ABCD".to_string(),
            alert_id: "01KS1HQA00000000000000ZZZZ".to_string(),
            starts_at: "2026-05-20T09:30:00Z".to_string(),
            expires_at: "2026-05-20T10:30:00Z".to_string(),
            reason: Some("Known maintenance window".to_string()),
            created_by: "user_abc123".to_string(),
        }
    }

    #[test]
    fn serializes_all_fields_when_reason_present() {
        let json = serde_json::to_string(&sample_record()).unwrap();
        assert!(json.contains("\"id\":\"01KS1HQA40000000000000ABCD\""));
        assert!(json.contains("\"alert_id\":\"01KS1HQA00000000000000ZZZZ\""));
        assert!(json.contains("\"starts_at\":\"2026-05-20T09:30:00Z\""));
        assert!(json.contains("\"expires_at\":\"2026-05-20T10:30:00Z\""));
        assert!(json.contains("\"reason\":\"Known maintenance window\""));
        assert!(json.contains("\"created_by\":\"user_abc123\""));
    }

    #[test]
    fn omits_reason_when_none() {
        let record = SilenceRecord {
            reason: None,
            ..sample_record()
        };
        let json = serde_json::to_string(&record).unwrap();
        assert!(!json.contains("\"reason\""), "reason must be omitted when None");
    }

    #[test]
    fn round_trips_through_serde() {
        let record = sample_record();
        let json = serde_json::to_string(&record).unwrap();
        let parsed: SilenceRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, record);
    }

    #[test]
    fn projects_to_detail_silence_view() {
        let record = sample_record();
        let view: detail::Silence = (&record).into();
        assert_eq!(view.id, record.id);
        assert_eq!(view.expires_at, record.expires_at);
        assert_eq!(view.reason, record.reason);
    }
}
