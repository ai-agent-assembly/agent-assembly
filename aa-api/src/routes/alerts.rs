//! Governance alert endpoints.

use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::{Extension, Json};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use ulid::Ulid;
use utoipa::ToSchema;

use crate::alerts::detail::{RoutingLogEntry, RuleSnapshot, Silence};
use crate::alerts::silence::SilenceRecord;
use crate::alerts::StoredAlert;
use crate::auth::AuthenticatedCaller;
use crate::error::ProblemDetail;
use crate::pagination::{PaginatedResponse, PaginationParams};
use crate::state::AppState;

/// Convert a `StoredAlert` into the public-facing `AlertResponse` shape.
///
/// Public so the alerts WebSocket handler (AAASM-1389) can emit the
/// same payload shape inside `AlertWsFrame::Fire`/`Resolve`/`Silence`.
pub fn alert_response_from_stored(a: StoredAlert) -> AlertResponse {
    AlertResponse {
        id: a.id,
        severity: a.severity.to_string(),
        category: a.category.to_string(),
        message: a.message,
        timestamp: a.timestamp,
        agent_id: Some(a.agent_id),
        team_id: a.team_id,
        status: a.status,
        updated_at: a.updated_at,
        detected_pattern_type: a.detected_pattern_type,
        redacted_value: a.redacted_value,
    }
}

/// Rich alert detail response used by `GET /api/v1/alerts/:id`.
///
/// Carries the rule-engine context defined in AAASM-1385 (rule snapshot,
/// routing log, silence, dedup state) alongside the legacy budget/secret
/// alert fields for backward compatibility. Rule-engine fields serialize
/// as `null` / empty when the underlying `StoredAlert` lacks a
/// `rule_context` (i.e. it was a budget or secret-detection alert).
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct AlertDetailResponse {
    /// Unique alert identifier.
    pub id: String,
    /// Identifier of the rule that produced the alert, or `null` for
    /// legacy budget/secret alerts.
    pub rule_id: Option<String>,
    /// Human-readable rule name, or `null` for legacy alerts.
    pub rule_name: Option<String>,
    /// Rule snapshot at fire time. `null` for legacy alerts.
    pub rule_snapshot: Option<RuleSnapshot>,
    /// Alert severity level (`info` / `warning` / `critical`).
    pub severity: String,
    /// Lifecycle status — `"unresolved"` on capture, flipped to
    /// `"resolved"` once `POST /alerts/:id/resolve` has fired.
    pub status: String,
    /// Agent ID that triggered the alert. `null` for org-scope alerts.
    pub agent_id: Option<String>,
    /// Team attribution. `null` when not scoped to a team.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub team_id: Option<String>,
    /// ISO 8601 timestamp of the first fire.
    pub first_fired_at: String,
    /// ISO 8601 timestamp at which the alert was resolved, or `null`
    /// while firing.
    pub resolved_at: Option<String>,
    /// Destinations the rule routes to. Empty for legacy alerts.
    pub destination_ids: Vec<String>,
    /// Free-form payload of the triggering event. `null` for legacy
    /// alerts.
    pub event_payload: serde_json::Value,
    /// Connector-framework delivery log. Empty for legacy alerts.
    pub routing_log: Vec<RoutingLogEntry>,
    /// Active silence record, or `null`.
    pub silence: Option<Silence>,
    /// Number of times this alert has matched within the active dedup
    /// window. Always `1` for legacy alerts.
    pub dedup_occurrence_count: u32,
    /// Timestamp when the active dedup window ends, or `null`.
    pub dedup_window_expires_at: Option<String>,
    // ------------------------------------------------------------
    // Backward-compatibility passthrough fields from AlertResponse.
    // ------------------------------------------------------------
    /// Alert category — `"budget"`, `"secret_detected"`, or `"rule"`.
    pub category: String,
    /// Human-readable alert message.
    pub message: String,
    /// ISO 8601 timestamp when the alert was captured (mirrors
    /// `first_fired_at` for legacy alerts).
    pub timestamp: String,
    /// ISO 8601 timestamp of the last mutation. `null` pre-resolve.
    pub updated_at: Option<String>,
    /// Primary detected credential kind for `secret_detected` alerts.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detected_pattern_type: Option<String>,
    /// `[REDACTED:<Kind>]` label for `secret_detected` alerts.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redacted_value: Option<String>,
}

/// Convert a `StoredAlert` into the rich `AlertDetailResponse`.
fn alert_detail_from_stored(a: StoredAlert) -> AlertDetailResponse {
    let (
        rule_id,
        rule_name,
        rule_snapshot,
        destination_ids,
        event_payload,
        routing_log,
        silence,
        dedup_count,
        dedup_expires,
    ) = match a.rule_context {
        Some(ctx) => (
            Some(ctx.rule_id),
            Some(ctx.rule_name),
            Some(ctx.rule_snapshot),
            ctx.destination_ids,
            ctx.event_payload,
            ctx.routing_log,
            ctx.silence,
            ctx.dedup_occurrence_count,
            ctx.dedup_window_expires_at,
        ),
        None => (
            None,
            None,
            None,
            Vec::new(),
            serde_json::Value::Null,
            Vec::new(),
            None,
            1,
            None,
        ),
    };

    AlertDetailResponse {
        id: a.id.to_string(),
        rule_id,
        rule_name,
        rule_snapshot,
        severity: a.severity.to_string(),
        status: a.status,
        agent_id: if a.agent_id.is_empty() { None } else { Some(a.agent_id) },
        team_id: a.team_id,
        first_fired_at: a.first_fired_at,
        resolved_at: a.resolved_at,
        destination_ids,
        event_payload,
        routing_log,
        silence,
        dedup_occurrence_count: dedup_count,
        dedup_window_expires_at: dedup_expires,
        category: a.category.to_string(),
        message: a.message,
        timestamp: a.timestamp,
        updated_at: a.updated_at,
        detected_pattern_type: a.detected_pattern_type,
        redacted_value: a.redacted_value,
    }
}

/// Request body for `POST /api/v1/alerts/:id/resolve`.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct ResolveAlertRequest {
    /// Optional human-readable note recorded with the resolution. The
    /// in-memory store does not persist this today but the field is
    /// accepted so CLI / dashboard clients can submit a reason.
    #[serde(default)]
    pub reason: Option<String>,
}

/// Request body for `POST /api/v1/alerts/silence` (AAASM-1387 / AAASM-1648).
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct SilenceAlertRequest {
    /// ULID of the alert to silence.
    pub alert_id: String,
    /// Duration of the silence window in seconds. Must be > 0 and
    /// ≤ 604_800 (7 days). Validation lives in the handler and returns
    /// HTTP 400 `invalid_duration` on violation.
    pub duration_seconds: u32,
    /// Optional free-text note recorded on the silence (max 500 chars).
    /// Returns HTTP 400 `reason_too_long` when oversize.
    #[serde(default)]
    pub reason: Option<String>,
}

/// Maximum allowed silence duration — 7 days, per AAASM-1387 spec.
const MAX_SILENCE_DURATION_SECS: u32 = 604_800;
/// Maximum allowed length of the optional silence `reason` field.
const MAX_SILENCE_REASON_LEN: usize = 500;

/// Response body for `POST /api/v1/alerts/silence` (AAASM-1387). Wire
/// shape matches the spec: silence identifier is exposed as `silence_id`
/// (the in-memory [`SilenceRecord`] uses `id` internally; the conversion
/// renames on the way out).
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct SilenceResponse {
    /// ULID identifier of the silence record.
    pub silence_id: String,
    /// ULID of the suppressed alert.
    pub alert_id: String,
    /// ISO 8601 timestamp at which the silence took effect.
    pub starts_at: String,
    /// ISO 8601 timestamp at which the silence expires; the
    /// `silence_watcher` (AAASM-1646) restores the alert at or shortly
    /// after this instant.
    pub expires_at: String,
    /// Free-text reason captured at silence creation time. Omitted in
    /// the response when no reason was supplied.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Stable identifier of the principal that created the silence
    /// (API-key id or JWT subject, per `AuthenticatedCaller.key_id`).
    pub created_by: String,
}

impl From<SilenceRecord> for SilenceResponse {
    fn from(record: SilenceRecord) -> Self {
        SilenceResponse {
            silence_id: record.id,
            alert_id: record.alert_id,
            starts_at: record.starts_at,
            expires_at: record.expires_at,
            reason: record.reason,
            created_by: record.created_by,
        }
    }
}

/// Validate a [`SilenceAlertRequest`] against the AAASM-1387 spec.
///
/// Returns the appropriate RFC 7807 `ProblemDetail` on the first failure:
/// * `400 invalid_duration` when `duration_seconds` is 0 or exceeds the
///   7-day cap.
/// * `400 reason_too_long` when `reason.len() > 500`.
///
/// The `detail` field encodes the structured error code as a prefix
/// (e.g. `"invalid_duration: ..."`). When AAASM-1618 lands its
/// `error_code` field on `ProblemDetail`, this helper should be updated
/// to populate it directly.
fn validate_silence_request(req: &SilenceAlertRequest) -> Result<(), ProblemDetail> {
    if req.duration_seconds == 0 || req.duration_seconds > MAX_SILENCE_DURATION_SECS {
        return Err(ProblemDetail::from_status(StatusCode::BAD_REQUEST).with_detail(format!(
            "invalid_duration: duration_seconds must be greater than 0 and at most {MAX_SILENCE_DURATION_SECS}"
        )));
    }
    if let Some(reason) = req.reason.as_ref() {
        if reason.len() > MAX_SILENCE_REASON_LEN {
            return Err(ProblemDetail::from_status(StatusCode::BAD_REQUEST).with_detail(format!(
                "reason_too_long: reason exceeds {MAX_SILENCE_REASON_LEN} character limit"
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod silence_validation_tests {
    use super::*;

    fn request(duration: u32, reason: Option<&str>) -> SilenceAlertRequest {
        SilenceAlertRequest {
            alert_id: "01HX0000000000000000000000".to_string(),
            duration_seconds: duration,
            reason: reason.map(String::from),
        }
    }

    #[test]
    fn happy_path_passes() {
        assert!(validate_silence_request(&request(3600, Some("ack"))).is_ok());
        assert!(
            validate_silence_request(&request(1, None)).is_ok(),
            "1s minimum is allowed"
        );
        assert!(
            validate_silence_request(&request(MAX_SILENCE_DURATION_SECS, None)).is_ok(),
            "exact 7d boundary is allowed"
        );
    }

    #[test]
    fn zero_duration_is_invalid_duration() {
        let err = validate_silence_request(&request(0, None)).unwrap_err();
        assert_eq!(err.status, 400);
        assert!(
            err.detail.as_deref().unwrap_or("").starts_with("invalid_duration:"),
            "detail must carry the invalid_duration code: {:?}",
            err.detail
        );
    }

    #[test]
    fn over_seven_days_is_invalid_duration() {
        let err = validate_silence_request(&request(MAX_SILENCE_DURATION_SECS + 1, None)).unwrap_err();
        assert_eq!(err.status, 400);
        assert!(err.detail.as_deref().unwrap_or("").starts_with("invalid_duration:"));
    }

    #[test]
    fn reason_over_500_chars_is_reason_too_long() {
        let long = "x".repeat(MAX_SILENCE_REASON_LEN + 1);
        let err = validate_silence_request(&request(3600, Some(&long))).unwrap_err();
        assert_eq!(err.status, 400);
        assert!(
            err.detail.as_deref().unwrap_or("").starts_with("reason_too_long:"),
            "detail must carry the reason_too_long code: {:?}",
            err.detail
        );
    }

    #[test]
    fn reason_exactly_500_chars_is_allowed() {
        let exact = "y".repeat(MAX_SILENCE_REASON_LEN);
        assert!(validate_silence_request(&request(3600, Some(&exact))).is_ok());
    }

    #[test]
    fn duration_check_runs_before_reason_check() {
        // Both invalid; spec says duration is checked first.
        let long = "z".repeat(MAX_SILENCE_REASON_LEN + 1);
        let err = validate_silence_request(&request(0, Some(&long))).unwrap_err();
        assert!(err.detail.as_deref().unwrap_or("").starts_with("invalid_duration:"));
    }
}

/// JSON representation of a governance alert.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct AlertResponse {
    /// Unique alert identifier.
    pub id: String,
    /// Alert severity level (e.g. "warning", "critical").
    pub severity: String,
    /// Alert category (e.g. "budget", "secret_detected").
    pub category: String,
    /// Human-readable alert message.
    pub message: String,
    /// ISO 8601 timestamp when the alert was raised.
    pub timestamp: String,
    /// Agent ID that triggered the alert (if applicable).
    pub agent_id: Option<String>,
    /// Team attribution propagated from the originating request
    /// context. Omitted when no team was associated.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub team_id: Option<String>,
    /// Lifecycle status — `"unresolved"` on capture, `"resolved"` once
    /// the alert has been acknowledged via `POST /alerts/:id/resolve`.
    pub status: String,
    /// ISO 8601 timestamp of the last mutation (e.g. resolve). `None`
    /// while the alert is still in its initial captured state.
    pub updated_at: Option<String>,
    /// Primary detected credential kind for `secret_detected` alerts
    /// (e.g. `"AwsAccessKey"`). Omitted for budget alerts.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detected_pattern_type: Option<String>,
    /// `[REDACTED:<Kind>]` label for `secret_detected` alerts — never
    /// contains the raw secret. Omitted for budget alerts.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redacted_value: Option<String>,
}

/// `GET /api/v1/alerts` — list recent governance alerts.
///
/// List recent governance alerts such as budget warnings and policy violations.
#[utoipa::path(
    get,
    path = "/api/v1/alerts",
    params(PaginationParams),
    responses(
        (status = 200, description = "Paginated list of recent alerts", body = Vec<AlertResponse>)
    ),
    tag = "alerts"
)]
pub async fn list_alerts(
    Extension(state): Extension<AppState>,
    axum::extract::Query(params): axum::extract::Query<PaginationParams>,
) -> impl IntoResponse {
    let limit = params.per_page() as usize;
    let offset = params.offset();

    let (stored, total) = state.alert_store.list(limit, offset);

    let items: Vec<AlertResponse> = stored.into_iter().map(alert_response_from_stored).collect();

    (
        StatusCode::OK,
        Json(PaginatedResponse {
            items,
            page: params.page(),
            per_page: params.per_page(),
            total,
        }),
    )
}

/// `GET /api/v1/alerts/:id` — fetch one governance alert by ID.
///
/// Returns the rich [`AlertDetailResponse`] shape — rule snapshot,
/// routing log, silence, dedup state, plus the legacy budget/secret
/// alert fields. Returns 404 with an RFC 7807 problem detail if the
/// alert is unknown or has been evicted from the in-memory ring buffer.
#[utoipa::path(
    get,
    path = "/api/v1/alerts/{id}",
    params(("id" = String, Path, description = "ULID alert identifier (26 chars)")),
    responses(
        (status = 200, description = "Alert detail", body = AlertDetailResponse),
        (status = 404, description = "Alert not found")
    ),
    tag = "alerts"
)]
pub async fn get_alert(
    Extension(state): Extension<AppState>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<(StatusCode, Json<AlertDetailResponse>), ProblemDetail> {
    let stored = state.alert_store.get_by_id(&id).ok_or_else(|| {
        ProblemDetail::from_status(StatusCode::NOT_FOUND).with_detail(format!("Alert not found: {id}"))
    })?;

    Ok((StatusCode::OK, Json(alert_detail_from_stored(stored))))
}

/// `POST /api/v1/alerts/:id/resolve` — mark a governance alert as resolved.
///
/// Idempotent — calling against an already-resolved alert returns the same
/// record with `updated_at` unchanged. Returns 404 if the id is unknown or
/// has been evicted from the ring buffer.
#[utoipa::path(
    post,
    path = "/api/v1/alerts/{id}/resolve",
    params(("id" = String, Path, description = "ULID alert identifier (26 chars)")),
    request_body(content = ResolveAlertRequest, description = "Optional resolution metadata"),
    responses(
        (status = 200, description = "Alert resolved", body = AlertResponse),
        (status = 404, description = "Alert not found")
    ),
    tag = "alerts"
)]
pub async fn resolve_alert(
    Extension(state): Extension<AppState>,
    axum::extract::Path(id): axum::extract::Path<String>,
    body: Option<Json<ResolveAlertRequest>>,
) -> Result<(StatusCode, Json<AlertResponse>), ProblemDetail> {
    let reason = body.and_then(|Json(req)| req.reason);

    let stored = state.alert_store.resolve(&id, reason.as_deref()).ok_or_else(|| {
        ProblemDetail::from_status(StatusCode::NOT_FOUND).with_detail(format!("Alert not found: {id}"))
    })?;

    Ok((StatusCode::OK, Json(alert_response_from_stored(stored))))
}

/// `POST /api/v1/alerts/silence` — silence an active alert for a
/// configurable duration (AAASM-1387 / AAASM-1648).
///
/// Validates the body, flips the target alert's status to
/// `"suppressed"` via [`AlertStore::suppress`](crate::alerts::AlertStore::suppress),
/// and records a [`SilenceRecord`] in the [`SilenceStore`](crate::alerts::silence_store::SilenceStore).
/// The silence-expiry watcher (AAASM-1646) restores the alert when
/// `expires_at` is reached.
///
/// `created_by` is resolved from the authenticated caller
/// (`AuthenticatedCaller.key_id`); under `AuthMode::Off` this is the
/// bypass principal `"__bypass__"`.
///
/// ## Errors
///
/// | Status | Code | Trigger |
/// |---|---|---|
/// | 400 | `invalid_duration` | `duration_seconds == 0` or `> 604_800` |
/// | 400 | `reason_too_long` | `reason.len() > 500` |
/// | 404 | `alert_not_found` | `alert_id` is not in `AlertStore` |
/// | 409 | `alert_already_silenced` | an active silence exists for `alert_id` |
#[utoipa::path(
    post,
    path = "/api/v1/alerts/silence",
    request_body(content = SilenceAlertRequest, description = "Silence parameters"),
    responses(
        (status = 201, description = "Silence applied", body = SilenceResponse),
        (status = 400, description = "Invalid request (`invalid_duration` or `reason_too_long`)", body = ProblemDetail),
        (status = 404, description = "Alert not found", body = ProblemDetail),
        (status = 409, description = "Alert already silenced", body = ProblemDetail),
    ),
    security(("bearer_auth" = [])),
    tag = "alerts"
)]
pub async fn silence_alert(
    caller: AuthenticatedCaller,
    Extension(state): Extension<AppState>,
    Json(req): Json<SilenceAlertRequest>,
) -> Result<(StatusCode, Json<SilenceResponse>), ProblemDetail> {
    validate_silence_request(&req)?;

    if state.alert_store.get_by_id(&req.alert_id).is_none() {
        return Err(
            ProblemDetail::from_status(StatusCode::NOT_FOUND).with_detail(format!("alert_not_found: {}", req.alert_id))
        );
    }

    let now = Utc::now();
    if state.silence_store.get_active_for_alert(&req.alert_id, now).is_some() {
        return Err(ProblemDetail::from_status(StatusCode::CONFLICT)
            .with_detail(format!("alert_already_silenced: {}", req.alert_id)));
    }

    let record = SilenceRecord {
        id: Ulid::new().to_string(),
        alert_id: req.alert_id.clone(),
        starts_at: now.to_rfc3339(),
        expires_at: (now + chrono::Duration::seconds(i64::from(req.duration_seconds))).to_rfc3339(),
        reason: req.reason,
        created_by: caller.key_id,
    };
    state.silence_store.insert(record.clone());
    // suppress() returns None if the alert was already suppressed, but we
    // checked the SilenceStore above so this should always succeed; tolerate
    // a race by treating it as the same 409 condition.
    if state.alert_store.suppress(&req.alert_id).is_none() {
        return Err(ProblemDetail::from_status(StatusCode::CONFLICT)
            .with_detail(format!("alert_already_silenced: {}", req.alert_id)));
    }

    Ok((StatusCode::CREATED, Json(SilenceResponse::from(record))))
}
