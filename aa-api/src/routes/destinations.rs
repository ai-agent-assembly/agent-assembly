//! `/api/v1/alerts/destinations` — notification-destination CRUD + test fire (AAASM-1388).
//!
//! This module is the HTTP face for [`crate::destinations`]: it accepts JSON
//! payloads, runs validation, mutates the store, and translates connector
//! outcomes into RFC 7807 problem details on failure.

use axum::body::Bytes;
use axum::extract::{Path, Query};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

use crate::auth::scope::{RequireRead, RequireWrite};
use crate::destinations::connectors::slack::SlackConnector;
use crate::destinations::connectors::webhook::WebhookConnector;
use crate::destinations::connectors::{ConnectorError, DispatchRequest, NotificationConnector};
use crate::destinations::store::StoreError;
use crate::destinations::types::{Destination, DestinationConfig, DestinationKind};
use crate::destinations::validate::{validate_config, validate_webhook_egress, ValidationError};
use crate::error::ProblemDetail;
use crate::state::AppState;

// ── DTOs ────────────────────────────────────────────────────────────────────

/// `?kind=...` filter for `GET /api/v1/alerts/destinations`.
#[derive(Debug, Clone, Deserialize, IntoParams)]
pub struct DestinationListFilter {
    /// Optional kind filter (`webhook`, `slack`, `pagerduty`, `opsgenie`).
    #[serde(default)]
    pub kind: Option<DestinationKind>,
}

/// Public JSON shape returned by every destination handler.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct DestinationResponse {
    /// Stable identifier (`dst_<32 hex>`).
    pub id: String,
    /// Operator-supplied display name.
    pub name: String,
    /// Discriminated per-kind configuration (`kind` + `config`).
    #[serde(flatten)]
    pub config: DestinationConfig,
    /// Whether dispatch is allowed.
    pub enabled: bool,
    /// RFC 3339 creation timestamp.
    pub created_at: String,
    /// RFC 3339 last-mutation timestamp.
    pub updated_at: String,
}

/// Sentinel returned in place of a configured webhook secret. The real value is
/// write-only (accepted on create/update, never returned).
const SECRET_MASK: &str = "********";

impl From<Destination> for DestinationResponse {
    fn from(d: Destination) -> Self {
        // AAASM-3688 / AAASM-3843: never return a connector secret in cleartext.
        // Mask each kind's secret-bearing field to a fixed sentinel so the
        // response still signals that a secret is configured without leaking
        // the value: webhook `secret_header`, Slack `webhook_url` (bearer-grade),
        // PagerDuty `routing_key`, OpsGenie `api_key`.
        let config = match d.config {
            DestinationConfig::Webhook {
                url,
                secret_header: Some(_),
            } => DestinationConfig::Webhook {
                url,
                secret_header: Some(SECRET_MASK.to_string()),
            },
            DestinationConfig::Slack { channel_override, .. } => DestinationConfig::Slack {
                webhook_url: SECRET_MASK.to_string(),
                channel_override,
            },
            DestinationConfig::PagerDuty { severity_map, .. } => DestinationConfig::PagerDuty {
                routing_key: SECRET_MASK.to_string(),
                severity_map,
            },
            DestinationConfig::OpsGenie { team_id, .. } => DestinationConfig::OpsGenie {
                api_key: SECRET_MASK.to_string(),
                team_id,
            },
            other => other,
        };
        Self {
            id: d.id,
            name: d.name,
            config,
            enabled: d.enabled,
            created_at: d.created_at,
            updated_at: d.updated_at,
        }
    }
}

/// Restore masked secrets on an incoming update from the stored config.
///
/// AAASM-3751 / AAASM-3843: every secret-bearing field is returned as
/// [`SECRET_MASK`] on read. A GET → edit → PUT round-trip would otherwise
/// write that literal sentinel back, clobbering the real stored secret. When an
/// incoming secret field equals the mask, replace it with the value already
/// persisted so the round-trip preserves the stored secret. Applied to every
/// connector kind's secret-bearing field, not just the webhook `secret_header`.
fn restore_masked_secrets(incoming: &mut DestinationConfig, stored: Option<DestinationConfig>) {
    match incoming {
        DestinationConfig::Webhook { secret_header, .. } => {
            if secret_header.as_deref() == Some(SECRET_MASK) {
                *secret_header = match stored {
                    Some(DestinationConfig::Webhook { secret_header, .. }) => secret_header,
                    _ => None,
                };
            }
        }
        DestinationConfig::Slack { webhook_url, .. } => {
            if webhook_url == SECRET_MASK {
                if let Some(DestinationConfig::Slack {
                    webhook_url: stored_url,
                    ..
                }) = stored
                {
                    *webhook_url = stored_url;
                }
            }
        }
        DestinationConfig::PagerDuty { routing_key, .. } => {
            if routing_key == SECRET_MASK {
                if let Some(DestinationConfig::PagerDuty {
                    routing_key: stored_key,
                    ..
                }) = stored
                {
                    *routing_key = stored_key;
                }
            }
        }
        DestinationConfig::OpsGenie { api_key, .. } => {
            if api_key == SECRET_MASK {
                if let Some(DestinationConfig::OpsGenie {
                    api_key: stored_key, ..
                }) = stored
                {
                    *api_key = stored_key;
                }
            }
        }
    }
}

/// Body for `POST /api/v1/alerts/destinations`.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct CreateDestinationRequest {
    /// Operator-supplied display name.
    pub name: String,
    /// Discriminated per-kind configuration.
    #[serde(flatten)]
    pub config: DestinationConfig,
    /// Whether dispatch is enabled on creation (defaults to true).
    #[serde(default = "default_enabled")]
    pub enabled: bool,
}

fn default_enabled() -> bool {
    true
}

/// Body for `PUT /api/v1/alerts/destinations/{id}`.
///
/// All fields are optional — supplying just `enabled` toggles dispatch
/// without touching the configuration payload.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct UpdateDestinationRequest {
    /// New display name.
    #[serde(default)]
    pub name: Option<String>,
    /// New discriminated configuration. When supplied it fully replaces
    /// the existing config and is re-validated.
    #[serde(default, flatten)]
    pub config: Option<DestinationConfig>,
    /// New enabled flag.
    #[serde(default)]
    pub enabled: Option<bool>,
}

/// Body for `POST /api/v1/alerts/destinations/{id}/test`.
#[derive(Debug, Clone, Default, Deserialize, ToSchema)]
pub struct TestDestinationRequest {
    /// Optional severity label; defaults to `"LOW"`.
    #[serde(default)]
    pub severity: Option<String>,
    /// Optional message body; defaults to `"AAASM test fire"`.
    #[serde(default)]
    pub message: Option<String>,
}

/// Response body for a successful test-fire.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct TestDestinationResponse {
    /// RFC 3339 timestamp when the connector reported success.
    pub delivered_at: String,
    /// HTTP status the connector observed.
    pub connector_response_status: u16,
    /// Up-to-2048-byte snippet of the connector response body.
    pub connector_response_body: String,
}

/// Response body for a failed test-fire (502).
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ConnectorFailedBody {
    /// Always `"connector_failed"`.
    pub error: String,
    /// HTTP status the connector observed, or `0` if no response was received.
    pub connector_status: u16,
    /// Up-to-2048-byte snippet of the connector response body (or transport
    /// error description if no HTTP response was reached).
    pub connector_body: String,
}

// ── Error helpers ───────────────────────────────────────────────────────────

fn validation_error_to_problem(e: ValidationError) -> ProblemDetail {
    let detail = match e {
        ValidationError::InvalidKind => "invalid_kind",
        ValidationError::InvalidConfig(msg) => msg,
    };
    ProblemDetail::from_status(StatusCode::BAD_REQUEST).with_detail(detail)
}

fn parse_create_body(bytes: &[u8]) -> Result<CreateDestinationRequest, ProblemDetail> {
    serde_json::from_slice::<CreateDestinationRequest>(bytes).map_err(|e| {
        let msg = e.to_string();
        // serde reports unknown discriminator values like `unknown variant
        // `carrier_pigeon`, expected one of …` when the `kind` tag is
        // unrecognised. Map those to invalid_kind so the client gets a
        // stable detail code instead of axum's default 422.
        if msg.contains("unknown variant") {
            validation_error_to_problem(ValidationError::InvalidKind)
        } else {
            ProblemDetail::from_status(StatusCode::BAD_REQUEST).with_detail(msg)
        }
    })
}

fn parse_update_body(bytes: &[u8]) -> Result<UpdateDestinationRequest, ProblemDetail> {
    serde_json::from_slice::<UpdateDestinationRequest>(bytes).map_err(|e| {
        let msg = e.to_string();
        if msg.contains("unknown variant") {
            validation_error_to_problem(ValidationError::InvalidKind)
        } else {
            ProblemDetail::from_status(StatusCode::BAD_REQUEST).with_detail(msg)
        }
    })
}

fn not_found_problem() -> ProblemDetail {
    ProblemDetail::from_status(StatusCode::NOT_FOUND).with_detail("destination_not_found")
}

fn in_use_problem() -> ProblemDetail {
    ProblemDetail::from_status(StatusCode::CONFLICT).with_detail("destination_in_use")
}

/// Pick the connector implementation matching a destination kind.
fn connector_for(kind: DestinationKind) -> Box<dyn NotificationConnector> {
    match kind {
        DestinationKind::Webhook => Box::new(WebhookConnector),
        DestinationKind::Slack => Box::new(SlackConnector),
        DestinationKind::PagerDuty => {
            #[cfg(feature = "connector-pagerduty")]
            {
                Box::new(crate::destinations::connectors::pagerduty::PagerDutyConnector)
            }
            #[cfg(not(feature = "connector-pagerduty"))]
            {
                Box::new(UnsupportedConnector("pagerduty"))
            }
        }
        DestinationKind::OpsGenie => {
            #[cfg(feature = "connector-opsgenie")]
            {
                Box::new(crate::destinations::connectors::opsgenie::OpsGenieConnector)
            }
            #[cfg(not(feature = "connector-opsgenie"))]
            {
                Box::new(UnsupportedConnector("opsgenie"))
            }
        }
    }
}

/// Connector returned for kinds whose real implementation was not compiled
/// into this binary. `dispatch` always fails with a transport error so the
/// HTTP layer surfaces 502 + `connector_failed` instead of panicking.
#[allow(dead_code)] // referenced only on builds without the kind's feature
struct UnsupportedConnector(&'static str);

#[async_trait::async_trait]
impl NotificationConnector for UnsupportedConnector {
    async fn dispatch(
        &self,
        _destination: &Destination,
        _req: &DispatchRequest,
    ) -> Result<crate::destinations::connectors::DispatchOutcome, ConnectorError> {
        Err(ConnectorError::Transport(format!(
            "connector kind '{}' not enabled in this build",
            self.0
        )))
    }
}

/// `test_destination` failure envelope. Variants are translated into the
/// matching HTTP status by `IntoResponse`.
pub enum TestDestinationFailure {
    /// Destination does not exist — surfaced as 404.
    NotFound(ProblemDetail),
    /// Request rejected before dispatch (e.g. the SSRF egress guard refused the
    /// webhook target) — surfaced as the status carried by the `ProblemDetail`
    /// (400). (AAASM-3789.)
    Rejected(ProblemDetail),
    /// Connector failed — surfaced as 502 with `ConnectorFailedBody`.
    Connector(ConnectorFailedBody),
}

impl IntoResponse for TestDestinationFailure {
    fn into_response(self) -> Response {
        match self {
            TestDestinationFailure::NotFound(p) => p.into_response(),
            TestDestinationFailure::Rejected(p) => p.into_response(),
            TestDestinationFailure::Connector(body) => (StatusCode::BAD_GATEWAY, Json(body)).into_response(),
        }
    }
}

// ── Handlers ────────────────────────────────────────────────────────────────

/// `GET /api/v1/alerts/destinations` — list destinations.
///
/// List configured notification destinations. The `kind` query parameter filters
/// to webhook, slack, pagerduty, or opsgenie. Returns the full set when absent.
#[utoipa::path(
    get,
    path = "/api/v1/alerts/destinations",
    params(DestinationListFilter),
    responses(
        (status = 200, description = "List of destinations", body = Vec<DestinationResponse>)
    ),
    tag = "alert-destinations"
)]
pub async fn list_destinations(
    _auth: RequireRead,
    Extension(state): Extension<AppState>,
    Query(filter): Query<DestinationListFilter>,
) -> Json<Vec<DestinationResponse>> {
    let items = state
        .destination_store
        .list(filter.kind)
        .into_iter()
        .map(DestinationResponse::from)
        .collect();
    Json(items)
}

/// `POST /api/v1/alerts/destinations` — create a destination.
///
/// Register a new notification destination. The request `kind` discriminates the
/// `config` shape and is validated server-side; an unknown kind returns 400
/// `invalid_kind` and a malformed config returns 400 `invalid_config`.
#[utoipa::path(
    post,
    path = "/api/v1/alerts/destinations",
    request_body = CreateDestinationRequest,
    responses(
        (status = 201, description = "Destination created", body = DestinationResponse),
        (status = 400, description = "Invalid kind or config")
    ),
    tag = "alert-destinations"
)]
pub async fn create_destination(
    _auth: RequireWrite,
    Extension(state): Extension<AppState>,
    body: Bytes,
) -> Result<(StatusCode, Json<DestinationResponse>), ProblemDetail> {
    let req = parse_create_body(&body)?;
    if req.name.trim().is_empty() {
        return Err(validation_error_to_problem(ValidationError::InvalidConfig(
            "name must be non-empty",
        )));
    }
    validate_config(&req.config).map_err(validation_error_to_problem)?;

    let d = state.destination_store.create(req.name, req.config, req.enabled);
    Ok((StatusCode::CREATED, Json(d.into())))
}

/// `GET /api/v1/alerts/destinations/{id}` — fetch one destination.
///
/// Retrieve a single notification destination by id. Returns 404
/// `destination_not_found` when the id is unknown.
#[utoipa::path(
    get,
    path = "/api/v1/alerts/destinations/{id}",
    params(("id" = String, Path, description = "Destination identifier")),
    responses(
        (status = 200, description = "Destination", body = DestinationResponse),
        (status = 404, description = "Destination not found")
    ),
    tag = "alert-destinations"
)]
pub async fn get_destination(
    _auth: RequireRead,
    Extension(state): Extension<AppState>,
    Path(id): Path<String>,
) -> Result<Json<DestinationResponse>, ProblemDetail> {
    let d = state.destination_store.get(&id).ok_or_else(not_found_problem)?;
    Ok(Json(d.into()))
}

/// `PUT /api/v1/alerts/destinations/{id}` — update a destination.
///
/// Replace name, config, or enabled state on an existing destination. Preserves
/// the original `created_at`, bumps `updated_at`, and re-validates the config —
/// invalid input returns 400.
#[utoipa::path(
    put,
    path = "/api/v1/alerts/destinations/{id}",
    params(("id" = String, Path, description = "Destination identifier")),
    request_body = UpdateDestinationRequest,
    responses(
        (status = 200, description = "Destination updated", body = DestinationResponse),
        (status = 400, description = "Invalid update payload"),
        (status = 404, description = "Destination not found")
    ),
    tag = "alert-destinations"
)]
pub async fn update_destination(
    _auth: RequireWrite,
    Extension(state): Extension<AppState>,
    Path(id): Path<String>,
    body: Bytes,
) -> Result<Json<DestinationResponse>, ProblemDetail> {
    let mut req = parse_update_body(&body)?;
    if let Some(name) = &req.name {
        if name.trim().is_empty() {
            return Err(validation_error_to_problem(ValidationError::InvalidConfig(
                "name must be non-empty",
            )));
        }
    }

    // AAASM-3751 / AAASM-3843: restore any masked secret field from the stored
    // config *before* validation. A masked Slack `webhook_url` (the sentinel)
    // would otherwise fail URL validation, and a masked value of any kind must
    // never overwrite the real stored secret on a GET → edit → PUT round-trip.
    if let Some(cfg) = &mut req.config {
        let stored = state.destination_store.get(&id).map(|d| d.config);
        restore_masked_secrets(cfg, stored);
    }

    if let Some(cfg) = &req.config {
        validate_config(cfg).map_err(validation_error_to_problem)?;
    }

    let updated = state
        .destination_store
        .update(&id, req.name, req.config, req.enabled)
        .map_err(|e| match e {
            StoreError::NotFound => not_found_problem(),
            StoreError::InUse => in_use_problem(),
        })?;
    Ok(Json(updated.into()))
}

/// `DELETE /api/v1/alerts/destinations/{id}` — remove a destination.
///
/// Remove a destination. Returns 409 `destination_in_use` when any active alert
/// rule still references this id — the rule must be removed or re-targeted
/// before the destination can be deleted.
#[utoipa::path(
    delete,
    path = "/api/v1/alerts/destinations/{id}",
    params(("id" = String, Path, description = "Destination identifier")),
    responses(
        (status = 204, description = "Destination removed"),
        (status = 404, description = "Destination not found"),
        (status = 409, description = "Destination still referenced by a routing rule")
    ),
    tag = "alert-destinations"
)]
pub async fn delete_destination(
    _auth: RequireWrite,
    Extension(state): Extension<AppState>,
    Path(id): Path<String>,
) -> Result<StatusCode, ProblemDetail> {
    state.destination_store.delete(&id).map_err(|e| match e {
        StoreError::NotFound => not_found_problem(),
        StoreError::InUse => in_use_problem(),
    })?;
    Ok(StatusCode::NO_CONTENT)
}

/// `POST /api/v1/alerts/destinations/{id}/test` — fire a test notification.
///
/// Send a real test notification through the destination's connector — no
/// dry-run — so operators can verify the round-trip end-to-end. Returns 502
/// `connector_failed` with the upstream status and body when the connector
/// rejects the payload.
#[utoipa::path(
    post,
    path = "/api/v1/alerts/destinations/{id}/test",
    params(("id" = String, Path, description = "Destination identifier")),
    request_body(content = TestDestinationRequest, description = "Optional severity / message overrides"),
    responses(
        (status = 200, description = "Connector accepted the test", body = TestDestinationResponse),
        (status = 404, description = "Destination not found"),
        (status = 502, description = "Connector failed", body = ConnectorFailedBody)
    ),
    tag = "alert-destinations"
)]
pub async fn test_destination(
    _auth: RequireWrite,
    Extension(state): Extension<AppState>,
    Path(id): Path<String>,
    body: Option<Json<TestDestinationRequest>>,
) -> Result<(StatusCode, Json<TestDestinationResponse>), TestDestinationFailure> {
    let destination = state
        .destination_store
        .get(&id)
        .ok_or_else(|| TestDestinationFailure::NotFound(not_found_problem()))?;

    // AAASM-3789: SSRF egress guard. Before dispatching a webhook test-fire,
    // reject targets that resolve to an internal address (loopback / RFC1918 /
    // link-local incl. the cloud-metadata endpoint / ULA). The resolution does
    // a blocking DNS lookup, so it runs on the blocking pool.
    if let DestinationConfig::Webhook { url, .. } = &destination.config {
        let parsed = url::Url::parse(url).map_err(|_| {
            TestDestinationFailure::Rejected(validation_error_to_problem(ValidationError::InvalidConfig(
                "webhook.url is not a valid URL",
            )))
        })?;
        let egress = tokio::task::spawn_blocking(move || validate_webhook_egress(&parsed))
            .await
            .map_err(|_| {
                TestDestinationFailure::Rejected(
                    ProblemDetail::from_status(StatusCode::INTERNAL_SERVER_ERROR).with_detail("egress_check_failed"),
                )
            })?;
        egress.map_err(|e| TestDestinationFailure::Rejected(validation_error_to_problem(e)))?;
    }

    let req_in = body.map(|Json(b)| b).unwrap_or_default();
    let dispatch = DispatchRequest {
        severity: req_in.severity.unwrap_or_else(|| "LOW".to_string()),
        message: req_in.message.unwrap_or_else(|| "AAASM test fire".to_string()),
    };

    let connector = connector_for(destination.config.kind());
    match connector.dispatch(&destination, &dispatch).await {
        Ok(outcome) => Ok((
            StatusCode::OK,
            Json(TestDestinationResponse {
                delivered_at: outcome.delivered_at,
                connector_response_status: outcome.connector_response_status,
                connector_response_body: outcome.connector_response_body,
            }),
        )),
        Err(ConnectorError::Http { status, body }) => Err(TestDestinationFailure::Connector(ConnectorFailedBody {
            error: "connector_failed".to_string(),
            connector_status: status,
            connector_body: body,
        })),
        Err(ConnectorError::Transport(msg)) => Err(TestDestinationFailure::Connector(ConnectorFailedBody {
            error: "connector_failed".to_string(),
            connector_status: 0,
            connector_body: msg,
        })),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::scope::Scope;
    use crate::auth::{AuthenticatedCaller, Tenant};

    fn writer() -> RequireWrite {
        RequireWrite(AuthenticatedCaller {
            key_id: "k".to_string(),
            scopes: vec![Scope::Admin],
            tenant: Tenant::default(),
        })
    }

    #[test]
    fn connector_for_resolves_builtin_kinds() {
        // Webhook + Slack are always compiled in; the factory must not panic.
        let _webhook = connector_for(DestinationKind::Webhook);
        let _slack = connector_for(DestinationKind::Slack);
    }

    #[tokio::test]
    async fn connector_for_unsupported_kind_fails_closed() {
        // OpsGenie has no compiled backend in the default build, so dispatch must
        // return a transport error rather than panic.
        let conn = connector_for(DestinationKind::OpsGenie);
        let dest = Destination {
            id: "dst_x".to_string(),
            name: "og".to_string(),
            config: DestinationConfig::OpsGenie {
                api_key: "k".to_string(),
                team_id: "t".to_string(),
            },
            enabled: true,
            created_at: String::new(),
            updated_at: String::new(),
        };
        let req = DispatchRequest {
            severity: "LOW".to_string(),
            message: "m".to_string(),
        };
        assert!(conn.dispatch(&dest, &req).await.is_err());
    }

    #[tokio::test]
    async fn test_destination_rejects_internal_webhook_target() {
        let state = AppState::local_in_memory().expect("state builds");
        let dest = state.destination_store.create(
            "internal".to_string(),
            DestinationConfig::Webhook {
                url: "http://127.0.0.1:9/hook".to_string(),
                secret_header: None,
            },
            true,
        );
        // SSRF egress guard (AAASM-3789): a loopback target is refused before dispatch.
        let failure = test_destination(writer(), Extension(state), Path(dest.id), None)
            .await
            .expect_err("loopback target rejected");
        assert_eq!(failure.into_response().status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn update_preserves_stored_secret_when_masked() {
        let state = AppState::local_in_memory().expect("state builds");
        let dest = state.destination_store.create(
            "wh".to_string(),
            DestinationConfig::Webhook {
                url: "https://example.com/hook".to_string(),
                secret_header: Some("real-secret".to_string()),
            },
            true,
        );
        // A GET → edit → PUT round-trip ships back the masked sentinel; it must not
        // clobber the real stored secret.
        let body = serde_json::to_vec(&serde_json::json!({
            "kind": "webhook",
            "config": { "url": "https://example.com/hook", "secret_header": "********" }
        }))
        .unwrap();
        let _ = update_destination(
            writer(),
            Extension(state.clone()),
            Path(dest.id.clone()),
            Bytes::from(body),
        )
        .await
        .expect("update applies");

        let stored = state.destination_store.get(&dest.id).expect("still present");
        match stored.config {
            DestinationConfig::Webhook { secret_header, .. } => {
                assert_eq!(secret_header.as_deref(), Some("real-secret"));
            }
            other => panic!("expected webhook config, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn update_unknown_destination_is_404() {
        let state = AppState::local_in_memory().expect("state builds");
        let body = serde_json::to_vec(&serde_json::json!({ "name": "x" })).unwrap();
        let err = update_destination(
            writer(),
            Extension(state),
            Path("dst_missing".to_string()),
            Bytes::from(body),
        )
        .await
        .expect_err("not found");
        assert_eq!(err.status, StatusCode::NOT_FOUND.as_u16());
    }

    #[test]
    fn from_destination_masks_every_connector_secret() {
        // AAASM-3843: every connector kind's secret-bearing field is masked on
        // read; non-secret fields are preserved.
        let cases = [
            DestinationConfig::Webhook {
                url: "https://example.com/hook".to_string(),
                secret_header: Some("real-secret".to_string()),
            },
            DestinationConfig::Slack {
                webhook_url: "https://hooks.slack.com/services/T/B/secret".to_string(),
                channel_override: Some("#ops".to_string()),
            },
            DestinationConfig::PagerDuty {
                routing_key: "real-routing-key".to_string(),
                severity_map: None,
            },
            DestinationConfig::OpsGenie {
                api_key: "real-api-key".to_string(),
                team_id: "team-1".to_string(),
            },
        ];
        for config in cases {
            let dest = Destination {
                id: "dst_1".to_string(),
                name: "d".to_string(),
                config,
                enabled: true,
                created_at: String::new(),
                updated_at: String::new(),
            };
            match DestinationResponse::from(dest).config {
                DestinationConfig::Webhook { secret_header, .. } => {
                    assert_eq!(secret_header.as_deref(), Some(SECRET_MASK));
                }
                DestinationConfig::Slack {
                    webhook_url,
                    channel_override,
                } => {
                    assert_eq!(webhook_url, SECRET_MASK);
                    assert_eq!(channel_override.as_deref(), Some("#ops"));
                }
                DestinationConfig::PagerDuty { routing_key, .. } => {
                    assert_eq!(routing_key, SECRET_MASK);
                }
                DestinationConfig::OpsGenie { api_key, team_id } => {
                    assert_eq!(api_key, SECRET_MASK);
                    assert_eq!(team_id, "team-1");
                }
            }
        }
    }

    #[test]
    fn restore_masked_secrets_preserves_stored_for_all_kinds() {
        // AAASM-3843: a masked sentinel on PUT is restored from the stored
        // secret for every kind; a genuinely-rotated value is left untouched.
        let mut slack = DestinationConfig::Slack {
            webhook_url: SECRET_MASK.to_string(),
            channel_override: None,
        };
        restore_masked_secrets(
            &mut slack,
            Some(DestinationConfig::Slack {
                webhook_url: "https://hooks.slack.com/services/real".to_string(),
                channel_override: None,
            }),
        );
        assert!(matches!(slack, DestinationConfig::Slack { webhook_url, .. }
            if webhook_url == "https://hooks.slack.com/services/real"));

        let mut pd = DestinationConfig::PagerDuty {
            routing_key: SECRET_MASK.to_string(),
            severity_map: None,
        };
        restore_masked_secrets(
            &mut pd,
            Some(DestinationConfig::PagerDuty {
                routing_key: "real-key".to_string(),
                severity_map: None,
            }),
        );
        assert!(matches!(pd, DestinationConfig::PagerDuty { routing_key, .. }
            if routing_key == "real-key"));

        let mut og = DestinationConfig::OpsGenie {
            api_key: SECRET_MASK.to_string(),
            team_id: "t".to_string(),
        };
        restore_masked_secrets(
            &mut og,
            Some(DestinationConfig::OpsGenie {
                api_key: "real-genie".to_string(),
                team_id: "t".to_string(),
            }),
        );
        assert!(matches!(og, DestinationConfig::OpsGenie { api_key, .. }
            if api_key == "real-genie"));

        // A non-masked incoming secret is a genuine rotation and must survive.
        let mut rotated = DestinationConfig::OpsGenie {
            api_key: "rotated-key".to_string(),
            team_id: "t".to_string(),
        };
        restore_masked_secrets(
            &mut rotated,
            Some(DestinationConfig::OpsGenie {
                api_key: "old-key".to_string(),
                team_id: "t".to_string(),
            }),
        );
        assert!(matches!(rotated, DestinationConfig::OpsGenie { api_key, .. }
            if api_key == "rotated-key"));
    }
}
