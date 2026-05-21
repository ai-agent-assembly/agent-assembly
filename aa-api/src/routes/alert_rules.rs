//! `/api/v1/alerts/rules` CRUD handlers (AAASM-1386).
//!
//! Five endpoints matching the Story's contract verbatim:
//!
//! ```text
//! GET    /api/v1/alerts/rules           -> list
//! POST   /api/v1/alerts/rules           -> create (201)
//! GET    /api/v1/alerts/rules/{id}      -> get  (200/404)
//! PUT    /api/v1/alerts/rules/{id}      -> update (200/404/400/409)
//! DELETE /api/v1/alerts/rules/{id}      -> delete (204/404)
//! ```
//!
//! Error responses follow the Story's table and use the `error_code`
//! field on [`ProblemDetail`] for stable machine-readable codes.

use std::collections::HashMap;

use axum::extract::Query;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::{Extension, Json};
use serde::Deserialize;
use utoipa::ToSchema;

use crate::alerts::rules::types::AlertRule;
use crate::state::AppState;

/// Wire shape for POST / PUT request bodies.
///
/// Mirrors the Story's JSON example. Enum-shaped fields are accepted as
/// strings so the handler can map unknown values onto the spec's
/// `invalid_metric` error code rather than relying on serde's default
/// 422 rejection.
#[derive(Debug, Clone, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct AlertRuleRequest {
    pub name: String,
    pub description: String,
    pub metric: String,
    pub operator: String,
    pub threshold: f64,
    pub evaluation_window_seconds: u32,
    pub severity: String,
    pub destination_ids: Vec<String>,
    pub dedup_window_seconds: u32,
    #[serde(default)]
    pub suppression_labels: HashMap<String, String>,
    pub enabled: bool,
}

/// Wire shape for response bodies — identical to [`AlertRule`].
pub type AlertRuleResponse = AlertRule;

/// Query parameters for `GET /alerts/rules`.
///
/// Only the `enabled` filter is exposed today — the dashboard's
/// `useAlertRulesQuery` (AAASM-1075) consumes the unpaged bare-array
/// response and does its own client-side filtering. A paginated
/// envelope can be added later without breaking the wire if the rule
/// count grows.
#[derive(Debug, Clone, Deserialize, utoipa::IntoParams)]
pub struct ListRulesParams {
    /// Filter by the rule's `enabled` flag. Omit to return every rule.
    #[serde(default)]
    pub enabled: Option<bool>,
}

/// List alert rules.
///
/// Returns every persisted [`AlertRule`] as a bare JSON array ordered
/// by `created_at` then `id` so the dashboard's
/// `useAlertRulesQuery` (AAASM-1075) can consume the response
/// directly. Pass `?enabled=true|false` to restrict the response to
/// the matching subset.
#[utoipa::path(
    get,
    path = "/api/v1/alerts/rules",
    params(ListRulesParams),
    responses(
        (status = 200, description = "Bare array of alert rules", body = Vec<AlertRuleResponse>)
    ),
    tag = "alert-rules"
)]
pub async fn list_rules(
    Extension(state): Extension<AppState>,
    Query(params): Query<ListRulesParams>,
) -> impl IntoResponse {
    let mut rules = state.alert_rule_store.list(params.enabled);
    // Deterministic order so the dashboard table doesn't reshuffle
    // between fetches.
    rules.sort_by(|a, b| a.created_at.cmp(&b.created_at).then(a.id.cmp(&b.id)));
    (StatusCode::OK, Json(rules))
}
