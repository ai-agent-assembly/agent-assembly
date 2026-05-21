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

use serde::Deserialize;
use utoipa::ToSchema;

use crate::alerts::rules::types::AlertRule;

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
