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

use axum::extract::{Path, Query};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::{Extension, Json};
use serde::Deserialize;
use utoipa::ToSchema;

use crate::alerts::rules::store::AlertRuleStoreError;
use crate::alerts::rules::types::{AlertRule, AlertRuleValidationError, RuleMetric, RuleOperator, RuleSeverity};
use crate::auth::scope::{RequireRead, RequireWrite, Scope};
use crate::auth::AuthenticatedCaller;
use crate::error::ProblemDetail;
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

impl AlertRuleRequest {
    /// Convert the wire request into a domain [`AlertRule`] with empty
    /// id / timestamps — the store overwrites them.
    fn into_alert_rule(self) -> Result<AlertRule, ProblemDetail> {
        let metric = parse_metric(&self.metric)?;
        let operator = parse_operator(&self.operator)?;
        let severity = parse_severity(&self.severity)?;
        Ok(AlertRule {
            id: String::new(),
            name: self.name,
            description: self.description,
            metric,
            operator,
            threshold: self.threshold,
            evaluation_window_seconds: self.evaluation_window_seconds,
            severity,
            destination_ids: self.destination_ids,
            dedup_window_seconds: self.dedup_window_seconds,
            suppression_labels: self.suppression_labels,
            enabled: self.enabled,
            created_at: String::new(),
            updated_at: String::new(),
            // AAASM-3911: tenant is stamped from the authenticated caller in
            // `create_rule`, not taken from the request body.
            team_id: None,
            org_id: None,
        })
    }
}

fn parse_metric(s: &str) -> Result<RuleMetric, ProblemDetail> {
    match s {
        "budget_spent_pct" => Ok(RuleMetric::BudgetSpentPct),
        "anomaly_score" => Ok(RuleMetric::AnomalyScore),
        "approval_pending_age" => Ok(RuleMetric::ApprovalPendingAge),
        "policy_violation_count" => Ok(RuleMetric::PolicyViolationCount),
        other => Err(ProblemDetail::from_status(StatusCode::BAD_REQUEST)
            .with_detail(format!("unknown metric: {other}"))
            .with_error_code("invalid_metric")),
    }
}

fn parse_operator(s: &str) -> Result<RuleOperator, ProblemDetail> {
    match s {
        ">" => Ok(RuleOperator::Gt),
        ">=" => Ok(RuleOperator::Gte),
        "<" => Ok(RuleOperator::Lt),
        "=" => Ok(RuleOperator::Eq),
        other => Err(ProblemDetail::from_status(StatusCode::BAD_REQUEST)
            .with_detail(format!("unknown operator: {other}"))
            .with_error_code("invalid_operator")),
    }
}

/// Map an `AlertRuleValidationError` produced by `AlertRule::validate`
/// onto a 400 ProblemDetail, propagating the validation error's stable
/// `error_code()` (`invalid_name`, `invalid_threshold`,
/// `invalid_evaluation_window`, `destination_unknown`).
fn validation_error_to_problem(err: AlertRuleValidationError) -> ProblemDetail {
    ProblemDetail::from_status(StatusCode::BAD_REQUEST)
        .with_detail(err.to_string())
        .with_error_code(err.error_code())
}

/// Map an `AlertRuleStoreError` onto a ProblemDetail with the
/// right HTTP status — 409 for name conflicts, 404 for unknown ids —
/// while preserving the store's stable `error_code()`
/// (`rule_name_conflict` or `rule_not_found`).
fn store_error_to_problem(err: AlertRuleStoreError) -> ProblemDetail {
    match &err {
        AlertRuleStoreError::NameConflict { .. } => ProblemDetail::from_status(StatusCode::CONFLICT)
            .with_detail(err.to_string())
            .with_error_code(err.error_code()),
        AlertRuleStoreError::NotFound => ProblemDetail::from_status(StatusCode::NOT_FOUND)
            .with_detail(err.to_string())
            .with_error_code(err.error_code()),
    }
}

fn parse_severity(s: &str) -> Result<RuleSeverity, ProblemDetail> {
    match s {
        "CRITICAL" => Ok(RuleSeverity::Critical),
        "HIGH" => Ok(RuleSeverity::High),
        "MEDIUM" => Ok(RuleSeverity::Medium),
        "LOW" => Ok(RuleSeverity::Low),
        other => Err(ProblemDetail::from_status(StatusCode::BAD_REQUEST)
            .with_detail(format!("unknown severity: {other}"))
            .with_error_code("invalid_severity")),
    }
}

/// Enforce tenant ownership of an alert rule for a caller that already cleared
/// the scope gate (AAASM-3911).
///
/// Mirrors `alerts::authorize_alert_owner` / `agents::authorize_agent_access`:
/// an admin may act on any rule; a tenant-scoped caller may act only on rules
/// its own tenant owns; a caller with neither admin scope nor any tenant scope
/// is denied up front (fail-closed) so it cannot enumerate rules. Rules with no
/// tenant tag (created by an admin / bypass caller) are admin-only.
///
/// A rule is matched on its finer-grained tag first: a `team_id` requires team
/// access, otherwise an `org_id` requires org access, otherwise (untagged) admin
/// is required.
fn authorize_rule_owner(caller: &AuthenticatedCaller, rule: &AlertRule) -> Result<(), ProblemDetail> {
    let is_admin = caller.scopes.contains(&Scope::Admin);
    if !is_admin && caller.tenant.team_id.is_none() && caller.tenant.org_id.is_none() {
        return Err(ProblemDetail::from_status(StatusCode::FORBIDDEN)
            .with_detail("This operation requires admin scope or a tenant scope".to_string()));
    }
    let authorized = match (rule.team_id.as_deref(), rule.org_id.as_deref()) {
        (Some(team), _) => caller.can_access_team(team),
        (None, Some(org)) => caller.can_access_org(org),
        (None, None) => is_admin,
    };
    if !authorized {
        return Err(ProblemDetail::from_status(StatusCode::FORBIDDEN)
            .with_detail("This operation requires admin scope or membership in the rule's tenant".to_string()));
    }
    Ok(())
}

/// Whether `caller` may see `rule` — the boolean form of
/// [`authorize_rule_owner`], used to filter the list response.
fn rule_visible_to(caller: &AuthenticatedCaller, rule: &AlertRule) -> bool {
    authorize_rule_owner(caller, rule).is_ok()
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
    RequireRead(caller): RequireRead,
    Extension(state): Extension<AppState>,
    Query(params): Query<ListRulesParams>,
) -> impl IntoResponse {
    let mut rules = state.alert_rule_store.list(params.enabled);
    // AAASM-3911: confine the listing to rules the caller's tenant owns. An
    // admin sees every rule; a tenant-scoped caller sees only its own tenant's
    // rules; a caller with no tenant scope (and no admin) sees none. Untagged
    // rules are admin-only.
    rules.retain(|r| rule_visible_to(&caller, r));
    // Deterministic order so the dashboard table doesn't reshuffle
    // between fetches.
    rules.sort_by(|a, b| a.created_at.cmp(&b.created_at).then(a.id.cmp(&b.id)));
    (StatusCode::OK, Json(rules))
}

/// Create a new alert rule.
///
/// Validates the request body against the destination registry and the
/// per-metric range rules, then persists it with a server-assigned id
/// and RFC 3339 `created_at` / `updated_at` timestamps. Returns the
/// stored record. Surfaces `invalid_metric`, `invalid_threshold`,
/// `destination_unknown`, or `rule_name_conflict` on rejection.
#[utoipa::path(
    post,
    path = "/api/v1/alerts/rules",
    request_body = AlertRuleRequest,
    responses(
        (status = 201, description = "Created rule", body = AlertRuleResponse),
        (status = 400, description = "Validation failure (invalid_metric, invalid_threshold, destination_unknown, ...)"),
        (status = 409, description = "rule_name_conflict")
    ),
    tag = "alert-rules"
)]
pub async fn create_rule(
    // AAASM-3911: reverts the AAASM-3894 admin-gate stopgap back to Write scope.
    // This is now safe because the rule is stamped with (and later confined to)
    // the creating caller's tenant, so a Write key can only manage its own
    // tenant's alerting.
    RequireWrite(caller): RequireWrite,
    Extension(state): Extension<AppState>,
    Json(body): Json<AlertRuleRequest>,
) -> Result<(StatusCode, Json<AlertRuleResponse>), ProblemDetail> {
    let mut rule = body.into_alert_rule()?;
    rule.validate(state.destination_registry.as_ref())
        .map_err(validation_error_to_problem)?;
    // AAASM-3911: stamp the owning tenant from the authenticated caller. An
    // admin / bypass caller has no tenant → the rule is untagged (admin-only).
    // The tenant is never taken from the request body.
    rule.team_id = caller.tenant.team_id.clone();
    rule.org_id = caller.tenant.org_id.clone();
    let created = state.alert_rule_store.create(rule).map_err(store_error_to_problem)?;
    Ok((StatusCode::CREATED, Json(created)))
}

/// Build the 404 ProblemDetail returned by `get_rule`, `update_rule`,
/// and `delete_rule` when the id is unknown — centralised so the
/// error_code stays consistent.
fn not_found(id: &str) -> ProblemDetail {
    ProblemDetail::from_status(StatusCode::NOT_FOUND)
        .with_detail(format!("rule not found: {id}"))
        .with_error_code("rule_not_found")
}

/// Fetch a single alert rule by id.
///
/// Returns the full [`AlertRule`] record, or `rule_not_found` (404)
/// when `id` is unknown.
#[utoipa::path(
    get,
    path = "/api/v1/alerts/rules/{id}",
    params(("id" = String, Path, description = "Rule id assigned by the server")),
    responses(
        (status = 200, description = "Rule detail", body = AlertRuleResponse),
        (status = 404, description = "rule_not_found")
    ),
    tag = "alert-rules"
)]
pub async fn get_rule(
    RequireRead(caller): RequireRead,
    Extension(state): Extension<AppState>,
    Path(id): Path<String>,
) -> Result<(StatusCode, Json<AlertRuleResponse>), ProblemDetail> {
    let rule = state.alert_rule_store.get(&id).ok_or_else(|| not_found(&id))?;
    // AAASM-3911: tenant ownership before exposing the rule.
    authorize_rule_owner(&caller, &rule)?;
    Ok((StatusCode::OK, Json(rule)))
}

/// Replace an alert rule.
///
/// Same validation as `POST`. The store preserves the existing `id`
/// and `created_at` while bumping `updated_at`. Returns the updated
/// record, or `rule_not_found` (404) when `id` is unknown.
#[utoipa::path(
    put,
    path = "/api/v1/alerts/rules/{id}",
    params(("id" = String, Path, description = "Rule id assigned by the server")),
    request_body = AlertRuleRequest,
    responses(
        (status = 200, description = "Updated rule", body = AlertRuleResponse),
        (status = 400, description = "Validation failure"),
        (status = 404, description = "rule_not_found"),
        (status = 409, description = "rule_name_conflict")
    ),
    tag = "alert-rules"
)]
pub async fn update_rule(
    // AAASM-3911: Write scope — see `create_rule`.
    RequireWrite(caller): RequireWrite,
    Extension(state): Extension<AppState>,
    Path(id): Path<String>,
    Json(body): Json<AlertRuleRequest>,
) -> Result<(StatusCode, Json<AlertRuleResponse>), ProblemDetail> {
    // AAASM-3911: tenant ownership on the existing rule before mutating it.
    let existing = state.alert_rule_store.get(&id).ok_or_else(|| not_found(&id))?;
    authorize_rule_owner(&caller, &existing)?;

    let mut rule = body.into_alert_rule()?;
    rule.validate(state.destination_registry.as_ref())
        .map_err(validation_error_to_problem)?;
    // Preserve the rule's original owning tenant — an update must not re-tenant
    // it (the request body carries no tenant and the caller must not be able to
    // move a rule between tenants).
    rule.team_id = existing.team_id.clone();
    rule.org_id = existing.org_id.clone();
    let updated = state
        .alert_rule_store
        .update(&id, rule)
        .map_err(store_error_to_problem)?;
    Ok((StatusCode::OK, Json(updated)))
}

/// Delete an alert rule.
///
/// Returns `204 No Content` on success, or `rule_not_found` (404) when
/// the id is unknown. Already-fired alerts derived from a deleted rule
/// keep their snapshot so the alert detail view still works.
#[utoipa::path(
    delete,
    path = "/api/v1/alerts/rules/{id}",
    params(("id" = String, Path, description = "Rule id assigned by the server")),
    responses(
        (status = 204, description = "Rule deleted"),
        (status = 404, description = "rule_not_found")
    ),
    tag = "alert-rules"
)]
pub async fn delete_rule(
    // AAASM-3911: Write scope — see `create_rule`.
    RequireWrite(caller): RequireWrite,
    Extension(state): Extension<AppState>,
    Path(id): Path<String>,
) -> Result<StatusCode, ProblemDetail> {
    // AAASM-3911: tenant ownership on the existing rule before deleting it.
    let existing = state.alert_rule_store.get(&id).ok_or_else(|| not_found(&id))?;
    authorize_rule_owner(&caller, &existing)?;

    if state.alert_rule_store.delete(&id) {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(not_found(&id))
    }
}
