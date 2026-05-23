//! Admin REST routes (AAASM-1592 S-K).
//!
//! Mounted at `/api/v1/admin/*`. Each handler requires
//! [`AppState::retention_engine`] to be populated; when the gateway
//! boots without a `storage` section the field is `None` and the
//! handlers respond with `503 Service Unavailable`.

use std::sync::Arc;

use axum::extract::Extension;
use axum::http::StatusCode;
use axum::Json;

use aa_gateway::storage::{ColdAction, RetentionConfig, RetentionEngine, RetentionStats};

use crate::error::ProblemDetail;
use crate::models::retention::{
    ColdActionDto, RetentionPolicyDocument, RetentionRunStatsDto, RunRetentionRequest, UpdateRetentionPolicyRequest,
};
use crate::state::AppState;

/// Resolve the live `RetentionEngine` handle or surface a 503 to the
/// caller. Used by every handler in this module.
fn require_engine(state: &AppState) -> Result<Arc<RetentionEngine>, ProblemDetail> {
    state.retention_engine.clone().ok_or_else(|| {
        ProblemDetail::from_status(StatusCode::SERVICE_UNAVAILABLE)
            .with_detail("retention engine is not configured — gateway started without a storage section")
            .with_error_code("retention_engine_unavailable")
    })
}

/// Convert a gateway `RetentionConfig` + last-run stats snapshot into
/// the wire DTO.
fn config_to_document(config: &RetentionConfig, last_run: Option<RetentionStats>) -> RetentionPolicyDocument {
    RetentionPolicyDocument {
        hot_days: config.hot_days,
        warm_days: config.warm_days,
        cold_action: match config.cold_action {
            ColdAction::Drop => ColdActionDto::Drop,
            ColdAction::Archive => ColdActionDto::Archive,
        },
        archive_url: config.archive_url.clone(),
        dry_run: config.dry_run,
        schedule: config.schedule.clone(),
        last_run: last_run.map(stats_to_dto),
    }
}

/// Map gateway `RetentionStats` onto the wire DTO.
fn stats_to_dto(stats: RetentionStats) -> RetentionRunStatsDto {
    // RetentionStats does not carry the dry_run flag; the caller of
    // stats_to_dto fills it in from the policy that drove the run when
    // it knows the answer. The Default here keeps the inline last_run
    // panel correct for runs that the engine completed asynchronously
    // (where we cannot recover the flag).
    RetentionRunStatsDto {
        ran_at: stats.ran_at,
        hot_rows: stats.hot_rows,
        compressed_rows: stats.compressed_rows,
        archived_rows: stats.archived_rows,
        dropped_rows: stats.dropped_rows,
        freed_bytes: stats.freed_bytes,
        dry_run: false,
    }
}

/// Return the live retention configuration plus the most recent run's
/// stats.
#[utoipa::path(
    get,
    path = "/api/v1/admin/retention-policy",
    summary = "Get the live retention policy + last-run stats",
    description = "Returns the gateway's currently-active retention configuration plus the most recent successful run's statistics. The `last_run` field is `null` until the engine has completed at least one pass.",
    responses(
        (status = 200, description = "Current retention policy document", body = RetentionPolicyDocument),
        (status = 503, description = "Retention engine not configured (gateway started without storage section)", body = ProblemDetail),
    ),
    tag = "admin"
)]
pub async fn get_retention_policy(
    Extension(state): Extension<AppState>,
) -> Result<Json<RetentionPolicyDocument>, ProblemDetail> {
    let engine = require_engine(&state)?;
    let config = engine.current_config();
    let last_run = engine.last_run_stats();
    Ok(Json(config_to_document(&config, last_run)))
}

/// Validate the incoming DTO at the HTTP layer so callers get a
/// field-level 400 before the gateway's `RetentionConfig::validate`
/// runs. Mirrors the dashboard's client-side form rules.
fn validate_update_request(req: &UpdateRetentionPolicyRequest) -> Result<(), ProblemDetail> {
    if req.hot_days < 1 {
        return Err(ProblemDetail::from_status(StatusCode::BAD_REQUEST)
            .with_detail("hot_days must be >= 1")
            .with_error_code("retention_policy_invalid_hot_days"));
    }
    if req.warm_days <= req.hot_days {
        return Err(ProblemDetail::from_status(StatusCode::BAD_REQUEST)
            .with_detail("warm_days must be strictly greater than hot_days")
            .with_error_code("retention_policy_invalid_warm_days"));
    }
    if req.cold_action == ColdActionDto::Archive {
        let url = req.archive_url.as_deref().unwrap_or("");
        if url.is_empty() {
            return Err(ProblemDetail::from_status(StatusCode::BAD_REQUEST)
                .with_detail("archive_url is required when cold_action == \"archive\"")
                .with_error_code("retention_policy_missing_archive_url"));
        }
        if !url.starts_with("s3://") && !url.starts_with("gs://") {
            return Err(ProblemDetail::from_status(StatusCode::BAD_REQUEST)
                .with_detail("archive_url must start with s3:// or gs://")
                .with_error_code("retention_policy_invalid_archive_url"));
        }
    }
    Ok(())
}

/// Build a fresh `RetentionConfig` from the live config (which carries
/// the cron schedule we cannot change at runtime) and the validated DTO.
fn merge_request_into_config(base: &RetentionConfig, req: &UpdateRetentionPolicyRequest) -> RetentionConfig {
    RetentionConfig {
        schedule: base.schedule.clone(),
        hot_days: req.hot_days,
        warm_days: req.warm_days,
        cold_action: match req.cold_action {
            ColdActionDto::Drop => ColdAction::Drop,
            ColdActionDto::Archive => ColdAction::Archive,
        },
        archive_url: req.archive_url.clone(),
        dry_run: base.dry_run,
    }
}

/// Hot-reload the retention configuration. Returns the updated config
/// + last-run stats so the caller can re-render the page without a
/// follow-up GET.
#[utoipa::path(
    put,
    path = "/api/v1/admin/retention-policy",
    summary = "Hot-reload the retention policy thresholds",
    description = "Atomically replaces the gateway's active retention configuration. Validation runs both client-side in the dashboard and server-side here; on validation failure the active config is preserved. The cron schedule is read-only at runtime — only thresholds and the cold action can be changed without a restart.",
    request_body = UpdateRetentionPolicyRequest,
    responses(
        (status = 200, description = "Configuration applied; updated document returned", body = RetentionPolicyDocument),
        (status = 400, description = "Invalid request body (validation failure)", body = ProblemDetail),
        (status = 503, description = "Retention engine not configured", body = ProblemDetail),
    ),
    tag = "admin"
)]
pub async fn update_retention_policy(
    Extension(state): Extension<AppState>,
    Json(req): Json<UpdateRetentionPolicyRequest>,
) -> Result<Json<RetentionPolicyDocument>, ProblemDetail> {
    validate_update_request(&req)?;
    let engine = require_engine(&state)?;
    let current = engine.current_config();
    let new_config = merge_request_into_config(&current, &req);
    engine.hot_reload(new_config).map_err(|e| {
        ProblemDetail::from_status(StatusCode::BAD_REQUEST)
            .with_detail(e.to_string())
            .with_error_code("retention_policy_gateway_rejected")
    })?;
    let applied = engine.current_config();
    let last_run = engine.last_run_stats();
    Ok(Json(config_to_document(&applied, last_run)))
}

/// Trigger an immediate retention pass (optionally in dry-run mode).
#[utoipa::path(
    post,
    path = "/api/v1/admin/retention-policy/run",
    summary = "Run the retention engine once immediately",
    description = "Triggers `RetentionEngine::run_once` with the live config, optionally forcing dry-run mode for this single invocation. Returns the resulting `RetentionStats` so the dashboard's \"Last retention run\" panel can refresh inline.",
    request_body = RunRetentionRequest,
    responses(
        (status = 200, description = "Run completed; stats returned", body = RetentionRunStatsDto),
        (status = 500, description = "Backend retention pass failed", body = ProblemDetail),
        (status = 503, description = "Retention engine not configured", body = ProblemDetail),
    ),
    tag = "admin"
)]
pub async fn run_retention_policy(
    Extension(state): Extension<AppState>,
    Json(req): Json<RunRetentionRequest>,
) -> Result<Json<RetentionRunStatsDto>, ProblemDetail> {
    let engine = require_engine(&state)?;
    if req.dry_run {
        // Temporarily flip dry_run on so this pass logs work without
        // taking action. The override is itself a hot_reload, so the
        // active config snapshot rolls forward visibly — same path as
        // any other admin write.
        let mut current = engine.current_config();
        let was_dry_run = current.dry_run;
        current.dry_run = true;
        engine.hot_reload(current.clone()).map_err(|e| {
            ProblemDetail::from_status(StatusCode::BAD_REQUEST)
                .with_detail(e.to_string())
                .with_error_code("retention_policy_dry_run_toggle_rejected")
        })?;
        let stats = engine.run_once().await.map_err(|e| {
            ProblemDetail::from_status(StatusCode::INTERNAL_SERVER_ERROR)
                .with_detail(e.to_string())
                .with_error_code("retention_run_failed")
        })?;
        // Restore the operator's dry_run preference.
        current.dry_run = was_dry_run;
        let _ = engine.hot_reload(current);
        let mut dto = stats_to_dto(stats);
        dto.dry_run = true;
        return Ok(Json(dto));
    }
    let stats = engine.run_once().await.map_err(|e| {
        ProblemDetail::from_status(StatusCode::INTERNAL_SERVER_ERROR)
            .with_detail(e.to_string())
            .with_error_code("retention_run_failed")
    })?;
    let mut dto = stats_to_dto(stats);
    dto.dry_run = engine.current_config().dry_run;
    Ok(Json(dto))
}

