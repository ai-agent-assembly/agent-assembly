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
use crate::models::retention::{ColdActionDto, RetentionPolicyDocument, RetentionRunStatsDto};
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

