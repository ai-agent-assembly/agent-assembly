//! DTOs for the admin retention-policy REST endpoints (AAASM-1592 S-K).
//!
//! These types are the wire surface between the dashboard
//! `Settings → Storage → Retention Policy` page and the gateway. They
//! mirror the shape of [`aa_gateway::storage::RetentionConfig`] /
//! [`aa_gateway::storage::RetentionStats`] without coupling the HTTP
//! layer to the gateway's internal representation.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// Cold-tier action chosen by the admin.
///
/// Wire-level enum kept lowercase (`drop` / `archive`) so the JSON body
/// is identical to the YAML config key and the dashboard dropdown value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum ColdActionDto {
    /// Permanently drop rows older than the warm tier.
    Drop,
    /// Reserved for a future archive implementation — **not implemented**
    /// on any backend. Selecting it is rejected at validation time
    /// (`retention_policy_archive_unsupported`); kept in the dropdown
    /// and the schema as inert/reserved rather than removed.
    Archive,
}

/// Snapshot of the active retention configuration plus the most recent
/// run's stats. Body of `GET /api/v1/admin/retention-policy`.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct RetentionPolicyDocument {
    /// Days a row stays indexed and queryable in the hot tier.
    pub hot_days: u32,
    /// Days the warm tier spans *following* the hot window — not an
    /// absolute age. Total row age when `cold_action` fires is
    /// `hot_days + warm_days` (e.g. 30 + 90 = 120 days at the shipped
    /// defaults).
    pub warm_days: u32,
    /// Action applied to rows older than `hot_days + warm_days`.
    pub cold_action: ColdActionDto,
    /// Reserved for a future archive implementation — not implemented
    /// on any backend today. `cold_action == "archive"` is rejected at
    /// validation time (see [`ColdActionDto::Archive`]). Always `None`
    /// in practice.
    pub archive_url: Option<String>,
    /// When true, the engine logs the work it *would* perform without
    /// taking action.
    pub dry_run: bool,
    /// Cron schedule (UTC) on which the background task fires. Read-only
    /// — schedule changes still require a gateway restart.
    pub schedule: String,
    /// Stats from the most recent successful run. `None` when the engine
    /// has not yet completed a pass.
    pub last_run: Option<RetentionRunStatsDto>,
}

/// Wire representation of [`aa_gateway::storage::RetentionStats`].
///
/// Used both inline on [`RetentionPolicyDocument`] (`last_run`) and as
/// the body of `POST /api/v1/admin/retention-policy/run`.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
pub struct RetentionRunStatsDto {
    /// Timestamp (UTC) at which the run completed (ISO 8601).
    #[schema(value_type = String)]
    pub ran_at: DateTime<Utc>,
    /// Rows remaining in the hot tier after the run.
    pub hot_rows: u64,
    /// Rows compressed into warm tier during the run.
    pub compressed_rows: u64,
    /// Rows archived during the run.
    pub archived_rows: u64,
    /// Rows dropped during the run.
    pub dropped_rows: u64,
    /// Bytes freed from primary storage by compression or drop.
    pub freed_bytes: u64,
    /// Whether the run executed in dry-run mode (logged work without
    /// actually deleting / compressing).
    pub dry_run: bool,
}

/// Body of `PUT /api/v1/admin/retention-policy` — partial update of the
/// runtime retention configuration. Each field must be present; the
/// server-side validation matches the dashboard's client-side rules
/// (hot_days &ge; 1, warm_days &ge; 1 — a span following hot_days, not
/// an age relative to it — and `cold_action == "archive"` is rejected
/// outright since no backend implements it).
#[derive(Debug, Clone, Deserialize, Serialize, ToSchema)]
pub struct UpdateRetentionPolicyRequest {
    /// New value for `hot_days`. Must be &ge; 1.
    pub hot_days: u32,
    /// New value for `warm_days`. Must be &ge; 1. This is the span of
    /// the warm tier following `hot_days`, not an age — total row age
    /// at which `cold_action` fires is `hot_days + warm_days`.
    pub warm_days: u32,
    /// New cold-tier action. `cold_action == "archive"` is rejected —
    /// not implemented on any backend.
    pub cold_action: ColdActionDto,
    /// Reserved for a future archive implementation — not implemented
    /// on any backend today; ignored since `cold_action == "archive"`
    /// is rejected before this field is consulted.
    #[serde(default)]
    pub archive_url: Option<String>,
}

/// Body of `POST /api/v1/admin/retention-policy/run`.
#[derive(Debug, Clone, Default, Deserialize, Serialize, ToSchema)]
pub struct RunRetentionRequest {
    /// When true, the run logs the work it *would* perform without
    /// taking action. Defaults to `false`.
    #[serde(default)]
    pub dry_run: bool,
}
