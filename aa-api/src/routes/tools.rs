//! `GET /api/v1/tools` — list auto-discovered AI dev tools on the gateway host.

use axum::{Extension, Json};
use aa_core::DevToolInfo;
use utoipa::ToSchema;

use crate::error::ProblemDetail;
use crate::state::AppState;

/// Response type alias used by utoipa to derive the OpenAPI schema.
#[allow(dead_code)]
type ToolsList = Vec<ToolInfoSchema>;

/// Schema wrapper so utoipa can derive the OpenAPI schema for [`DevToolInfo`].
///
/// The real handler returns `Vec<DevToolInfo>` directly; this wrapper is only
/// referenced by utoipa's `#[utoipa::path]` macro so it can generate a schema
/// entry without requiring [`DevToolInfo`] itself to implement `ToSchema`.
#[derive(ToSchema)]
struct ToolInfoSchema {
    kind: String,
    version: Option<String>,
    install_path: String,
    governance_level: String,
    supports_mcp: bool,
    supports_managed_settings: bool,
}

/// List all auto-discovered AI dev tools on the gateway host.
///
/// Runs all registered [`DevToolAdapter`][aa_core::DevToolAdapter]
/// implementations concurrently and returns the subset that are installed.
/// If no tools are detected, an empty array is returned (not an error).
#[utoipa::path(
    get,
    path = "/api/v1/tools",
    responses(
        (status = 200, description = "Discovered tools", body = Vec<ToolInfoSchema>)
    )
)]
pub async fn list_tools(
    Extension(state): Extension<AppState>,
) -> Result<Json<Vec<DevToolInfo>>, ProblemDetail> {
    let tools = state.discovery.discover_all().await;
    Ok(Json(tools))
}
