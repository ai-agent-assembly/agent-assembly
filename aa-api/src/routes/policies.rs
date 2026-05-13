//! Policy management endpoints.

use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::{Extension, Json};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use aa_gateway::policy::rbac::MutationKind;
use aa_gateway::policy::scope::PolicyScope;

use crate::auth::policy_auth::{PolicyAuthorizationDenied, PolicyWriteAuth};
use crate::error::ProblemDetail;
use crate::pagination::{PaginatedResponse, PaginationParams};
use crate::state::AppState;

/// JSON representation of a governance policy version.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct PolicyResponse {
    /// Policy name from metadata.
    pub name: String,
    /// Policy version string.
    pub version: String,
    /// Whether this is the currently active policy.
    pub active: bool,
    /// Number of rules in this policy version.
    pub rule_count: usize,
    /// Raw YAML content of this policy version. Empty string when the
    /// underlying snapshot is not retrievable from the history store
    /// (e.g. a policy loaded at startup before any history entry exists).
    pub policy_yaml: String,
}

/// `GET /api/v1/policies` — list all policy versions.
///
/// List all governance policy versions with pagination.
#[utoipa::path(
    get,
    path = "/api/v1/policies",
    params(PaginationParams),
    responses(
        (status = 200, description = "Paginated list of policy versions", body = Vec<PolicyResponse>)
    ),
    tag = "policies"
)]
pub async fn list_policies(
    Extension(state): Extension<AppState>,
    axum::extract::Query(params): axum::extract::Query<PaginationParams>,
) -> Result<impl IntoResponse, ProblemDetail> {
    let all = state
        .policy_history
        .list(usize::MAX)
        .await
        .map_err(|e| ProblemDetail::from_status(StatusCode::INTERNAL_SERVER_ERROR).with_detail(format!("{e:?}")))?;

    let total = all.len() as u64;

    let paged: Vec<_> = all
        .into_iter()
        .skip(params.offset())
        .take(params.per_page() as usize)
        .collect();

    let mut items: Vec<PolicyResponse> = Vec::with_capacity(paged.len());
    for (i, meta) in paged.into_iter().enumerate() {
        // Fetch the YAML body for this version. If the history store cannot
        // resolve it (rare — corrupted entry), surface an empty string rather
        // than failing the whole list.
        let yaml = state
            .policy_history
            .get(&meta.sha256)
            .await
            .map(|snap| snap.yaml_content)
            .unwrap_or_default();
        items.push(PolicyResponse {
            name: meta.sha256[..12].to_string(),
            version: meta.timestamp,
            active: i == 0 && params.page() == 1,
            rule_count: 0,
            policy_yaml: yaml,
        });
    }

    Ok((
        StatusCode::OK,
        Json(PaginatedResponse {
            items,
            page: params.page(),
            per_page: params.per_page(),
            total,
        }),
    ))
}

/// Request body for creating a new policy.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct CreatePolicyRequest {
    /// Raw YAML content of the governance policy.
    pub policy_yaml: String,
    /// Governance scope this policy targets (e.g. `"global"`, `"team:platform"`).
    ///
    /// Used for RBAC authorization — the caller must hold the role required
    /// to mutate policies at this scope. Defaults to `"global"` when absent.
    #[serde(default)]
    pub scope: Option<String>,
}

impl CreatePolicyRequest {
    /// Parse `scope` into a [`PolicyScope`], defaulting to `Global`.
    pub fn policy_scope(&self) -> Result<PolicyScope, String> {
        match &self.scope {
            None => Ok(PolicyScope::Global),
            Some(s) => s
                .parse()
                .map_err(|e: aa_gateway::policy::error::PolicyParseError| e.to_string()),
        }
    }
}

/// `POST /api/v1/policies` — apply a new governance policy.
///
/// Submit and activate a new governance policy from YAML.
/// The caller must hold the role required for the target `scope`
/// (default: `global`, requires `OrgAdmin`).
#[utoipa::path(
    post,
    path = "/api/v1/policies",
    request_body = CreatePolicyRequest,
    responses(
        (status = 201, description = "Policy created", body = PolicyResponse),
        (status = 400, description = "Invalid policy YAML or scope"),
        (status = 403, description = "Insufficient role for this policy scope")
    ),
    tag = "policies"
)]
pub async fn create_policy(
    policy_auth: PolicyWriteAuth,
    Extension(state): Extension<AppState>,
    Json(body): Json<CreatePolicyRequest>,
) -> Result<(StatusCode, Json<PolicyResponse>), PolicyCreateError> {
    let scope = body.policy_scope().map_err(|e| {
        PolicyCreateError::BadRequest(
            ProblemDetail::from_status(StatusCode::BAD_REQUEST).with_detail(format!("Invalid scope: {e}")),
        )
    })?;

    policy_auth
        .check_mutation(&scope, MutationKind::Create)
        .map_err(PolicyCreateError::Forbidden)?;

    let meta = state
        .policy_engine
        .apply_yaml(&body.policy_yaml, Some("api"), state.policy_history.as_ref())
        .await
        .map_err(|e| {
            PolicyCreateError::BadRequest(
                ProblemDetail::from_status(StatusCode::BAD_REQUEST).with_detail(format!("Invalid policy: {e:?}")),
            )
        })?;

    Ok((
        StatusCode::CREATED,
        Json(PolicyResponse {
            name: meta.sha256[..12].to_string(),
            version: meta.timestamp,
            active: true,
            rule_count: 0,
            policy_yaml: body.policy_yaml,
        }),
    ))
}

/// Unified error type for `create_policy` so both 400 and 403 paths render correctly.
#[derive(Debug)]
pub enum PolicyCreateError {
    BadRequest(ProblemDetail),
    Forbidden(PolicyAuthorizationDenied),
}

impl IntoResponse for PolicyCreateError {
    fn into_response(self) -> axum::response::Response {
        match self {
            Self::BadRequest(p) => p.into_response(),
            Self::Forbidden(d) => d.into_response(),
        }
    }
}

/// `GET /api/v1/policies/active` — get the currently active policy.
///
/// Retrieve the currently active governance policy.
#[utoipa::path(
    get,
    path = "/api/v1/policies/active",
    responses(
        (status = 200, description = "Currently active policy", body = PolicyResponse),
        (status = 404, description = "No active policy loaded")
    ),
    tag = "policies"
)]
pub async fn get_active_policy(
    Extension(state): Extension<AppState>,
) -> Result<(StatusCode, Json<PolicyResponse>), ProblemDetail> {
    let info = state.policy_engine.active_policy_info();

    // The active policy's YAML lives in the history store. We treat the
    // most-recent history entry as the active one (apply_yaml always
    // saves to history before swapping the engine). A startup-loaded
    // policy with no history entry yields an empty string.
    let policy_yaml = match state.policy_history.list(1).await {
        Ok(metas) => match metas.first() {
            Some(m) => state
                .policy_history
                .get(&m.sha256)
                .await
                .map(|snap| snap.yaml_content)
                .unwrap_or_default(),
            None => String::new(),
        },
        Err(_) => String::new(),
    };

    Ok((
        StatusCode::OK,
        Json(PolicyResponse {
            name: info.name.unwrap_or_else(|| "unnamed".to_string()),
            version: info.policy_version.unwrap_or_else(|| "unknown".to_string()),
            active: true,
            rule_count: info.rule_count,
            policy_yaml,
        }),
    ))
}
