//! Policy management endpoints.

use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::{Extension, Json};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

use aa_gateway::policy::rbac::MutationKind;
use aa_gateway::policy::scope::PolicyScope;
use aa_gateway::policy::PolicyValidator;

use crate::auth::policy_auth::{PolicyAuthorizationDenied, PolicyWriteAuth};
use crate::auth::scope::{RequireRead, Scope};
use crate::error::ProblemDetail;
use crate::pagination::PaginationParams;
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

/// Additional filter parameters for `GET /api/v1/policies`.
#[derive(Debug, Clone, Deserialize, IntoParams)]
pub struct PolicyListFilter {
    /// When `true`, include older (inactive) policy versions in the response.
    /// Defaults to `false` — only the currently active policy version is returned.
    #[serde(default)]
    pub include_archived: bool,
}

/// Paginated `GET /api/v1/policies` body (AAASM-4892) — a named wrapper so the
/// OpenAPI schema `$ref`s `PolicyResponse` and matches the `{ items, total }`
/// object the handler serializes, not a bare array.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct PaginatedPolicyResponse {
    /// Policy versions in the current page.
    pub items: Vec<PolicyResponse>,
    /// 1-indexed page number echoed from the request.
    pub page: u32,
    /// Items per page echoed from the request.
    pub per_page: u32,
    /// Total policy versions across all pages.
    pub total: u64,
}

/// `GET /api/v1/policies` — list all policy versions.
///
/// List governance policy versions with optional archive inclusion.
/// By default only the active (most recent) version is returned.
#[utoipa::path(
    get,
    path = "/api/v1/policies",
    params(PaginationParams, PolicyListFilter),
    responses(
        (status = 200, description = "Paginated list of policy versions", body = PaginatedPolicyResponse),
        (status = 403, description = "Caller lacks admin scope")
    ),
    tag = "policies"
)]
pub async fn list_policies(
    // AAASM-3865: governance policy YAML is sensitive; require read scope so an
    // unauthenticated caller cannot dump the full policy set.
    RequireRead(caller): RequireRead,
    Extension(state): Extension<AppState>,
    axum::extract::Query(params): axum::extract::Query<PaginationParams>,
    axum::extract::Query(filter): axum::extract::Query<PolicyListFilter>,
) -> Result<impl IntoResponse, ProblemDetail> {
    // AAASM-3995(a): a policy version is a whole governance document spanning
    // every tenant's cascade (global + org + team + agent rules), so it is not
    // attributable to a single team/org that could be filtered per caller.
    // Enumerating the full policy set therefore requires cross-tenant Admin
    // scope; a plain Read caller must not be able to dump every tenant's rules.
    if !caller.scopes.contains(&Scope::Admin) {
        return Err(ProblemDetail::from_status(StatusCode::FORBIDDEN)
            .with_detail("listing policy versions requires admin scope".to_string()));
    }

    let all = state
        .policy_history
        .list(usize::MAX)
        .await
        .map_err(|e| ProblemDetail::from_status(StatusCode::INTERNAL_SERVER_ERROR).with_detail(format!("{e:?}")))?;

    // Without include_archived only the most-recent (active) version is visible.
    let visible: Vec<_> = if filter.include_archived {
        all
    } else {
        all.into_iter().take(1).collect()
    };

    let total = visible.len() as u64;

    let paged: Vec<_> = visible
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
        Json(PaginatedPolicyResponse {
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
    /// Optional client-declared RBAC scope. **Advisory only** (AAASM-4933): the
    /// authorization scope is derived from the policy *document's own* declared
    /// scope, never this field. When present it must equal the document's scope
    /// — a value that disagrees is rejected (`400`) rather than trusted, closing
    /// the pre-fix path where a caller under-claimed a narrow scope (e.g.
    /// `tool:x`) to satisfy a lower role while installing a global-effect policy.
    #[serde(default)]
    pub scope: Option<String>,
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
    // Parse the (advisory) client-declared scope for input validation only.
    let requested_scope = body
        .scope
        .as_deref()
        .map(str::parse::<PolicyScope>)
        .transpose()
        .map_err(|e: aa_gateway::policy::error::PolicyParseError| {
            PolicyCreateError::BadRequest(
                ProblemDetail::from_status(StatusCode::BAD_REQUEST).with_detail(format!("Invalid scope: {e}")),
            )
        })?;

    // AAASM-4933: authorize against the policy DOCUMENT's own declared scope,
    // never the client-asserted `body.scope`. Validate the YAML up front so the
    // real scope is known before the RBAC gate. `apply_yaml` re-validates below;
    // the duplication is deliberate — it keeps this security fix contained to the
    // handler (no change to the engine's evaluate/install path) on a cold,
    // low-frequency write endpoint.
    let validated = PolicyValidator::from_yaml(&body.policy_yaml).map_err(|errs| {
        PolicyCreateError::BadRequest(
            ProblemDetail::from_status(StatusCode::BAD_REQUEST).with_detail(format!("Invalid policy: {errs:?}")),
        )
    })?;
    let doc_scope = validated.document.scope;

    // The client may annotate the request with a scope, but it must agree with
    // the document — a divergent claim is rejected, not trusted. This is the
    // pre-fix privilege-escalation vector: a Write/Developer caller declared
    // `scope: tool:x` (Developer-authorized) while submitting a scope-less
    // (global) policy, installing a global-effect policy with a Developer role.
    if let Some(requested) = &requested_scope {
        if requested != &doc_scope {
            return Err(PolicyCreateError::BadRequest(
                ProblemDetail::from_status(StatusCode::BAD_REQUEST).with_detail(format!(
                    "scope mismatch: request scope '{requested}' does not match policy document scope '{doc_scope}'"
                )),
            ));
        }
    }

    // This endpoint hot-swaps the single GLOBAL primary policy slot (see
    // `PolicyEngine::apply_yaml`), so it can only honor a Global-scoped document.
    // A narrower declared scope would be silently globalised — installed for
    // every agent — so it is rejected until scoped installation is wired into the
    // `scope_index` cascade (AAASM-4933 follow-up).
    if doc_scope != PolicyScope::Global {
        return Err(PolicyCreateError::BadRequest(
            ProblemDetail::from_status(StatusCode::BAD_REQUEST).with_detail(format!(
                "scoped policy installation is not supported via this endpoint; only global \
                 policies may be applied (policy declared scope '{doc_scope}')"
            )),
        ));
    }

    // Gate on the document's true scope: a global install requires OrgAdmin.
    policy_auth
        .check_mutation(&doc_scope, MutationKind::Create)
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
        (status = 403, description = "Caller lacks admin scope"),
        (status = 404, description = "No active policy loaded")
    ),
    tag = "policies"
)]
pub async fn get_active_policy(
    // AAASM-3865: the active policy YAML is sensitive; require read scope.
    RequireRead(caller): RequireRead,
    Extension(state): Extension<AppState>,
) -> Result<(StatusCode, Json<PolicyResponse>), ProblemDetail> {
    // AAASM-3995(a): the active policy is the full cross-tenant governance
    // document; gate its raw YAML behind Admin scope, like the version list.
    if !caller.scopes.contains(&Scope::Admin) {
        return Err(ProblemDetail::from_status(StatusCode::FORBIDDEN)
            .with_detail("reading the active policy requires admin scope".to_string()));
    }

    let info = state.policy_engine.active_policy_info();

    // No named policy is loaded — honour the 404 documented in the OpenAPI spec.
    let name = info.name.ok_or_else(|| {
        ProblemDetail::from_status(StatusCode::NOT_FOUND).with_detail("no active policy loaded".to_string())
    })?;
    let version = info.policy_version.unwrap_or_else(|| "unknown".to_string());

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
            name,
            version,
            active: true,
            rule_count: info.rule_count,
            policy_yaml,
        }),
    ))
}
