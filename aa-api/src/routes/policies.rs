//! Policy management endpoints.

use std::collections::BTreeMap;

use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::{Extension, Json};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

use aa_core::identity::{AgentId, SessionId};
use aa_core::time::Timestamp;
use aa_core::{AgentContext, GovernanceAction};
use aa_gateway::policy::rbac::MutationKind;
use aa_gateway::policy::scope::PolicyScope;
use aa_gateway::policy::PolicyValidator;
use aa_gateway::service::convert::hash_to_16;

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

    let all = state.policy_history.list(usize::MAX).await.map_err(|e| {
        // AAASM-4950 (L3): log the underlying store error server-side, but return
        // a generic 500 body — the internal error string may reveal storage paths
        // or implementation detail and must not cross the API boundary.
        tracing::error!(error = ?e, "failed to list policy history");
        ProblemDetail::from_status(StatusCode::INTERNAL_SERVER_ERROR)
            .with_detail("Failed to list policy versions".to_string())
    })?;

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
    /// Optional client-declared governance scope (e.g. `"global"`,
    /// `"team:platform"`). Advisory: authorization is derived from the policy
    /// document's own declared scope, and a value that disagrees with the
    /// document is rejected.
    //
    // AAASM-4933: this field must NOT lower the RBAC gate. `create_policy`
    // authorizes against the *validated document's* declared scope; a
    // `body.scope` that disagrees is rejected (400), closing the pre-fix
    // privilege-escalation path where a caller under-claimed a narrow scope
    // (e.g. `tool:x`) to satisfy a lower role while installing a global-effect
    // policy. The rationale is an inline `//` comment, not `///`, so it does not
    // fold into the OpenAPI schema description (utoipa folds `///` into the spec).
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

/// Request body for `POST /api/v1/policies/simulate` (AAASM-5037).
///
/// Describes a hypothetical `(agent, tool, target)` request to evaluate against
/// the active policy. No part of it is persisted — it is a pure what-if.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct SimulatePolicyRequest {
    /// Identifier (id or name) of the hypothetical agent to evaluate as. Mapped
    /// to the same internal `AgentId` a live request for this agent would use,
    /// so a registered agent's org/team lineage is honored.
    pub agent_id: String,
    /// Tool or capability the agent would invoke (e.g. `"gmail.send"`, `"shell"`).
    pub tool: String,
    /// Optional target/resource of the action (e.g. a recipient, host, or path).
    /// Folded into the simulated tool-call arguments so target-sensitive
    /// predicates and credential/PII scanning apply.
    #[serde(default)]
    pub target: Option<String>,
    /// Optional organization attribute used for policy-cascade lineage when the
    /// agent is not resolvable from the registry.
    #[serde(default)]
    pub org_id: Option<String>,
    /// Optional team attribute used for policy-cascade lineage when the agent is
    /// not resolvable from the registry.
    #[serde(default)]
    pub team_id: Option<String>,
}

/// Response body for `POST /api/v1/policies/simulate` (AAASM-5037).
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct SimulatePolicyResponse {
    /// Dry-run verdict: `"allow"`, `"narrow"`, `"approval"`, or `"deny"`.
    pub verdict: String,
    /// Label of the policy rule / reason that produced the verdict. `null` for a
    /// clean allow with no matched narrowing or deny rule.
    pub matched_rule: Option<String>,
    /// Human-readable explanation of the verdict.
    pub reason: String,
    /// Whether the payload would be scrubbed before reaching the model because
    /// credential/PII content was detected (drives the `"narrow"` verdict).
    pub redacted: bool,
}

/// `POST /api/v1/policies/simulate` — dry-run a hypothetical request.
///
/// Evaluate a hypothetical `(agent, tool, target)` request against the active
/// governance policy and return the verdict (allow / narrow / approval / deny),
/// the matched rule/reason, and whether the payload would be scrubbed.
///
/// This is a pure, read-only what-if: it runs the policy engine in dry-run mode
/// ([`aa_gateway::engine::PolicyEngine::simulate`]) with no state mutation, no
/// budget debit, no audit write, and no enforcement side effect.
#[utoipa::path(
    post,
    path = "/api/v1/policies/simulate",
    request_body = SimulatePolicyRequest,
    responses(
        (status = 200, description = "Dry-run verdict for the hypothetical request", body = SimulatePolicyResponse),
        (status = 403, description = "Caller lacks read scope")
    ),
    tag = "policies"
)]
pub async fn simulate_policy(
    // AAASM-5037: simulation reveals policy behavior for a probe request, so
    // require read scope. Unlike list/active (which additionally gate on Admin
    // because they disclose the full cross-tenant policy YAML), this endpoint
    // returns only a single verdict and mutates nothing, so plain Read suffices.
    RequireRead(_caller): RequireRead,
    Extension(state): Extension<AppState>,
    Json(body): Json<SimulatePolicyRequest>,
) -> Result<(StatusCode, Json<SimulatePolicyResponse>), ProblemDetail> {
    // Build the hypothetical agent context, mirroring the gRPC request→core
    // conversion (`aa_gateway::service::convert`) so a simulated request maps to
    // the same AgentId a live request for this agent would — a registered
    // agent's authoritative org/team lineage is then honored by the engine.
    let agent_id = AgentId::from_bytes(hash_to_16(&body.agent_id));
    let session_id = SessionId::from_bytes(hash_to_16("simulate"));

    let mut metadata = BTreeMap::new();
    if let Some(org) = body.org_id.as_deref().filter(|s| !s.is_empty()) {
        metadata.insert("org_id".to_string(), org.to_string());
    }
    if let Some(team) = body.team_id.as_deref().filter(|s| !s.is_empty()) {
        metadata.insert("team_id".to_string(), team.to_string());
    }

    let ctx = AgentContext {
        agent_id,
        session_id,
        pid: 0,
        started_at: Timestamp::from_nanos(0),
        metadata,
        governance_level: aa_core::GovernanceLevel::default(),
        parent_agent_id: None,
        team_id: None,
        depth: 0,
        delegation_reason: None,
        spawned_by_tool: None,
        root_agent_id: None,
    };

    // Encode the optional target into the tool-call args so target-sensitive
    // policy predicates and the credential/PII scan see it.
    let args = match body.target.as_deref().filter(|s| !s.is_empty()) {
        Some(target) => serde_json::json!({ "target": target }).to_string(),
        None => "{}".to_string(),
    };
    let action = GovernanceAction::ToolCall {
        name: body.tool.clone(),
        args,
    };

    // Dry-run: `simulate` runs the same pipeline as the live `evaluate` but on a
    // throwaway engine, so no rate token is consumed, no cache is touched, no
    // budget window is reset, and nothing is persisted.
    let eval = state.policy_engine.simulate(&ctx, &action);

    let redacted = !eval.credential_findings.is_empty();
    let (verdict, matched_rule, reason) = match &eval.decision {
        // Allowed, but the scanner would scrub sensitive content first — the
        // request is narrowed rather than passed through verbatim.
        aa_core::PolicyResult::Allow if redacted => (
            "narrow",
            Some("sensitive content scrubbed".to_string()),
            "allowed after redacting sensitive content".to_string(),
        ),
        aa_core::PolicyResult::Allow => ("allow", None, "allowed by policy".to_string()),
        aa_core::PolicyResult::Deny { reason } => ("deny", Some(reason.clone()), reason.clone()),
        aa_core::PolicyResult::RequiresApproval { timeout_secs } => (
            "approval",
            Some("requires_approval".to_string()),
            format!("human approval required (timeout {timeout_secs}s)"),
        ),
    };

    Ok((
        StatusCode::OK,
        Json(SimulatePolicyResponse {
            verdict: verdict.to_string(),
            matched_rule,
            reason,
            redacted,
        }),
    ))
}
