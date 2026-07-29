//! Policy management endpoints.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

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
use aa_gateway::policy::{PolicyDocument, PolicyValidator};
use aa_gateway::registry::AgentRecord;
use aa_gateway::service::convert::hash_to_16;

use crate::auth::policy_auth::{PolicyAuthorizationDenied, PolicyWriteAuth};
use crate::auth::scope::{RequireRead, Scope};
use crate::auth::AuthenticatedCaller;
use crate::error::ProblemDetail;
use crate::pagination::PaginationParams;
use crate::routes::topology::record_visible_to;
use crate::state::AppState;

// ---------------------------------------------------------------------------
// Policy reach — which agents a policy document is in force for (AAASM-5096)
// ---------------------------------------------------------------------------

/// Grouping key for a policy document as the live cascade sees it: its scope
/// label plus its `metadata.name`.
///
/// Deliberately the same key `capability::collect_policy_rows` builds, so the
/// Policy list, the capability matrix and the team view all name one document
/// the same way. A runtime `PolicyDocument` carries no id or digest, so this
/// pair is the only *nameable* handle available — see [`policy_key`].
///
/// It is explicitly **not** an identity. `policy_version` is not part of it (it
/// is not part of `PolicyDocument`'s identity either), so every historical
/// version of `global/baseline` shares one key with the live one, and in the
/// flat/non-envelope format — where `name` is `None` — every unnamed document at
/// a scope collapses to a single key. Anything that must know *which* document
/// it is holding therefore compares whole documents, not keys: see [`DocSet`]
/// and [`affects_for`].
type PolicyKey = (String, Option<String>);

/// The distinct live documents the cascade carries under one [`PolicyKey`].
///
/// Exists because a key is a grouping handle, not an identity: two different
/// documents can share one. Keeping every distinct document lets a caller tell
/// an unambiguous key from a colliding one instead of silently reporting
/// whichever the registry walk happened to reach first.
#[derive(Debug, Default)]
struct DocSet(Vec<Arc<PolicyDocument>>);

impl DocSet {
    /// Record `doc` unless an equal document is already held. `PolicyDocument`
    /// is `PartialEq` over its whole validated content, so equality here means
    /// "the same document", not "the same name".
    fn insert(&mut self, doc: Arc<PolicyDocument>) {
        if !self.0.iter().any(|held| **held == *doc) {
            self.0.push(doc);
        }
    }

    /// The one document under this key, or `None` when the key is ambiguous —
    /// either unused (impossible for an inserted key) or shared by two distinct
    /// documents, in which case nothing derived from "the" document can be
    /// stated truthfully.
    fn unique(&self) -> Option<&Arc<PolicyDocument>> {
        match self.0.as_slice() {
            [only] => Some(only),
            _ => None,
        }
    }

    /// `metadata.version` of the unambiguous document under this key. Absent
    /// when the key is shared, rather than reporting one colliding document's
    /// revision as if it were the other's.
    fn version(&self) -> Option<String> {
        self.unique().and_then(|doc| doc.policy_version.clone())
    }

    /// AAASM-5107 — content digest of the unambiguous document under this key,
    /// the identity a per-document hit count joins on. Absent when the key is
    /// shared by two distinct live documents (nothing "the" document could be
    /// counted for).
    fn digest(&self) -> Option<String> {
        self.unique().map(|doc| doc.content_digest())
    }
}

/// Which agents a cascade-carried policy document is in force for, together with
/// the document(s) that claim it, so a caller can verify a stored snapshot really
/// is the document the engine carries before inheriting its reach.
#[derive(Debug, Default)]
struct PolicyReach {
    docs: DocSet,
    agents: BTreeSet<String>,
}

/// The live policy cascade for one agent, resolved through an **explicit**
/// lineage.
///
/// `PolicyEngine::collect_cascade` resolves the lineage through the engine's own
/// registry handle. aa-api's engine is built without one (AAASM-5102), so that
/// path yields a default `Lineage` and silently walks only the Global and Agent
/// tiers — every Org- and Team-scoped document drops out and any projection
/// built on it under-reports. Resolving the lineage from the registry here and
/// passing it in keeps all four tiers present regardless of how the engine was
/// constructed. `capability::project_matrix` and `topology::project_graph_nodes`
/// apply the same workaround for the same reason.
///
/// **The `tool:` tier is out of reach here, by construction.**
/// `collect_cascade_with_lineage` walks Global → Org → Team → Agent only;
/// `PolicyEngine::evaluate` appends the `tool:`-scoped tier itself, selected from
/// the tool name of the action being evaluated (AAASM-3981). Tool selection is
/// therefore per-action, and no projection built from an agent alone can name it.
/// A `tool:`-scoped document that *is* enforced consequently never appears in
/// `PolicyResponse::affects` or on the team mapping. That is a reporting gap, not
/// an enforcement one — nothing here decides anything — and closing it needs a
/// per-(agent, tool) surface rather than a per-agent one.
fn cascade_for(state: &AppState, record: &AgentRecord) -> Vec<Arc<PolicyDocument>> {
    let agent_id = AgentId::from_bytes(record.agent_id);
    let lineage = state.agent_registry.lineage(&record.agent_id).unwrap_or_default();
    state.policy_engine.collect_cascade_with_lineage(&agent_id, &lineage)
}

/// The cascade-visible identity of `doc`.
fn policy_key(doc: &PolicyDocument) -> PolicyKey {
    (doc.scope.to_string(), doc.name.clone())
}

/// Stable display id for a policy document — scope-qualified so two same-named
/// documents at different tiers stay distinguishable. Matches the `id` the
/// capability matrix emits for the same document.
fn policy_display_id(key: &PolicyKey) -> String {
    match &key.1 {
        Some(name) => format!("{}/{name}", key.0),
        None => key.0.clone(),
    }
}

/// Map every policy document currently in force to the names of the agents it
/// is in force for.
///
/// Membership only: a document is reported for an agent because it sits in that
/// agent's cascade, which is what "this policy targets that agent" means. It is
/// **not** a claim that the policy blocks anything for that agent — deciding
/// that needs an action to evaluate, and `aa_gateway::engine::decision`'s
/// `evaluate_single_doc` runs `stage_network` → `stage_tool_allow` →
/// `stage_capability` → `stage_approval` and returns on the first deny, so an
/// allow/deny answer is per-action, not per-document. No stage of that evaluator
/// is mirrored here precisely because nothing on this surface asserts a verdict;
/// the mirrors in `super::enforcement_mirror` exist for the surfaces that do.
///
/// Tenant-scoped: only agents the caller may see contribute, so the reach set can
/// never name an agent the caller could not otherwise read.
fn policy_reach(state: &AppState, caller: &AuthenticatedCaller) -> BTreeMap<PolicyKey, PolicyReach> {
    let mut reach: BTreeMap<PolicyKey, PolicyReach> = BTreeMap::new();
    for record in state.agent_registry.list() {
        if !record_visible_to(caller, &record) {
            continue;
        }
        for doc in cascade_for(state, &record) {
            let entry = reach.entry(policy_key(&doc)).or_default();
            entry.agents.insert(record.name.clone());
            entry.docs.insert(doc);
        }
    }
    reach
}

/// Parse a stored policy snapshot back into the document the engine would load.
///
/// Returns `None` for an empty or invalid snapshot: the row then reports no
/// reach at all rather than guessing one from a document it could not read.
///
/// The blank check is not redundant. A snapshot the history store could not
/// resolve arrives here as `""`, and `PolicyValidator::from_yaml("")` **succeeds**
/// — every section is optional, so it yields a permissive default document that
/// declares no name and defaults to `PolicyScope::Global`. That document keys
/// onto `("global", None)`, exactly the key an unnamed global policy occupies, so
/// letting it through would let an unreadable snapshot inherit the reach of a
/// document nobody could show it is. Reject it before it can key onto anything.
fn document_from_yaml(yaml: &str) -> Option<PolicyDocument> {
    if yaml.trim().is_empty() {
        return None;
    }
    PolicyValidator::from_yaml(yaml).ok().map(|out| out.document)
}

/// The agents a stored policy version is in force for, or `None` when that
/// cannot be established.
///
/// The snapshot must parse **and** be equal to the one document the live cascade
/// carries under its key. Matching on the key alone is not enough: the key omits
/// `policy_version`, so with `include_archived=true` every superseded snapshot of
/// e.g. `global/baseline` would key onto the live document and inherit its full
/// reach — asserting that a retired version is in force. Comparing whole
/// documents (`PolicyDocument: PartialEq`) is the strongest identity available,
/// since a runtime document carries no id or digest; where it cannot decide —
/// an unreadable snapshot, or a key shared by two distinct live documents — the
/// answer is the conservative absent, never an inherited reach.
fn affects_for(yaml: &str, reach: &BTreeMap<PolicyKey, PolicyReach>) -> Option<Vec<String>> {
    let doc = document_from_yaml(yaml)?;
    let entry = reach.get(&policy_key(&doc))?;
    let live = entry.docs.unique()?;
    (**live == doc).then(|| entry.agents.iter().cloned().collect())
}

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
    /// Names of the agents this policy version is in force for — the agents
    /// whose live policy cascade carries this document (AAASM-5096).
    ///
    /// Absent, never `[]`, when the version is not in force for any agent the
    /// caller may see: an archived version, or one whose document the running
    /// engine does not carry. `[]` would assert "this policy targets nobody",
    /// which is a different and stronger claim than "not currently loaded".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub affects: Option<Vec<String>>,
    /// Number of times this policy document fired in the last 24 hours.
    ///
    /// Sourced (AAASM-5107) by joining this row's document content digest against
    /// the per-document decision counts tallied from the last-24h audit window —
    /// each policy decision now records the deciding document's digest on its
    /// audit entry (`AuditEntry::policy_doc_id`, stamped at the enforcement
    /// boundary from `PolicyDocument::content_digest`). The digest distinguishes
    /// two versions of the same `(scope, name)` pair.
    ///
    /// **Absent, never `0`.** A document that recorded no decision in the window,
    /// a row whose snapshot cannot be parsed to a digest, or a key shared by two
    /// distinct live documents (no single "the" document to count) all report
    /// absent — preserving the absent-vs-"fired zero times" distinction
    /// AAASM-5096 established. The same sourcing applies to the capability
    /// matrix's `Policy.hits24h`.
    #[serde(default, rename = "hits24h", skip_serializing_if = "Option::is_none")]
    pub hits_24h: Option<u64>,
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

    // Resolved once per request, not per row: the walk is O(visible agents) and
    // every row looks its document up in the same map.
    let reach = policy_reach(&state, &caller);
    // AAASM-5107 — per-document 24h decision counts, read once per request. A row
    // whose parsed document fired at least once carries `hits24h`; one that did
    // not stays absent (never 0) — see [`crate::routes::policy_hits`].
    let hits = crate::routes::policy_hits::PolicyHitCounts::from_window(&state.audit_reader).await;

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
        // The deciding-document digest is the content digest of the parsed
        // snapshot — the same identity the gateway stamps on the audit write, so
        // this joins to the recorded hits even across two versions of one
        // (scope, name). An unreadable snapshot yields no digest → absent.
        let hits_24h = document_from_yaml(&yaml).and_then(|doc| hits.count(&doc.content_digest()));
        items.push(PolicyResponse {
            name: meta.sha256[..12].to_string(),
            version: meta.timestamp,
            active: i == 0 && params.page() == 1,
            rule_count: 0,
            affects: affects_for(&yaml, &reach),
            hits_24h,
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
            // `apply_yaml` swaps the primary slot only — it never inserts into
            // the engine's scope index — so the version just applied is in no
            // agent's cascade yet and has no reach to report. The list endpoint
            // resolves it once the engine carries the document.
            affects: None,
            hits_24h: None,
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
            affects: affects_for(&policy_yaml, &policy_reach(&state, &caller)),
            hits_24h: None,
            policy_yaml,
        }),
    ))
}

// ---------------------------------------------------------------------------
// Team → policy mapping (AAASM-5096)
// ---------------------------------------------------------------------------

/// One policy document in force for a team, as shown on the Teams surface's
/// Active-policies card (`design/v1/hi-fi/teams.jsx`).
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct TeamPolicyResponse {
    /// Scope-qualified document id (`"{scope}/{name}"`, or the bare scope for a
    /// document declaring no `metadata.name`). Matches the id the capability
    /// matrix emits for the same document.
    pub id: String,
    /// The document's `metadata.name`, falling back to its scope label when the
    /// document declares none (the flat, non-envelope policy format).
    pub name: String,
    /// The document's declared scope (`global` / `org:x` / `team:x` / `agent:x`),
    /// so the card can show which tier of the cascade the policy comes from.
    pub scope: String,
    /// Revision from the document's `metadata.version`. Absent for a document
    /// that declares none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Number of times this policy document fired in the last 24 hours. Sourced
    /// from per-document decision counts (AAASM-5107); absent, never `0`, when
    /// the document recorded no decision in the window — see
    /// [`PolicyResponse::hits_24h`] for the full sourcing and absent-vs-zero rule.
    #[serde(default, rename = "hits24h", skip_serializing_if = "Option::is_none")]
    pub hits_24h: Option<u64>,
}

/// Response body for `GET /api/v1/policies/team/{team_id}` (AAASM-5096).
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct TeamPoliciesResponse {
    /// The team the mapping was resolved for, echoed from the request.
    pub team_id: String,
    /// Every policy document in force for at least one visible agent in the
    /// team, ordered by scope then name.
    ///
    /// **`null`, never `[]`, when the mapping could not be resolved** — the same
    /// absent-vs-empty discipline as [`PolicyResponse::affects`], and for a
    /// sharper reason. `[]` is a positive governance claim: "nothing governs this
    /// team". That claim is only true when the team has no agent this caller can
    /// see, so there is nothing for a policy to be in force over — the one case
    /// that serializes `[]`.
    ///
    /// When the team *does* have visible agents but not one of them resolved a
    /// cascade document, the honest answer is "unknown", not "none":
    /// `PolicyEngine::evaluate` falls back to `evaluate_primary` for exactly
    /// those agents, so the primary policy slot is still in force over them —
    /// this projection just cannot name it. That is the state of **every shipped
    /// aa-api deployment today**: `AppState::local_in_memory` loads the policy
    /// through `load_from_file`, which populates the primary slot and leaves
    /// `scope_index` empty, and nothing else in aa-api ever calls
    /// `load_cascade_from_dir` (AAASM-5106). Emitting `[]` there would render as
    /// "No policy is in force for this team" while a policy *is* being enforced.
    //
    // Required-but-nullable, not optional: the key is always on the wire, so a
    // client reads an explicit `null` it has to handle rather than a missing
    // field it can shrug off with `?? []` — which is precisely how "unknown"
    // would decay back into "none".
    #[schema(required = true)]
    pub policies: Option<Vec<TeamPolicyResponse>>,
}

/// `GET /api/v1/policies/team/{team_id}` — policies in force for one team.
///
/// Read-only inverse of [`PolicyResponse::affects`]: the union of the policy
/// cascades of the team's agents, deduplicated by document. Backs the Teams
/// surface's Active-policies card (AAASM-5080 / AAASM-5096).
///
/// It is a separate path rather than a field on `GET /api/v1/policies` because
/// that endpoint is Admin-only — it discloses every tenant's raw policy YAML —
/// while a team's own operator must be able to read the policies governing its
/// team. This endpoint discloses no YAML, only document identities, so plain
/// Read plus membership in the requested team is the right gate.
///
/// Deny-by-default and tenant-scoped: a non-admin caller may only ask about its
/// own team, and each member is additionally filtered through the shared
/// `record_visible_to` org+team check, so no agent outside the caller's tenant
/// contributes a document.
///
/// Returns `policies: null` rather than `[]` when the team has agents but no
/// resolvable cascade — see [`TeamPoliciesResponse::policies`] for why the two
/// must not collapse.
#[utoipa::path(
    get,
    path = "/api/v1/policies/team/{team_id}",
    params(("team_id" = String, Path, description = "Team identifier")),
    responses(
        (status = 200, description = "Policies in force for the team", body = TeamPoliciesResponse),
        (status = 403, description = "Caller lacks admin scope or membership in this team")
    ),
    tag = "policies"
)]
pub async fn list_team_policies(
    RequireRead(caller): RequireRead,
    Extension(state): Extension<AppState>,
    axum::extract::Path(team_id): axum::extract::Path<String>,
) -> Result<(StatusCode, Json<TeamPoliciesResponse>), ProblemDetail> {
    if !caller.can_access_team(&team_id) {
        return Err(ProblemDetail::from_status(StatusCode::FORBIDDEN)
            .with_detail("reading a team's policies requires admin scope or membership in that team".to_string()));
    }

    let (by_key, visible_members) = team_cascade(&state, &caller, &team_id);

    // AAASM-5107 — per-document 24h decision counts, read once per request.
    let hits = crate::routes::policy_hits::PolicyHitCounts::from_window(&state.audit_reader).await;

    // Absent, not empty, when the team has agents whose cascade resolved nothing:
    // those agents fall back to the primary policy slot, which this projection
    // cannot enumerate (AAASM-5106). `[]` is reserved for the one case where
    // "nothing is in force" is actually true — no visible agent to govern.
    let policies = if by_key.is_empty() && visible_members > 0 {
        None
    } else {
        Some(
            by_key
                .into_iter()
                .map(|(key, docs)| TeamPolicyResponse {
                    id: policy_display_id(&key),
                    name: key.1.clone().unwrap_or_else(|| key.0.clone()),
                    scope: key.0.clone(),
                    version: docs.version(),
                    // Only an unambiguous key names one document, so only then can
                    // a hit count be attributed; a key shared by two distinct live
                    // documents stays absent rather than summing colliding docs.
                    hits_24h: docs.digest().and_then(|d| hits.count(&d)),
                })
                .collect(),
        )
    };

    Ok((StatusCode::OK, Json(TeamPoliciesResponse { team_id, policies })))
}

/// Union the cascades of every agent in `team_id` the caller may see.
///
/// Returns the documents grouped by [`PolicyKey`] (ordered by scope then name,
/// one entry per key however many members carry it) **and** the number of
/// visible members walked — the caller needs the latter to tell "no agent to
/// govern" from "agents whose cascade resolved nothing".
fn team_cascade(state: &AppState, caller: &AuthenticatedCaller, team_id: &str) -> (BTreeMap<PolicyKey, DocSet>, usize) {
    let mut by_key: BTreeMap<PolicyKey, DocSet> = BTreeMap::new();
    let mut visible_members = 0usize;
    for member in state.agent_registry.team_members(team_id) {
        let Some(record) = state.agent_registry.get(&member) else {
            continue;
        };
        if !record_visible_to(caller, &record) {
            continue;
        }
        visible_members += 1;
        for doc in cascade_for(state, &record) {
            by_key.entry(policy_key(&doc)).or_default().insert(doc);
        }
    }
    (by_key, visible_members)
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

/// Dry-run verdict returned by `POST /api/v1/policies/simulate`.
///
/// AAASM-5220 — constrains the [`SimulatePolicyResponse::verdict`] wire
/// vocabulary to the closed set the simulate handler emits, so the generated
/// OpenAPI spec advertises an enum rather than a free-form `string`. Serializes
/// lowercase.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum SimulateVerdict {
    Allow,
    Narrow,
    Approval,
    Deny,
}

/// Response body for `POST /api/v1/policies/simulate` (AAASM-5037).
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct SimulatePolicyResponse {
    /// Dry-run verdict: `allow`, `narrow`, `approval`, or `deny`.
    pub verdict: SimulateVerdict,
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
            SimulateVerdict::Narrow,
            Some("sensitive content scrubbed".to_string()),
            "allowed after redacting sensitive content".to_string(),
        ),
        aa_core::PolicyResult::Allow => (SimulateVerdict::Allow, None, "allowed by policy".to_string()),
        aa_core::PolicyResult::Deny { reason } => (SimulateVerdict::Deny, Some(reason.clone()), reason.clone()),
        aa_core::PolicyResult::RequiresApproval { timeout_secs } => (
            SimulateVerdict::Approval,
            Some("requires_approval".to_string()),
            format!("human approval required (timeout {timeout_secs}s)"),
        ),
    };

    Ok((
        StatusCode::OK,
        Json(SimulatePolicyResponse {
            verdict,
            matched_rule,
            reason,
            redacted,
        }),
    ))
}

// ---------------------------------------------------------------------------
// Policy-impact traffic replay (AAASM-5094)
// ---------------------------------------------------------------------------

/// Default corpus window for `POST /api/v1/policies/replay` when the caller
/// supplies no `window_hours`: the last 24 hours of recorded traffic.
const REPLAY_DEFAULT_WINDOW_HOURS: u64 = 24;

/// Upper bound on audit events a single replay pulls from the audit log,
/// matching the analytics/policy-hits 100k cap so a hot window can never turn
/// one replay into an unbounded scan (AAASM-4145 / AAASM-5107).
const REPLAY_MAX_EVENTS: usize = 100_000;

/// Default number of per-request before/after diffs returned when the caller
/// supplies no `sample_size`.
const REPLAY_DEFAULT_SAMPLE_SIZE: usize = 10;

/// Hard ceiling on `sample_size` so a caller cannot ask the response to carry
/// an unbounded number of sample diffs.
const REPLAY_MAX_SAMPLE_SIZE: usize = 100;

/// Request body for `POST /api/v1/policies/replay` (AAASM-5094).
///
/// Describes a *proposed* (unloaded) policy plus the corpus window to replay it
/// against. Nothing here is persisted and the proposed policy is never applied —
/// it is a pure, read-only what-if over recorded traffic.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct ReplayPolicyRequest {
    /// Proposed policy document as raw YAML. Parsed and validated exactly like a
    /// `create_policy` body, but evaluated through an ephemeral engine
    /// ([`aa_gateway::engine::PolicyEngine::simulate_against`]) so it is never
    /// loaded, applied, or persisted.
    pub policy_yaml: String,
    /// How many hours of recent recorded traffic to replay. Defaults to
    /// [`REPLAY_DEFAULT_WINDOW_HOURS`] (24h) when omitted. The read is bounded to
    /// the most recent [`REPLAY_MAX_EVENTS`] events within the window.
    #[serde(default)]
    pub window_hours: Option<u64>,
    /// Maximum number of per-request before/after sample diffs to return.
    /// Defaults to [`REPLAY_DEFAULT_SAMPLE_SIZE`], capped at
    /// [`REPLAY_MAX_SAMPLE_SIZE`]. Does not affect the aggregate counts, which
    /// always reflect the whole replayed corpus.
    #[serde(default)]
    pub sample_size: Option<usize>,
}

/// One per-request before/after diff in a replay response: the recorded verdict
/// vs. the verdict the proposed policy would have produced for the same action.
///
/// Only entries whose verdict actually *changed* are returned as samples — an
/// unchanged entry carries no impact to illustrate.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ReplaySampleDiff {
    /// Tool/capability the recorded action invoked (from the audit entry's
    /// persisted `detail.tool_name`).
    pub tool: String,
    /// Verdict recorded when this action actually ran, mapped from the audit
    /// entry's persisted decision.
    pub before: SimulateVerdict,
    /// Verdict the proposed policy would produce for the same action.
    pub after: SimulateVerdict,
}

/// Response body for `POST /api/v1/policies/replay` (AAASM-5094).
///
/// Aggregate impact of the proposed policy over the replayed corpus, plus a
/// bounded sample of the per-request verdict changes. Every count is a real
/// tally of re-evaluating recorded actions — an empty corpus yields all-zero
/// counts and no samples, never a fabricated figure.
///
/// ## Fidelity caveat
///
/// The audit log deliberately persists only non-secret action *metadata* (tool
/// name, path, host) and never the raw tool arguments/target
/// (`aa_runtime::audit_publisher::conversion::build_payload`). Replay therefore
/// reconstructs each action from its persisted tool name with **empty
/// arguments**, so target-sensitive predicates and the credential/PII scrubber
/// cannot be re-exercised from the corpus. Verdict changes driven purely by
/// per-tool allow/deny/approval rules are faithful; changes that would depend on
/// argument content are out of reach and are not counted. See
/// [`replayable_actions`] and the endpoint doc comment.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ReplayPolicyResponse {
    /// Number of corpus entries the proposed policy would newly block (recorded
    /// verdict allowed/narrowed/approval, proposed verdict `deny`).
    pub newly_blocked: u64,
    /// Number of corpus entries the proposed policy would newly narrow — allowed
    /// but with sensitive content scrubbed (recorded verdict `allow`, proposed
    /// verdict `narrow`).
    pub newly_narrowed: u64,
    /// Number of corpus entries whose recorded verdict was a block/deny but the
    /// proposed policy would now allow — a regression that opens previously
    /// closed traffic.
    pub regressions: u64,
    /// Number of corpus entries whose recorded verdict was a clean `allow` but
    /// the proposed policy would now require human approval — a false-positive /
    /// friction increase short of an outright block.
    pub false_positives: u64,
    /// Total corpus entries replayed (tool-call decisions in the window that
    /// carried a recorded verdict and a tool name). Denominator for the counts
    /// above; `0` when the corpus is empty.
    pub replayed: u64,
    /// A bounded sample of the per-request verdict changes, capped by the
    /// request's `sample_size`. Empty when no verdict changed.
    pub samples: Vec<ReplaySampleDiff>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::Tenant;
    use aa_gateway::registry::AgentRecord;

    fn caller(scopes: Vec<Scope>, org_id: Option<&str>, team_id: Option<&str>) -> RequireRead {
        RequireRead(AuthenticatedCaller {
            key_id: "k".to_string(),
            scopes,
            tenant: Tenant {
                team_id: team_id.map(str::to_string),
                org_id: org_id.map(str::to_string),
            },
        })
    }

    fn admin() -> RequireRead {
        caller(vec![Scope::Admin], None, None)
    }

    /// Minimal registered agent; only the fields the reach walk reads carry
    /// meaningful values.
    fn record(id_byte: u8, name: &str, org_id: Option<&str>, team_id: Option<&str>) -> AgentRecord {
        AgentRecord {
            agent_id: [id_byte; 16],
            name: name.to_string(),
            framework: "langgraph".to_string(),
            version: "0.1.0".to_string(),
            risk_tier: 1,
            tool_names: Vec::new(),
            public_key: "pk".to_string(),
            credential_token: "tok".to_string(),
            metadata: std::collections::BTreeMap::new(),
            registered_at: chrono::Utc::now(),
            last_heartbeat: chrono::Utc::now(),
            status: aa_gateway::registry::AgentStatus::Active,
            pid: None,
            session_count: 0,
            last_event: None,
            policy_violations_count: 0,
            active_sessions: Vec::new(),
            recent_events: std::collections::VecDeque::new(),
            recent_traces: Vec::new(),
            layer: None,
            governance_level: aa_core::GovernanceLevel::default(),
            parent_agent_id: None,
            team_id: team_id.map(str::to_string),
            org_id: org_id.map(str::to_string),
            depth: 0,
            delegation_reason: None,
            spawned_by_tool: None,
            root_agent_id: Some([id_byte; 16]),
            children: Vec::new(),
            parent_key: None,
            enforcement_mode: None,
        }
    }

    /// A policy document scoped to one team, at an explicit revision.
    ///
    /// Deliberately Team-scoped: a reach walk that resolved the cascade without
    /// an explicit lineage would never see it, so every assertion built on it is
    /// a regression guard for that.
    fn versioned_team_yaml(name: &str, team: &str, version: &str, allow: bool) -> String {
        format!(
            "apiVersion: agent-assembly/v1\nkind: Policy\nmetadata:\n  name: {name}\n  version: \"{version}\"\nspec:\n  scope: team:{team}\n  tools:\n    bash:\n      allow: {allow}\n"
        )
    }

    fn team_scoped_yaml(name: &str, team: &str) -> String {
        versioned_team_yaml(name, team, "1.0.0", false)
    }

    fn state_with(records: Vec<AgentRecord>) -> AppState {
        let state = AppState::local_in_memory().expect("state builds");
        for r in records {
            state.agent_registry.register(r).expect("register");
        }
        state
    }

    /// Load `yaml` into the engine's cascade **and** record it in the history
    /// store, mirroring a policy that was applied and is now in force.
    async fn install(state: &mut AppState, yaml: &str) {
        let doc = document_from_yaml(yaml).expect("fixture yaml is valid");
        let engine = Arc::get_mut(&mut state.policy_engine).expect("engine is unshared before the state is cloned");
        engine.load_policy(doc);
        state
            .policy_history
            .save(yaml, Some("test"))
            .await
            .expect("history accepts the snapshot");
    }

    /// Every version on one page, so `include_archived` results are all visible.
    fn all_pages() -> PaginationParams {
        PaginationParams {
            page: None,
            per_page: None,
        }
    }

    /// The serialized `items` array, asserted on as JSON so the test sees exactly
    /// the wire shape a client would — including which fields are omitted.
    async fn list_items(state: &AppState, who: RequireRead) -> Vec<serde_json::Value> {
        let response = list_policies(
            who,
            Extension(state.clone()),
            axum::extract::Query(all_pages()),
            axum::extract::Query(PolicyListFilter { include_archived: true }),
        )
        .await
        .expect("caller may list");
        let body = axum::body::to_bytes(response.into_response().into_body(), usize::MAX)
            .await
            .expect("body reads");
        let parsed: serde_json::Value = serde_json::from_slice(&body).expect("body is JSON");
        parsed["items"].as_array().expect("items is an array").clone()
    }

    async fn team_policies(state: &AppState, who: RequireRead, team: &str) -> TeamPoliciesResponse {
        let (status, Json(body)) =
            list_team_policies(who, Extension(state.clone()), axum::extract::Path(team.to_string()))
                .await
                .expect("caller may read this team");
        assert_eq!(status, StatusCode::OK);
        body
    }

    /// The serialized team-policies body, so the unknown/none distinction is
    /// asserted on the wire a client actually sees, not on the Rust `Option`.
    async fn team_policies_json(state: &AppState, who: RequireRead, team: &str) -> serde_json::Value {
        serde_json::to_value(team_policies(state, who, team).await).expect("body serializes")
    }

    // ── affects[] ───────────────────────────────────────────────────────────

    #[tokio::test]
    async fn affects_names_agents_whose_team_scoped_cascade_carries_the_policy() {
        let mut state = state_with(vec![
            record(0x01, "checkout-agent", None, Some("team-alpha")),
            record(0x02, "outsider", None, Some("team-beta")),
        ]);
        install(&mut state, &team_scoped_yaml("alpha-guard", "team-alpha")).await;

        let items = list_items(&state, admin()).await;
        assert_eq!(items.len(), 1, "one applied version");
        // The whole point: a Team-scoped document is only in the cascade when the
        // lineage is resolved explicitly. `collect_cascade` on aa-api's
        // registry-less engine walks Global+Agent only and would omit the field.
        assert_eq!(
            items[0]["affects"],
            serde_json::json!(["checkout-agent"]),
            "a team-scoped policy reaches exactly that team's agents, and only those"
        );
    }

    #[tokio::test]
    async fn affects_is_absent_not_empty_for_a_version_the_engine_does_not_carry() {
        let state = state_with(vec![record(0x01, "checkout-agent", None, Some("team-alpha"))]);
        // Recorded in history but never loaded into the engine — an archived
        // version, in force for nobody.
        state
            .policy_history
            .save(&team_scoped_yaml("retired", "team-alpha"), Some("test"))
            .await
            .expect("history accepts the snapshot");

        let items = list_items(&state, admin()).await;
        assert!(
            items[0].get("affects").is_none(),
            "a version not in force omits the field rather than claiming it targets nobody: {}",
            items[0]
        );
    }

    #[tokio::test]
    async fn hits_24h_is_always_absent_from_the_wire() {
        let mut state = state_with(vec![record(0x01, "checkout-agent", None, Some("team-alpha"))]);
        install(&mut state, &team_scoped_yaml("alpha-guard", "team-alpha")).await;

        let items = list_items(&state, admin()).await;
        // No audit record attributes a decision to a policy document, so the
        // count must be omitted — never serialized as a 0 the UI would render.
        assert!(
            items[0].get("hits24h").is_none(),
            "an absent hit count must be omitted, never serialized as 0: {}",
            items[0]
        );
    }

    #[tokio::test]
    async fn listing_policies_denies_a_caller_without_admin_scope() {
        let state = state_with(vec![record(0x01, "checkout-agent", None, Some("team-alpha"))]);
        let err = list_policies(
            caller(vec![Scope::Read], Some("acme"), Some("team-alpha")),
            Extension(state.clone()),
            axum::extract::Query(all_pages()),
            axum::extract::Query(PolicyListFilter { include_archived: true }),
        )
        .await
        .err()
        .expect("a tenant-scoped reader must not enumerate policy versions");
        assert_eq!(err.into_response().status(), StatusCode::FORBIDDEN);
    }

    // ── team → policy mapping ───────────────────────────────────────────────

    #[tokio::test]
    async fn team_policies_report_the_documents_in_force_for_that_team() {
        let mut state = state_with(vec![
            record(0x01, "checkout-agent", None, Some("team-alpha")),
            record(0x02, "outsider", None, Some("team-beta")),
        ]);
        install(&mut state, &team_scoped_yaml("alpha-guard", "team-alpha")).await;

        let body = team_policies(&state, admin(), "team-alpha").await;
        assert_eq!(body.team_id, "team-alpha");
        let policies = body
            .policies
            .as_ref()
            .expect("the cascade resolved, so the mapping is known");
        let ids: Vec<&str> = policies.iter().map(|p| p.id.as_str()).collect();
        assert!(
            ids.contains(&"team:team-alpha/alpha-guard"),
            "the team tier must appear — it is dropped entirely by an unlineaged cascade: {ids:?}"
        );
        let row = policies.iter().find(|p| p.id == "team:team-alpha/alpha-guard").unwrap();
        assert_eq!(row.name, "alpha-guard");
        assert_eq!(row.scope, "team:team-alpha");
        assert_eq!(row.version.as_deref(), Some("1.0.0"));
        assert!(row.hits_24h.is_none());

        // The other team does not inherit it. team-beta's agent resolves no
        // cascade document at all, so the honest answer there is "unknown".
        let beta = team_policies(&state, admin(), "team-beta").await;
        assert!(
            beta.policies.is_none(),
            "a team-scoped document must not leak into another team: {:?}",
            beta.policies
        );
    }

    #[tokio::test]
    async fn team_policies_are_empty_for_a_team_with_no_agents() {
        let mut state = state_with(vec![]);
        install(&mut state, &team_scoped_yaml("alpha-guard", "team-alpha")).await;

        // No visible member means nothing for a policy to be in force over, so
        // "none" is a claim the endpoint can actually make — `[]`, not `null`.
        let body = team_policies_json(&state, admin(), "team-alpha").await;
        assert_eq!(
            body["policies"],
            serde_json::json!([]),
            "no visible member means no cascade to union, not an invented one: {body}"
        );
    }

    #[tokio::test]
    async fn team_policies_are_unknown_not_empty_when_the_engine_carries_no_cascade() {
        // A registered, visible team member — but nothing loaded into the
        // engine's scope index. This is every shipped aa-api deployment
        // (AAASM-5106): `evaluate` falls back to the primary policy slot, so a
        // policy IS in force over this agent; it just cannot be named here.
        let state = state_with(vec![record(0x01, "checkout-agent", None, Some("team-alpha"))]);

        let body = team_policies_json(&state, admin(), "team-alpha").await;
        assert_eq!(
            body["policies"],
            serde_json::Value::Null,
            "an unresolvable mapping must be null — `[]` would assert that nothing governs \
             this team while the primary slot is enforcing: {body}"
        );
    }

    #[tokio::test]
    async fn team_policies_deny_a_caller_scoped_to_a_different_team() {
        let state = state_with(vec![record(0x01, "checkout-agent", None, Some("team-alpha"))]);
        let err = list_team_policies(
            caller(vec![Scope::Read], None, Some("team-beta")),
            Extension(state.clone()),
            axum::extract::Path("team-alpha".to_string()),
        )
        .await
        .expect_err("a caller scoped to another team must be denied");
        assert_eq!(err.into_response().status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn team_policies_exclude_members_outside_the_callers_org() {
        let mut state = state_with(vec![record(
            0x01,
            "checkout-agent",
            Some("other-org"),
            Some("team-alpha"),
        )]);
        install(&mut state, &team_scoped_yaml("alpha-guard", "team-alpha")).await;

        // Same team name, different org: the member is out of tenant, so it
        // contributes nothing and the caller learns nothing about it — not even
        // that it exists, which is why this reads as "no visible agent" (`[]`)
        // and not as the unknown state.
        let body = team_policies_json(
            &state,
            caller(vec![Scope::Read], Some("acme"), Some("team-alpha")),
            "team-alpha",
        )
        .await;
        assert_eq!(
            body["policies"],
            serde_json::json!([]),
            "an out-of-tenant member must not contribute its cascade: {body}"
        );
    }

    #[tokio::test]
    async fn team_policy_version_is_absent_when_two_documents_share_one_key() {
        let mut state = state_with(vec![record(0x01, "checkout-agent", None, Some("team-alpha"))]);
        // Same scope and same metadata.name, different revisions — one
        // `(scope, name)` key, two distinct live documents.
        install(
            &mut state,
            &versioned_team_yaml("alpha-guard", "team-alpha", "1.0.0", false),
        )
        .await;
        install(
            &mut state,
            &versioned_team_yaml("alpha-guard", "team-alpha", "2.0.0", false),
        )
        .await;

        let body = team_policies(&state, admin(), "team-alpha").await;
        let policies = body.policies.expect("the cascade resolved");
        let row = policies
            .iter()
            .find(|p| p.id == "team:team-alpha/alpha-guard")
            .expect("the colliding key still names one row");
        assert!(
            row.version.is_none(),
            "with two documents under one key the revision is unknowable — reporting whichever \
             was walked first would attribute one document's revision to the other: {:?}",
            row.version
        );
    }

    // ── document identity ───────────────────────────────────────────────────

    #[tokio::test]
    async fn affects_is_absent_for_a_superseded_version_of_the_live_policys_name() {
        let mut state = state_with(vec![record(0x01, "checkout-agent", None, Some("team-alpha"))]);
        // v1 is archived: recorded in history, never loaded. v2 is live. They
        // share a `(scope, name)` key and differ only in `metadata.version`, so
        // a key-only match would hand v1 the live document's whole reach.
        state
            .policy_history
            .save(
                &versioned_team_yaml("alpha-guard", "team-alpha", "1.0.0", false),
                Some("test"),
            )
            .await
            .expect("history accepts the snapshot");
        install(
            &mut state,
            &versioned_team_yaml("alpha-guard", "team-alpha", "2.0.0", false),
        )
        .await;

        let items = list_items(&state, admin()).await;
        assert_eq!(items.len(), 2, "both versions are visible with include_archived");
        // Selected by content, not by position: both snapshots land in the same
        // history millisecond, so their relative order is not meaningful.
        let find = |revision: &str| {
            items
                .iter()
                .find(|item| item["policy_yaml"].as_str().unwrap_or_default().contains(revision))
                .unwrap_or_else(|| panic!("the {revision} snapshot is listed"))
                .clone()
        };
        let live = find("2.0.0");
        let superseded = find("1.0.0");
        assert_eq!(
            live["affects"],
            serde_json::json!(["checkout-agent"]),
            "the live version reports its real reach: {live}"
        );
        assert!(
            superseded.get("affects").is_none(),
            "a superseded version of the SAME name must not inherit the live document's reach: {superseded}"
        );
    }

    #[test]
    fn document_from_yaml_rejects_an_unreadable_snapshot() {
        // A snapshot the history store could not resolve arrives as "". It must
        // not parse into a permissive default `(global, None)` document, which
        // would key onto whatever global document the engine carries and inherit
        // its reach.
        assert!(document_from_yaml("").is_none(), "an empty snapshot is not a document");
        assert!(
            document_from_yaml("this is not: [valid: yaml").is_none(),
            "an unparseable snapshot is not a document"
        );
    }
}
