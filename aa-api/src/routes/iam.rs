//! Identity & Access (`/api/v1/iam/...`) endpoints (AAASM-1397).
//!
//! Backs the dashboard's Identity & Access page (AAASM-119). The store is
//! [`aa_gateway::iam::IamApiKeyStore`] — see `iam/mod.rs` there for the
//! deliberate boundary against `aa-api::auth::api_key`, which authenticates
//! *incoming* bearer tokens.

use std::sync::Arc;

use aa_gateway::iam::{
    api_keys::{RevokeError, RotateError},
    ApiKeyEntry, ApiKeyScope as GwApiKeyScope, ApiKeyStatus as GwApiKeyStatus, GeneratedApiKey as GwGeneratedApiKey,
    IamApiKeyStore, RecentActivityEntry,
};
use aa_gateway::policy::rbac::{required_role_for, CallerRole, MutationKind};
use aa_gateway::policy::scope::PolicyScope;
use axum::extract::Path;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::{Extension, Json};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::auth::policy_auth::{PolicyAuthorizationDenied, PolicyWriteAuth};
use crate::auth::scope::{RequireAdmin, RequireRead};
use crate::error::ProblemDetail;
use crate::state::AppState;

// ── Wire types — mirror the dashboard's TypeScript ApiKey shape exactly. ──

/// Scopes a key may hold. Wire form matches the dashboard's TS union.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub enum ApiKeyScopeResponse {
    #[serde(rename = "read:members")]
    ReadMembers,
    #[serde(rename = "write:members")]
    WriteMembers,
    #[serde(rename = "read:policies")]
    ReadPolicies,
    #[serde(rename = "write:policies")]
    WritePolicies,
    #[serde(rename = "read:audit")]
    ReadAudit,
    #[serde(rename = "admin")]
    Admin,
}

impl From<GwApiKeyScope> for ApiKeyScopeResponse {
    fn from(s: GwApiKeyScope) -> Self {
        match s {
            GwApiKeyScope::ReadMembers => Self::ReadMembers,
            GwApiKeyScope::WriteMembers => Self::WriteMembers,
            GwApiKeyScope::ReadPolicies => Self::ReadPolicies,
            GwApiKeyScope::WritePolicies => Self::WritePolicies,
            GwApiKeyScope::ReadAudit => Self::ReadAudit,
            GwApiKeyScope::Admin => Self::Admin,
        }
    }
}

impl From<ApiKeyScopeResponse> for GwApiKeyScope {
    fn from(s: ApiKeyScopeResponse) -> Self {
        match s {
            ApiKeyScopeResponse::ReadMembers => Self::ReadMembers,
            ApiKeyScopeResponse::WriteMembers => Self::WriteMembers,
            ApiKeyScopeResponse::ReadPolicies => Self::ReadPolicies,
            ApiKeyScopeResponse::WritePolicies => Self::WritePolicies,
            ApiKeyScopeResponse::ReadAudit => Self::ReadAudit,
            ApiKeyScopeResponse::Admin => Self::Admin,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum ApiKeyStatusResponse {
    Active,
    Revoked,
}

impl From<GwApiKeyStatus> for ApiKeyStatusResponse {
    fn from(s: GwApiKeyStatus) -> Self {
        match s {
            GwApiKeyStatus::Active => Self::Active,
            GwApiKeyStatus::Revoked => Self::Revoked,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct RecentActivityResponse {
    pub id: String,
    pub timestamp: String,
    pub action: String,
    pub target: String,
}

impl From<RecentActivityEntry> for RecentActivityResponse {
    fn from(e: RecentActivityEntry) -> Self {
        Self {
            id: e.id,
            timestamp: e.timestamp.to_rfc3339(),
            action: e.action,
            target: e.target,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ApiKeyResponse {
    pub id: String,
    pub label: String,
    pub prefix: String,
    pub scopes: Vec<ApiKeyScopeResponse>,
    pub status: ApiKeyStatusResponse,
    pub created_at: String,
    pub last_used: Option<String>,
    pub owner: String,
    pub role: String,
    pub assigned_policies: Vec<String>,
    pub recent_activity: Vec<RecentActivityResponse>,
}

impl From<ApiKeyEntry> for ApiKeyResponse {
    fn from(e: ApiKeyEntry) -> Self {
        Self {
            id: e.id,
            label: e.label,
            prefix: e.prefix,
            scopes: e.scopes.into_iter().map(Into::into).collect(),
            status: e.status.into(),
            created_at: e.created_at.to_rfc3339(),
            last_used: e.last_used.map(|d| d.to_rfc3339()),
            owner: e.owner,
            role: e.role,
            assigned_policies: e.assigned_policies,
            recent_activity: e.recent_activity.into_iter().map(Into::into).collect(),
        }
    }
}

/// One-shot reveal shape returned by generate / rotate. `secret` MUST be
/// captured by the caller — the server does not store it.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct GeneratedApiKeyResponse {
    pub id: String,
    pub prefix: String,
    pub secret: String,
}

impl From<GwGeneratedApiKey> for GeneratedApiKeyResponse {
    fn from(g: GwGeneratedApiKey) -> Self {
        Self {
            id: g.id,
            prefix: g.prefix,
            secret: g.secret,
        }
    }
}

#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct GenerateApiKeyRequest {
    pub label: String,
    pub scopes: Vec<ApiKeyScopeResponse>,
}

// ── Role → capability grants (AAASM-5046) ──
//
// The dashboard's Identity → Roles tab (AAASM-5042) shipped role-capability
// cards backed by a *static* front-end catalogue behind a flag banner, because
// the gateway exposed no role→grant endpoint. This surfaces the real model.
//
// The authoritative role→capability data in the gateway is the
// `PolicyMutationRequiredRole` table in `aa-gateway/src/policy/rbac.rs`: it
// maps `(policy-scope, mutation) → minimum CallerRole`. There is deliberately
// no richer per-capability catalogue on the server — the grants below are
// *derived* from that table (exactly like `generate_policy_rbac_doc`), so this
// endpoint reflects the coarse policy-RBAC model faithfully rather than
// fabricating the design's richer catalogue.

/// One built-in RBAC role and the governance capabilities it grants.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct RoleCapabilitiesResponse {
    /// Canonical role identifier, snake_case (e.g. `org_admin`).
    pub role: String,
    /// Human-readable summary of what the role may do.
    pub description: String,
    /// Capability grant strings derived from the policy-RBAC table. Read grants
    /// (`read:policies` / `read:audit`) reflect each role's read authority;
    /// `write:policies:<scope>` grants come straight from `required_role_for`.
    pub capabilities: Vec<String>,
}

/// The 5 canonical roles, highest → lowest privilege — the render order the
/// dashboard cards expect.
const ROLE_ORDER: [CallerRole; 5] = [
    CallerRole::OrgAdmin,
    CallerRole::TeamAdmin,
    CallerRole::Developer,
    CallerRole::Viewer,
    CallerRole::Auditor,
];

/// Human-readable description per role, mirroring the role doc-comments in
/// `aa-gateway/src/policy/rbac.rs` (the single source of truth for role intent).
fn role_description(role: CallerRole) -> &'static str {
    match role {
        CallerRole::OrgAdmin => "Full policy mutation rights across all scopes.",
        CallerRole::TeamAdmin => "Can mutate team-scoped policies and below (Agent, Tool).",
        CallerRole::Developer => "Can mutate agent- and tool-scoped policies only.",
        CallerRole::Viewer => "Read-only access — no writes permitted.",
        CallerRole::Auditor => "Read-only audit access — no writes permitted.",
    }
}

/// Derive the capability grant list for `role` from the policy-RBAC table.
///
/// The write grants are computed the same way `generate_policy_rbac_doc` builds
/// `docs/src/policy-rbac.md`: for each policy scope, a role is granted
/// `write:policies:<scope>` iff it satisfies the minimum role the table
/// requires to mutate that scope. Read grants reflect the role's documented
/// read authority (`Auditor` is audit-scoped; every other role has standard
/// policy read). `MutationKind` does not change the required role, so any
/// mutation kind is representative here.
fn role_capabilities(role: CallerRole) -> Vec<String> {
    let mut caps = Vec::new();

    // Read authority: Auditor is audit-scoped; all others have standard read.
    caps.push(match role {
        CallerRole::Auditor => "read:audit".to_string(),
        _ => "read:policies".to_string(),
    });

    // Representative PolicyScope per scope kind (labels match the wire scope).
    let scopes: [(&str, PolicyScope); 5] = [
        ("global", PolicyScope::Global),
        ("org", PolicyScope::Org("*".into())),
        ("team", PolicyScope::Team("*".into())),
        (
            "agent",
            PolicyScope::Agent(aa_core::identity::AgentId::from_bytes([0u8; 16])),
        ),
        ("tool", PolicyScope::Tool("*".into())),
    ];

    for (label, scope) in scopes {
        if role.satisfies(required_role_for(&scope, MutationKind::Update)) {
            caps.push(format!("write:policies:{label}"));
        }
    }

    caps
}

// ── Handlers ──

/// `GET /api/v1/iam/roles` — the built-in RBAC roles and their capability grants.
///
/// Read-only reflection of the gateway's policy-RBAC model
/// (`PolicyMutationRequiredRole`). Grants are derived server-side, not stored,
/// so the response is stable and requires no IAM state. Gated `RequireRead`
/// (deny-by-default): the authz model is not per-tenant secret — it is the same
/// data published in `docs/src/policy-rbac.md` — but still requires a valid
/// read-scoped caller.
#[utoipa::path(
    get,
    path = "/api/v1/iam/roles",
    responses(
        (status = 200, description = "Built-in roles with derived capability grants, highest privilege first", body = [RoleCapabilitiesResponse]),
        (status = 401, description = "Caller is unauthenticated"),
        (status = 403, description = "Caller lacks the read scope required to view IAM roles")
    ),
    tag = "iam"
)]
pub async fn list_roles(RequireRead(_caller): RequireRead) -> (StatusCode, Json<Vec<RoleCapabilitiesResponse>>) {
    let roles = ROLE_ORDER
        .into_iter()
        .map(|role| RoleCapabilitiesResponse {
            role: role.to_string(),
            description: role_description(role).to_string(),
            capabilities: role_capabilities(role),
        })
        .collect();
    (StatusCode::OK, Json(roles))
}

/// `GET /api/v1/iam/api-keys` — list every API key the IAM store knows.
///
/// Returned in newest-first order. Active and revoked keys are both
/// included; the dashboard filters by status in its tabs.
#[utoipa::path(
    get,
    path = "/api/v1/iam/api-keys",
    responses(
        (status = 200, description = "All API keys, newest first", body = [ApiKeyResponse]),
        (status = 403, description = "Caller lacks the admin role required to read IAM state")
    ),
    tag = "iam"
)]
pub async fn list_api_keys(
    // AAASM-3846 — listing API keys discloses sensitive IAM state (labels,
    // scopes, owners, activity), so it requires the same admin authority as the
    // generate / revoke / rotate mutations rather than being open to any caller.
    RequireAdmin(_caller): RequireAdmin,
    Extension(state): Extension<AppState>,
) -> (StatusCode, Json<Vec<ApiKeyResponse>>) {
    let keys = state
        .iam_api_key_store
        .list()
        .into_iter()
        .map(ApiKeyResponse::from)
        .collect();
    (StatusCode::OK, Json(keys))
}

/// `POST /api/v1/iam/api-keys` — issue a new API key.
///
/// IAM mutations are gated as a `Global`-scope policy update — the caller
/// must hold the `OrgAdmin` role.
///
/// The response `secret` field is shown to the caller **once**; the server
/// does not persist it.
#[utoipa::path(
    post,
    path = "/api/v1/iam/api-keys",
    request_body = GenerateApiKeyRequest,
    responses(
        (status = 200, description = "Generated key (with one-shot secret)", body = GeneratedApiKeyResponse),
        (status = 403, description = "Caller lacks the role required to mutate IAM state")
    ),
    tag = "iam"
)]
pub async fn generate_api_key(
    policy_auth: PolicyWriteAuth,
    Extension(state): Extension<AppState>,
    Json(body): Json<GenerateApiKeyRequest>,
) -> Result<(StatusCode, Json<GeneratedApiKeyResponse>), IamHandlerError> {
    policy_auth
        .check_mutation(&PolicyScope::Global, MutationKind::Create)
        .map_err(IamHandlerError::Forbidden)?;

    let scopes: Vec<GwApiKeyScope> = body.scopes.into_iter().map(Into::into).collect();
    let generated = state
        .iam_api_key_store
        .generate(&body.label, scopes, &policy_auth.caller.key_id);
    Ok((StatusCode::OK, Json(generated.into())))
}

/// `POST /api/v1/iam/api-keys/{id}/revoke` — revoke an existing key.
///
/// 404 if the key is unknown, 409 if it is already revoked.
#[utoipa::path(
    post,
    path = "/api/v1/iam/api-keys/{id}/revoke",
    params(("id" = String, Path, description = "API key id")),
    responses(
        (status = 204, description = "Key revoked"),
        (status = 404, description = "Unknown api key id"),
        (status = 409, description = "Key is already revoked"),
        (status = 403, description = "Caller lacks the role required to mutate IAM state")
    ),
    tag = "iam"
)]
pub async fn revoke_api_key(
    policy_auth: PolicyWriteAuth,
    Path(id): Path<String>,
    Extension(state): Extension<AppState>,
) -> Result<StatusCode, IamHandlerError> {
    policy_auth
        .check_mutation(&PolicyScope::Global, MutationKind::Update)
        .map_err(IamHandlerError::Forbidden)?;

    state
        .iam_api_key_store
        .revoke(&id, &policy_auth.caller.key_id)
        .map_err(|e| match e {
            RevokeError::NotFound => IamHandlerError::NotFound(
                ProblemDetail::from_status(StatusCode::NOT_FOUND).with_detail(format!("Unknown api key id: {id}")),
            ),
            RevokeError::AlreadyRevoked => IamHandlerError::Conflict(
                ProblemDetail::from_status(StatusCode::CONFLICT)
                    .with_detail(format!("Api key {id} is already revoked")),
            ),
        })?;
    Ok(StatusCode::NO_CONTENT)
}

/// `POST /api/v1/iam/api-keys/{id}/rotate` — atomically revoke `id` and
/// issue a replacement carrying the same label, scopes, and owner.
///
/// Returns the new key's one-shot reveal. 404 if `id` is unknown, 409 if
/// the source key is already revoked.
#[utoipa::path(
    post,
    path = "/api/v1/iam/api-keys/{id}/rotate",
    params(("id" = String, Path, description = "API key id to rotate")),
    responses(
        (status = 200, description = "Replacement key with one-shot secret", body = GeneratedApiKeyResponse),
        (status = 404, description = "Unknown api key id"),
        (status = 409, description = "Source key is already revoked"),
        (status = 403, description = "Caller lacks the role required to mutate IAM state")
    ),
    tag = "iam"
)]
pub async fn rotate_api_key(
    policy_auth: PolicyWriteAuth,
    Path(id): Path<String>,
    Extension(state): Extension<AppState>,
) -> Result<(StatusCode, Json<GeneratedApiKeyResponse>), IamHandlerError> {
    policy_auth
        .check_mutation(&PolicyScope::Global, MutationKind::Update)
        .map_err(IamHandlerError::Forbidden)?;

    let generated = state
        .iam_api_key_store
        .rotate(&id, &policy_auth.caller.key_id)
        .map_err(|e| match e {
            RotateError::NotFound => IamHandlerError::NotFound(
                ProblemDetail::from_status(StatusCode::NOT_FOUND).with_detail(format!("Unknown api key id: {id}")),
            ),
            RotateError::AlreadyRevoked => IamHandlerError::Conflict(
                ProblemDetail::from_status(StatusCode::CONFLICT)
                    .with_detail(format!("Api key {id} is already revoked")),
            ),
        })?;

    Ok((StatusCode::OK, Json(generated.into())))
}

/// Unified handler error so 404 / 409 / 403 each render through their own
/// `IntoResponse` impl without leaking the gateway error variants.
#[derive(Debug)]
pub enum IamHandlerError {
    NotFound(ProblemDetail),
    Conflict(ProblemDetail),
    Forbidden(PolicyAuthorizationDenied),
}

impl IntoResponse for IamHandlerError {
    fn into_response(self) -> axum::response::Response {
        match self {
            Self::NotFound(p) | Self::Conflict(p) => p.into_response(),
            Self::Forbidden(d) => d.into_response(),
        }
    }
}

/// Build a seeded [`IamApiKeyStore`] mirroring the dashboard's mock fixture.
///
/// Kept here (rather than in `aa-gateway::iam`) so the seed shape stays close
/// to the dashboard-facing wire definitions. The seeded entries match the
/// `SEED_API_KEYS` array in `dashboard/src/features/iam/apiKeys.ts`.
pub fn seeded_iam_store() -> Arc<IamApiKeyStore> {
    use chrono::{DateTime, Utc};
    fn ts(s: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(s)
            .expect("valid rfc3339 seed")
            .with_timezone(&Utc)
    }
    let store = IamApiKeyStore::new();
    store.seed([
        ApiKeyEntry {
            id: "key-1".into(),
            label: "gateway-ci".into(),
            prefix: "aa_live_3f9c".into(),
            scopes: vec![GwApiKeyScope::ReadMembers, GwApiKeyScope::ReadPolicies],
            status: GwApiKeyStatus::Active,
            created_at: ts("2026-04-30T09:12:00Z"),
            last_used: Some(ts("2026-05-13T07:55:00Z")),
            owner: "alice".into(),
            role: "service:reader".into(),
            assigned_policies: vec!["read-only-baseline".into(), "audit-export-allow".into()],
            recent_activity: vec![
                RecentActivityEntry {
                    id: "act-1-a".into(),
                    timestamp: ts("2026-05-13T07:55:00Z"),
                    action: "called".into(),
                    target: "GET /api/v1/agents".into(),
                },
                RecentActivityEntry {
                    id: "act-1-b".into(),
                    timestamp: ts("2026-05-13T07:54:00Z"),
                    action: "called".into(),
                    target: "GET /api/v1/policies".into(),
                },
                RecentActivityEntry {
                    id: "act-1-c".into(),
                    timestamp: ts("2026-04-30T09:12:00Z"),
                    action: "issued".into(),
                    target: "key issued by alice".into(),
                },
            ],
        },
        ApiKeyEntry {
            id: "key-2".into(),
            label: "observability-exporter".into(),
            prefix: "aa_live_8b2a".into(),
            scopes: vec![GwApiKeyScope::ReadAudit],
            status: GwApiKeyStatus::Active,
            created_at: ts("2026-05-02T14:30:00Z"),
            last_used: None,
            owner: "carol".into(),
            role: "service:observer".into(),
            assigned_policies: vec!["audit-export-allow".into()],
            recent_activity: vec![RecentActivityEntry {
                id: "act-2-a".into(),
                timestamp: ts("2026-05-02T14:30:00Z"),
                action: "issued".into(),
                target: "key issued by carol".into(),
            }],
        },
        ApiKeyEntry {
            id: "key-3".into(),
            label: "retired-runner".into(),
            prefix: "aa_live_d041".into(),
            scopes: vec![GwApiKeyScope::Admin],
            status: GwApiKeyStatus::Revoked,
            created_at: ts("2026-03-14T11:00:00Z"),
            last_used: Some(ts("2026-04-21T10:18:00Z")),
            owner: "bob".into(),
            role: "service:admin".into(),
            assigned_policies: vec!["admin-baseline".into()],
            recent_activity: vec![
                RecentActivityEntry {
                    id: "act-3-a".into(),
                    timestamp: ts("2026-04-25T16:00:00Z"),
                    action: "revoked".into(),
                    target: "key revoked by alice".into(),
                },
                RecentActivityEntry {
                    id: "act-3-b".into(),
                    timestamp: ts("2026-04-21T10:18:00Z"),
                    action: "called".into(),
                    target: "POST /api/v1/policies".into(),
                },
                RecentActivityEntry {
                    id: "act-3-c".into(),
                    timestamp: ts("2026-03-14T11:00:00Z"),
                    action: "issued".into(),
                    target: "key issued by bob".into(),
                },
            ],
        },
    ]);
    Arc::new(store)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn api_key_scope_conversions_round_trip_every_variant() {
        let wire_variants = [
            ApiKeyScopeResponse::ReadMembers,
            ApiKeyScopeResponse::WriteMembers,
            ApiKeyScopeResponse::ReadPolicies,
            ApiKeyScopeResponse::WritePolicies,
            ApiKeyScopeResponse::ReadAudit,
            ApiKeyScopeResponse::Admin,
        ];
        for wire in wire_variants {
            // wire → gateway → wire must be the identity for every scope.
            let gw: GwApiKeyScope = wire.into();
            let back: ApiKeyScopeResponse = gw.into();
            assert_eq!(back, wire);
        }
    }

    #[test]
    fn gateway_scope_maps_to_matching_wire_variant() {
        assert_eq!(
            ApiKeyScopeResponse::from(GwApiKeyScope::WriteMembers),
            ApiKeyScopeResponse::WriteMembers
        );
        assert_eq!(
            ApiKeyScopeResponse::from(GwApiKeyScope::Admin),
            ApiKeyScopeResponse::Admin
        );
    }

    // ── AAASM-5046 — role → capability grant derivation ──

    #[test]
    fn org_admin_grants_read_plus_every_write_scope() {
        assert_eq!(
            role_capabilities(CallerRole::OrgAdmin),
            vec![
                "read:policies",
                "write:policies:global",
                "write:policies:org",
                "write:policies:team",
                "write:policies:agent",
                "write:policies:tool",
            ]
        );
    }

    #[test]
    fn team_admin_grants_team_and_below_only() {
        assert_eq!(
            role_capabilities(CallerRole::TeamAdmin),
            vec![
                "read:policies",
                "write:policies:team",
                "write:policies:agent",
                "write:policies:tool",
            ]
        );
    }

    #[test]
    fn developer_grants_agent_and_tool_only() {
        assert_eq!(
            role_capabilities(CallerRole::Developer),
            vec!["read:policies", "write:policies:agent", "write:policies:tool"]
        );
    }

    #[test]
    fn viewer_is_read_only_policies() {
        assert_eq!(role_capabilities(CallerRole::Viewer), vec!["read:policies"]);
    }

    #[test]
    fn auditor_is_read_only_audit() {
        // Auditor is audit-scoped and may never mutate any policy.
        assert_eq!(role_capabilities(CallerRole::Auditor), vec!["read:audit"]);
    }

    #[test]
    fn read_only_roles_grant_no_write_capabilities() {
        for role in [CallerRole::Viewer, CallerRole::Auditor] {
            let caps = role_capabilities(role);
            assert!(
                !caps.iter().any(|c| c.starts_with("write:")),
                "{role} must not grant any write capability, got {caps:?}"
            );
        }
    }

    #[test]
    fn every_role_has_a_description_and_at_least_one_capability() {
        for role in ROLE_ORDER {
            assert!(!role_description(role).is_empty(), "{role} needs a description");
            assert!(
                !role_capabilities(role).is_empty(),
                "{role} must grant at least its read capability"
            );
        }
    }
}
