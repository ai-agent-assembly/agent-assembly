//! RBAC authorization for policy mutation endpoints (AAASM-949 / F101).
//!
//! Provides `PolicyWriteAuth` — an Axum `FromRequestParts` extractor that
//! validates the authenticated caller possesses a `CallerRole`. Use it as
//! a handler parameter, then call [`check_mutation`] with the resolved
//! `PolicyScope` and `MutationKind` to enforce the role table.
//!
//! Denials are returned as HTTP 403 and logged as structured audit events
//! via `tracing::warn!`. Full `AuditEntry` persistence is deferred to
//! when the audit write channel is wired into `aa-api` (TODO AAASM-237).

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

use aa_gateway::policy::rbac::{required_role_for, CallerRole, MutationKind, PolicyScopeKind};
use aa_gateway::policy::scope::PolicyScope;

use crate::auth::{AuthError, AuthenticatedCaller};
use crate::error::ProblemDetail;

/// Maps an API `Scope` onto the coarsest `CallerRole` it implies.
///
/// This is a temporary mapping valid until AAASM-237 (Enterprise RBAC Engine)
/// ships a proper role claim in the JWT / API key metadata.
///
/// | API Scope | Derived CallerRole |
/// |-----------|-------------------|
/// | Admin     | OrgAdmin           |
/// | Write     | Developer          |
/// | Read      | Viewer             |
pub fn caller_role_from_authenticated(caller: &AuthenticatedCaller) -> CallerRole {
    use crate::auth::scope::Scope;
    if caller.scopes.contains(&Scope::Admin) {
        CallerRole::OrgAdmin
    } else if caller.scopes.contains(&Scope::Write) {
        CallerRole::Developer
    } else {
        CallerRole::Viewer
    }
}

/// Error returned when a caller may not mutate a policy.
///
/// Two independent reasons, both rendered as HTTP 403: the caller's role is
/// below the requirement (`Role`), or the caller holds the role but is confined
/// to a different tenant than the policy's scope (`TenantMismatch`, AAASM-4935).
#[derive(Debug, Clone)]
pub enum PolicyAuthorizationDenied {
    /// The caller's role is below the minimum required for the scope/mutation.
    Role {
        /// The role the caller actually has.
        actual_role: CallerRole,
        /// The minimum role required for this operation.
        required_role: CallerRole,
        /// The scope kind of the policy being mutated.
        scope_kind: PolicyScopeKind,
        /// The kind of mutation being attempted.
        mutation_kind: MutationKind,
    },
    /// The caller holds the required role but is scoped to a different tenant
    /// than the policy (AAASM-4935). The role table alone is tenant-blind — an
    /// OrgAdmin/TeamAdmin key satisfies the role requirement for *every*
    /// org/team — so a key confined to one tenant must not mutate another
    /// tenant's policy.
    TenantMismatch {
        /// The scope kind of the policy being mutated (`org` or `team`).
        scope_kind: PolicyScopeKind,
        /// The kind of mutation being attempted.
        mutation_kind: MutationKind,
        /// The org/team identity carried by the policy scope.
        scope_tenant: String,
        /// The caller's confined tenant identity for that dimension, if any.
        caller_tenant: Option<String>,
    },
}

impl std::fmt::Display for PolicyAuthorizationDenied {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Role {
                actual_role,
                required_role,
                scope_kind,
                mutation_kind,
            } => write!(
                f,
                "policy mutation denied: role '{actual_role}' is below required '{required_role}' \
                 for {scope_kind}/{mutation_kind} mutation",
            ),
            Self::TenantMismatch {
                scope_kind,
                mutation_kind,
                scope_tenant,
                caller_tenant,
            } => write!(
                f,
                "policy mutation denied: caller tenant '{}' may not perform {mutation_kind} on \
                 {scope_kind}:'{scope_tenant}'",
                caller_tenant.as_deref().unwrap_or("<none>"),
            ),
        }
    }
}

impl IntoResponse for PolicyAuthorizationDenied {
    fn into_response(self) -> Response {
        // TODO(AAASM-237): emit AuditEntry via audit_tx when the write channel
        // is wired into AppState.
        match &self {
            Self::Role {
                actual_role,
                required_role,
                scope_kind,
                mutation_kind,
            } => tracing::warn!(
                actual_role = %actual_role,
                required_role = %required_role,
                scope_kind = %scope_kind,
                mutation_kind = %mutation_kind,
                "policy_mutation_denied"
            ),
            Self::TenantMismatch {
                scope_kind,
                mutation_kind,
                scope_tenant,
                caller_tenant,
            } => tracing::warn!(
                scope_kind = %scope_kind,
                mutation_kind = %mutation_kind,
                scope_tenant = %scope_tenant,
                caller_tenant = caller_tenant.as_deref().unwrap_or("<none>"),
                "policy_mutation_denied_tenant_mismatch"
            ),
        }
        ProblemDetail::from_status(StatusCode::FORBIDDEN)
            .with_detail(self.to_string())
            .into_response()
    }
}

/// Axum extractor that authenticates the caller and resolves their `CallerRole`.
///
/// Add this as a handler parameter on any policy-mutation handler to gate
/// access. After extraction, call [`check_mutation`] with the resolved scope
/// and mutation kind:
///
/// ```ignore
/// async fn create_policy(
///     policy_write_auth: PolicyWriteAuth,
///     Extension(state): Extension<AppState>,
///     Json(body): Json<CreatePolicyRequest>,
/// ) -> Result<impl IntoResponse, impl IntoResponse> {
///     let scope = body.scope_parsed();
///     policy_write_auth.check_mutation(&scope, MutationKind::Create)?;
///     // … rest of handler
/// }
/// ```
#[derive(Debug, Clone)]
pub struct PolicyWriteAuth {
    /// The authenticated caller identity.
    pub caller: AuthenticatedCaller,
    /// The derived RBAC role.
    pub role: CallerRole,
}

impl PolicyWriteAuth {
    /// Enforce that this caller may perform `mutation` on a policy at `scope`.
    ///
    /// Returns `Ok(())` when the role satisfies the requirement, or
    /// `Err(PolicyAuthorizationDenied)` when it does not.
    pub fn check_mutation(&self, scope: &PolicyScope, mutation: MutationKind) -> Result<(), PolicyAuthorizationDenied> {
        let required = required_role_for(scope, mutation);
        if !self.role.satisfies(required) {
            return Err(PolicyAuthorizationDenied::Role {
                actual_role: self.role,
                required_role: required,
                scope_kind: PolicyScopeKind::from(scope),
                mutation_kind: mutation,
            });
        }
        self.check_tenant_binding(scope, mutation)
    }

    /// Bind the caller's verified tenant to a scoped policy's org/team identity.
    ///
    /// AAASM-4935: [`required_role_for`] ranks only the *kind* of scope, so an
    /// OrgAdmin/TeamAdmin key satisfies the role requirement for *every*
    /// org/team — the check is tenant-blind. Without this step any Admin-scoped
    /// key could mutate another tenant's policy. A scoped mutation therefore
    /// additionally requires the caller's confined tenant to equal the scope's
    /// own org (`Org`) or team (`Team`) id.
    ///
    /// The match is exact and fail-closed: a caller with no confined tenant for
    /// the relevant dimension (e.g. a cross-tenant key with `org_id: None`)
    /// cannot prove ownership and is denied. `Global`, `Agent`, and `Tool`
    /// scopes carry no org/team identity, so there is nothing to bind against —
    /// their role gate stands alone, unchanged (`Global` stays OrgAdmin-only).
    fn check_tenant_binding(
        &self,
        scope: &PolicyScope,
        mutation: MutationKind,
    ) -> Result<(), PolicyAuthorizationDenied> {
        let (scope_tenant, caller_tenant) = match scope {
            PolicyScope::Org(org) => (org, self.caller.tenant.org_id.as_deref()),
            PolicyScope::Team(team) => (team, self.caller.tenant.team_id.as_deref()),
            PolicyScope::Global | PolicyScope::Agent(_) | PolicyScope::Tool(_) => return Ok(()),
        };

        if caller_tenant == Some(scope_tenant.as_str()) {
            Ok(())
        } else {
            Err(PolicyAuthorizationDenied::TenantMismatch {
                scope_kind: PolicyScopeKind::from(scope),
                mutation_kind: mutation,
                scope_tenant: scope_tenant.clone(),
                caller_tenant: caller_tenant.map(str::to_owned),
            })
        }
    }
}

impl<S> FromRequestParts<S> for PolicyWriteAuth
where
    S: Send + Sync,
{
    type Rejection = AuthError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let caller = AuthenticatedCaller::from_request_parts(parts, state).await?;
        let role = caller_role_from_authenticated(&caller);
        Ok(PolicyWriteAuth { caller, role })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::scope::Scope;

    fn caller_with_scopes(scopes: Vec<Scope>) -> AuthenticatedCaller {
        caller_with_scopes_and_tenant(scopes, crate::auth::Tenant::default())
    }

    fn caller_with_scopes_and_tenant(scopes: Vec<Scope>, tenant: crate::auth::Tenant) -> AuthenticatedCaller {
        AuthenticatedCaller {
            key_id: "test".into(),
            scopes,
            tenant,
        }
    }

    fn tenant(org_id: Option<&str>, team_id: Option<&str>) -> crate::auth::Tenant {
        crate::auth::Tenant {
            org_id: org_id.map(str::to_owned),
            team_id: team_id.map(str::to_owned),
        }
    }

    // ── caller_role_from_authenticated ───────────────────────────────────────

    #[test]
    fn admin_scope_maps_to_org_admin() {
        let caller = caller_with_scopes(vec![Scope::Read, Scope::Write, Scope::Admin]);
        assert_eq!(caller_role_from_authenticated(&caller), CallerRole::OrgAdmin);
    }

    #[test]
    fn write_scope_maps_to_developer() {
        let caller = caller_with_scopes(vec![Scope::Read, Scope::Write]);
        assert_eq!(caller_role_from_authenticated(&caller), CallerRole::Developer);
    }

    #[test]
    fn read_only_scope_maps_to_viewer() {
        let caller = caller_with_scopes(vec![Scope::Read]);
        assert_eq!(caller_role_from_authenticated(&caller), CallerRole::Viewer);
    }

    // ── PolicyWriteAuth::check_mutation ─────────────────────────────────────

    fn policy_write_auth(role: CallerRole) -> PolicyWriteAuth {
        PolicyWriteAuth {
            caller: caller_with_scopes(vec![]),
            role,
        }
    }

    fn policy_write_auth_with_tenant(role: CallerRole, tenant: crate::auth::Tenant) -> PolicyWriteAuth {
        PolicyWriteAuth {
            caller: caller_with_scopes_and_tenant(vec![], tenant),
            role,
        }
    }

    #[test]
    fn org_admin_may_create_global_policy() {
        let auth = policy_write_auth(CallerRole::OrgAdmin);
        assert!(auth.check_mutation(&PolicyScope::Global, MutationKind::Create).is_ok());
    }

    #[test]
    fn org_admin_may_create_org_policy() {
        // AAASM-4935: an OrgAdmin may mutate a policy scoped to *their own* org.
        let auth = policy_write_auth_with_tenant(CallerRole::OrgAdmin, tenant(Some("acme"), None));
        assert!(auth
            .check_mutation(&PolicyScope::Org("acme".into()), MutationKind::Create)
            .is_ok());
    }

    #[test]
    fn team_admin_may_create_team_policy() {
        // AAASM-4935: a TeamAdmin may mutate a policy scoped to *their own* team.
        let auth = policy_write_auth_with_tenant(CallerRole::TeamAdmin, tenant(None, Some("platform")));
        assert!(auth
            .check_mutation(&PolicyScope::Team("platform".into()), MutationKind::Create)
            .is_ok());
    }

    #[test]
    fn team_admin_cannot_create_global_policy() {
        let auth = policy_write_auth(CallerRole::TeamAdmin);
        let err = auth
            .check_mutation(&PolicyScope::Global, MutationKind::Create)
            .unwrap_err();
        let PolicyAuthorizationDenied::Role {
            required_role,
            actual_role,
            ..
        } = err
        else {
            panic!("expected a Role denial, got {err:?}");
        };
        assert_eq!(required_role, CallerRole::OrgAdmin);
        assert_eq!(actual_role, CallerRole::TeamAdmin);
    }

    #[test]
    fn developer_may_create_tool_policy() {
        let auth = policy_write_auth(CallerRole::Developer);
        assert!(auth
            .check_mutation(&PolicyScope::Tool("slack-mcp".into()), MutationKind::Create)
            .is_ok());
    }

    #[test]
    fn developer_cannot_create_team_policy() {
        let auth = policy_write_auth(CallerRole::Developer);
        let err = auth
            .check_mutation(&PolicyScope::Team("x".into()), MutationKind::Update)
            .unwrap_err();
        let PolicyAuthorizationDenied::Role {
            required_role,
            scope_kind,
            mutation_kind,
            ..
        } = err
        else {
            panic!("expected a Role denial, got {err:?}");
        };
        assert_eq!(required_role, CallerRole::TeamAdmin);
        assert_eq!(scope_kind, PolicyScopeKind::Team);
        assert_eq!(mutation_kind, MutationKind::Update);
    }

    #[test]
    fn viewer_cannot_mutate_any_scope() {
        let auth = policy_write_auth(CallerRole::Viewer);
        for scope in [
            PolicyScope::Global,
            PolicyScope::Org("x".into()),
            PolicyScope::Team("y".into()),
            PolicyScope::Tool("z".into()),
        ] {
            assert!(
                auth.check_mutation(&scope, MutationKind::Create).is_err(),
                "Viewer should be denied for {scope:?}"
            );
        }
    }

    #[test]
    fn denied_error_display_contains_roles_and_scope() {
        let err = PolicyAuthorizationDenied::Role {
            actual_role: CallerRole::Developer,
            required_role: CallerRole::OrgAdmin,
            scope_kind: PolicyScopeKind::Global,
            mutation_kind: MutationKind::Delete,
        };
        let msg = err.to_string();
        assert!(msg.contains("developer"), "expected 'developer' in: {msg}");
        assert!(msg.contains("org_admin"), "expected 'org_admin' in: {msg}");
        assert!(msg.contains("global"), "expected 'global' in: {msg}");
        assert!(msg.contains("delete"), "expected 'delete' in: {msg}");
    }

    // ── Tenant binding (AAASM-4935) ─────────────────────────────────────────
    //
    // `required_role_for` is tenant-blind: an OrgAdmin/TeamAdmin key satisfies
    // the role for *every* org/team. These cases pin the additional binding
    // that confines a scoped mutation to the caller's own tenant.

    #[test]
    fn org_admin_denied_for_other_org() {
        // Holds OrgAdmin, but is confined to org "acme" and targets org "evil".
        let auth = policy_write_auth_with_tenant(CallerRole::OrgAdmin, tenant(Some("acme"), None));
        let err = auth
            .check_mutation(&PolicyScope::Org("evil".into()), MutationKind::Update)
            .unwrap_err();
        let PolicyAuthorizationDenied::TenantMismatch {
            scope_kind,
            scope_tenant,
            caller_tenant,
            ..
        } = err
        else {
            panic!("expected a TenantMismatch denial, got {err:?}");
        };
        assert_eq!(scope_kind, PolicyScopeKind::Org);
        assert_eq!(scope_tenant, "evil");
        assert_eq!(caller_tenant.as_deref(), Some("acme"));
    }

    #[test]
    fn team_admin_denied_for_other_team() {
        let auth = policy_write_auth_with_tenant(CallerRole::TeamAdmin, tenant(None, Some("platform")));
        let err = auth
            .check_mutation(&PolicyScope::Team("payments".into()), MutationKind::Delete)
            .unwrap_err();
        assert!(
            matches!(err, PolicyAuthorizationDenied::TenantMismatch { .. }),
            "expected TenantMismatch, got {err:?}"
        );
    }

    #[test]
    fn org_admin_with_no_tenant_denied_for_org_scope() {
        // Fail-closed: a caller with no confined org cannot prove ownership of
        // org "acme", even though it holds OrgAdmin.
        let auth = policy_write_auth(CallerRole::OrgAdmin);
        let err = auth
            .check_mutation(&PolicyScope::Org("acme".into()), MutationKind::Create)
            .unwrap_err();
        let PolicyAuthorizationDenied::TenantMismatch { caller_tenant, .. } = err else {
            panic!("expected a TenantMismatch denial, got {err:?}");
        };
        assert_eq!(caller_tenant, None);
    }

    #[test]
    fn org_admin_allowed_for_own_org() {
        let auth = policy_write_auth_with_tenant(CallerRole::OrgAdmin, tenant(Some("acme"), None));
        assert!(auth
            .check_mutation(&PolicyScope::Org("acme".into()), MutationKind::Update)
            .is_ok());
    }

    #[test]
    fn global_scope_ignores_tenant() {
        // Global carries no tenant identity — an OrgAdmin with no confined
        // tenant still installs it (unchanged pre-AAASM-4935 behavior).
        let auth = policy_write_auth(CallerRole::OrgAdmin);
        assert!(auth.check_mutation(&PolicyScope::Global, MutationKind::Create).is_ok());
    }

    #[test]
    fn tool_scope_ignores_tenant() {
        // Tool scope carries no org/team identity, so tenant binding is a no-op;
        // the Developer role gate alone applies.
        let auth = policy_write_auth(CallerRole::Developer);
        assert!(auth
            .check_mutation(&PolicyScope::Tool("slack-mcp".into()), MutationKind::Create)
            .is_ok());
    }
}
