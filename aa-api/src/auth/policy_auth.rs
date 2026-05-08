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

use aa_gateway::policy::rbac::{CallerRole, MutationKind, PolicyScopeKind, required_role_for};
use aa_gateway::policy::scope::PolicyScope;

use crate::auth::{AuthenticatedCaller, AuthError};
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

/// Error returned when a caller lacks the required role to mutate a policy.
#[derive(Debug, Clone)]
pub struct PolicyAuthorizationDenied {
    /// The role the caller actually has.
    pub actual_role: CallerRole,
    /// The minimum role required for this operation.
    pub required_role: CallerRole,
    /// The scope kind of the policy being mutated.
    pub scope_kind: PolicyScopeKind,
    /// The kind of mutation being attempted.
    pub mutation_kind: MutationKind,
}

impl std::fmt::Display for PolicyAuthorizationDenied {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "policy mutation denied: role '{}' is below required '{}' for {}/{} mutation",
            self.actual_role, self.required_role, self.scope_kind, self.mutation_kind
        )
    }
}

impl IntoResponse for PolicyAuthorizationDenied {
    fn into_response(self) -> Response {
        tracing::warn!(
            actual_role = %self.actual_role,
            required_role = %self.required_role,
            scope_kind = %self.scope_kind,
            mutation_kind = %self.mutation_kind,
            "policy_mutation_denied"
            // TODO(AAASM-237): emit AuditEntry via audit_tx when the write
            // channel is wired into AppState.
        );
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
    pub fn check_mutation(
        &self,
        scope: &PolicyScope,
        mutation: MutationKind,
    ) -> Result<(), PolicyAuthorizationDenied> {
        let required = required_role_for(scope, mutation);
        if self.role.satisfies(required) {
            Ok(())
        } else {
            Err(PolicyAuthorizationDenied {
                actual_role: self.role,
                required_role: required,
                scope_kind: PolicyScopeKind::from(scope),
                mutation_kind: mutation,
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
        AuthenticatedCaller {
            key_id: "test".into(),
            scopes,
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

    #[test]
    fn org_admin_may_create_global_policy() {
        let auth = policy_write_auth(CallerRole::OrgAdmin);
        assert!(auth.check_mutation(&PolicyScope::Global, MutationKind::Create).is_ok());
    }

    #[test]
    fn org_admin_may_create_org_policy() {
        let auth = policy_write_auth(CallerRole::OrgAdmin);
        assert!(auth.check_mutation(&PolicyScope::Org("acme".into()), MutationKind::Create).is_ok());
    }

    #[test]
    fn team_admin_may_create_team_policy() {
        let auth = policy_write_auth(CallerRole::TeamAdmin);
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
        assert_eq!(err.required_role, CallerRole::OrgAdmin);
        assert_eq!(err.actual_role, CallerRole::TeamAdmin);
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
        assert_eq!(err.required_role, CallerRole::TeamAdmin);
        assert_eq!(err.scope_kind, PolicyScopeKind::Team);
        assert_eq!(err.mutation_kind, MutationKind::Update);
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
        let err = PolicyAuthorizationDenied {
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
}
