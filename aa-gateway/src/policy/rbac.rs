//! RBAC types for policy-mutation authorization (AAASM-949 / F101).
//!
//! Defines `CallerRole`, `MutationKind`, `PolicyScopeKind`, and the static
//! `PolicyMutationRequiredRole` table that maps `(scope, mutation) → minimum role`.

use serde::{Deserialize, Serialize};

use crate::policy::scope::PolicyScope;

/// Discriminant of [`PolicyScope`] used as the table key.
///
/// `PolicyScope` carries data (org-id, team-id, …); `PolicyScopeKind` strips
/// that data so it can be used in comparisons and the role table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyScopeKind {
    Global,
    Org,
    Team,
    Agent,
    Tool,
}

impl From<&PolicyScope> for PolicyScopeKind {
    fn from(scope: &PolicyScope) -> Self {
        match scope {
            PolicyScope::Global => Self::Global,
            PolicyScope::Org(_) => Self::Org,
            PolicyScope::Team(_) => Self::Team,
            PolicyScope::Agent(_) => Self::Agent,
            PolicyScope::Tool(_) => Self::Tool,
        }
    }
}

impl std::fmt::Display for PolicyScopeKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Global => write!(f, "global"),
            Self::Org => write!(f, "org"),
            Self::Team => write!(f, "team"),
            Self::Agent => write!(f, "agent"),
            Self::Tool => write!(f, "tool"),
        }
    }
}

/// The kind of mutation being performed on a policy resource.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MutationKind {
    Create,
    Update,
    Delete,
}

impl std::fmt::Display for MutationKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Create => write!(f, "create"),
            Self::Update => write!(f, "update"),
            Self::Delete => write!(f, "delete"),
        }
    }
}

/// The 5 canonical RBAC roles for policy governance (F101 / AAASM-949).
///
/// Privilege ordering (highest → lowest):
/// `OrgAdmin > TeamAdmin > Developer > Viewer > Auditor`
///
/// `Auditor` is a read-only role — any write attempt returns
/// `PolicyAuthorizationDenied`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CallerRole {
    /// Read-only audit access — no writes permitted.
    Auditor,
    /// Read-only standard access.
    Viewer,
    /// Can mutate agent- and tool-scoped policies.
    Developer,
    /// Can mutate team-scoped policies (and below).
    TeamAdmin,
    /// Full policy mutation rights across all scopes.
    OrgAdmin,
}

impl std::fmt::Display for CallerRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::OrgAdmin => write!(f, "org_admin"),
            Self::TeamAdmin => write!(f, "team_admin"),
            Self::Developer => write!(f, "developer"),
            Self::Viewer => write!(f, "viewer"),
            Self::Auditor => write!(f, "auditor"),
        }
    }
}

impl CallerRole {
    /// Returns `true` if this role meets or exceeds `required`.
    ///
    /// `Auditor` never satisfies any write-capable role requirement, even
    /// though its numeric value is lowest — Auditor is a read-only marker
    /// and is explicitly excluded from all mutation checks.
    pub fn satisfies(self, required: CallerRole) -> bool {
        if self == CallerRole::Auditor {
            return false;
        }
        self >= required
    }
}

/// The `PolicyMutationRequiredRole` table.
///
/// Returns the minimum [`CallerRole`] required to perform `mutation` on a
/// policy at the given `scope`.
///
/// | Scope         | Any mutation |
/// |---------------|-------------|
/// | Global / Org  | OrgAdmin    |
/// | Team          | TeamAdmin   |
/// | Agent / Tool  | Developer   |
pub fn required_role_for(scope: &PolicyScope, _mutation: MutationKind) -> CallerRole {
    match PolicyScopeKind::from(scope) {
        PolicyScopeKind::Global | PolicyScopeKind::Org => CallerRole::OrgAdmin,
        PolicyScopeKind::Team => CallerRole::TeamAdmin,
        PolicyScopeKind::Agent | PolicyScopeKind::Tool => CallerRole::Developer,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── required_role_for ────────────────────────────────────────────────────

    #[test]
    fn global_scope_requires_org_admin() {
        assert_eq!(
            required_role_for(&PolicyScope::Global, MutationKind::Create),
            CallerRole::OrgAdmin
        );
    }

    #[test]
    fn org_scope_requires_org_admin() {
        assert_eq!(
            required_role_for(&PolicyScope::Org("acme".into()), MutationKind::Update),
            CallerRole::OrgAdmin
        );
    }

    #[test]
    fn team_scope_requires_team_admin() {
        assert_eq!(
            required_role_for(&PolicyScope::Team("platform".into()), MutationKind::Delete),
            CallerRole::TeamAdmin
        );
    }

    #[test]
    fn agent_scope_requires_developer() {
        use aa_core::identity::AgentId;
        assert_eq!(
            required_role_for(
                &PolicyScope::Agent(AgentId::from_bytes([0u8; 16])),
                MutationKind::Create
            ),
            CallerRole::Developer
        );
    }

    #[test]
    fn tool_scope_requires_developer() {
        assert_eq!(
            required_role_for(&PolicyScope::Tool("slack-mcp".into()), MutationKind::Update),
            CallerRole::Developer
        );
    }

    #[test]
    fn mutation_kind_does_not_change_required_role() {
        let scope = PolicyScope::Team("x".into());
        assert_eq!(
            required_role_for(&scope, MutationKind::Create),
            required_role_for(&scope, MutationKind::Update),
        );
        assert_eq!(
            required_role_for(&scope, MutationKind::Update),
            required_role_for(&scope, MutationKind::Delete),
        );
    }

    // ── CallerRole::satisfies ────────────────────────────────────────────────

    #[test]
    fn org_admin_satisfies_all_roles() {
        for req in [
            CallerRole::OrgAdmin,
            CallerRole::TeamAdmin,
            CallerRole::Developer,
            CallerRole::Viewer,
        ] {
            assert!(CallerRole::OrgAdmin.satisfies(req), "OrgAdmin should satisfy {req}");
        }
    }

    #[test]
    fn team_admin_satisfies_team_admin_and_below() {
        assert!(CallerRole::TeamAdmin.satisfies(CallerRole::TeamAdmin));
        assert!(CallerRole::TeamAdmin.satisfies(CallerRole::Developer));
        assert!(CallerRole::TeamAdmin.satisfies(CallerRole::Viewer));
        assert!(!CallerRole::TeamAdmin.satisfies(CallerRole::OrgAdmin));
    }

    #[test]
    fn developer_satisfies_developer_and_viewer() {
        assert!(CallerRole::Developer.satisfies(CallerRole::Developer));
        assert!(CallerRole::Developer.satisfies(CallerRole::Viewer));
        assert!(!CallerRole::Developer.satisfies(CallerRole::TeamAdmin));
    }

    #[test]
    fn auditor_never_satisfies_any_write_role() {
        for req in [
            CallerRole::OrgAdmin,
            CallerRole::TeamAdmin,
            CallerRole::Developer,
            CallerRole::Viewer,
        ] {
            assert!(!CallerRole::Auditor.satisfies(req), "Auditor must not satisfy {req}");
        }
    }

    // ── PolicyScopeKind conversions ─────────────────────────────────────────

    #[test]
    fn scope_kind_from_policy_scope() {
        assert_eq!(PolicyScopeKind::from(&PolicyScope::Global), PolicyScopeKind::Global);
        assert_eq!(
            PolicyScopeKind::from(&PolicyScope::Org("x".into())),
            PolicyScopeKind::Org
        );
        assert_eq!(
            PolicyScopeKind::from(&PolicyScope::Team("y".into())),
            PolicyScopeKind::Team
        );
        assert_eq!(
            PolicyScopeKind::from(&PolicyScope::Tool("z".into())),
            PolicyScopeKind::Tool
        );
    }
}
