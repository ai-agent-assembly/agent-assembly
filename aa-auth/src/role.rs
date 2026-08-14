//! Native-account user roles and their mapping onto the JWT [`Scope`] set
//! (AAASM-5304, ADR 0031 §Q1).
//!
//! A native email/password account carries a coarse [`Role`]; the scoped JWT it
//! mints carries the fine-grained [`Scope`] set every RBAC gate already reads.
//! [`Role::scopes`] is the fixed, total translation between them, so an
//! account-minted JWT is scope-compatible with an API-key-minted one and every
//! existing gate keeps working unchanged (ADR 0031 §Q1: full mapping, not a
//! reduced OSS subset).

use serde::{Deserialize, Serialize};

use crate::scope::Scope;

/// A native-account user role (ADR 0031 data model).
///
/// Roles are a coarse, human-facing label stored on the user row; authorization
/// is still driven by the [`Scope`] set [`Role::scopes`] expands each role to.
/// Serialized lowercase to match the `users.role` enum values in the migration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    /// The workspace owner — the first bootstrapped account. Full access,
    /// including administrative scope.
    Owner,
    /// An administrator — administrative scope plus read/write.
    Admin,
    /// A developer — read and write, no administrative scope.
    Developer,
    /// A viewer — read-only.
    Viewer,
}

impl Role {
    /// Expand this role to the [`Scope`] set an account-minted JWT carries
    /// (ADR 0031 §Q1, full mapping).
    ///
    /// | Role        | Scopes                      |
    /// |-------------|-----------------------------|
    /// | `Owner`     | `Read`, `Write`, `Admin`    |
    /// | `Admin`     | `Read`, `Write`, `Admin`    |
    /// | `Developer` | `Read`, `Write`             |
    /// | `Viewer`    | `Read`                      |
    ///
    /// The scopes are returned lowest-privilege first, matching how the API-key
    /// path stores its granted scopes, so the two credential sources produce the
    /// same JWT scope claim shape.
    pub fn scopes(self) -> Vec<Scope> {
        match self {
            Role::Owner | Role::Admin => vec![Scope::Read, Scope::Write, Scope::Admin],
            Role::Developer => vec![Scope::Read, Scope::Write],
            Role::Viewer => vec![Scope::Read],
        }
    }

    /// The lowercase wire/enum name for this role, matching the `users.role`
    /// Postgres enum and the serde representation.
    pub fn as_str(self) -> &'static str {
        match self {
            Role::Owner => "owner",
            Role::Admin => "admin",
            Role::Developer => "developer",
            Role::Viewer => "viewer",
        }
    }
}

impl std::fmt::Display for Role {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn owner_gets_all_scopes_including_admin() {
        assert_eq!(Role::Owner.scopes(), vec![Scope::Read, Scope::Write, Scope::Admin]);
    }

    #[test]
    fn admin_gets_admin_plus_read_write() {
        assert_eq!(Role::Admin.scopes(), vec![Scope::Read, Scope::Write, Scope::Admin]);
    }

    #[test]
    fn developer_gets_read_write_only() {
        let scopes = Role::Developer.scopes();
        assert_eq!(scopes, vec![Scope::Read, Scope::Write]);
        assert!(!scopes.contains(&Scope::Admin), "developer must not hold admin scope");
    }

    #[test]
    fn viewer_gets_read_only() {
        let scopes = Role::Viewer.scopes();
        assert_eq!(scopes, vec![Scope::Read]);
        assert!(!scopes.contains(&Scope::Write), "viewer must not hold write scope");
        assert!(!scopes.contains(&Scope::Admin), "viewer must not hold admin scope");
    }

    #[test]
    fn admin_scope_is_reachable_only_for_owner_and_admin() {
        for role in [Role::Owner, Role::Admin] {
            assert!(role.scopes().contains(&Scope::Admin), "{role} must hold admin scope");
        }
        for role in [Role::Developer, Role::Viewer] {
            assert!(
                !role.scopes().contains(&Scope::Admin),
                "{role} must not hold admin scope"
            );
        }
    }

    #[test]
    fn account_minted_scopes_satisfy_the_matching_gate() {
        // The mapping must stay compatible with the existing scope gate: a
        // developer's scopes satisfy a Write requirement but not Admin.
        assert!(Scope::Write.is_satisfied_by(&Role::Developer.scopes()));
        assert!(!Scope::Admin.is_satisfied_by(&Role::Developer.scopes()));
        assert!(Scope::Admin.is_satisfied_by(&Role::Owner.scopes()));
    }

    #[test]
    fn role_serializes_lowercase() {
        assert_eq!(serde_json::to_string(&Role::Owner).unwrap(), "\"owner\"");
        assert_eq!(serde_json::to_string(&Role::Developer).unwrap(), "\"developer\"");
    }

    #[test]
    fn role_as_str_matches_display_and_serde() {
        for role in [Role::Owner, Role::Admin, Role::Developer, Role::Viewer] {
            assert_eq!(role.as_str(), role.to_string());
        }
    }
}
