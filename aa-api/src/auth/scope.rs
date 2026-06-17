//! Authorization scope levels for API operations.

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use serde::{Deserialize, Serialize};

use super::{AuthError, AuthenticatedCaller};

/// Authorization scope level for API operations.
///
/// Variants are ordered by privilege: `Read < Write < Admin`.
/// A caller with `Admin` scope satisfies any scope requirement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum Scope {
    /// Read-only access to resources.
    Read,
    /// Read and write access (create, update, delete).
    Write,
    /// Full administrative access including agent kill.
    Admin,
}

impl Scope {
    /// Check whether the given set of scopes satisfies this required scope.
    ///
    /// Returns `true` if any scope in `granted` is >= `self` in the
    /// privilege ordering.
    pub fn is_satisfied_by(self, granted: &[Scope]) -> bool {
        granted.iter().any(|s| *s >= self)
    }
}

impl std::fmt::Display for Scope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Scope::Read => write!(f, "read"),
            Scope::Write => write!(f, "write"),
            Scope::Admin => write!(f, "admin"),
        }
    }
}

/// Axum extractor that enforces a minimum scope level.
///
/// Use as a handler parameter to gate access:
///
/// ```ignore
/// async fn admin_only(_scope: RequireScope<{ Scope::Admin as u8 }>) { ... }
/// ```
///
/// This extractor first resolves the [`AuthenticatedCaller`] and then
/// checks that the caller's scopes satisfy the required level.
pub struct RequireScope(pub AuthenticatedCaller);

impl RequireScope {
    /// Validate that the caller has at least the given scope.
    fn check(caller: &AuthenticatedCaller, required: Scope) -> Result<(), AuthError> {
        if required.is_satisfied_by(&caller.scopes) {
            Ok(())
        } else {
            Err(AuthError::InsufficientScope { required })
        }
    }
}

/// Require `Scope::Read` — the caller must have at least read access.
pub struct RequireRead(pub AuthenticatedCaller);

impl<S> FromRequestParts<S> for RequireRead
where
    S: Send + Sync,
{
    type Rejection = AuthError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let caller = AuthenticatedCaller::from_request_parts(parts, state).await?;
        RequireScope::check(&caller, Scope::Read)?;
        Ok(Self(caller))
    }
}

/// Require `Scope::Write` — the caller must have at least write access.
pub struct RequireWrite(pub AuthenticatedCaller);

impl<S> FromRequestParts<S> for RequireWrite
where
    S: Send + Sync,
{
    type Rejection = AuthError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let caller = AuthenticatedCaller::from_request_parts(parts, state).await?;
        RequireScope::check(&caller, Scope::Write)?;
        Ok(Self(caller))
    }
}

/// Require `Scope::Admin` — the caller must have admin access.
pub struct RequireAdmin(pub AuthenticatedCaller);

impl<S> FromRequestParts<S> for RequireAdmin
where
    S: Send + Sync,
{
    type Rejection = AuthError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let caller = AuthenticatedCaller::from_request_parts(parts, state).await?;
        RequireScope::check(&caller, Scope::Admin)?;
        Ok(Self(caller))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scope_ordering() {
        assert!(Scope::Admin > Scope::Write);
        assert!(Scope::Write > Scope::Read);
        assert!(Scope::Admin > Scope::Read);
    }

    #[test]
    fn test_scope_contains_same_level() {
        assert!(Scope::Write.is_satisfied_by(&[Scope::Write]));
        assert!(Scope::Read.is_satisfied_by(&[Scope::Read]));
        assert!(Scope::Admin.is_satisfied_by(&[Scope::Admin]));
    }

    #[test]
    fn test_scope_contains_higher_level() {
        assert!(Scope::Write.is_satisfied_by(&[Scope::Admin]));
        assert!(Scope::Read.is_satisfied_by(&[Scope::Admin]));
        assert!(Scope::Read.is_satisfied_by(&[Scope::Write]));
    }

    #[test]
    fn test_scope_rejects_lower_level() {
        assert!(!Scope::Write.is_satisfied_by(&[Scope::Read]));
        assert!(!Scope::Admin.is_satisfied_by(&[Scope::Write]));
        assert!(!Scope::Admin.is_satisfied_by(&[Scope::Read]));
    }

    #[test]
    fn test_scope_empty_grants_rejects_all() {
        assert!(!Scope::Read.is_satisfied_by(&[]));
        assert!(!Scope::Write.is_satisfied_by(&[]));
        assert!(!Scope::Admin.is_satisfied_by(&[]));
    }

    #[test]
    fn test_scope_check_with_caller() {
        let caller = AuthenticatedCaller {
            key_id: "test".to_string(),
            scopes: vec![Scope::Read, Scope::Write],
            tenant: crate::auth::Tenant::default(),
        };
        assert!(RequireScope::check(&caller, Scope::Read).is_ok());
        assert!(RequireScope::check(&caller, Scope::Write).is_ok());
        assert!(RequireScope::check(&caller, Scope::Admin).is_err());
    }
}
