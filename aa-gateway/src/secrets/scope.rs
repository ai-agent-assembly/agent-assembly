//! Tenant scoping for Secret Injection (AAASM-3845).
//!
//! The [`SecretsStore`] surface is a flat `name → value` registry with no
//! per-tenant ownership (per-team scoping is an explicit non-goal of the
//! AAASM-1920 v0.0.1 stub). On its own that means `dispatch_tool` resolves any
//! registered `${NAME}` placeholder for *any* caller — a cross-tenant secret
//! disclosure once more than one tenant shares a gateway.
//!
//! [`TenantScopedStore`] closes that gap at the resolution boundary: it wraps a
//! shared `&dyn SecretsStore` and binds every operation to a single tenant
//! namespace derived from the *verified* caller. A placeholder registered by
//! tenant A is stored under A's namespace, so a tenant-B caller resolving the
//! same bare name looks in B's namespace, misses, and the resolver surfaces
//! [`SecretInjectionError::UnknownPlaceholder`](crate::secrets::SecretInjectionError::UnknownPlaceholder)
//! rather than leaking A's credential. Because it implements [`SecretsStore`]
//! itself, it drops straight into
//! [`resolve_placeholders`](crate::secrets::resolver::resolve_placeholders)
//! with no resolver change.
//!
//! The tenant identity is taken **only** from the authenticated caller
//! (HTTP `AuthenticatedCaller::tenant`, gRPC `VerifiedCaller`), never from the
//! request body — a client cannot widen its scope by naming a different tenant.

use crate::secrets::{Secret, SecretsError, SecretsStore};

/// Field separator used when composing a scoped storage key.
///
/// ASCII Unit Separator (`0x1F`): it cannot appear in a valid placeholder name
/// (`[A-Z][A-Z0-9_]*`), so `"<org>\u{1f}<team>\u{1f}<name>"` is unambiguous and
/// no `(org, team, name)` triple can collide with a different one.
const SEP: char = '\u{1f}';

/// Derive a stable tenant namespace from a caller's verified `(org_id, team_id)`.
///
/// The namespace is the isolation boundary for secret resolution: two callers
/// resolve the *same* secrets iff they produce the *same* namespace. Both
/// fields participate so that two teams within one org — or one team across two
/// orgs — never share a secret namespace.
///
/// A caller with neither field (an untenanted / single-tenant-deployment caller)
/// maps to the shared empty namespace, mirroring the untenanted-fallback
/// convention used by the approval and topology tenancy guards (AAASM-3788).
/// The tenant values are read only from the authenticated identity, never from
/// request input, so this cannot be redirected by a client.
pub fn tenant_namespace(org_id: Option<&str>, team_id: Option<&str>) -> String {
    format!("{}{SEP}{}", org_id.unwrap_or(""), team_id.unwrap_or(""))
}

/// A tenant-bound view over a shared [`SecretsStore`].
///
/// Every operation transparently rewrites the bare placeholder name to a
/// namespaced storage key (`"<namespace>\u{1f}<name>"`) before delegating to the
/// inner store, so a tenant can only register, look up, list, or delete secrets
/// within its own namespace. Construct one per request from the verified
/// caller's tenant and hand it to the resolver.
pub struct TenantScopedStore<'a> {
    inner: &'a dyn SecretsStore,
    namespace: String,
}

impl<'a> TenantScopedStore<'a> {
    /// Bind `inner` to `namespace` (typically from [`tenant_namespace`]).
    pub fn new(inner: &'a dyn SecretsStore, namespace: impl Into<String>) -> Self {
        Self {
            inner,
            namespace: namespace.into(),
        }
    }

    /// Bind `inner` to the namespace derived from a caller's `(org_id, team_id)`.
    pub fn for_tenant(inner: &'a dyn SecretsStore, org_id: Option<&str>, team_id: Option<&str>) -> Self {
        Self::new(inner, tenant_namespace(org_id, team_id))
    }

    /// Compose the namespaced storage key for a bare placeholder name.
    fn scoped_key(&self, name: &str) -> String {
        format!("{}{SEP}{}", self.namespace, name)
    }

    /// The key prefix (`"<namespace>\u{1f}"`) that every key in this tenant's
    /// namespace starts with — used to filter [`SecretsStore::list`].
    fn prefix(&self) -> String {
        format!("{}{SEP}", self.namespace)
    }
}

impl SecretsStore for TenantScopedStore<'_> {
    fn register(&self, secret: Secret) -> Result<(), SecretsError> {
        self.inner.register(Secret {
            name: self.scoped_key(&secret.name),
            value: secret.value,
        })
    }

    fn lookup(&self, name: &str) -> Option<String> {
        self.inner.lookup(&self.scoped_key(name))
    }

    fn list(&self) -> Vec<String> {
        let prefix = self.prefix();
        self.inner
            .list()
            .into_iter()
            .filter_map(|k| k.strip_prefix(&prefix).map(str::to_owned))
            .collect()
    }

    fn delete(&self, name: &str) -> Result<(), SecretsError> {
        self.inner.delete(&self.scoped_key(name))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secrets::resolver::resolve_placeholders;
    use crate::secrets::{InMemorySecretsStore, SecretInjectionError};
    use serde_json::json;

    fn secret(name: &str, value: &str) -> Secret {
        Secret {
            name: name.to_owned(),
            value: value.to_owned(),
        }
    }

    #[test]
    fn distinct_tenants_produce_distinct_namespaces() {
        let a = tenant_namespace(Some("org-a"), Some("team-1"));
        let b = tenant_namespace(Some("org-b"), Some("team-1"));
        let c = tenant_namespace(Some("org-a"), Some("team-2"));
        assert_ne!(a, b, "different org must isolate");
        assert_ne!(a, c, "different team must isolate");
    }

    #[test]
    fn untenanted_callers_share_one_namespace() {
        assert_eq!(tenant_namespace(None, None), tenant_namespace(None, None));
    }

    #[test]
    fn same_tenant_resolves_its_own_secret() {
        let backing = InMemorySecretsStore::new();
        let store = TenantScopedStore::for_tenant(&backing, Some("org-a"), Some("team-1"));
        store.register(secret("DB_PASSWORD", "real-secret-a")).unwrap();

        let out = resolve_placeholders(&json!("${DB_PASSWORD}"), &store).unwrap();
        assert_eq!(out.resolved, json!("real-secret-a"));
        assert_eq!(out.names_substituted, vec!["DB_PASSWORD"]);
    }

    #[test]
    fn cross_tenant_lookup_does_not_resolve() {
        let backing = InMemorySecretsStore::new();
        // Tenant A registers a secret.
        TenantScopedStore::for_tenant(&backing, Some("org-a"), Some("team-1"))
            .register(secret("DB_PASSWORD", "real-secret-a"))
            .unwrap();

        // Tenant B references the same bare name and must NOT resolve it.
        let tenant_b = TenantScopedStore::for_tenant(&backing, Some("org-b"), Some("team-1"));
        assert_eq!(tenant_b.lookup("DB_PASSWORD"), None);

        let err = resolve_placeholders(&json!("${DB_PASSWORD}"), &tenant_b)
            .expect_err("cross-tenant placeholder must not resolve");
        assert_eq!(
            err,
            SecretInjectionError::UnknownPlaceholder {
                name: "DB_PASSWORD".to_owned()
            }
        );
    }

    #[test]
    fn list_returns_only_this_tenants_names_unwrapped() {
        let backing = InMemorySecretsStore::new();
        TenantScopedStore::for_tenant(&backing, Some("org-a"), None)
            .register(secret("A_SECRET", "va"))
            .unwrap();
        TenantScopedStore::for_tenant(&backing, Some("org-b"), None)
            .register(secret("B_SECRET", "vb"))
            .unwrap();

        let a = TenantScopedStore::for_tenant(&backing, Some("org-a"), None);
        assert_eq!(a.list(), vec!["A_SECRET"]);
    }

    #[test]
    fn delete_is_scoped_to_the_tenant() {
        let backing = InMemorySecretsStore::new();
        let tenant_a = TenantScopedStore::for_tenant(&backing, Some("org-a"), None);
        tenant_a.register(secret("DB_PASSWORD", "va")).unwrap();

        // Tenant B cannot delete tenant A's secret (different namespace → NotFound).
        let tenant_b = TenantScopedStore::for_tenant(&backing, Some("org-b"), None);
        assert!(tenant_b.delete("DB_PASSWORD").is_err());

        // Tenant A can.
        assert!(tenant_a.delete("DB_PASSWORD").is_ok());
        assert_eq!(tenant_a.lookup("DB_PASSWORD"), None);
    }
}
