//! The [`SecretsStore`] trait — gateway-side registry of placeholder →
//! credential mappings used by Secret Injection — and the canonical
//! in-memory implementation [`InMemorySecretsStore`].

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use crate::secrets::{Secret, SecretsError};

/// CRUD surface over registered placeholder secrets.
///
/// Implementations must be safe to share across threads — the gateway holds
/// the store in `AppState` (`Arc<dyn SecretsStore>`) and concurrent
/// `dispatch_tool` calls may resolve placeholders in parallel.
///
/// ## Method contract
///
/// * [`register`](SecretsStore::register) — adds a new mapping. Returns
///   [`SecretsError::AlreadyRegistered`] if a secret with the same `name`
///   already exists. Registration is **not** idempotent so the operator
///   gets a signal when two callers race for the same key.
/// * [`lookup`](SecretsStore::lookup) — returns the real value, cloned.
///   Used by the resolver (AAASM-1924) to substitute `${NAME}` tokens.
///   `None` means the placeholder is not registered — the resolver
///   surfaces that as `SecretInjectionError::UnknownPlaceholder`.
/// * [`list`](SecretsStore::list) — returns only the registered placeholder
///   names, never the values. Intended for admin / debugging UIs.
/// * [`delete`](SecretsStore::delete) — removes a mapping. Returns
///   [`SecretsError::NotFound`] when the name is absent so calls are not
///   silently no-ops.
pub trait SecretsStore: Send + Sync {
    /// Registers a new placeholder → credential mapping.
    ///
    /// Returns [`SecretsError::AlreadyRegistered`] if `secret.name` is
    /// already present. Implementations must not silently overwrite.
    fn register(&self, secret: Secret) -> Result<(), SecretsError>;

    /// Looks up the real credential value for a placeholder name.
    ///
    /// `name` is the bare placeholder identifier (e.g. `DB_PASSWORD`)
    /// without the `${…}` wrapping. Returns the cloned value, or `None`
    /// if no entry is registered for the name.
    fn lookup(&self, name: &str) -> Option<String>;

    /// Returns every registered placeholder name, in insertion order.
    ///
    /// **Never** returns the real credential values. The store-wide value
    /// surface is `lookup(name)` only — `list()` exists so admin tooling
    /// can show what secrets are available without exposing them.
    fn list(&self) -> Vec<String>;

    /// Removes a registered placeholder.
    ///
    /// Returns [`SecretsError::NotFound`] when no entry exists for `name`
    /// so callers cannot accidentally treat a no-op as a successful delete.
    fn delete(&self, name: &str) -> Result<(), SecretsError>;
}

/// In-memory [`SecretsStore`] implementation — the default for v0.0.1.
///
/// Backed by a single `Arc<RwLock<HashMap<String, String>>>`. Reads
/// (`lookup`, `list`) take a read lock; writes (`register`, `delete`)
/// take a write lock. Persistence and per-team scoping are explicit
/// non-goals for v0.0.1 (tracked as follow-ups in `secrets/README.md`).
///
/// `Clone` is cheap (Arc bump) so callers can stash a handle in
/// `AppState` and hand it to async tasks.
#[derive(Clone, Default)]
pub struct InMemorySecretsStore {
    data: Arc<RwLock<HashMap<String, String>>>,
}

impl InMemorySecretsStore {
    /// Builds a fresh, empty store.
    pub fn new() -> Self {
        Self::default()
    }
}

impl SecretsStore for InMemorySecretsStore {
    fn register(&self, secret: Secret) -> Result<(), SecretsError> {
        let mut data = self.data.write().expect("secrets store lock poisoned");
        if data.contains_key(&secret.name) {
            return Err(SecretsError::AlreadyRegistered { name: secret.name });
        }
        data.insert(secret.name, secret.value);
        Ok(())
    }

    fn lookup(&self, name: &str) -> Option<String> {
        let data = self.data.read().expect("secrets store lock poisoned");
        data.get(name).cloned()
    }

    fn list(&self) -> Vec<String> {
        let data = self.data.read().expect("secrets store lock poisoned");
        let mut names: Vec<String> = data.keys().cloned().collect();
        names.sort();
        names
    }

    fn delete(&self, name: &str) -> Result<(), SecretsError> {
        let mut data = self.data.write().expect("secrets store lock poisoned");
        if data.remove(name).is_none() {
            return Err(SecretsError::NotFound { name: name.to_owned() });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret(name: &str, value: &str) -> Secret {
        Secret {
            name: name.to_owned(),
            value: value.to_owned(),
        }
    }

    #[test]
    fn register_stores_a_new_secret() {
        let store = InMemorySecretsStore::new();
        let result = store.register(secret("DB_PASSWORD", "real-secret-1"));
        assert!(result.is_ok());
        assert_eq!(store.lookup("DB_PASSWORD").as_deref(), Some("real-secret-1"));
    }

    #[test]
    fn lookup_returns_none_for_unknown_name() {
        let store = InMemorySecretsStore::new();
        store.register(secret("DB_PASSWORD", "real-secret-1")).unwrap();
        assert_eq!(store.lookup("UNKNOWN"), None);
    }

    #[test]
    fn delete_removes_a_registered_secret() {
        let store = InMemorySecretsStore::new();
        store.register(secret("DB_PASSWORD", "real-secret-1")).unwrap();
        store.delete("DB_PASSWORD").unwrap();
        assert_eq!(store.lookup("DB_PASSWORD"), None);
        assert!(store.list().is_empty());
    }

    #[test]
    fn list_returns_only_names_sorted_lexicographically() {
        let store = InMemorySecretsStore::new();
        store.register(secret("STRIPE_KEY", "real-1")).unwrap();
        store.register(secret("DB_PASSWORD", "real-2")).unwrap();
        store.register(secret("API_TOKEN", "real-3")).unwrap();
        let names = store.list();
        assert_eq!(names, vec!["API_TOKEN", "DB_PASSWORD", "STRIPE_KEY"]);
        for value in ["real-1", "real-2", "real-3"] {
            assert!(
                !names.iter().any(|n| n.contains(value)),
                "list() must never expose credential values; found {value:?}"
            );
        }
    }
}
