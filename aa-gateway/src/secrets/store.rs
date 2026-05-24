//! The [`SecretsStore`] trait — gateway-side registry of placeholder →
//! credential mappings used by Secret Injection.

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
