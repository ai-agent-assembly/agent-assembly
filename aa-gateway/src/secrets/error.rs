//! Errors returned by [`crate::secrets::SecretsStore`] CRUD operations.

use thiserror::Error;

/// Error returned by [`crate::secrets::SecretsStore`] CRUD operations.
///
/// The placeholder-resolver path has its own error type
/// (`SecretInjectionError`, AAASM-1924) — this enum only covers
/// failures internal to the store itself.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum SecretsError {
    /// A `register` call was made for a placeholder name that already has
    /// an entry. Registering the same name twice is rejected rather than
    /// silently overwritten so operators get a signal that two callers are
    /// racing for the same key.
    #[error("placeholder already registered: {name}")]
    AlreadyRegistered {
        /// The placeholder name (no `${…}` wrapping) that was already in
        /// the store when the duplicate `register` was attempted.
        name: String,
    },
    /// A `delete` call referenced a placeholder name that is not in the
    /// store.
    #[error("placeholder not found: {name}")]
    NotFound {
        /// The placeholder name (no `${…}` wrapping) that was missing.
        name: String,
    },
}
