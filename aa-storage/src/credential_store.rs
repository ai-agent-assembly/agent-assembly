//! [`CredentialStore`] — storage for named secret material.

use crate::Result;
use async_trait::async_trait;
use std::vec::Vec;

/// Stores and retrieves named secret material as opaque bytes.
///
/// Keys are caller-defined names (for example `"openai/api_key"`); values are
/// opaque byte strings so the contract stays agnostic to the secret's encoding.
/// Backends are expected to encrypt at rest; this trait only defines the access
/// contract, not the protection mechanism.
///
/// # Example
///
/// ```
/// use aa_storage::{CredentialStore, Result, StorageError};
/// use async_trait::async_trait;
///
/// /// A store that holds no secrets.
/// struct EmptyCredentialStore;
///
/// #[async_trait]
/// impl CredentialStore for EmptyCredentialStore {
///     async fn get_secret(&self, key: &str) -> Result<Vec<u8>> {
///         Err(StorageError::NotFound(key.to_owned()))
///     }
///
///     async fn put_secret(&self, _key: &str, _value: Vec<u8>) -> Result<()> {
///         Ok(())
///     }
///
///     async fn delete_secret(&self, _key: &str) -> Result<()> {
///         Ok(())
///     }
/// }
/// ```
#[async_trait]
pub trait CredentialStore: Send + Sync {
    /// Return the secret bytes stored under `key`.
    ///
    /// Returns [`StorageError::NotFound`](crate::StorageError::NotFound) when no
    /// secret exists for the key.
    async fn get_secret(&self, key: &str) -> Result<Vec<u8>>;

    /// Store `value` under `key`, overwriting any existing secret.
    async fn put_secret(&self, key: &str, value: Vec<u8>) -> Result<()>;

    /// Delete the secret stored under `key`.
    ///
    /// Idempotent: deleting an absent key succeeds.
    async fn delete_secret(&self, key: &str) -> Result<()>;
}
