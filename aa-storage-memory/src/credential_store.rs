//! In-memory [`CredentialStore`] backed by a `DashMap`.

use std::sync::Arc;

use aa_storage::{CredentialStore, Result, StorageError};
use async_trait::async_trait;
use dashmap::DashMap;

/// A `DashMap`-backed [`CredentialStore`] mapping key strings to opaque secret
/// bytes. Cloning shares the same underlying map.
#[derive(Clone, Default)]
pub struct MemoryCredentialStore {
    secrets: Arc<DashMap<String, Vec<u8>>>,
}

impl MemoryCredentialStore {
    /// Create an empty store.
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl CredentialStore for MemoryCredentialStore {
    async fn get_secret(&self, key: &str) -> Result<Vec<u8>> {
        self.secrets
            .get(key)
            .map(|entry| entry.value().clone())
            .ok_or_else(|| StorageError::NotFound(format!("secret {key}")))
    }

    async fn put_secret(&self, key: &str, value: Vec<u8>) -> Result<()> {
        self.secrets.insert(key.to_owned(), value);
        Ok(())
    }

    async fn delete_secret(&self, key: &str) -> Result<()> {
        self.secrets.remove(key);
        Ok(())
    }
}
