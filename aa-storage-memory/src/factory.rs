//! Factories that build the in-memory backends for the `aa-storage` driver
//! registry.
//!
//! The memory driver needs no connection settings, so every factory ignores its
//! `[storage.memory]` TOML subsection and returns a fresh, empty store. They are
//! registered under the driver name `"memory"` by [`crate::register`].

use std::sync::Arc;

use aa_storage::factory::{
    AuditSinkFactory, CredentialStoreFactory, LifecycleStoreFactory, PolicyStoreFactory, RateLimitCounterFactory,
    SessionStoreFactory,
};
use aa_storage::{AuditSink, CredentialStore, LifecycleStore, PolicyStore, RateLimitCounter, Result, SessionStore};

use crate::{
    MemoryAuditSink, MemoryCredentialStore, MemoryLifecycleStore, MemoryPolicyStore, MemoryRateLimitCounter,
    MemorySessionStore,
};

/// Builds a [`MemoryPolicyStore`](crate::MemoryPolicyStore).
#[derive(Debug, Default, Clone, Copy)]
pub struct MemoryPolicyStoreFactory;

impl PolicyStoreFactory for MemoryPolicyStoreFactory {
    fn build(&self, _config: &toml::Value) -> Result<Arc<dyn PolicyStore>> {
        Ok(Arc::new(MemoryPolicyStore::new()))
    }
}

/// Builds a [`MemoryAuditSink`](crate::MemoryAuditSink).
#[derive(Debug, Default, Clone, Copy)]
pub struct MemoryAuditSinkFactory;

impl AuditSinkFactory for MemoryAuditSinkFactory {
    fn build(&self, _config: &toml::Value) -> Result<Arc<dyn AuditSink>> {
        Ok(Arc::new(MemoryAuditSink::new()))
    }
}

/// Builds a [`MemorySessionStore`](crate::MemorySessionStore).
#[derive(Debug, Default, Clone, Copy)]
pub struct MemorySessionStoreFactory;

impl SessionStoreFactory for MemorySessionStoreFactory {
    fn build(&self, _config: &toml::Value) -> Result<Arc<dyn SessionStore>> {
        Ok(Arc::new(MemorySessionStore::new()))
    }
}

/// Builds a [`MemoryCredentialStore`](crate::MemoryCredentialStore).
#[derive(Debug, Default, Clone, Copy)]
pub struct MemoryCredentialStoreFactory;

impl CredentialStoreFactory for MemoryCredentialStoreFactory {
    fn build(&self, _config: &toml::Value) -> Result<Arc<dyn CredentialStore>> {
        Ok(Arc::new(MemoryCredentialStore::new()))
    }
}

/// Builds a [`MemoryRateLimitCounter`](crate::MemoryRateLimitCounter).
#[derive(Debug, Default, Clone, Copy)]
pub struct MemoryRateLimitCounterFactory;

impl RateLimitCounterFactory for MemoryRateLimitCounterFactory {
    fn build(&self, _config: &toml::Value) -> Result<Arc<dyn RateLimitCounter>> {
        Ok(Arc::new(MemoryRateLimitCounter::new()))
    }
}

/// Builds a [`MemoryLifecycleStore`](crate::MemoryLifecycleStore).
#[derive(Debug, Default, Clone, Copy)]
pub struct MemoryLifecycleStoreFactory;

impl LifecycleStoreFactory for MemoryLifecycleStoreFactory {
    fn build(&self, _config: &toml::Value) -> Result<Arc<dyn LifecycleStore>> {
        Ok(Arc::new(MemoryLifecycleStore::new()))
    }
}
