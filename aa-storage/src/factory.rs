//! Factory traits that build a storage backend from its TOML subsection.
//!
//! A driver crate implements the factory for each storage kind it provides and
//! registers it on the [`Registry`](crate::Registry). The loader then calls the
//! factory with the driver's `[storage.<name>]` subsection (as a
//! [`toml::Value`]) to construct the trait object.

use std::sync::Arc;

use crate::{AuditSink, CredentialStore, LifecycleStore, PolicyStore, RateLimitCounter, Result, SessionStore};

/// Builds a [`PolicyStore`] from its `[storage.<name>]` TOML subsection.
pub trait PolicyStoreFactory: Send + Sync {
    /// Construct the policy-store backend from its config subsection.
    fn build(&self, config: &toml::Value) -> Result<Arc<dyn PolicyStore>>;
}

/// Builds an [`AuditSink`] from its `[storage.<name>]` TOML subsection.
pub trait AuditSinkFactory: Send + Sync {
    /// Construct the audit-sink backend from its config subsection.
    fn build(&self, config: &toml::Value) -> Result<Arc<dyn AuditSink>>;
}

/// Builds a [`SessionStore`] from its `[storage.<name>]` TOML subsection.
pub trait SessionStoreFactory: Send + Sync {
    /// Construct the session-store backend from its config subsection.
    fn build(&self, config: &toml::Value) -> Result<Arc<dyn SessionStore>>;
}

/// Builds a [`CredentialStore`] from its `[storage.<name>]` TOML subsection.
pub trait CredentialStoreFactory: Send + Sync {
    /// Construct the credential-store backend from its config subsection.
    fn build(&self, config: &toml::Value) -> Result<Arc<dyn CredentialStore>>;
}

/// Builds a [`RateLimitCounter`] from its `[storage.<name>]` TOML subsection.
pub trait RateLimitCounterFactory: Send + Sync {
    /// Construct the rate-limit-counter backend from its config subsection.
    fn build(&self, config: &toml::Value) -> Result<Arc<dyn RateLimitCounter>>;
}

/// Builds a [`LifecycleStore`] from its `[storage.<name>]` TOML subsection.
pub trait LifecycleStoreFactory: Send + Sync {
    /// Construct the lifecycle-store backend from its config subsection.
    fn build(&self, config: &toml::Value) -> Result<Arc<dyn LifecycleStore>>;
}
