//! Placeholder registration of the OSS driver names.
//!
//! The concrete OSS backends (`memory`, `redis`, `postgres`) ship in Epic B and
//! will register their own real factories from their own crates. Until then,
//! [`register_builtin_drivers`] registers those names with a stub factory so the
//! config loader recognizes them (and `aasm config validate` reports the correct
//! set of valid names), while attempting to *build* one returns a clear
//! "not yet implemented" error.

use std::sync::Arc;

use crate::factory::{
    AuditSinkFactory, CredentialStoreFactory, LifecycleStoreFactory, PolicyStoreFactory, RateLimitCounterFactory,
    SessionStoreFactory,
};
use crate::{
    AuditSink, CredentialStore, LifecycleStore, PolicyStore, RateLimitCounter, Registry, Result, SessionStore,
    StorageError,
};

/// The OSS driver names the loader recognizes ahead of their Epic B impls.
const BUILTIN_DRIVERS: [&str; 3] = ["memory", "postgres", "redis"];

/// A factory stand-in for an OSS driver whose backend is not implemented yet.
///
/// Registering it makes the driver *name* resolvable (so config validation
/// passes and lists it among the valid names), but building it returns
/// [`StorageError::Backend`] explaining the backend lands in Epic B.
struct NotImplemented {
    driver: &'static str,
}

impl NotImplemented {
    fn unimplemented<T>(&self) -> Result<T> {
        Err(StorageError::Backend(format!(
            "storage driver {:?} is not implemented yet (ships in Epic B)",
            self.driver
        )))
    }
}

impl PolicyStoreFactory for NotImplemented {
    fn build(&self, _config: &toml::Value) -> Result<Arc<dyn PolicyStore>> {
        self.unimplemented()
    }
}

impl AuditSinkFactory for NotImplemented {
    fn build(&self, _config: &toml::Value) -> Result<Arc<dyn AuditSink>> {
        self.unimplemented()
    }
}

impl SessionStoreFactory for NotImplemented {
    fn build(&self, _config: &toml::Value) -> Result<Arc<dyn SessionStore>> {
        self.unimplemented()
    }
}

impl CredentialStoreFactory for NotImplemented {
    fn build(&self, _config: &toml::Value) -> Result<Arc<dyn CredentialStore>> {
        self.unimplemented()
    }
}

impl RateLimitCounterFactory for NotImplemented {
    fn build(&self, _config: &toml::Value) -> Result<Arc<dyn RateLimitCounter>> {
        self.unimplemented()
    }
}

impl LifecycleStoreFactory for NotImplemented {
    fn build(&self, _config: &toml::Value) -> Result<Arc<dyn LifecycleStore>> {
        self.unimplemented()
    }
}

/// Register the placeholder OSS drivers (`memory`, `redis`, `postgres`) for
/// every storage kind.
///
/// This is the manual `register_drivers()`-at-boot hook the design calls for;
/// Epic B replaces each placeholder with the real driver crate's `register`
/// call.
pub fn register_builtin_drivers(registry: &mut Registry) {
    for driver in BUILTIN_DRIVERS {
        registry.register_policy_store(driver, Box::new(NotImplemented { driver }));
        registry.register_audit_sink(driver, Box::new(NotImplemented { driver }));
        registry.register_session_store(driver, Box::new(NotImplemented { driver }));
        registry.register_credential_store(driver, Box::new(NotImplemented { driver }));
        registry.register_rate_limit_counter(driver, Box::new(NotImplemented { driver }));
        registry.register_lifecycle_store(driver, Box::new(NotImplemented { driver }));
    }
}
