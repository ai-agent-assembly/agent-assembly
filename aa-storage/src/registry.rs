//! [`Registry`] — maps driver names to backend factories and resolves a
//! [`StorageConfig`] into concrete stores.

use std::collections::BTreeMap;
use std::sync::Arc;

use crate::factory::{
    AuditSinkFactory, CredentialStoreFactory, LifecycleStoreFactory, PolicyStoreFactory, RateLimitCounterFactory,
    SessionStoreFactory,
};
use crate::{
    AuditSink, ConfigError, CredentialStore, DriverName, LifecycleStore, PolicyStore, RateLimitCounter, SessionStore,
    StorageConfig,
};

/// Registry of storage-driver factories, keyed by [`DriverName`] per kind.
///
/// Each driver crate calls the `register_*` methods (typically from a single
/// `register(&mut Registry)` entry point) to make its backends selectable by
/// name. The loader then uses [`validate`](Registry::validate) to check a
/// [`StorageConfig`] and the `build_*` methods to instantiate the chosen stores.
#[derive(Default)]
pub struct Registry {
    policy_stores: BTreeMap<DriverName, Box<dyn PolicyStoreFactory>>,
    audit_sinks: BTreeMap<DriverName, Box<dyn AuditSinkFactory>>,
    session_stores: BTreeMap<DriverName, Box<dyn SessionStoreFactory>>,
    credential_stores: BTreeMap<DriverName, Box<dyn CredentialStoreFactory>>,
    rate_limit_counters: BTreeMap<DriverName, Box<dyn RateLimitCounterFactory>>,
    lifecycle_stores: BTreeMap<DriverName, Box<dyn LifecycleStoreFactory>>,
}

impl Registry {
    /// Create an empty registry with no drivers registered.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a policy-store driver under `name`.
    pub fn register_policy_store(&mut self, name: impl Into<DriverName>, factory: Box<dyn PolicyStoreFactory>) {
        self.policy_stores.insert(name.into(), factory);
    }

    /// Register an audit-sink driver under `name`.
    pub fn register_audit_sink(&mut self, name: impl Into<DriverName>, factory: Box<dyn AuditSinkFactory>) {
        self.audit_sinks.insert(name.into(), factory);
    }

    /// Register a session-store driver under `name`.
    pub fn register_session_store(&mut self, name: impl Into<DriverName>, factory: Box<dyn SessionStoreFactory>) {
        self.session_stores.insert(name.into(), factory);
    }

    /// Register a credential-store driver under `name`.
    pub fn register_credential_store(&mut self, name: impl Into<DriverName>, factory: Box<dyn CredentialStoreFactory>) {
        self.credential_stores.insert(name.into(), factory);
    }

    /// Register a rate-limit-counter driver under `name`.
    pub fn register_rate_limit_counter(
        &mut self,
        name: impl Into<DriverName>,
        factory: Box<dyn RateLimitCounterFactory>,
    ) {
        self.rate_limit_counters.insert(name.into(), factory);
    }

    /// Register a lifecycle-store driver under `name`.
    pub fn register_lifecycle_store(&mut self, name: impl Into<DriverName>, factory: Box<dyn LifecycleStoreFactory>) {
        self.lifecycle_stores.insert(name.into(), factory);
    }

    /// Names of all registered policy-store drivers, sorted.
    pub fn policy_store_names(&self) -> Vec<&str> {
        self.policy_stores.keys().map(DriverName::as_str).collect()
    }

    /// Names of all registered audit-sink drivers, sorted.
    pub fn audit_sink_names(&self) -> Vec<&str> {
        self.audit_sinks.keys().map(DriverName::as_str).collect()
    }

    /// Names of all registered session-store drivers, sorted.
    pub fn session_store_names(&self) -> Vec<&str> {
        self.session_stores.keys().map(DriverName::as_str).collect()
    }

    /// Names of all registered credential-store drivers, sorted.
    pub fn credential_store_names(&self) -> Vec<&str> {
        self.credential_stores.keys().map(DriverName::as_str).collect()
    }

    /// Names of all registered rate-limit-counter drivers, sorted.
    pub fn rate_limit_counter_names(&self) -> Vec<&str> {
        self.rate_limit_counters.keys().map(DriverName::as_str).collect()
    }

    /// Names of all registered lifecycle-store drivers, sorted.
    pub fn lifecycle_store_names(&self) -> Vec<&str> {
        self.lifecycle_stores.keys().map(DriverName::as_str).collect()
    }

    /// Check that `name` is registered in `factories` and that `config` carries
    /// its `[storage.<name>]` subsection.
    fn check<F: ?Sized>(
        kind: &'static str,
        name: &DriverName,
        factories: &BTreeMap<DriverName, Box<F>>,
        config: &StorageConfig,
    ) -> Result<(), ConfigError> {
        if !factories.contains_key(name) {
            return Err(ConfigError::UnknownDriver {
                kind,
                name: name.to_string(),
                available: factories.keys().map(DriverName::to_string).collect(),
            });
        }
        if config.driver_section(name).is_none() {
            return Err(ConfigError::MissingDriverSection {
                kind,
                name: name.to_string(),
            });
        }
        Ok(())
    }

    /// Check every driver named in `config` is registered and has a subsection.
    ///
    /// Returns the first [`ConfigError`] encountered. This is the entry point
    /// behind `aasm config validate`.
    pub fn validate(&self, config: &StorageConfig) -> Result<(), ConfigError> {
        Self::check("policy_store", &config.policy_store, &self.policy_stores, config)?;
        Self::check("audit_sink", &config.audit_sink, &self.audit_sinks, config)?;
        Self::check("session_store", &config.session_store, &self.session_stores, config)?;
        Self::check(
            "credential_store",
            &config.credential_store,
            &self.credential_stores,
            config,
        )?;
        Self::check(
            "rate_limit_counter",
            &config.rate_limit_counter,
            &self.rate_limit_counters,
            config,
        )?;
        Self::check(
            "lifecycle_store",
            &config.lifecycle_store,
            &self.lifecycle_stores,
            config,
        )?;
        Ok(())
    }

    /// Build the configured [`PolicyStore`].
    pub fn build_policy_store(&self, config: &StorageConfig) -> Result<Arc<dyn PolicyStore>, ConfigError> {
        let name = &config.policy_store;
        Self::check("policy_store", name, &self.policy_stores, config)?;
        let section = config.driver_section(name).expect("subsection checked by `check`");
        self.policy_stores[name]
            .build(section)
            .map_err(|source| ConfigError::Build {
                kind: "policy_store",
                name: name.to_string(),
                source,
            })
    }

    /// Build the configured [`AuditSink`].
    pub fn build_audit_sink(&self, config: &StorageConfig) -> Result<Arc<dyn AuditSink>, ConfigError> {
        let name = &config.audit_sink;
        Self::check("audit_sink", name, &self.audit_sinks, config)?;
        let section = config.driver_section(name).expect("subsection checked by `check`");
        self.audit_sinks[name]
            .build(section)
            .map_err(|source| ConfigError::Build {
                kind: "audit_sink",
                name: name.to_string(),
                source,
            })
    }

    /// Build the configured [`SessionStore`].
    pub fn build_session_store(&self, config: &StorageConfig) -> Result<Arc<dyn SessionStore>, ConfigError> {
        let name = &config.session_store;
        Self::check("session_store", name, &self.session_stores, config)?;
        let section = config.driver_section(name).expect("subsection checked by `check`");
        self.session_stores[name]
            .build(section)
            .map_err(|source| ConfigError::Build {
                kind: "session_store",
                name: name.to_string(),
                source,
            })
    }

    /// Build the configured [`CredentialStore`].
    pub fn build_credential_store(&self, config: &StorageConfig) -> Result<Arc<dyn CredentialStore>, ConfigError> {
        let name = &config.credential_store;
        Self::check("credential_store", name, &self.credential_stores, config)?;
        let section = config.driver_section(name).expect("subsection checked by `check`");
        self.credential_stores[name]
            .build(section)
            .map_err(|source| ConfigError::Build {
                kind: "credential_store",
                name: name.to_string(),
                source,
            })
    }

    /// Build the configured [`RateLimitCounter`].
    pub fn build_rate_limit_counter(&self, config: &StorageConfig) -> Result<Arc<dyn RateLimitCounter>, ConfigError> {
        let name = &config.rate_limit_counter;
        Self::check("rate_limit_counter", name, &self.rate_limit_counters, config)?;
        let section = config.driver_section(name).expect("subsection checked by `check`");
        self.rate_limit_counters[name]
            .build(section)
            .map_err(|source| ConfigError::Build {
                kind: "rate_limit_counter",
                name: name.to_string(),
                source,
            })
    }

    /// Build the configured [`LifecycleStore`].
    pub fn build_lifecycle_store(&self, config: &StorageConfig) -> Result<Arc<dyn LifecycleStore>, ConfigError> {
        let name = &config.lifecycle_store;
        Self::check("lifecycle_store", name, &self.lifecycle_stores, config)?;
        let section = config.driver_section(name).expect("subsection checked by `check`");
        self.lifecycle_stores[name]
            .build(section)
            .map_err(|source| ConfigError::Build {
                kind: "lifecycle_store",
                name: name.to_string(),
                source,
            })
    }
}
