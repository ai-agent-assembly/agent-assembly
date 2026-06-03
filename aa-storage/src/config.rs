//! [`StorageConfig`] — the `[storage]` section of `agent-assembly.toml`.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::DriverName;

/// The `[storage]` section: which driver backs each storage kind, plus the
/// per-driver connection subsections.
///
/// ```toml
/// [storage]
/// policy_store       = "redis"
/// audit_sink         = "postgres"
/// session_store      = "redis"
/// credential_store   = "postgres"
/// rate_limit_counter = "redis"
/// lifecycle_store    = "postgres"
///
/// [storage.redis]
/// url = "redis://localhost:6379"
///
/// [storage.postgres]
/// url = "postgresql://localhost:5432/assembly"
/// ```
///
/// The six driver-kind keys select a backend by [`DriverName`]; every other key
/// under `[storage]` is a `[storage.<name>]` table captured into [`drivers`]
/// and handed verbatim to that driver's factory.
///
/// [`drivers`]: StorageConfig::drivers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    /// Driver backing the [`PolicyStore`](crate::PolicyStore).
    pub policy_store: DriverName,
    /// Driver backing the [`AuditSink`](crate::AuditSink).
    pub audit_sink: DriverName,
    /// Driver backing the [`SessionStore`](crate::SessionStore).
    pub session_store: DriverName,
    /// Driver backing the [`CredentialStore`](crate::CredentialStore).
    pub credential_store: DriverName,
    /// Driver backing the [`RateLimitCounter`](crate::RateLimitCounter).
    pub rate_limit_counter: DriverName,
    /// Driver backing the [`LifecycleStore`](crate::LifecycleStore).
    pub lifecycle_store: DriverName,
    /// Per-driver `[storage.<name>]` subsections, keyed by driver name.
    ///
    /// Each value is the raw TOML table for that driver; the driver's own
    /// factory parses the keys it needs.
    #[serde(flatten)]
    pub drivers: HashMap<DriverName, toml::Value>,
}

impl StorageConfig {
    /// Return the `[storage.<name>]` subsection for `name`, if present.
    pub fn driver_section(&self, name: &DriverName) -> Option<&toml::Value> {
        self.drivers.get(name)
    }
}
