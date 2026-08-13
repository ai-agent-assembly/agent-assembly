//! [`StorageConfig`] — the `[storage]` section of `agent-assembly.toml`.

use std::collections::HashMap;
use std::fmt;

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
///
/// `Debug` is implemented by hand rather than derived: the per-driver
/// [`drivers`](StorageConfig::drivers) sections hold raw `toml::Value` tables that
/// typically carry a driver's connection string (e.g. `url =
/// "postgresql://user:password@host/db"`). A derived `Debug` would render those
/// DSNs verbatim into any log line that formats a `StorageConfig`, leaking the
/// embedded credentials. The manual impl below redacts every driver section's
/// value, printing only its name (AAASM-3997).
#[derive(Clone, Serialize, Deserialize)]
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

impl fmt::Debug for StorageConfig {
    /// Redacting `Debug`: renders the driver-kind selections but replaces every
    /// `[storage.<name>]` section's raw value with `<redacted>` so a connection
    /// string (and any credentials embedded in it) can never reach a log line
    /// (AAASM-3997).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StorageConfig")
            .field("policy_store", &self.policy_store)
            .field("audit_sink", &self.audit_sink)
            .field("session_store", &self.session_store)
            .field("credential_store", &self.credential_store)
            .field("rate_limit_counter", &self.rate_limit_counter)
            .field("lifecycle_store", &self.lifecycle_store)
            .field("drivers", &RedactedDrivers(&self.drivers))
            .finish()
    }
}

/// `Debug` adapter that prints the driver-section names but redacts their raw
/// `toml::Value` contents (which carry DSNs / credentials).
struct RedactedDrivers<'a>(&'a HashMap<DriverName, toml::Value>);

impl fmt::Debug for RedactedDrivers<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut map = f.debug_map();
        for name in self.0.keys() {
            map.key(name).value(&"<redacted>");
        }
        map.finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_config(drivers: HashMap<DriverName, toml::Value>) -> StorageConfig {
        StorageConfig {
            policy_store: DriverName::new("redis"),
            audit_sink: DriverName::new("postgres"),
            session_store: DriverName::new("redis"),
            credential_store: DriverName::new("postgres"),
            rate_limit_counter: DriverName::new("redis"),
            lifecycle_store: DriverName::new("postgres"),
            drivers,
        }
    }

    #[test]
    fn debug_redacts_driver_connection_strings() {
        let mut drivers = HashMap::new();
        let mut section = toml::value::Table::new();
        section.insert(
            "url".to_string(),
            toml::Value::String("postgresql://admin:s3cr3t-pw@db.internal:5432/assembly".to_string()),
        );
        drivers.insert(DriverName::new("postgres"), toml::Value::Table(section));
        let config = base_config(drivers);

        let rendered = format!("{config:?}");
        // The DSN and the password embedded in it must never render.
        assert!(
            !rendered.contains("s3cr3t-pw"),
            "connection-string password leaked into Debug output: {rendered}"
        );
        assert!(
            !rendered.contains("postgresql://"),
            "connection string leaked into Debug output: {rendered}"
        );
        // The driver name and a redaction marker are still shown for diagnostics.
        assert!(
            rendered.contains("<redacted>"),
            "expected a redaction marker: {rendered}"
        );
        assert!(
            rendered.contains("postgres"),
            "driver name should still render: {rendered}"
        );
    }
}
