//! Operator configuration for the NATS audit publisher.
//!
//! Deserialized from the `[gateway.nats]` table of `agent-assembly.toml`.

use std::path::PathBuf;

use serde::Deserialize;

/// Default NATS server URL when `[gateway.nats] url` is omitted.
pub const DEFAULT_URL: &str = "nats://127.0.0.1:4222";

/// Default cap on in-flight (unacknowledged) publishes when `max_inflight` is
/// omitted.
pub const DEFAULT_MAX_INFLIGHT: usize = 1_024;

/// TLS material for the NATS connection, configured under `[gateway.nats.tls]`.
///
/// All three paths are optional: provide `ca` to trust a private server
/// certificate, and `cert` + `key` together for mutual-TLS client
/// authentication.
#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct NatsTlsConfig {
    /// Path to a PEM bundle of root certificates used to verify the server.
    pub ca: Option<PathBuf>,
    /// Path to the client certificate (PEM) for mutual TLS.
    pub cert: Option<PathBuf>,
    /// Path to the client private key (PEM) for mutual TLS.
    pub key: Option<PathBuf>,
}

/// Connection settings for the Assembly-side NATS audit publisher.
///
/// Deserialized from the `[gateway.nats]` table; every field is optional and
/// falls back to a sensible default so a bare `[gateway.nats]` (or no table at
/// all) still yields a usable local-development configuration.
///
/// ```
/// use aa_runtime::audit_publisher::NatsConfig;
///
/// let cfg = NatsConfig::default();
/// assert_eq!(cfg.url, "nats://127.0.0.1:4222");
/// assert!(cfg.token.is_none());
/// assert!(cfg.tls.is_none());
/// ```
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct NatsConfig {
    /// NATS server URL (e.g. `nats://host:4222` or `tls://host:4222`).
    pub url: String,
    /// Bearer token presented to the server for authentication.
    pub token: Option<String>,
    /// TLS material; `None` leaves the connection plaintext.
    pub tls: Option<NatsTlsConfig>,
    /// Upper bound on concurrently in-flight publishes.
    pub max_inflight: usize,
}

impl Default for NatsConfig {
    fn default() -> Self {
        Self {
            url: DEFAULT_URL.to_string(),
            token: None,
            tls: None,
            max_inflight: DEFAULT_MAX_INFLIGHT,
        }
    }
}

/// The `[gateway]` table, holding the nested `nats` configuration.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct GatewaySection {
    nats: NatsConfig,
}

/// Document root used to reach `[gateway.nats]` from a full
/// `agent-assembly.toml`.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct ConfigRoot {
    gateway: GatewaySection,
}

impl NatsConfig {
    /// Parse the `[gateway.nats]` table out of an `agent-assembly.toml` document.
    ///
    /// A document with neither `[gateway]` nor `[gateway.nats]` yields the
    /// [`Default`] configuration, so callers can pass the whole config file
    /// unconditionally.
    ///
    /// # Errors
    ///
    /// Returns the underlying [`toml::de::Error`] when the document is not valid
    /// TOML or the `[gateway.nats]` table has a type-incompatible value.
    pub fn from_toml_str(toml: &str) -> Result<Self, toml::de::Error> {
        Ok(toml::from_str::<ConfigRoot>(toml)?.gateway.nats)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_full_gateway_nats_table() {
        let toml = r#"
            [gateway.nats]
            url = "tls://nats.example.com:4222"
            token = "s3cr3t"
            max_inflight = 4096

            [gateway.nats.tls]
            ca = "/etc/aa/ca.pem"
            cert = "/etc/aa/client.pem"
            key = "/etc/aa/client.key"
        "#;

        let cfg = NatsConfig::from_toml_str(toml).expect("valid config");

        assert_eq!(cfg.url, "tls://nats.example.com:4222");
        assert_eq!(cfg.token.as_deref(), Some("s3cr3t"));
        assert_eq!(cfg.max_inflight, 4096);
        let tls = cfg.tls.expect("tls table present");
        assert_eq!(tls.ca, Some(PathBuf::from("/etc/aa/ca.pem")));
        assert_eq!(tls.cert, Some(PathBuf::from("/etc/aa/client.pem")));
        assert_eq!(tls.key, Some(PathBuf::from("/etc/aa/client.key")));
    }

    #[test]
    fn falls_back_to_defaults_when_table_absent() {
        // A config document with an unrelated table and no [gateway.nats].
        let cfg = NatsConfig::from_toml_str("[storage]\naudit_sink = \"postgres\"\n").expect("valid config");

        assert_eq!(cfg, NatsConfig::default());
        assert_eq!(cfg.url, DEFAULT_URL);
        assert_eq!(cfg.max_inflight, DEFAULT_MAX_INFLIGHT);
        assert!(cfg.token.is_none());
        assert!(cfg.tls.is_none());
    }
}
