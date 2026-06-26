//! gRPC server TLS / mTLS configuration scaffold (AAASM-3788; the live
//! handshake is tracked as a follow-up under AAASM-3418).
//!
//! The credential-token interceptor ([`super::grpc_auth`]) is the application
//! authentication layer and is always on for the agent-plane services. mTLS is
//! an OPTIONAL *transport* hardening layered on top of it. This type captures
//! the configuration surface and resolves it from the environment.
//!
//! Wiring the resolved config into `Server::builder().tls_config(...)` requires
//! enabling a tonic TLS feature (`tls-aws-lc`) and provisioning certificates,
//! which is intentionally deferred — see the wire point in
//! [`crate::server::serve_tcp`] and `SECURITY.md`. Until then, when TLS is
//! requested via the environment the server **fails closed** (refuses to start
//! plaintext) rather than silently serving an unprotected socket the operator
//! believes is encrypted.

use std::path::PathBuf;

/// Resolved gRPC transport-security configuration.
#[derive(Debug, Clone)]
pub struct GrpcTlsConfig {
    /// PEM server certificate chain path.
    pub cert_path: PathBuf,
    /// PEM server private key path.
    pub key_path: PathBuf,
    /// Optional PEM client-CA bundle. When set, clients must present a
    /// certificate signed by this CA (mutual TLS).
    pub client_ca_path: Option<PathBuf>,
}

impl GrpcTlsConfig {
    /// Environment variable naming the server certificate chain (PEM).
    pub const ENV_CERT: &'static str = "AA_GATEWAY_GRPC_TLS_CERT";
    /// Environment variable naming the server private key (PEM).
    pub const ENV_KEY: &'static str = "AA_GATEWAY_GRPC_TLS_KEY";
    /// Environment variable naming the client-CA bundle (PEM); presence enables mTLS.
    pub const ENV_CLIENT_CA: &'static str = "AA_GATEWAY_GRPC_CLIENT_CA";

    /// Resolve TLS config from the environment.
    ///
    /// Returns `None` (the default plaintext, loopback-only posture) unless both
    /// [`ENV_CERT`](Self::ENV_CERT) and [`ENV_KEY`](Self::ENV_KEY) are set to a
    /// non-empty value. When [`ENV_CLIENT_CA`](Self::ENV_CLIENT_CA) is also set,
    /// the config requests mutual TLS.
    pub fn from_env() -> Option<Self> {
        let cert = non_empty_var(Self::ENV_CERT)?;
        let key = non_empty_var(Self::ENV_KEY)?;
        let client_ca = non_empty_var(Self::ENV_CLIENT_CA).map(PathBuf::from);
        Some(Self {
            cert_path: PathBuf::from(cert),
            key_path: PathBuf::from(key),
            client_ca_path: client_ca,
        })
    }

    /// Whether this config requests mutual TLS (client-certificate verification).
    pub fn is_mutual(&self) -> bool {
        self.client_ca_path.is_some()
    }
}

/// Read an environment variable, treating empty values as unset.
fn non_empty_var(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_only_config_is_not_mutual() {
        let cfg = GrpcTlsConfig {
            cert_path: PathBuf::from("/tmp/cert.pem"),
            key_path: PathBuf::from("/tmp/key.pem"),
            client_ca_path: None,
        };
        assert!(!cfg.is_mutual());
    }

    #[test]
    fn config_with_client_ca_is_mutual() {
        let cfg = GrpcTlsConfig {
            cert_path: PathBuf::from("/tmp/cert.pem"),
            key_path: PathBuf::from("/tmp/key.pem"),
            client_ca_path: Some(PathBuf::from("/tmp/ca.pem")),
        };
        assert!(cfg.is_mutual());
    }

    #[test]
    fn non_empty_var_treats_empty_as_unset() {
        // A var that is overwhelmingly unlikely to be set in any environment.
        assert!(non_empty_var("AA_GATEWAY_GRPC_TLS_DEFINITELY_UNSET_XYZ").is_none());
    }
}
