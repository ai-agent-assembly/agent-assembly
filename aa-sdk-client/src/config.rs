//! Configuration for the SDK assembly client.
//!
//! Resolves the runtime socket path from explicit parameters, environment
//! variables, or the default convention (`/tmp/aa-runtime-<agent_id>.sock`).

use std::env;
use std::path::PathBuf;

/// Default gateway gRPC endpoint, matching `aa-runtime`'s
/// `AA_GATEWAY_ENDPOINT` default. This is the **gRPC** port (`:50051`) that
/// serves `AgentLifecycleService` / `PolicyService` — *not* the gateway's
/// `:8080` HTTP/OpenAPI surface that some docs reference for REST.
pub const DEFAULT_GATEWAY_ENDPOINT: &str = "http://127.0.0.1:50051";

/// Configuration for connecting to `aa-runtime`.
#[derive(Debug, Clone)]
pub struct AssemblyConfig {
    /// The agent identifier used for socket path resolution and event tagging.
    pub agent_id: String,
    /// Explicit socket path override. When `None`, resolved from env or default.
    pub socket_path: Option<String>,
    /// Explicit gateway gRPC endpoint override (e.g. `"http://127.0.0.1:50051"`).
    /// When `None`, resolved from env or [`DEFAULT_GATEWAY_ENDPOINT`].
    pub gateway_endpoint: Option<String>,
    /// Team the agent belongs to. Forwarded on gateway registration as the
    /// `team_id` of the composite `AgentId` so the gateway can attribute the
    /// agent's spend to the correct team budget. `None` leaves it unset.
    pub team_id: Option<String>,
    /// UUID of the parent agent that spawned this one. Forwarded on gateway
    /// registration so the gateway can build the topology / delegation graph.
    /// `None` marks the agent as a root agent.
    pub parent_agent_id: Option<String>,
    /// User-facing language-package version of the SDK that opened this session
    /// (the PyPI / npm / go-module version), passed down through the FFI at init.
    /// Signed into the IPC handshake (AAASM-3666) so AAASM-3571 downgrade
    /// detection reflects the *installed SDK release* the customer runs, not the
    /// shared `aa-sdk-client` crate version. `None` falls back to the crate's
    /// `CARGO_PKG_VERSION` (AAASM-3683), preserving the pre-passthrough behaviour.
    pub sdk_version: Option<String>,
    /// Explicit directory for this agent's durable identity key (AAASM-5332).
    /// When `None`, resolved from `AASM_STATE_DIR`, else `~/.aasm/identity`.
    ///
    /// Follows the same explicit-overrides-ambient shape as `socket_path` and
    /// `gateway_endpoint` above. An embedder that keeps agent state somewhere of
    /// its own choosing needs the key to follow it, and a test needs each case's
    /// enrolments to be its own — a process-wide environment variable cannot
    /// give parallel tests separate identities.
    pub identity_dir: Option<String>,
}

impl AssemblyConfig {
    /// Resolve the Unix domain socket path to connect to.
    ///
    /// Resolution order:
    /// 1. Explicit `socket_path` if provided
    /// 2. `AA_RUNTIME_SOCKET` environment variable
    /// 3. Default: `/tmp/aa-runtime-<agent_id>.sock`
    pub fn resolve_socket_path(&self) -> PathBuf {
        if let Some(ref path) = self.socket_path {
            return PathBuf::from(path);
        }

        if let Ok(env_path) = env::var("AA_RUNTIME_SOCKET") {
            if !env_path.is_empty() {
                return PathBuf::from(env_path);
            }
        }

        PathBuf::from(format!("/tmp/aa-runtime-{}.sock", self.agent_id))
    }

    /// Resolve the gateway gRPC endpoint to use for registration.
    ///
    /// Resolution order:
    /// 1. Explicit `gateway_endpoint` if provided
    /// 2. `AA_GATEWAY_ENDPOINT` environment variable (the same knob
    ///    `aa-runtime` reads)
    /// 3. Default: [`DEFAULT_GATEWAY_ENDPOINT`] (`http://127.0.0.1:50051`)
    ///
    /// Note this is the gRPC `:50051` endpoint, not the gateway's `:8080`
    /// HTTP/OpenAPI URL.
    pub fn resolve_gateway_endpoint(&self) -> String {
        if let Some(ref endpoint) = self.gateway_endpoint {
            if !endpoint.is_empty() {
                return endpoint.clone();
            }
        }

        if let Ok(env_endpoint) = env::var("AA_GATEWAY_ENDPOINT") {
            if !env_endpoint.is_empty() {
                return env_endpoint;
            }
        }

        DEFAULT_GATEWAY_ENDPOINT.to_string()
    }

    /// Resolve the SDK version string to sign into the IPC handshake.
    ///
    /// Resolution order (mirrors the explicit-overrides-ambient precedence used
    /// for `gateway_endpoint`):
    /// 1. Explicit non-empty `sdk_version` — the language-package version the FFI
    ///    forwards at init (PyPI / npm / go-module version, AAASM-3683).
    /// 2. Fallback: this crate's `CARGO_PKG_VERSION` (the pre-AAASM-3683
    ///    behaviour from AAASM-3666, so there is no regression when the FFI does
    ///    not supply a version).
    ///
    /// The result authenticates the version under the handshake signature
    /// (`nonce || sdk_version`, AAASM-3666); an empty explicit value is treated
    /// as absent rather than signing an empty version.
    pub fn resolved_sdk_version(&self) -> String {
        if let Some(ref version) = self.sdk_version {
            if !version.is_empty() {
                return version.clone();
            }
        }

        env!("CARGO_PKG_VERSION").to_string()
    }

    /// Return the agent identity to send on gateway registration.
    ///
    /// The gateway's `AgentLifecycleService.Register` rejects a plain
    /// `agent_id`; it must be a `did:key` DID naming the key the registration's
    /// possession proof is made with. This resolves the configured `agent_id` to
    /// the DID of that agent's **durable identity key**, enrolling one on first
    /// use (AAASM-5332). An `agent_id` that is already a `did:key` is refused:
    /// this crate holds no private key for a DID it did not generate, so it
    /// could not prove possession of one. The socket-path / event-tag `agent_id`
    /// is intentionally left as-is.
    ///
    /// Fallible because the identity now lives on disk: there is no DID to
    /// report for an agent whose key cannot be established, and returning a
    /// plausible-looking one would recreate the defect this replaced.
    pub fn registration_did(&self) -> Result<String, crate::identity_store::IdentityStoreError> {
        if self.agent_id.starts_with("did:key:") {
            return Err(crate::identity_store::IdentityStoreError::ProvisionedDidUnsupported {
                did: self.agent_id.clone(),
            });
        }
        Ok(self.identity_keypair()?.did_key())
    }

    /// The agent's durable identity keypair, enrolling one on first use.
    ///
    /// The single place the registration path obtains key material, so the
    /// `did:key`, the `public_key` and the possession-proof signature in one
    /// `RegisterRequest` cannot come from different keys.
    pub fn identity_keypair(&self) -> Result<crate::keypair::AgentKeypair, crate::identity_store::IdentityStoreError> {
        self.identity_store()?.load_or_enroll(&self.agent_id)
    }

    /// The identity store this config's agent keeps its durable key in.
    ///
    /// Resolution order:
    /// 1. Explicit `identity_dir` if provided
    /// 2. `${AASM_STATE_DIR:-$HOME/.aasm}/identity`
    pub fn identity_store(
        &self,
    ) -> Result<crate::identity_store::IdentityStore, crate::identity_store::IdentityStoreError> {
        match self.identity_dir {
            Some(ref dir) if !dir.is_empty() => Ok(crate::identity_store::IdentityStore::at(dir)),
            _ => crate::identity_store::IdentityStore::default_location(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_config(agent_id: &str, socket_path: Option<&str>) -> AssemblyConfig {
        AssemblyConfig {
            agent_id: agent_id.to_string(),
            socket_path: socket_path.map(|s| s.to_string()),
            gateway_endpoint: None,
            team_id: None,
            parent_agent_id: None,
            sdk_version: None,
            identity_dir: None,
        }
    }

    #[test]
    fn resolve_uses_explicit_socket_path() {
        let config = make_config("test-agent", Some("/custom/path.sock"));
        assert_eq!(config.resolve_socket_path(), PathBuf::from("/custom/path.sock"));
    }

    #[test]
    fn resolve_falls_back_to_default_path() {
        // Clear env var to ensure default path is used.
        env::remove_var("AA_RUNTIME_SOCKET");
        let config = make_config("my-agent", None);
        assert_eq!(
            config.resolve_socket_path(),
            PathBuf::from("/tmp/aa-runtime-my-agent.sock")
        );
    }

    #[test]
    fn resolve_gateway_uses_explicit_endpoint() {
        let config = AssemblyConfig {
            agent_id: "a".into(),
            socket_path: None,
            gateway_endpoint: Some("http://gw.example:50051".into()),
            team_id: None,
            parent_agent_id: None,
            sdk_version: None,
            identity_dir: None,
        };
        assert_eq!(config.resolve_gateway_endpoint(), "http://gw.example:50051");
    }

    #[test]
    fn resolve_gateway_falls_back_to_default() {
        env::remove_var("AA_GATEWAY_ENDPOINT");
        let config = make_config("a", None);
        assert_eq!(config.resolve_gateway_endpoint(), DEFAULT_GATEWAY_ENDPOINT);
    }

    #[test]
    fn resolved_sdk_version_prefers_explicit_language_version() {
        let mut config = make_config("a", None);
        config.sdk_version = Some("9.9.9".into());
        // The FFI-forwarded language-package version wins over the crate version.
        assert_eq!(config.resolved_sdk_version(), "9.9.9");
    }

    #[test]
    fn resolved_sdk_version_falls_back_to_crate_version_when_none() {
        // AAASM-3683: no FFI-supplied version → fall back to CARGO_PKG_VERSION
        // (the AAASM-3666 behaviour), so there is no regression.
        let config = make_config("a", None);
        assert_eq!(config.resolved_sdk_version(), env!("CARGO_PKG_VERSION"));
    }

    #[test]
    fn resolved_sdk_version_treats_empty_explicit_as_absent() {
        let mut config = make_config("a", None);
        config.sdk_version = Some(String::new());
        // An empty explicit value must not sign an empty version — fall back.
        assert_eq!(config.resolved_sdk_version(), env!("CARGO_PKG_VERSION"));
    }

    #[test]
    fn config_is_clone() {
        let config = make_config("agent", None);
        let cloned = config.clone();
        assert_eq!(cloned.agent_id, "agent");
    }
}
