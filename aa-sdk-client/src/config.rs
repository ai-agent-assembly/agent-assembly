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

    /// Return the agent identity to send on gateway registration.
    ///
    /// The gateway's `AgentLifecycleService.Register` rejects a plain
    /// `agent_id`; it must be a `did:key` DID. This derives a conformant
    /// `did:key` from the configured `agent_id` (passing through an
    /// already-`did:key` identifier unchanged). The socket-path / event-tag
    /// `agent_id` is intentionally left as-is.
    pub fn registration_did(&self) -> String {
        crate::identity::agent_id_to_did_key(&self.agent_id)
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
    fn config_is_clone() {
        let config = make_config("agent", None);
        let cloned = config.clone();
        assert_eq!(cloned.agent_id, "agent");
    }
}
