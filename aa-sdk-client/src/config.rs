//! Configuration for the SDK assembly client.
//!
//! Resolves the runtime socket path from explicit parameters, environment
//! variables, or the default convention (`/tmp/aa-runtime-<agent_id>.sock`).

use std::env;
use std::path::PathBuf;

/// Configuration for connecting to `aa-runtime`.
#[derive(Debug, Clone)]
pub struct AssemblyConfig {
    /// The agent identifier used for socket path resolution and event tagging.
    pub agent_id: String,
    /// Explicit socket path override. When `None`, resolved from env or default.
    pub socket_path: Option<String>,
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
    fn config_is_clone() {
        let config = make_config("agent", None);
        let cloned = config.clone();
        assert_eq!(cloned.agent_id, "agent");
    }
}
