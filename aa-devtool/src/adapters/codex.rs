//! Detection-only adapter for OpenAI Codex CLI.
//!
//! Full adapter implementation (managed settings, launch wiring)
//! is tracked in AAASM-202.

use std::path::PathBuf;

use aa_core::policy::PolicyDocument;
use aa_core::{AdapterError, DevToolAdapter, DevToolInfo, DevToolKind, GovernanceLevel, McpServerInfo};
use async_trait::async_trait;

use super::util::{find_on_path, probe_version};

/// Adapter for OpenAI Codex CLI.
///
/// Detects the `codex` binary on PATH or the npm global bin location.
/// Governance level: [`GovernanceLevel::L2Enforce`].
#[derive(Debug, Default)]
pub struct CodexAdapter;

#[async_trait]
impl DevToolAdapter for CodexAdapter {
    fn detect(&self) -> Option<DevToolInfo> {
        // Primary: binary on PATH.
        let install_path: PathBuf = if let Some(p) = find_on_path("codex") {
            p
        } else {
            // Fallback: ~/.npm/bin/codex
            let npm_bin = dirs::home_dir()?.join(".npm").join("bin").join("codex");
            if npm_bin.exists() {
                npm_bin
            } else {
                return None;
            }
        };

        let version = probe_version(&install_path);

        Some(DevToolInfo {
            kind: DevToolKind::Codex,
            version,
            install_path,
            governance_level: GovernanceLevel::L2Enforce,
            supports_mcp: false,
            supports_managed_settings: true,
        })
    }

    async fn generate_managed_settings(&self, _policy: &PolicyDocument) -> Result<String, AdapterError> {
        Err(AdapterError::SettingsGenerationFailed(
            "Codex adapter not yet fully implemented (AAASM-202)".into(),
        ))
    }

    async fn apply_settings(&self, _settings: &str) -> Result<(), AdapterError> {
        Err(AdapterError::SettingsApplyFailed(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "Codex adapter not yet fully implemented (AAASM-202)",
        )))
    }

    fn build_launch_command(
        &self,
        _tool_args: &[String],
        _agent_id: &str,
        _team_id: Option<&str>,
        _proxy_addr: Option<&str>,
    ) -> Result<std::process::Command, AdapterError> {
        Err(AdapterError::LaunchFailed(
            "Codex adapter not yet fully implemented (AAASM-202)".into(),
        ))
    }

    async fn list_mcp_servers(&self) -> Result<Vec<McpServerInfo>, AdapterError> {
        Ok(vec![])
    }

    async fn apply_mcp_governance(&self, _allowed: &[String], _denied: &[String]) -> Result<(), AdapterError> {
        Ok(())
    }

    fn governance_level(&self) -> GovernanceLevel {
        GovernanceLevel::L2Enforce
    }
}

#[cfg(test)]
mod tests {
    use aa_core::policy::PolicyDocument;
    use aa_core::GovernanceLevel;

    use super::*;

    #[test]
    fn governance_level_is_l2enforce() {
        assert_eq!(CodexAdapter.governance_level(), GovernanceLevel::L2Enforce);
    }

    #[tokio::test]
    async fn generate_managed_settings_returns_err() {
        let policy = PolicyDocument { version: 1, name: "test".into(), rules: vec![] };
        assert!(CodexAdapter.generate_managed_settings(&policy).await.is_err());
    }

    #[tokio::test]
    async fn apply_settings_returns_err() {
        assert!(CodexAdapter.apply_settings("{}").await.is_err());
    }

    #[test]
    fn build_launch_command_returns_err() {
        assert!(CodexAdapter.build_launch_command(&[], "agent-1", None, None).is_err());
    }

    #[tokio::test]
    async fn list_mcp_servers_returns_empty() {
        assert!(CodexAdapter.list_mcp_servers().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn apply_mcp_governance_returns_ok() {
        assert!(CodexAdapter.apply_mcp_governance(&[], &[]).await.is_ok());
    }
}
