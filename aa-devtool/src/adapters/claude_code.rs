//! Detection-only adapter for Anthropic Claude Code.
//!
//! Full adapter implementation (managed settings, MCP governance, launch wiring)
//! is tracked in AAASM-201.

use std::path::PathBuf;

use aa_core::policy::PolicyDocument;
use aa_core::{AdapterError, DevToolAdapter, DevToolInfo, DevToolKind, GovernanceLevel, McpServerInfo};
use async_trait::async_trait;

use super::util::{find_on_path, probe_version};

/// Adapter for Anthropic Claude Code.
///
/// Detects the `claude` binary on PATH or the `~/.claude` install marker.
/// Governance level: [`GovernanceLevel::L3Native`].
#[derive(Debug, Default)]
pub struct ClaudeCodeAdapter;

#[async_trait]
impl DevToolAdapter for ClaudeCodeAdapter {
    fn detect(&self) -> Option<DevToolInfo> {
        // Primary: binary on PATH.
        let install_path: PathBuf = if let Some(p) = find_on_path("claude") {
            p
        } else {
            // Fallback: ~/.claude directory existence (e.g. installed via npm global).
            let marker = dirs::home_dir()?.join(".claude");
            if marker.exists() {
                marker
            } else {
                return None;
            }
        };

        let version = probe_version(&install_path);

        Some(DevToolInfo {
            kind: DevToolKind::ClaudeCode,
            version,
            install_path,
            governance_level: GovernanceLevel::L3Native,
            supports_mcp: true,
            supports_managed_settings: true,
        })
    }

    async fn generate_managed_settings(&self, _policy: &PolicyDocument) -> Result<String, AdapterError> {
        Err(AdapterError::SettingsGenerationFailed(
            "ClaudeCode adapter not yet fully implemented (AAASM-201)".into(),
        ))
    }

    async fn apply_settings(&self, _settings: &str) -> Result<(), AdapterError> {
        Err(AdapterError::SettingsApplyFailed(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "ClaudeCode adapter not yet fully implemented (AAASM-201)",
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
            "ClaudeCode adapter not yet fully implemented (AAASM-201)".into(),
        ))
    }

    async fn list_mcp_servers(&self) -> Result<Vec<McpServerInfo>, AdapterError> {
        Ok(vec![])
    }

    async fn apply_mcp_governance(&self, _allowed: &[String], _denied: &[String]) -> Result<(), AdapterError> {
        Ok(())
    }

    fn governance_level(&self) -> GovernanceLevel {
        GovernanceLevel::L3Native
    }
}

#[cfg(test)]
mod tests {
    use aa_core::policy::PolicyDocument;
    use aa_core::GovernanceLevel;

    use super::*;

    #[test]
    fn governance_level_is_l3native() {
        assert_eq!(ClaudeCodeAdapter.governance_level(), GovernanceLevel::L3Native);
    }

    #[tokio::test]
    async fn generate_managed_settings_returns_err() {
        let policy = PolicyDocument {
            version: 1,
            name: "test".into(),
            rules: vec![],
        };
        assert!(ClaudeCodeAdapter.generate_managed_settings(&policy).await.is_err());
    }

    #[tokio::test]
    async fn apply_settings_returns_err() {
        assert!(ClaudeCodeAdapter.apply_settings("{}").await.is_err());
    }

    #[test]
    fn build_launch_command_returns_err() {
        assert!(ClaudeCodeAdapter
            .build_launch_command(&[], "agent-1", None, None)
            .is_err());
    }

    #[tokio::test]
    async fn list_mcp_servers_returns_empty() {
        assert!(ClaudeCodeAdapter.list_mcp_servers().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn apply_mcp_governance_returns_ok() {
        assert!(ClaudeCodeAdapter.apply_mcp_governance(&[], &[]).await.is_ok());
    }
}
