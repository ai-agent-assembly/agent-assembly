//! Detection-only adapter for Anthropic Claude Code.
//!
//! Full adapter implementation (managed settings, MCP governance, launch wiring)
//! is tracked in AAASM-201.

use std::path::PathBuf;

use async_trait::async_trait;
use aa_core::{AdapterError, DevToolAdapter, DevToolInfo, DevToolKind, GovernanceLevel, McpServerInfo};
use aa_core::policy::PolicyDocument;

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
