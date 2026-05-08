//! Detection-only adapter for Codeium Windsurf Cascade IDE.
//!
//! Full adapter implementation is tracked in AAASM-204.

use std::path::PathBuf;

use aa_core::policy::PolicyDocument;
use aa_core::{AdapterError, DevToolAdapter, DevToolInfo, DevToolKind, GovernanceLevel, McpServerInfo};
use async_trait::async_trait;

use super::util::{find_on_path, probe_version};

/// Adapter for Codeium Windsurf Cascade.
///
/// Detects the `windsurf` binary on PATH, `/Applications/Windsurf.app` (macOS),
/// or `~/.local/share/windsurf` (Linux).
/// Governance level: [`GovernanceLevel::L1Observe`].
#[derive(Debug, Default)]
pub struct WindsurfAdapter;

#[async_trait]
impl DevToolAdapter for WindsurfAdapter {
    fn detect(&self) -> Option<DevToolInfo> {
        // Primary: binary on PATH — attempt version probe.
        if let Some(binary_path) = find_on_path("windsurf") {
            let version = probe_version(&binary_path);
            return Some(DevToolInfo {
                kind: DevToolKind::WindsurfCascade,
                version,
                install_path: binary_path,
                governance_level: GovernanceLevel::L1Observe,
                supports_mcp: false,
                supports_managed_settings: false,
            });
        }

        // Fallback macOS: application bundle.
        let macos_app = PathBuf::from("/Applications/Windsurf.app");
        if macos_app.exists() {
            return Some(DevToolInfo {
                kind: DevToolKind::WindsurfCascade,
                version: None,
                install_path: macos_app,
                governance_level: GovernanceLevel::L1Observe,
                supports_mcp: false,
                supports_managed_settings: false,
            });
        }

        // Fallback Linux: ~/.local/share/windsurf
        let linux_dir = dirs::home_dir()?.join(".local").join("share").join("windsurf");
        if linux_dir.exists() {
            return Some(DevToolInfo {
                kind: DevToolKind::WindsurfCascade,
                version: None,
                install_path: linux_dir,
                governance_level: GovernanceLevel::L1Observe,
                supports_mcp: false,
                supports_managed_settings: false,
            });
        }

        None
    }

    async fn generate_managed_settings(&self, _policy: &PolicyDocument) -> Result<String, AdapterError> {
        Err(AdapterError::SettingsGenerationFailed(
            "Windsurf adapter not yet fully implemented (AAASM-204)".into(),
        ))
    }

    async fn apply_settings(&self, _settings: &str) -> Result<(), AdapterError> {
        Err(AdapterError::SettingsApplyFailed(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "Windsurf adapter not yet fully implemented (AAASM-204)",
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
            "Windsurf adapter not yet fully implemented (AAASM-204)".into(),
        ))
    }

    async fn list_mcp_servers(&self) -> Result<Vec<McpServerInfo>, AdapterError> {
        Ok(vec![])
    }

    async fn apply_mcp_governance(&self, _allowed: &[String], _denied: &[String]) -> Result<(), AdapterError> {
        Ok(())
    }

    fn governance_level(&self) -> GovernanceLevel {
        GovernanceLevel::L1Observe
    }
}

#[cfg(test)]
mod tests {
    use aa_core::policy::PolicyDocument;
    use aa_core::GovernanceLevel;

    use super::*;

    #[test]
    fn governance_level_is_l1observe() {
        assert_eq!(WindsurfAdapter.governance_level(), GovernanceLevel::L1Observe);
    }

    #[tokio::test]
    async fn generate_managed_settings_returns_err() {
        let policy = PolicyDocument {
            version: 1,
            name: "test".into(),
            rules: vec![],
        };
        assert!(WindsurfAdapter.generate_managed_settings(&policy).await.is_err());
    }

    #[tokio::test]
    async fn apply_settings_returns_err() {
        assert!(WindsurfAdapter.apply_settings("{}").await.is_err());
    }

    #[test]
    fn build_launch_command_returns_err() {
        assert!(WindsurfAdapter
            .build_launch_command(&[], "agent-1", None, None)
            .is_err());
    }

    #[tokio::test]
    async fn list_mcp_servers_returns_empty() {
        assert!(WindsurfAdapter.list_mcp_servers().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn apply_mcp_governance_returns_ok() {
        assert!(WindsurfAdapter.apply_mcp_governance(&[], &[]).await.is_ok());
    }
}
