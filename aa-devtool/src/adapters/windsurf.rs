//! Detection-only adapter for Codeium Windsurf Cascade IDE.
//!
//! Full adapter implementation is tracked in AAASM-204.

use std::path::PathBuf;

use async_trait::async_trait;
use aa_core::{AdapterError, DevToolAdapter, DevToolInfo, DevToolKind, GovernanceLevel, McpServerInfo};
use aa_core::policy::PolicyDocument;

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
