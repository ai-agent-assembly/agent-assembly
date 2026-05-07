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
