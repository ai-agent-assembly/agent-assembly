//! [`SaasCodingAgentAdapter`] — [`DevToolAdapter`] implementation for SaaS
//! coding agents (Claude.ai, ChatGPT, Cursor cloud).
//!
//! This adapter is capped at [`GovernanceLevel::L1Observe`]. SaaS agents run
//! in opaque cloud environments, so in-process enforcement (L2/L3) is not
//! possible. The adapter supports:
//! - Detect: presence check via `api_key_secret_ref` (no network I/O).
//! - Webhook ingestion: via the `aa-api` route that calls [`crate::signature`].
//! - MCP advisory overlay: [`crate::overlay::claude_ai::ClaudeAiOverlay`] (Claude.ai only).
//!
//! [`DevToolAdapter`]: aa_core::DevToolAdapter
//! [`GovernanceLevel::L1Observe`]: aa_core::GovernanceLevel::L1Observe

use std::path::PathBuf;

use aa_core::{AdapterError, DevToolAdapter, DevToolInfo, DevToolKind, GovernanceLevel, McpServerInfo};
use async_trait::async_trait;

use crate::provider::{SaasProvider, SaasProviderConfig};

/// [`DevToolAdapter`] implementation for SaaS-hosted coding agents.
///
/// Governance level is always [`GovernanceLevel::L1Observe`]; L2/L3 are
/// structurally unreachable for SaaS-boundary tools.
///
/// [`DevToolAdapter`]: aa_core::DevToolAdapter
#[derive(Debug, Clone)]
pub struct SaasCodingAgentAdapter {
    config: SaasProviderConfig,
}

impl SaasCodingAgentAdapter {
    /// Construct an adapter for the given provider configuration.
    pub fn new(config: SaasProviderConfig) -> Self {
        Self { config }
    }
}

/// Returns a stable `DevToolKind::Custom` identifier for the given provider.
fn provider_kind_id(p: &SaasProvider) -> String {
    match p {
        SaasProvider::ClaudeAi => "claude-ai-saas".to_string(),
        SaasProvider::ChatGpt => "chatgpt-saas".to_string(),
        SaasProvider::CursorCloud => "cursor-cloud".to_string(),
    }
}

#[async_trait]
impl DevToolAdapter for SaasCodingAgentAdapter {
    /// Detect whether this SaaS integration is configured.
    ///
    /// Returns `Some` when `api_key_secret_ref` is non-empty, indicating the
    /// integration has been wired up (even if the secret has not yet been
    /// resolved). Returns `None` when the ref is empty, which signals the
    /// integration is not configured and the adapter should be skipped.
    ///
    /// No network I/O is performed — this method runs on the hot path.
    fn detect(&self) -> Option<DevToolInfo> {
        if self.config.api_key_secret_ref.is_empty() {
            return None;
        }
        Some(DevToolInfo {
            kind: DevToolKind::Custom(provider_kind_id(&self.config.provider)),
            version: None,
            install_path: PathBuf::from("/saas"),
            governance_level: GovernanceLevel::L1Observe,
            // Claude.ai exposes MCP server configuration via Workspaces API.
            supports_mcp: matches!(self.config.provider, SaasProvider::ClaudeAi),
            // SaaS adapters do not write managed settings files locally.
            supports_managed_settings: false,
        })
    }

    /// SaaS adapters do not support managed settings generation.
    async fn generate_managed_settings(
        &self,
        _policy: &aa_core::policy::PolicyDocument,
    ) -> Result<String, AdapterError> {
        Err(AdapterError::SettingsGenerationFailed(
            "SaaS adapters do not support managed settings".into(),
        ))
    }

    /// SaaS adapters do not support applying managed settings.
    async fn apply_settings(&self, _settings: &str) -> Result<(), AdapterError> {
        Err(AdapterError::SettingsApplyFailed(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "SaaS adapters do not support managed settings",
        )))
    }

    /// SaaS adapters cannot be launched locally.
    fn build_launch_command(
        &self,
        _tool_args: &[String],
        _agent_id: &str,
        _team_id: Option<&str>,
        _proxy_addr: Option<&str>,
    ) -> Result<std::process::Command, AdapterError> {
        Err(AdapterError::LaunchFailed(
            "SaaS adapters cannot be launched locally".into(),
        ))
    }

    /// SaaS adapters have no local MCP configuration to read.
    async fn list_mcp_servers(&self) -> Result<Vec<McpServerInfo>, AdapterError> {
        Ok(vec![])
    }

    /// L1 governance overlay is advisory; no local config is written.
    ///
    /// For Claude.ai, the [`crate::overlay::claude_ai::ClaudeAiOverlay`]
    /// type holds the MCP allowlist and is applied separately by the
    /// operator via the Workspaces API — not by this method.
    async fn apply_mcp_governance(
        &self,
        _allowed: &[String],
        _denied: &[String],
    ) -> Result<(), AdapterError> {
        Ok(())
    }

    /// Returns [`GovernanceLevel::L1Observe`] — the maximum achievable level
    /// for SaaS-boundary tools.
    fn governance_level(&self) -> GovernanceLevel {
        GovernanceLevel::L1Observe
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::{SaasProvider, SaasProviderConfig};

    fn make_adapter(provider: SaasProvider, secret_ref: &str) -> SaasCodingAgentAdapter {
        SaasCodingAgentAdapter::new(SaasProviderConfig {
            provider,
            api_url: "https://api.example.com".into(),
            api_key_secret_ref: secret_ref.into(),
        })
    }

    #[test]
    fn detect_returns_none_when_secret_ref_empty() {
        let adapter = make_adapter(SaasProvider::ClaudeAi, "");
        assert!(adapter.detect().is_none());
    }

    #[test]
    fn detect_returns_some_when_configured() {
        let adapter = make_adapter(SaasProvider::ClaudeAi, "vault:secret/claude/hmac");
        let info = adapter.detect().expect("should detect");
        assert_eq!(info.governance_level, GovernanceLevel::L1Observe);
        assert!(!info.supports_managed_settings);
    }

    #[test]
    fn governance_level_is_always_l1observe() {
        for provider in [SaasProvider::ClaudeAi, SaasProvider::ChatGpt, SaasProvider::CursorCloud] {
            let adapter = make_adapter(provider, "vault:secret/x/hmac");
            assert_eq!(adapter.governance_level(), GovernanceLevel::L1Observe);
        }
    }

    #[test]
    fn build_launch_command_always_errors() {
        let adapter = make_adapter(SaasProvider::ChatGpt, "vault:secret/chatgpt/hmac");
        let result = adapter.build_launch_command(&[], "agent-1", None, None);
        assert!(matches!(result, Err(AdapterError::LaunchFailed(_))));
    }
}
