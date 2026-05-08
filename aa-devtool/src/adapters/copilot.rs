//! Detection-only adapter for GitHub Copilot (VS Code extension).
//!
//! Full adapter implementation is tracked in AAASM-203.

use std::path::PathBuf;

use aa_core::policy::PolicyDocument;
use aa_core::{AdapterError, DevToolAdapter, DevToolInfo, DevToolKind, GovernanceLevel, McpServerInfo};
use async_trait::async_trait;

/// Adapter for GitHub Copilot (VS Code extension).
///
/// Detects the `github.copilot-*` extension under `~/.vscode/extensions/`.
/// Governance level: [`GovernanceLevel::L1Observe`].
#[derive(Debug, Default)]
pub struct CopilotAdapter;

/// Scan `~/.vscode/extensions/` for a directory starting with `github.copilot-`.
///
/// Returns `(extension_dir, version)` when found.
fn find_copilot_extension() -> Option<(PathBuf, Option<String>)> {
    let ext_dir = dirs::home_dir()?.join(".vscode").join("extensions");
    let entries = std::fs::read_dir(&ext_dir).ok()?;
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if name_str.starts_with("github.copilot-") {
            let ext_path = entry.path();
            // Try to read version from package.json.
            let version = read_package_json_version(&ext_path);
            return Some((ext_path, version));
        }
    }
    None
}

fn read_package_json_version(ext_path: &std::path::Path) -> Option<String> {
    let pkg_json_path = ext_path.join("package.json");
    let content = std::fs::read_to_string(pkg_json_path).ok()?;
    let v: serde_json::Value = serde_json::from_str(&content).ok()?;
    v["version"].as_str().map(|s| s.to_owned())
}

#[async_trait]
impl DevToolAdapter for CopilotAdapter {
    fn detect(&self) -> Option<DevToolInfo> {
        let (install_path, version) = find_copilot_extension()?;

        Some(DevToolInfo {
            kind: DevToolKind::GitHubCopilot,
            version,
            install_path,
            governance_level: GovernanceLevel::L1Observe,
            supports_mcp: false,
            supports_managed_settings: false,
        })
    }

    async fn generate_managed_settings(&self, _policy: &PolicyDocument) -> Result<String, AdapterError> {
        Err(AdapterError::SettingsGenerationFailed(
            "Copilot adapter not yet fully implemented (AAASM-203)".into(),
        ))
    }

    async fn apply_settings(&self, _settings: &str) -> Result<(), AdapterError> {
        Err(AdapterError::SettingsApplyFailed(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "Copilot adapter not yet fully implemented (AAASM-203)",
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
            "Copilot adapter not yet fully implemented (AAASM-203)".into(),
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
        assert_eq!(CopilotAdapter.governance_level(), GovernanceLevel::L1Observe);
    }

    #[tokio::test]
    async fn generate_managed_settings_returns_err() {
        let policy = PolicyDocument {
            version: 1,
            name: "test".into(),
            rules: vec![],
        };
        assert!(CopilotAdapter.generate_managed_settings(&policy).await.is_err());
    }

    #[tokio::test]
    async fn apply_settings_returns_err() {
        assert!(CopilotAdapter.apply_settings("{}").await.is_err());
    }

    #[test]
    fn build_launch_command_returns_err() {
        assert!(CopilotAdapter.build_launch_command(&[], "agent-1", None, None).is_err());
    }

    #[tokio::test]
    async fn list_mcp_servers_returns_empty() {
        assert!(CopilotAdapter.list_mcp_servers().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn apply_mcp_governance_returns_ok() {
        assert!(CopilotAdapter.apply_mcp_governance(&[], &[]).await.is_ok());
    }

    #[test]
    fn read_package_json_version_returns_some_for_valid_json() {
        let tmp = std::env::temp_dir().join("aaasm_copilot_test_ext");
        std::fs::create_dir_all(&tmp).unwrap();
        std::fs::write(
            tmp.join("package.json"),
            r#"{"version":"1.234.5","name":"github.copilot"}"#,
        )
        .unwrap();
        let result = read_package_json_version(&tmp);
        let _ = std::fs::remove_dir_all(&tmp);
        assert_eq!(result, Some("1.234.5".to_string()));
    }

    #[test]
    fn read_package_json_version_returns_none_for_missing_file() {
        let path = std::path::Path::new("/nonexistent/path/for/aaasm/test");
        assert!(read_package_json_version(path).is_none());
    }
}
