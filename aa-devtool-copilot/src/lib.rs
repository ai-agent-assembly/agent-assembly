//! [`DevToolAdapter`] implementation for GitHub Copilot running in VS Code
//! agent mode.
//!
//! Copilot is a VS Code extension — governance is applied by writing VS Code
//! workspace / user settings, not by wrapping a launcher binary. This adapter
//! therefore returns [`AdapterError::LaunchFailed`] from
//! [`build_launch_command`] and operates at **L2 (Enforce)**: it controls MCP
//! server access, tool-approval prompts, and per-session request limits via
//! `.vscode/settings.json`.
//!
//! ## Version requirements
//!
//! | Component | Minimum version |
//! |---|---|
//! | VS Code | 1.92 |
//! | `github.copilot` extension | 1.226 |
//! | `github.copilot-chat` extension | 0.21 |
//!
//! [`build_launch_command`]: CopilotAdapter::build_launch_command
//! [`DevToolAdapter`]: aa_core::DevToolAdapter

#![warn(missing_docs)]

use std::path::{Path, PathBuf};
use std::process::Command;

use aa_core::{AdapterError, DevToolAdapter, DevToolInfo, DevToolKind, GovernanceLevel, McpServerInfo, PolicyDocument};
use async_trait::async_trait;

/// Minimum `github.copilot` extension version this adapter supports.
pub const MIN_COPILOT_VERSION: &str = "1.226.0";
/// Minimum `github.copilot-chat` extension version this adapter supports.
pub const MIN_COPILOT_CHAT_VERSION: &str = "0.21.0";

/// Extension name prefix for the core Copilot extension.
const COPILOT_EXT_PREFIX: &str = "github.copilot-";
/// Extension name prefix for the Copilot Chat extension (must be excluded
/// from core-Copilot detection — different extension, same org prefix).
const COPILOT_CHAT_EXT_PREFIX: &str = "github.copilot-chat-";

/// [`DevToolAdapter`] for GitHub Copilot (VS Code agent mode).
///
/// Constructor takes an explicit extensions-directory override so the test
/// suite can point at temporary directories without touching the real VS Code
/// installation. Production code calls [`CopilotAdapter::new`] and relies on
/// the platform-default `~/.vscode/extensions` path.
///
/// The `settings_path` field and VS Code user-settings helpers are added in
/// AAASM-1002 when [`generate_managed_settings`] and [`apply_settings`] are
/// implemented.
///
/// [`DevToolAdapter`]: aa_core::DevToolAdapter
/// [`generate_managed_settings`]: CopilotAdapter::generate_managed_settings
/// [`apply_settings`]: CopilotAdapter::apply_settings
#[derive(Debug, Clone)]
pub struct CopilotAdapter {
    /// Override for `~/.vscode/extensions`. When `None` the adapter resolves
    /// the platform default at detection time.
    extensions_dir: Option<PathBuf>,
}

impl CopilotAdapter {
    /// Create an adapter that uses the platform-default VS Code paths.
    pub fn new() -> Self {
        Self { extensions_dir: None }
    }

    /// Create an adapter that reads extensions from `extensions_dir` instead
    /// of the default `~/.vscode/extensions`. Useful in tests.
    pub fn with_extensions_dir(extensions_dir: impl Into<PathBuf>) -> Self {
        Self {
            extensions_dir: Some(extensions_dir.into()),
        }
    }

    /// Resolve the VS Code extensions directory: explicit override wins,
    /// otherwise fall back to the platform default (`~/.vscode/extensions`).
    fn resolve_extensions_dir(&self) -> Option<PathBuf> {
        if let Some(p) = &self.extensions_dir {
            return Some(p.clone());
        }
        default_extensions_dir()
    }

    /// Scan `extensions_dir` for a `github.copilot-<version>` subdirectory
    /// (excluding `github.copilot-chat-*`) and parse the version from its
    /// `package.json`. Returns `(install_path, version)` when found.
    fn find_copilot_extension(extensions_dir: &Path) -> Option<(PathBuf, String)> {
        let entries = std::fs::read_dir(extensions_dir).ok()?;
        for entry in entries.flatten() {
            let path = entry.path();
            let name = path.file_name()?.to_str()?;
            // Exclude the copilot-chat extension which shares the same prefix.
            if name.starts_with(COPILOT_CHAT_EXT_PREFIX) {
                continue;
            }
            if name.starts_with(COPILOT_EXT_PREFIX) {
                let version = read_package_version(&path).unwrap_or_default();
                return Some((path, version));
            }
        }
        None
    }
}

impl Default for CopilotAdapter {
    fn default() -> Self {
        Self::new()
    }
}

/// Read the `"version"` field from a VS Code extension's `package.json`.
fn read_package_version(extension_dir: &Path) -> Option<String> {
    let raw = std::fs::read_to_string(extension_dir.join("package.json")).ok()?;
    let parsed: serde_json::Value = serde_json::from_str(&raw).ok()?;
    parsed["version"].as_str().map(|s| s.to_string())
}

/// Platform-default VS Code extensions directory.
fn default_extensions_dir() -> Option<PathBuf> {
    #[cfg(windows)]
    {
        std::env::var_os("USERPROFILE").map(|p| PathBuf::from(p).join(".vscode").join("extensions"))
    }
    #[cfg(not(windows))]
    {
        std::env::var_os("HOME").map(|p| PathBuf::from(p).join(".vscode").join("extensions"))
    }
}

#[async_trait]
impl DevToolAdapter for CopilotAdapter {
    fn detect(&self) -> Option<DevToolInfo> {
        let extensions_dir = self.resolve_extensions_dir()?;
        let (install_path, version) = Self::find_copilot_extension(&extensions_dir)?;
        Some(DevToolInfo {
            kind: DevToolKind::GitHubCopilot,
            version: Some(version),
            install_path,
            governance_level: GovernanceLevel::L2Enforce,
            supports_mcp: true,
            supports_managed_settings: true,
        })
    }

    async fn generate_managed_settings(&self, _policy: &PolicyDocument) -> Result<String, AdapterError> {
        // Implemented in AAASM-1002.
        Ok(serde_json::to_string_pretty(&serde_json::json!({})).map_err(|e| AdapterError::Serde(e.to_string()))?)
    }

    async fn apply_settings(&self, _settings: &str) -> Result<(), AdapterError> {
        // Implemented in AAASM-1002.
        Ok(())
    }

    fn build_launch_command(
        &self,
        _tool_args: &[String],
        _agent_id: &str,
        _team_id: Option<&str>,
        _proxy_addr: Option<&str>,
    ) -> Result<Command, AdapterError> {
        Err(AdapterError::LaunchFailed(
            "GitHub Copilot is a VS Code extension and cannot be launched by `aa run`; \
             apply governance settings with `aa tool apply copilot` instead"
                .to_string(),
        ))
    }

    async fn list_mcp_servers(&self) -> Result<Vec<McpServerInfo>, AdapterError> {
        // Implemented in AAASM-1006.
        Ok(vec![])
    }

    async fn apply_mcp_governance(&self, _allowed: &[String], _denied: &[String]) -> Result<(), AdapterError> {
        // Implemented in AAASM-1006.
        Ok(())
    }

    fn governance_level(&self) -> GovernanceLevel {
        GovernanceLevel::L2Enforce
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn make_extension(base: &Path, name: &str, version: &str) {
        let dir = base.join(format!("{name}-{version}"));
        std::fs::create_dir_all(&dir).unwrap();
        let pkg = serde_json::json!({ "name": name, "version": version });
        std::fs::write(dir.join("package.json"), pkg.to_string()).unwrap();
    }

    #[test]
    fn detects_installed_copilot() {
        let tmp = TempDir::new().unwrap();
        make_extension(tmp.path(), "github.copilot", "1.230.0");
        let adapter = CopilotAdapter::with_extensions_dir(tmp.path());
        let info = adapter.detect().expect("should detect copilot");
        assert_eq!(info.kind, DevToolKind::GitHubCopilot);
        assert_eq!(info.version, Some("1.230.0".to_string()));
        assert_eq!(info.governance_level, GovernanceLevel::L2Enforce);
        assert!(info.supports_mcp);
        assert!(info.supports_managed_settings);
    }

    #[test]
    fn returns_none_when_not_installed() {
        let tmp = TempDir::new().unwrap();
        let adapter = CopilotAdapter::with_extensions_dir(tmp.path());
        assert!(adapter.detect().is_none());
    }

    #[test]
    fn ignores_copilot_chat_extension() {
        let tmp = TempDir::new().unwrap();
        make_extension(tmp.path(), "github.copilot-chat", "0.22.0");
        let adapter = CopilotAdapter::with_extensions_dir(tmp.path());
        assert!(
            adapter.detect().is_none(),
            "copilot-chat alone must not satisfy core-Copilot detection"
        );
    }

    #[test]
    fn detects_copilot_alongside_chat() {
        let tmp = TempDir::new().unwrap();
        make_extension(tmp.path(), "github.copilot", "1.228.0");
        make_extension(tmp.path(), "github.copilot-chat", "0.21.0");
        let adapter = CopilotAdapter::with_extensions_dir(tmp.path());
        let info = adapter.detect().expect("core copilot present");
        assert_eq!(info.kind, DevToolKind::GitHubCopilot);
        assert_eq!(info.version, Some("1.228.0".to_string()));
    }

    #[test]
    fn governance_level_is_l2_enforce() {
        let adapter = CopilotAdapter::new();
        assert_eq!(adapter.governance_level(), GovernanceLevel::L2Enforce);
    }

    #[test]
    fn build_launch_command_returns_launch_failed() {
        let adapter = CopilotAdapter::new();
        let result = adapter.build_launch_command(&[], "agent-1", None, None);
        assert!(
            matches!(result, Err(AdapterError::LaunchFailed(_))),
            "expected LaunchFailed, got {result:?}"
        );
    }

    #[test]
    fn detect_returns_none_when_extensions_dir_missing() {
        let adapter = CopilotAdapter::with_extensions_dir("/nonexistent/__no_such_dir__/extensions");
        assert!(adapter.detect().is_none());
    }

    #[test]
    fn detect_install_path_points_to_extension_dir() {
        let tmp = TempDir::new().unwrap();
        make_extension(tmp.path(), "github.copilot", "1.226.0");
        let adapter = CopilotAdapter::with_extensions_dir(tmp.path());
        let info = adapter.detect().unwrap();
        assert!(
            info.install_path.starts_with(tmp.path()),
            "install_path should be inside extensions dir"
        );
    }
}
