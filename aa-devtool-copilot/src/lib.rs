//! [`DevToolAdapter`] implementation for GitHub Copilot running in VS Code
//! agent mode.
//!
//! Copilot is a VS Code extension — governance is applied by writing VS Code
//! workspace / user settings, not by wrapping a launcher binary. This adapter
//! therefore returns [`AdapterError::LaunchFailed`] from
//! [`build_launch_command`] and operates at **L1 (Observe)** by default:
//! detection reports the installed version and capabilities without modifying
//! any settings. Enforcement (L2) is applied separately in subsequent
//! sub-tasks by writing `.vscode/settings.json` and MCP policy.
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
/// Extension name prefix for the Copilot Chat extension (excluded from
/// core-Copilot detection — different extension, same org prefix).
const COPILOT_CHAT_EXT_PREFIX: &str = "github.copilot-chat-";

/// [`DevToolAdapter`] for GitHub Copilot (VS Code agent mode).
///
/// Production code calls [`CopilotAdapter::new`] and probes the
/// platform-default candidate paths in order:
/// `~/.vscode/extensions/`, `~/.vscode-insiders/extensions/`,
/// `~/.cursor/extensions/`.
///
/// The test suite may inject controlled directories via
/// [`CopilotAdapter::with_extensions_dir`] (single dir) or
/// [`CopilotAdapter::with_candidate_dirs`] (ordered list) to avoid touching
/// the real VS Code installation.
///
/// [`DevToolAdapter`]: aa_core::DevToolAdapter
#[derive(Debug, Clone)]
pub struct CopilotAdapter {
    /// When `Some`, replaces the default candidate directory list entirely.
    candidate_dirs: Option<Vec<PathBuf>>,
}

impl CopilotAdapter {
    /// Create an adapter that probes the platform-default VS Code paths.
    pub fn new() -> Self {
        Self { candidate_dirs: None }
    }

    /// Create an adapter that searches only `extensions_dir`. Useful in tests.
    pub fn with_extensions_dir(extensions_dir: impl Into<PathBuf>) -> Self {
        Self {
            candidate_dirs: Some(vec![extensions_dir.into()]),
        }
    }

    /// Create an adapter that searches `dirs` in order, stopping at the first
    /// directory that contains a Copilot extension. Useful in multi-dir tests.
    pub fn with_candidate_dirs(dirs: impl IntoIterator<Item = impl Into<PathBuf>>) -> Self {
        Self {
            candidate_dirs: Some(dirs.into_iter().map(Into::into).collect()),
        }
    }

    /// Returns the ordered list of candidate extension directories to probe.
    fn resolve_candidate_dirs(&self) -> Vec<PathBuf> {
        if let Some(dirs) = &self.candidate_dirs {
            return dirs.clone();
        }
        default_candidate_dirs()
    }

    /// Scan `extensions_dir` for `github.copilot-<version>` subdirectories
    /// (excluding `github.copilot-chat-*`). Returns the highest-semver match
    /// as `(install_path, version_string)`, or `None` if no match is found.
    fn find_copilot_extension(extensions_dir: &Path) -> Option<(PathBuf, String)> {
        let entries = std::fs::read_dir(extensions_dir).ok()?;
        let mut best: Option<(PathBuf, semver::Version)> = None;
        for entry in entries.flatten() {
            let path = entry.path();
            let name = match path.file_name().and_then(|n| n.to_str()) {
                Some(n) => n,
                None => continue,
            };
            if name.starts_with(COPILOT_CHAT_EXT_PREFIX) {
                continue;
            }
            if name.starts_with(COPILOT_EXT_PREFIX) {
                let raw = match read_package_version(&path) {
                    Some(v) => v,
                    None => continue,
                };
                let ver = match semver::Version::parse(&raw) {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                match &best {
                    None => best = Some((path, ver)),
                    Some((_, best_ver)) if ver > *best_ver => best = Some((path, ver)),
                    _ => {}
                }
            }
        }
        best.map(|(path, ver)| (path, ver.to_string()))
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

/// Platform-default ordered list of VS Code extension candidate directories.
fn default_candidate_dirs() -> Vec<PathBuf> {
    #[cfg(windows)]
    let base_var = "USERPROFILE";
    #[cfg(not(windows))]
    let base_var = "HOME";

    let Some(home) = std::env::var_os(base_var) else {
        return Vec::new();
    };
    let home = PathBuf::from(home);
    vec![
        home.join(".vscode").join("extensions"),
        home.join(".vscode-insiders").join("extensions"),
        home.join(".cursor").join("extensions"),
    ]
}

#[async_trait]
impl DevToolAdapter for CopilotAdapter {
    fn detect(&self) -> Option<DevToolInfo> {
        for dir in self.resolve_candidate_dirs() {
            if let Some((install_path, version)) = Self::find_copilot_extension(&dir) {
                return Some(DevToolInfo {
                    kind: DevToolKind::GitHubCopilot,
                    version: Some(version),
                    install_path,
                    governance_level: GovernanceLevel::L1Observe,
                    supports_mcp: true,
                    supports_managed_settings: true,
                });
            }
        }
        None
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
        GovernanceLevel::L1Observe
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
        assert_eq!(info.governance_level, GovernanceLevel::L1Observe);
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
    fn governance_level_is_l1_observe() {
        let adapter = CopilotAdapter::new();
        assert_eq!(adapter.governance_level(), GovernanceLevel::L1Observe);
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

    #[test]
    fn detect_picks_latest_version() {
        let tmp = TempDir::new().unwrap();
        make_extension(tmp.path(), "github.copilot", "1.226.0");
        make_extension(tmp.path(), "github.copilot", "1.230.0");
        make_extension(tmp.path(), "github.copilot", "1.228.0");
        let adapter = CopilotAdapter::with_extensions_dir(tmp.path());
        let info = adapter.detect().expect("should detect copilot");
        assert_eq!(info.version, Some("1.230.0".to_string()));
    }

    #[test]
    fn detect_searches_insiders_dir() {
        let vscode_tmp = TempDir::new().unwrap();
        let insiders_tmp = TempDir::new().unwrap();
        make_extension(insiders_tmp.path(), "github.copilot", "1.226.0");
        let adapter = CopilotAdapter::with_candidate_dirs([vscode_tmp.path(), insiders_tmp.path()]);
        let info = adapter.detect().expect("should find copilot in insiders dir");
        assert_eq!(info.kind, DevToolKind::GitHubCopilot);
        assert_eq!(info.version, Some("1.226.0".to_string()));
    }

    // Exercises default_candidate_dirs() and the None branch of resolve_candidate_dirs().
    // nextest runs each test in its own process, so set_var is safe here.
    #[test]
    fn detect_uses_home_env_via_default_dirs() {
        let tmp = TempDir::new().unwrap();
        let vscode_ext = tmp.path().join(".vscode").join("extensions");
        std::fs::create_dir_all(&vscode_ext).unwrap();
        make_extension(&vscode_ext, "github.copilot", "1.226.0");
        std::env::set_var("HOME", tmp.path());
        let info = CopilotAdapter::new().detect().expect("found via default dirs");
        assert_eq!(info.kind, DevToolKind::GitHubCopilot);
        assert_eq!(info.version, Some("1.226.0".to_string()));
    }

    // Exercises the `None => continue` branch when package.json is absent.
    #[test]
    fn find_copilot_extension_skips_dir_without_package_json() {
        let tmp = TempDir::new().unwrap();
        // Looks like a copilot ext dir but has no package.json.
        std::fs::create_dir_all(tmp.path().join("github.copilot-broken")).unwrap();
        // A good extension that should still be found.
        make_extension(tmp.path(), "github.copilot", "1.228.0");
        let adapter = CopilotAdapter::with_extensions_dir(tmp.path());
        let info = adapter.detect().expect("good extension found despite broken sibling");
        assert_eq!(info.version, Some("1.228.0".to_string()));
    }

    // Exercises the `Err(_) => continue` branch when the version string is not valid semver.
    #[test]
    fn find_copilot_extension_skips_invalid_semver_version() {
        let tmp = TempDir::new().unwrap();
        // Extension with a non-semver version string.
        let bad = tmp.path().join("github.copilot-nightly");
        std::fs::create_dir_all(&bad).unwrap();
        let pkg = serde_json::json!({ "name": "github.copilot", "version": "nightly-build" });
        std::fs::write(bad.join("package.json"), pkg.to_string()).unwrap();
        // A good extension with a proper semver version.
        make_extension(tmp.path(), "github.copilot", "1.228.0");
        let adapter = CopilotAdapter::with_extensions_dir(tmp.path());
        let info = adapter
            .detect()
            .expect("good extension found despite invalid-semver sibling");
        assert_eq!(info.version, Some("1.228.0".to_string()));
    }
}
