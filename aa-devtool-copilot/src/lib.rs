//! [`DevToolAdapter`] implementation for GitHub Copilot running in VS Code
//! agent mode.
//!
//! Copilot is a VS Code extension — governance is applied by writing VS Code
//! workspace / user settings, not by wrapping a launcher binary. This adapter
//! therefore returns [`AdapterError::LaunchFailed`] from
//! [`build_launch_command`] and operates at **L2 (Enforce)**: it controls MCP
//! server access, tool-approval prompts, and per-session request limits via
//! VS Code `settings.json`.
//!
//! ## VS Code settings written by this adapter
//!
//! | Key | Value | Derived from |
//! |---|---|---|
//! | `github.copilot.enable` | `{"*": true\|false}` | deny rule `dev_tools.copilot.enable` |
//! | `chat.tools.autoApprove` | `true\|false` | any `RequireApproval` rule |
//! | `chat.agent.maxRequests` | `<u32>` (default 25) | rule `dev_tools.copilot.max_requests:<N>` |
//! | `chat.mcp.requireApproval` | `"always"\|"never"` | MCP tool `RequireApproval` rule |
//! | `chat.mcp.deny` | `["<server>:<tool>", …]` | MCP tool `Deny` rules |
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

use aa_core::{
    AdapterError, DevToolAdapter, DevToolInfo, DevToolKind, GovernanceLevel, McpServerInfo, PolicyDecision,
    PolicyDocument,
};
use async_trait::async_trait;

/// Minimum `github.copilot` extension version this adapter supports.
pub const MIN_COPILOT_VERSION: &str = "1.226.0";
/// Minimum `github.copilot-chat` extension version this adapter supports.
pub const MIN_COPILOT_CHAT_VERSION: &str = "0.21.0";

/// Default value for `chat.agent.maxRequests` when no override rule is present.
const DEFAULT_MAX_REQUESTS: u32 = 25;

/// Extension name prefix for the core Copilot extension.
const COPILOT_EXT_PREFIX: &str = "github.copilot-";
/// Extension name prefix for the Copilot Chat extension (must be excluded
/// from core-Copilot detection — different extension, same org prefix).
const COPILOT_CHAT_EXT_PREFIX: &str = "github.copilot-chat-";

/// Action-pattern for a rule that globally disables Copilot.
const COPILOT_ENABLE_DENY_PATTERN: &str = "dev_tools.copilot.enable";

/// Action-pattern prefix for a rule that overrides `chat.agent.maxRequests`.
/// Full form: `"dev_tools.copilot.max_requests:<N>"`.
const MAX_REQUESTS_PREFIX: &str = "dev_tools.copilot.max_requests:";

/// Action-pattern prefix in a [`PolicyRule`] that targets an MCP tool.
/// Full pattern form: `"mcp_tool:<server>:<tool>"`.
///
/// [`PolicyRule`]: aa_core::PolicyRule
const MCP_TOOL_PATTERN_PREFIX: &str = "mcp_tool:";

/// [`DevToolAdapter`] for GitHub Copilot (VS Code agent mode).
///
/// Constructor takes optional path overrides so the test suite can point at
/// temporary directories without touching the real VS Code installation.
/// Production code calls [`CopilotAdapter::new`] and relies on platform
/// defaults.
///
/// [`DevToolAdapter`]: aa_core::DevToolAdapter
#[derive(Debug, Clone)]
pub struct CopilotAdapter {
    /// Override for `~/.vscode/extensions`. When `None` the adapter resolves
    /// the platform default at detection time.
    extensions_dir: Option<PathBuf>,
    /// Override for the VS Code user-settings JSON path. When `None` the
    /// adapter resolves the platform default at apply time.
    settings_path: Option<PathBuf>,
}

impl CopilotAdapter {
    /// Create an adapter that uses the platform-default VS Code paths.
    pub fn new() -> Self {
        Self {
            extensions_dir: None,
            settings_path: None,
        }
    }

    /// Create an adapter that reads extensions from `extensions_dir` instead
    /// of the default `~/.vscode/extensions`. Useful in tests.
    pub fn with_extensions_dir(extensions_dir: impl Into<PathBuf>) -> Self {
        Self {
            extensions_dir: Some(extensions_dir.into()),
            settings_path: None,
        }
    }

    /// Create an adapter with explicit overrides for both the extensions
    /// directory and the VS Code user-settings path. Useful in tests that
    /// exercise [`apply_settings`].
    ///
    /// [`apply_settings`]: CopilotAdapter::apply_settings
    pub fn with_paths(extensions_dir: impl Into<PathBuf>, settings_path: impl Into<PathBuf>) -> Self {
        Self {
            extensions_dir: Some(extensions_dir.into()),
            settings_path: Some(settings_path.into()),
        }
    }

    fn resolve_extensions_dir(&self) -> Option<PathBuf> {
        if let Some(p) = &self.extensions_dir {
            return Some(p.clone());
        }
        default_extensions_dir()
    }

    fn resolve_settings_path(&self) -> Option<PathBuf> {
        if let Some(p) = &self.settings_path {
            return Some(p.clone());
        }
        default_settings_path()
    }

    fn find_copilot_extension(extensions_dir: &Path) -> Option<(PathBuf, String)> {
        let entries = std::fs::read_dir(extensions_dir).ok()?;
        for entry in entries.flatten() {
            let path = entry.path();
            let name = path.file_name()?.to_str()?;
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

    /// Collect MCP tool entries that policy denies.
    fn collect_mcp_deny(policy: &PolicyDocument) -> Vec<String> {
        policy
            .rules
            .iter()
            .filter(|r| r.action_pattern.starts_with(MCP_TOOL_PATTERN_PREFIX) && r.decision == PolicyDecision::Deny)
            .map(|r| r.action_pattern[MCP_TOOL_PATTERN_PREFIX.len()..].to_string())
            .collect()
    }
}

impl Default for CopilotAdapter {
    fn default() -> Self {
        Self::new()
    }
}

// ── Policy → VS Code setting derivation helpers ───────────────────────────────

/// `github.copilot.enable["*"]` — `false` when a rule globally denies Copilot.
fn copilot_enabled(policy: &PolicyDocument) -> bool {
    !policy
        .rules
        .iter()
        .any(|r| r.action_pattern == COPILOT_ENABLE_DENY_PATTERN && r.decision == PolicyDecision::Deny)
}

/// `chat.tools.autoApprove` — `false` when any rule requires human approval.
fn auto_approve(policy: &PolicyDocument) -> bool {
    !policy
        .rules
        .iter()
        .any(|r| r.decision == PolicyDecision::RequireApproval)
}

/// `chat.agent.maxRequests` — from `dev_tools.copilot.max_requests:<N>` rule,
/// falling back to [`DEFAULT_MAX_REQUESTS`].
fn max_requests(policy: &PolicyDocument) -> u32 {
    policy
        .rules
        .iter()
        .find_map(|r| {
            let suffix = r.action_pattern.strip_prefix(MAX_REQUESTS_PREFIX)?;
            suffix.parse::<u32>().ok()
        })
        .unwrap_or(DEFAULT_MAX_REQUESTS)
}

/// `chat.mcp.requireApproval` — `"always"` when any MCP tool rule requires
/// approval, `"never"` otherwise.
fn mcp_require_approval(policy: &PolicyDocument) -> &'static str {
    let needs = policy.rules.iter().any(|r| {
        r.action_pattern.starts_with(MCP_TOOL_PATTERN_PREFIX) && r.decision == PolicyDecision::RequireApproval
    });
    if needs {
        "always"
    } else {
        "never"
    }
}

// ─────────────────────────────────────────────────────────────────────────────

fn read_package_version(extension_dir: &Path) -> Option<String> {
    let raw = std::fs::read_to_string(extension_dir.join("package.json")).ok()?;
    let parsed: serde_json::Value = serde_json::from_str(&raw).ok()?;
    parsed["version"].as_str().map(|s| s.to_string())
}

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

fn default_settings_path() -> Option<PathBuf> {
    #[cfg(target_os = "macos")]
    {
        std::env::var_os("HOME").map(|p| {
            PathBuf::from(p)
                .join("Library")
                .join("Application Support")
                .join("Code")
                .join("User")
                .join("settings.json")
        })
    }
    #[cfg(target_os = "linux")]
    {
        std::env::var_os("HOME").map(|p| {
            PathBuf::from(p)
                .join(".config")
                .join("Code")
                .join("User")
                .join("settings.json")
        })
    }
    #[cfg(windows)]
    {
        std::env::var_os("APPDATA").map(|p| PathBuf::from(p).join("Code").join("User").join("settings.json"))
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

    /// Translate `policy` into a VS Code settings JSON string.
    ///
    /// Emits five keys derived from policy rules (see module-level table).
    async fn generate_managed_settings(&self, policy: &PolicyDocument) -> Result<String, AdapterError> {
        let value = serde_json::json!({
            "github.copilot.enable": { "*": copilot_enabled(policy) },
            "chat.tools.autoApprove": auto_approve(policy),
            "chat.agent.maxRequests": max_requests(policy),
            "chat.mcp.requireApproval": mcp_require_approval(policy),
            "chat.mcp.deny": Self::collect_mcp_deny(policy),
        });
        serde_json::to_string_pretty(&value).map_err(|e| AdapterError::Serde(e.to_string()))
    }

    /// Merge `settings` (JSON from [`generate_managed_settings`]) into the VS
    /// Code user-settings file.
    ///
    /// Reads the existing `settings.json` (starting from `{}` when absent),
    /// overwrites every key present in `settings`, and writes the merged
    /// document back atomically. Other user settings are preserved.
    ///
    /// [`generate_managed_settings`]: Self::generate_managed_settings
    async fn apply_settings(&self, settings: &str) -> Result<(), AdapterError> {
        let path = self.resolve_settings_path().ok_or_else(|| {
            AdapterError::SettingsGenerationFailed("could not resolve VS Code settings path".to_string())
        })?;

        let incoming: serde_json::Value =
            serde_json::from_str(settings).map_err(|e| AdapterError::Serde(e.to_string()))?;

        let mut existing: serde_json::Value = if path.exists() {
            let raw = std::fs::read_to_string(&path)?;
            serde_json::from_str(&raw).unwrap_or(serde_json::json!({}))
        } else {
            serde_json::json!({})
        };

        if let (Some(obj), Some(inc)) = (existing.as_object_mut(), incoming.as_object()) {
            for (k, v) in inc {
                obj.insert(k.clone(), v.clone());
            }
        }

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(
            &path,
            serde_json::to_string_pretty(&existing).map_err(|e| AdapterError::Serde(e.to_string()))?,
        )
        .map_err(AdapterError::SettingsApplyFailed)?;
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
    use aa_core::PolicyRule;
    use tempfile::TempDir;

    fn make_extension(base: &Path, name: &str, version: &str) {
        let dir = base.join(format!("{name}-{version}"));
        std::fs::create_dir_all(&dir).unwrap();
        let pkg = serde_json::json!({ "name": name, "version": version });
        std::fs::write(dir.join("package.json"), pkg.to_string()).unwrap();
    }

    fn empty_policy() -> PolicyDocument {
        PolicyDocument {
            version: 1,
            name: "test".to_string(),
            rules: vec![],
        }
    }

    fn policy_with_rule(pattern: &str, decision: PolicyDecision) -> PolicyDocument {
        PolicyDocument {
            version: 1,
            name: "test".to_string(),
            rules: vec![PolicyRule {
                action_pattern: pattern.to_string(),
                decision,
            }],
        }
    }

    fn policy_with_mcp_deny(patterns: &[&str]) -> PolicyDocument {
        PolicyDocument {
            version: 1,
            name: "test".to_string(),
            rules: patterns
                .iter()
                .map(|p| PolicyRule {
                    action_pattern: format!("mcp_tool:{p}"),
                    decision: PolicyDecision::Deny,
                })
                .collect(),
        }
    }

    // ── detect() tests ────────────────────────────────────────────────────────

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

    // ── generate_managed_settings() — AC-required tests ──────────────────────

    #[tokio::test]
    async fn policy_enforce_disables_auto_approve() {
        let policy = policy_with_rule("fs:write", PolicyDecision::RequireApproval);
        let adapter = CopilotAdapter::new();
        let json = adapter.generate_managed_settings(&policy).await.unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(
            v["chat.tools.autoApprove"], false,
            "RequireApproval rule must set autoApprove to false"
        );
    }

    #[tokio::test]
    async fn policy_max_requests_propagates() {
        let policy = policy_with_rule("dev_tools.copilot.max_requests:50", PolicyDecision::Allow);
        let adapter = CopilotAdapter::new();
        let json = adapter.generate_managed_settings(&policy).await.unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["chat.agent.maxRequests"], 50u32);
    }

    #[tokio::test]
    async fn full_json_snapshot_for_fixture_policy() {
        // Fixture: deny one MCP tool, require approval for file writes, cap requests at 10.
        let policy = PolicyDocument {
            version: 1,
            name: "fixture".to_string(),
            rules: vec![
                PolicyRule {
                    action_pattern: "dev_tools.copilot.max_requests:10".to_string(),
                    decision: PolicyDecision::Allow,
                },
                PolicyRule {
                    action_pattern: "fs:write".to_string(),
                    decision: PolicyDecision::RequireApproval,
                },
                PolicyRule {
                    action_pattern: "mcp_tool:github:push".to_string(),
                    decision: PolicyDecision::Deny,
                },
            ],
        };
        let adapter = CopilotAdapter::new();
        let json = adapter.generate_managed_settings(&policy).await.unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(v["github.copilot.enable"]["*"], true, "copilot not disabled");
        assert_eq!(
            v["chat.tools.autoApprove"], false,
            "RequireApproval disables autoApprove"
        );
        assert_eq!(v["chat.agent.maxRequests"], 10u32, "max_requests override");
        assert_eq!(v["chat.mcp.requireApproval"], "never", "no mcp RequireApproval rule");
        assert_eq!(v["chat.mcp.deny"], serde_json::json!(["github:push"]));
    }

    #[tokio::test]
    async fn apply_settings_preserves_unmanaged_keys() {
        let tmp = TempDir::new().unwrap();
        let settings_file = tmp.path().join("settings.json");
        std::fs::write(&settings_file, r#"{"editor.fontSize": 14}"#).unwrap();

        let adapter = CopilotAdapter::with_paths(tmp.path(), &settings_file);
        let json = adapter.generate_managed_settings(&empty_policy()).await.unwrap();
        adapter.apply_settings(&json).await.unwrap();

        let written = std::fs::read_to_string(&settings_file).unwrap();
        let v: serde_json::Value = serde_json::from_str(&written).unwrap();
        assert_eq!(v["editor.fontSize"], 14, "unmanaged key must be preserved");
        assert!(v["github.copilot.enable"].is_object(), "managed key written");
    }

    // ── generate_managed_settings() — additional coverage ────────────────────

    #[tokio::test]
    async fn default_policy_enables_copilot_and_auto_approve() {
        let adapter = CopilotAdapter::new();
        let json = adapter.generate_managed_settings(&empty_policy()).await.unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["github.copilot.enable"]["*"], true);
        assert_eq!(v["chat.tools.autoApprove"], true);
        assert_eq!(v["chat.agent.maxRequests"], DEFAULT_MAX_REQUESTS);
        assert_eq!(v["chat.mcp.requireApproval"], "never");
        assert_eq!(v["chat.mcp.deny"], serde_json::json!([]));
    }

    #[tokio::test]
    async fn deny_rule_disables_copilot_enable() {
        let policy = policy_with_rule(COPILOT_ENABLE_DENY_PATTERN, PolicyDecision::Deny);
        let adapter = CopilotAdapter::new();
        let json = adapter.generate_managed_settings(&policy).await.unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["github.copilot.enable"]["*"], false);
    }

    #[tokio::test]
    async fn mcp_require_approval_rule_sets_always() {
        let policy = PolicyDocument {
            version: 1,
            name: "test".to_string(),
            rules: vec![PolicyRule {
                action_pattern: "mcp_tool:filesystem:read_file".to_string(),
                decision: PolicyDecision::RequireApproval,
            }],
        };
        let adapter = CopilotAdapter::new();
        let json = adapter.generate_managed_settings(&policy).await.unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["chat.mcp.requireApproval"], "always");
    }

    #[tokio::test]
    async fn mcp_deny_entries_from_policy_rules() {
        let policy = policy_with_mcp_deny(&["filesystem:write_file", "github:push"]);
        let adapter = CopilotAdapter::new();
        let json = adapter.generate_managed_settings(&policy).await.unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        let deny = v["chat.mcp.deny"].as_array().unwrap();
        assert!(deny.contains(&serde_json::json!("filesystem:write_file")));
        assert!(deny.contains(&serde_json::json!("github:push")));
    }

    #[tokio::test]
    async fn allow_rules_not_added_to_deny_list() {
        let policy = policy_with_rule("mcp_tool:filesystem:read_file", PolicyDecision::Allow);
        let adapter = CopilotAdapter::new();
        let json = adapter.generate_managed_settings(&policy).await.unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        let deny = v["chat.mcp.deny"].as_array().unwrap();
        assert!(deny.is_empty(), "Allow rules must not appear in deny list");
    }

    // ── apply_settings() tests ────────────────────────────────────────────────

    #[tokio::test]
    async fn apply_settings_writes_to_settings_path() {
        let tmp = TempDir::new().unwrap();
        let settings_file = tmp.path().join("settings.json");
        let adapter = CopilotAdapter::with_paths(tmp.path(), &settings_file);
        let json = adapter.generate_managed_settings(&empty_policy()).await.unwrap();
        adapter.apply_settings(&json).await.unwrap();

        let written = std::fs::read_to_string(&settings_file).unwrap();
        let v: serde_json::Value = serde_json::from_str(&written).unwrap();
        assert_eq!(v["github.copilot.enable"]["*"], true);
        assert_eq!(v["chat.agent.maxRequests"], DEFAULT_MAX_REQUESTS);
    }

    #[tokio::test]
    async fn apply_settings_creates_parent_dirs() {
        let tmp = TempDir::new().unwrap();
        let settings_file = tmp.path().join("deep").join("nested").join("settings.json");
        let adapter = CopilotAdapter::with_paths(tmp.path(), &settings_file);
        let json = adapter.generate_managed_settings(&empty_policy()).await.unwrap();
        adapter.apply_settings(&json).await.unwrap();
        assert!(settings_file.exists());
    }

    #[tokio::test]
    async fn apply_settings_is_idempotent() {
        let tmp = TempDir::new().unwrap();
        let settings_file = tmp.path().join("settings.json");
        let adapter = CopilotAdapter::with_paths(tmp.path(), &settings_file);
        let policy = policy_with_mcp_deny(&["filesystem:write_file"]);
        let json = adapter.generate_managed_settings(&policy).await.unwrap();
        adapter.apply_settings(&json).await.unwrap();
        adapter.apply_settings(&json).await.unwrap();

        let written = std::fs::read_to_string(&settings_file).unwrap();
        let v: serde_json::Value = serde_json::from_str(&written).unwrap();
        let deny = v["chat.mcp.deny"].as_array().unwrap();
        assert_eq!(deny.len(), 1, "idempotent apply must not duplicate deny entries");
    }
}
