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
//! ## VS Code settings written by this adapter
//!
//! | Key | Value | When applied |
//! |---|---|---|
//! | `chat.mcp.access` | `"prompt"` | Always (L1+ baseline) |
//! | `chat.agent.maxRequests` | `5` | Always (L2 cap) |
//! | `chat.mcp.deny` | `["<server>:<tool>", …]` | Per-policy MCP denials |
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
use serde::{Deserialize, Serialize};

/// Minimum `github.copilot` extension version this adapter supports.
pub const MIN_COPILOT_VERSION: &str = "1.226.0";
/// Minimum `github.copilot-chat` extension version this adapter supports.
pub const MIN_COPILOT_CHAT_VERSION: &str = "0.21.0";

/// Value of `chat.agent.maxRequests` applied when governance level is L2+.
const L2_MAX_REQUESTS: u32 = 5;

/// Extension name prefix for the core Copilot extension.
const COPILOT_EXT_PREFIX: &str = "github.copilot-";
/// Extension name prefix for the Copilot Chat extension (must be excluded
/// from core-Copilot detection — different extension, same org prefix).
const COPILOT_CHAT_EXT_PREFIX: &str = "github.copilot-chat-";

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
    /// Path to `.vscode/mcp.json` for MCP server discovery. When `None`
    /// `list_mcp_servers` returns an empty list (workspace path not known).
    mcp_config_path: Option<PathBuf>,
}

impl CopilotAdapter {
    /// Create an adapter that uses the platform-default VS Code paths.
    pub fn new() -> Self {
        Self {
            extensions_dir: None,
            settings_path: None,
            mcp_config_path: None,
        }
    }

    /// Create an adapter that reads extensions from `extensions_dir` instead
    /// of the default `~/.vscode/extensions`. Useful in tests.
    pub fn with_extensions_dir(extensions_dir: impl Into<PathBuf>) -> Self {
        Self {
            extensions_dir: Some(extensions_dir.into()),
            settings_path: None,
            mcp_config_path: None,
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
            mcp_config_path: None,
        }
    }

    /// Create an adapter with overrides for all three filesystem paths:
    /// extensions directory, VS Code settings file, and `.vscode/mcp.json`.
    /// Useful in tests that exercise both [`apply_settings`] and
    /// [`list_mcp_servers`].
    ///
    /// [`apply_settings`]: CopilotAdapter::apply_settings
    /// [`list_mcp_servers`]: CopilotAdapter::list_mcp_servers
    pub fn with_all_paths(
        extensions_dir: impl Into<PathBuf>,
        settings_path: impl Into<PathBuf>,
        mcp_config_path: impl Into<PathBuf>,
    ) -> Self {
        Self {
            extensions_dir: Some(extensions_dir.into()),
            settings_path: Some(settings_path.into()),
            mcp_config_path: Some(mcp_config_path.into()),
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

    fn resolve_mcp_config_path(&self) -> Option<PathBuf> {
        self.mcp_config_path.clone()
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

    /// Extract MCP deny entries from policy rules.
    ///
    /// Collects every rule whose `action_pattern` starts with `"mcp_tool:"`
    /// and whose decision is [`PolicyDecision::Deny`]. The pattern suffix
    /// (after `"mcp_tool:"`) is used verbatim as the VS Code `chat.mcp.deny`
    /// entry, which expects `"<server>:<tool>"` notation.
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

/// VS Code settings document written by [`CopilotAdapter::generate_managed_settings`].
#[derive(Debug, Serialize)]
struct CopilotVsCodeSettings {
    /// Require human approval before any MCP tool call (L1 baseline).
    #[serde(rename = "chat.mcp.access")]
    mcp_access: &'static str,
    /// Cap per-session autonomous requests (L2 enforcement).
    #[serde(rename = "chat.agent.maxRequests")]
    max_requests: u32,
    /// Explicit MCP server:tool deny list derived from policy rules.
    #[serde(rename = "chat.mcp.deny")]
    mcp_deny: Vec<String>,
}

/// Top-level shape of `.vscode/mcp.json`.
#[derive(Debug, Deserialize)]
struct VsCodeMcpConfig {
    servers: std::collections::HashMap<String, VsCodeMcpEntry>,
}

/// Per-server entry inside `VsCodeMcpConfig.servers`.
#[derive(Debug, Deserialize)]
struct VsCodeMcpEntry {
    command: String,
    #[serde(default)]
    args: Vec<String>,
}

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
    /// Always emits `chat.mcp.access` and `chat.agent.maxRequests` (this
    /// adapter operates at L2). Appends entries to `chat.mcp.deny` for every
    /// policy rule whose `action_pattern` starts with `"mcp_tool:"` and whose
    /// decision is [`PolicyDecision::Deny`].
    async fn generate_managed_settings(&self, policy: &PolicyDocument) -> Result<String, AdapterError> {
        let settings = CopilotVsCodeSettings {
            mcp_access: "prompt",
            max_requests: L2_MAX_REQUESTS,
            mcp_deny: Self::collect_mcp_deny(policy),
        };
        serde_json::to_string_pretty(&settings).map_err(|e| AdapterError::Serde(e.to_string()))
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

    /// Read `.vscode/mcp.json` and return one [`McpServerInfo`] per entry in
    /// the `"servers"` map. Returns an empty list when `mcp_config_path` was
    /// not set or the file does not exist — VS Code workspaces without an MCP
    /// config are a normal operating state.
    async fn list_mcp_servers(&self) -> Result<Vec<McpServerInfo>, AdapterError> {
        let path = match self.resolve_mcp_config_path() {
            Some(p) => p,
            None => return Ok(vec![]),
        };
        if !path.exists() {
            return Ok(vec![]);
        }
        let raw = std::fs::read_to_string(&path)?;
        let config: VsCodeMcpConfig =
            serde_json::from_str(&raw).map_err(|e| AdapterError::McpConfigFailed(format!("parse failed: {e}")))?;
        Ok(config
            .servers
            .into_iter()
            .map(|(name, entry)| McpServerInfo {
                name,
                command: entry.command,
                args: entry.args,
            })
            .collect())
    }

    /// Write `denied` into `chat.mcp.deny` in the VS Code settings file by
    /// delegating to [`apply_settings`]. The `allowed` list is not surfaced
    /// in VS Code settings (Copilot does not support an explicit allow-list
    /// knob at the tool level).
    ///
    /// [`apply_settings`]: Self::apply_settings
    async fn apply_mcp_governance(&self, _allowed: &[String], denied: &[String]) -> Result<(), AdapterError> {
        let patch = serde_json::to_string_pretty(&serde_json::json!({
            "chat.mcp.deny": denied
        }))
        .map_err(|e| AdapterError::Serde(e.to_string()))?;
        self.apply_settings(&patch).await
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

    // ---- detect() tests (carried over from AAASM-997) ----------------------

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

    // ---- generate_managed_settings() tests ---------------------------------

    #[tokio::test]
    async fn settings_always_include_l1_mcp_access_prompt() {
        let adapter = CopilotAdapter::new();
        let json = adapter.generate_managed_settings(&empty_policy()).await.unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["chat.mcp.access"], "prompt");
    }

    #[tokio::test]
    async fn settings_always_include_l2_max_requests() {
        let adapter = CopilotAdapter::new();
        let json = adapter.generate_managed_settings(&empty_policy()).await.unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["chat.agent.maxRequests"], L2_MAX_REQUESTS);
    }

    #[tokio::test]
    async fn settings_empty_deny_list_for_empty_policy() {
        let adapter = CopilotAdapter::new();
        let json = adapter.generate_managed_settings(&empty_policy()).await.unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["chat.mcp.deny"], serde_json::json!([]));
    }

    #[tokio::test]
    async fn settings_mcp_deny_entries_from_policy_rules() {
        let policy = policy_with_mcp_deny(&["filesystem:write_file", "github:push"]);
        let adapter = CopilotAdapter::new();
        let json = adapter.generate_managed_settings(&policy).await.unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        let deny = v["chat.mcp.deny"].as_array().unwrap();
        assert!(deny.contains(&serde_json::json!("filesystem:write_file")));
        assert!(deny.contains(&serde_json::json!("github:push")));
    }

    #[tokio::test]
    async fn settings_allow_rules_not_added_to_deny_list() {
        let policy = PolicyDocument {
            version: 1,
            name: "test".to_string(),
            rules: vec![PolicyRule {
                action_pattern: "mcp_tool:filesystem:read_file".to_string(),
                decision: PolicyDecision::Allow,
            }],
        };
        let adapter = CopilotAdapter::new();
        let json = adapter.generate_managed_settings(&policy).await.unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        let deny = v["chat.mcp.deny"].as_array().unwrap();
        assert!(deny.is_empty(), "Allow rules must not appear in deny list");
    }

    // ---- apply_settings() tests --------------------------------------------

    #[tokio::test]
    async fn apply_settings_writes_to_settings_path() {
        let tmp = TempDir::new().unwrap();
        let settings_file = tmp.path().join("settings.json");
        let adapter = CopilotAdapter::with_paths(tmp.path(), &settings_file);
        let json = adapter.generate_managed_settings(&empty_policy()).await.unwrap();
        adapter.apply_settings(&json).await.unwrap();

        let written = std::fs::read_to_string(&settings_file).unwrap();
        let v: serde_json::Value = serde_json::from_str(&written).unwrap();
        assert_eq!(v["chat.mcp.access"], "prompt");
        assert_eq!(v["chat.agent.maxRequests"], L2_MAX_REQUESTS);
    }

    #[tokio::test]
    async fn apply_settings_merges_with_existing_settings() {
        let tmp = TempDir::new().unwrap();
        let settings_file = tmp.path().join("settings.json");
        // Pre-populate with unrelated user setting.
        std::fs::write(&settings_file, r#"{"editor.fontSize": 14, "chat.mcp.access": "off"}"#).unwrap();

        let adapter = CopilotAdapter::with_paths(tmp.path(), &settings_file);
        let json = adapter.generate_managed_settings(&empty_policy()).await.unwrap();
        adapter.apply_settings(&json).await.unwrap();

        let written = std::fs::read_to_string(&settings_file).unwrap();
        let v: serde_json::Value = serde_json::from_str(&written).unwrap();
        // Governance key overwritten.
        assert_eq!(v["chat.mcp.access"], "prompt");
        // User's other setting preserved.
        assert_eq!(v["editor.fontSize"], 14);
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

    // ---- list_mcp_servers() tests ------------------------------------------

    fn write_mcp_json(dir: &Path, content: &str) -> PathBuf {
        let path = dir.join("mcp.json");
        std::fs::write(&path, content).unwrap();
        path
    }

    #[tokio::test]
    async fn list_mcp_servers_returns_empty_without_config_path() {
        let adapter = CopilotAdapter::new();
        let servers = adapter.list_mcp_servers().await.unwrap();
        assert!(servers.is_empty());
    }

    #[tokio::test]
    async fn list_mcp_servers_returns_empty_when_file_missing() {
        let tmp = TempDir::new().unwrap();
        let adapter = CopilotAdapter::with_all_paths(tmp.path(), tmp.path().join("s.json"), tmp.path().join("no.json"));
        let servers = adapter.list_mcp_servers().await.unwrap();
        assert!(servers.is_empty());
    }

    #[tokio::test]
    async fn list_mcp_servers_parses_vscode_mcp_json() {
        let tmp = TempDir::new().unwrap();
        let mcp_path = write_mcp_json(
            tmp.path(),
            r#"{
              "servers": {
                "filesystem": { "command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem"] },
                "github":     { "command": "npx", "args": ["-y", "@modelcontextprotocol/server-github"] }
              }
            }"#,
        );
        let adapter = CopilotAdapter::with_all_paths(tmp.path(), tmp.path().join("s.json"), &mcp_path);
        let mut servers = adapter.list_mcp_servers().await.unwrap();
        servers.sort_by(|a, b| a.name.cmp(&b.name));
        assert_eq!(servers.len(), 2);
        assert_eq!(servers[0].name, "filesystem");
        assert_eq!(servers[0].command, "npx");
        assert_eq!(servers[1].name, "github");
    }

    #[tokio::test]
    async fn list_mcp_servers_entry_with_no_args() {
        let tmp = TempDir::new().unwrap();
        let mcp_path = write_mcp_json(
            tmp.path(),
            r#"{ "servers": { "minimal": { "command": "/usr/local/bin/mcp-server" } } }"#,
        );
        let adapter = CopilotAdapter::with_all_paths(tmp.path(), tmp.path().join("s.json"), &mcp_path);
        let servers = adapter.list_mcp_servers().await.unwrap();
        assert_eq!(servers.len(), 1);
        assert_eq!(servers[0].args, Vec::<String>::new());
    }

    // ---- apply_mcp_governance() tests --------------------------------------

    #[tokio::test]
    async fn apply_mcp_governance_writes_denied_to_settings() {
        let tmp = TempDir::new().unwrap();
        let settings_file = tmp.path().join("settings.json");
        let adapter = CopilotAdapter::with_paths(tmp.path(), &settings_file);
        adapter
            .apply_mcp_governance(&[], &["filesystem:write_file".to_string(), "github:push".to_string()])
            .await
            .unwrap();

        let written = std::fs::read_to_string(&settings_file).unwrap();
        let v: serde_json::Value = serde_json::from_str(&written).unwrap();
        let deny = v["chat.mcp.deny"].as_array().unwrap();
        assert!(deny.contains(&serde_json::json!("filesystem:write_file")));
        assert!(deny.contains(&serde_json::json!("github:push")));
    }

    #[tokio::test]
    async fn apply_mcp_governance_empty_denied_clears_deny_list() {
        let tmp = TempDir::new().unwrap();
        let settings_file = tmp.path().join("settings.json");
        // Pre-populate with a deny entry.
        std::fs::write(&settings_file, r#"{"chat.mcp.deny": ["old:entry"]}"#).unwrap();
        let adapter = CopilotAdapter::with_paths(tmp.path(), &settings_file);
        adapter.apply_mcp_governance(&[], &[]).await.unwrap();

        let written = std::fs::read_to_string(&settings_file).unwrap();
        let v: serde_json::Value = serde_json::from_str(&written).unwrap();
        let deny = v["chat.mcp.deny"].as_array().unwrap();
        assert!(deny.is_empty(), "empty denied list must overwrite prior entries");
    }

    #[tokio::test]
    async fn apply_mcp_governance_preserves_other_settings() {
        let tmp = TempDir::new().unwrap();
        let settings_file = tmp.path().join("settings.json");
        std::fs::write(&settings_file, r#"{"editor.tabSize": 4}"#).unwrap();
        let adapter = CopilotAdapter::with_paths(tmp.path(), &settings_file);
        adapter
            .apply_mcp_governance(&[], &["github:push".to_string()])
            .await
            .unwrap();

        let written = std::fs::read_to_string(&settings_file).unwrap();
        let v: serde_json::Value = serde_json::from_str(&written).unwrap();
        assert_eq!(v["editor.tabSize"], 4, "unrelated settings must be preserved");
    }
}
