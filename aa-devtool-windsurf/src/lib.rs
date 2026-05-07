//! [`DevToolAdapter`] implementation for Windsurf Cascade.
//!
//! Governs Windsurf at **L2 (Enforce)** via its admin settings file
//! (`~/.codeium/windsurf/admin_settings.json`) and MCP configuration file
//! (`~/.codeium/windsurf/mcp_settings.json`).  The adapter:
//!
//! * Detects Windsurf by checking `$WINDSURF_BIN`, `which windsurf`, and the
//!   macOS application bundle at `/Applications/Windsurf.app`.
//! * Translates an Agent Assembly [`PolicyDocument`] into Windsurf admin JSON
//!   (MCP disabled-server list, terminal command allowlist, optional policy
//!   registry URL).
//! * Enumerates configured MCP servers from the Windsurf MCP config file.
//! * Applies MCP governance by updating the disabled-servers list in the admin
//!   settings file.
//! * Builds the `aa run windsurf` launch [`Command`] with governance identity
//!   and proxy wiring.
//!
//! [`DevToolAdapter`]: aa_core::DevToolAdapter
//! [`PolicyDocument`]: aa_core::PolicyDocument

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use aa_core::{AdapterError, DevToolAdapter, DevToolInfo, DevToolKind, GovernanceLevel, McpServerInfo, PolicyDocument, PolicyDecision};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Public constants
// ---------------------------------------------------------------------------

/// Environment variable that overrides Windsurf binary detection (test hook).
///
/// When set, `detect()` and `build_launch_command()` use this path verbatim
/// without checking whether it exists on disk.  This allows tests to succeed
/// in CI where no Windsurf installation is present.
pub const WINDSURF_BIN_ENV: &str = "WINDSURF_BIN";

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

fn home_dir() -> PathBuf {
    std::env::var_os("HOME").map(PathBuf::from).unwrap_or_else(|| PathBuf::from("."))
}

/// Locate the Windsurf binary.
///
/// Resolution order:
/// 1. `$WINDSURF_BIN` env var — used as-is (test hook, no existence check).
/// 2. `which windsurf` — first token on stdout.
/// 3. `/Applications/Windsurf.app/Contents/MacOS/Electron` — existence checked.
fn find_windsurf_binary() -> Option<PathBuf> {
    // 1. Test-hook env var (no existence check).
    if let Some(val) = std::env::var_os(WINDSURF_BIN_ENV) {
        return Some(PathBuf::from(val));
    }

    // 2. `which windsurf`.
    if let Ok(output) = Command::new("which").arg("windsurf").output() {
        if output.status.success() {
            let s = String::from_utf8_lossy(&output.stdout);
            let path = PathBuf::from(s.trim());
            if !path.as_os_str().is_empty() {
                return Some(path);
            }
        }
    }

    // 3. macOS application bundle.
    let app_path = PathBuf::from("/Applications/Windsurf.app/Contents/MacOS/Electron");
    if app_path.exists() {
        return Some(app_path);
    }

    None
}

/// Run `binary --version` and return the first `.`-separated version token.
fn probe_version(binary: &Path) -> Option<String> {
    let output = Command::new(binary).arg("--version").output().ok()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let token = stdout.split_whitespace().find(|t| t.contains('.') && t.chars().next().is_some_and(|c| c.is_ascii_digit()))?;
    Some(token.to_string())
}

// ---------------------------------------------------------------------------
// Public path helpers
// ---------------------------------------------------------------------------

/// Default path to the Windsurf admin settings file.
pub fn default_admin_settings_path() -> PathBuf {
    home_dir().join(".codeium/windsurf/admin_settings.json")
}

/// Default path to the Windsurf MCP configuration file.
pub fn default_mcp_config_path() -> PathBuf {
    home_dir().join(".codeium/windsurf/mcp_settings.json")
}

// ---------------------------------------------------------------------------
// Internal serde types — admin settings
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize, Default)]
struct WindsurfAdminSettings {
    mcp: WindsurfMcpAdmin,
    terminal: WindsurfTerminalAdmin,
    #[serde(skip_serializing_if = "WindsurfPolicyAdmin::is_empty")]
    policy: WindsurfPolicyAdmin,
}

#[derive(Debug, Serialize, Deserialize, Default)]
struct WindsurfMcpAdmin {
    auto_approve: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    disabled_servers: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Default)]
struct WindsurfTerminalAdmin {
    command_allowlist: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Default)]
struct WindsurfPolicyAdmin {
    #[serde(skip_serializing_if = "Option::is_none")]
    registry_url: Option<String>,
}

impl WindsurfPolicyAdmin {
    fn is_empty(&self) -> bool {
        self.registry_url.is_none()
    }
}

// ---------------------------------------------------------------------------
// Internal serde types — MCP settings
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct WindsurfMcpSettings {
    #[serde(rename = "mcpServers", default)]
    mcp_servers: BTreeMap<String, WindsurfMcpEntry>,
}

#[derive(Debug, Deserialize)]
struct WindsurfMcpEntry {
    command: String,
    #[serde(default)]
    args: Vec<String>,
}

// ---------------------------------------------------------------------------
// Adapter
// ---------------------------------------------------------------------------

/// [`DevToolAdapter`] for Windsurf Cascade.
///
/// Governs Windsurf at L2 (Enforce) by writing admin settings and managing
/// the MCP disabled-server list.
///
/// Use [`WindsurfCascadeAdapter::new`] for the default configuration (reads
/// from `~/.codeium/windsurf/`) or [`WindsurfCascadeAdapter::with_paths`]
/// to supply explicit paths for testing.
#[derive(Debug, Clone)]
pub struct WindsurfCascadeAdapter {
    admin_settings_path: PathBuf,
    mcp_config_path: PathBuf,
}

impl WindsurfCascadeAdapter {
    /// Construct an adapter using default Windsurf configuration paths.
    pub fn new() -> Self {
        Self {
            admin_settings_path: default_admin_settings_path(),
            mcp_config_path: default_mcp_config_path(),
        }
    }

    /// Construct an adapter with explicit configuration paths (for testing).
    pub fn with_paths(admin: impl Into<PathBuf>, mcp: impl Into<PathBuf>) -> Self {
        Self {
            admin_settings_path: admin.into(),
            mcp_config_path: mcp.into(),
        }
    }

    /// Path to the admin settings file this adapter reads and writes.
    pub fn admin_settings_path(&self) -> &Path {
        &self.admin_settings_path
    }

    /// Path to the MCP configuration file this adapter reads.
    pub fn mcp_config_path(&self) -> &Path {
        &self.mcp_config_path
    }
}

impl Default for WindsurfCascadeAdapter {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl DevToolAdapter for WindsurfCascadeAdapter {
    fn detect(&self) -> Option<DevToolInfo> {
        let install_path = find_windsurf_binary()?;
        let version = probe_version(&install_path);
        Some(DevToolInfo {
            kind: DevToolKind::WindsurfCascade,
            version,
            install_path,
            governance_level: GovernanceLevel::L2Enforce,
            supports_mcp: true,
            supports_managed_settings: true,
        })
    }

    async fn generate_managed_settings(&self, policy: &PolicyDocument) -> Result<String, AdapterError> {
        let mut settings = WindsurfAdminSettings {
            mcp: WindsurfMcpAdmin { auto_approve: false, disabled_servers: vec![] },
            terminal: WindsurfTerminalAdmin { command_allowlist: vec![] },
            policy: WindsurfPolicyAdmin::default(),
        };

        let mut terminal_deny_all = false;
        let mut terminal_allowlist: Vec<String> = vec![];

        for rule in &policy.rules {
            let pat = rule.action_pattern.as_str();

            if let Some(server) = pat.strip_prefix("mcp_tool:") {
                if rule.decision == PolicyDecision::Deny {
                    // Strip trailing ":deny" if present (defensive).
                    let server_name = server.strip_suffix(":deny").unwrap_or(server);
                    settings.mcp.disabled_servers.push(server_name.to_string());
                }
            } else if pat == "terminal_exec" {
                if rule.decision == PolicyDecision::Deny {
                    terminal_deny_all = true;
                }
            } else if let Some(cmd) = pat.strip_prefix("terminal_exec:") {
                if rule.decision == PolicyDecision::Allow {
                    terminal_allowlist.push(cmd.to_string());
                }
            } else if pat == "team_policy_sync" && rule.decision == PolicyDecision::Allow {
                settings.policy.registry_url = std::env::var("AA_GATEWAY_URL").ok();
            }
        }

        settings.terminal.command_allowlist = if terminal_deny_all {
            vec![]
        } else {
            terminal_allowlist
        };

        serde_json::to_string_pretty(&settings).map_err(|e| AdapterError::Serde(e.to_string()))
    }

    async fn apply_settings(&self, settings: &str) -> Result<(), AdapterError> {
        if let Some(parent) = self.admin_settings_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&self.admin_settings_path, settings).map_err(AdapterError::SettingsApplyFailed)?;
        Ok(())
    }

    fn build_launch_command(
        &self,
        tool_args: &[String],
        agent_id: &str,
        team_id: Option<&str>,
        proxy_addr: Option<&str>,
    ) -> Result<Command, AdapterError> {
        let bin = find_windsurf_binary().ok_or_else(|| {
            AdapterError::LaunchFailed("windsurf not found; set WINDSURF_BIN or install windsurf".into())
        })?;
        let mut cmd = Command::new(bin);
        cmd.args(tool_args);
        cmd.env("AA_AGENT_ID", agent_id);
        if let Some(team) = team_id {
            cmd.env("AA_TEAM_ID", team);
        }
        if let Some(proxy) = proxy_addr {
            cmd.env("HTTPS_PROXY", proxy);
        }
        Ok(cmd)
    }

    async fn list_mcp_servers(&self) -> Result<Vec<McpServerInfo>, AdapterError> {
        let raw = std::fs::read_to_string(&self.mcp_config_path)?;
        let parsed: WindsurfMcpSettings = serde_json::from_str(&raw)
            .map_err(|e| AdapterError::McpConfigFailed(format!("parse failed: {e}")))?;
        Ok(parsed
            .mcp_servers
            .into_iter()
            .map(|(name, entry)| McpServerInfo {
                name,
                command: entry.command,
                args: entry.args,
            })
            .collect())
    }

    async fn apply_mcp_governance(&self, allowed: &[String], denied: &[String]) -> Result<(), AdapterError> {
        // Read existing admin settings (or start from default).
        let mut admin: WindsurfAdminSettings = if self.admin_settings_path.exists() {
            let raw = std::fs::read_to_string(&self.admin_settings_path)?;
            serde_json::from_str(&raw).unwrap_or_default()
        } else {
            WindsurfAdminSettings::default()
        };

        // Read configured MCP server names from mcp_config_path if it exists.
        let configured: Vec<String> = if self.mcp_config_path.exists() {
            let raw = std::fs::read_to_string(&self.mcp_config_path)?;
            serde_json::from_str::<WindsurfMcpSettings>(&raw)
                .map(|s| s.mcp_servers.into_keys().collect())
                .unwrap_or_default()
        } else {
            vec![]
        };

        // Build disabled list: explicit denied + configured servers not in allowed.
        let mut disabled: Vec<String> = denied.to_vec();
        for server in &configured {
            if !allowed.contains(server) && !disabled.contains(server) {
                disabled.push(server.clone());
            }
        }
        admin.mcp.disabled_servers = disabled;

        // Write back.
        if let Some(parent) = self.admin_settings_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let serialized = serde_json::to_string_pretty(&admin)
            .map_err(|e| AdapterError::McpConfigFailed(e.to_string()))?;
        std::fs::write(&self.admin_settings_path, serialized)
            .map_err(|e| AdapterError::McpConfigFailed(e.to_string()))?;
        Ok(())
    }

    fn governance_level(&self) -> GovernanceLevel {
        GovernanceLevel::L2Enforce
    }
}
