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
//! [`DevToolAdapter`]: aa_devtool_contract::DevToolAdapter
//! [`PolicyDocument`]: aa_devtool_contract::PolicyDocument

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use aa_devtool_contract::{
    AdapterError, DevToolAdapter, DevToolInfo, DevToolKind, GovernanceLevel, McpServerInfo, PolicyDecision,
    PolicyDocument, PolicyRule,
};
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
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
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
    let token = stdout
        .split_whitespace()
        .find(|t| t.contains('.') && t.chars().next().is_some_and(|c| c.is_ascii_digit()))?;
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

/// Fold a single policy rule into the in-progress Windsurf admin settings.
///
/// Split out of `generate_managed_settings` so the four action-pattern cases
/// (MCP server deny, blanket terminal deny, terminal-command allowlist, team
/// policy-sync registry URL) read as a flat classification rather than a deeply
/// nested loop body. `terminal_deny_all`/`terminal_allowlist` are accumulated
/// here and reconciled by the caller after the loop.
fn apply_policy_rule(
    rule: &PolicyRule,
    settings: &mut WindsurfAdminSettings,
    terminal_deny_all: &mut bool,
    terminal_allowlist: &mut Vec<String>,
) {
    let pat = rule.action_pattern.as_str();

    if let Some(server) = pat.strip_prefix("mcp_tool:") {
        if rule.decision == PolicyDecision::Deny {
            // Strip trailing ":deny" if present (defensive).
            let server_name = server.strip_suffix(":deny").unwrap_or(server);
            settings.mcp.disabled_servers.push(server_name.to_string());
        }
    } else if pat == "terminal_exec" {
        if rule.decision == PolicyDecision::Deny {
            *terminal_deny_all = true;
        }
    } else if let Some(cmd) = pat.strip_prefix("terminal_exec:") {
        if rule.decision == PolicyDecision::Allow {
            terminal_allowlist.push(cmd.to_string());
        }
    } else if pat == "team_policy_sync" && rule.decision == PolicyDecision::Allow {
        settings.policy.registry_url = std::env::var("AA_GATEWAY_URL").ok();
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
            mcp: WindsurfMcpAdmin {
                auto_approve: false,
                disabled_servers: vec![],
            },
            terminal: WindsurfTerminalAdmin {
                command_allowlist: vec![],
            },
            policy: WindsurfPolicyAdmin::default(),
        };

        let mut terminal_deny_all = false;
        let mut terminal_allowlist: Vec<String> = vec![];

        for rule in &policy.rules {
            apply_policy_rule(rule, &mut settings, &mut terminal_deny_all, &mut terminal_allowlist);
        }

        settings.terminal.command_allowlist = if terminal_deny_all { vec![] } else { terminal_allowlist };

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
        let parsed: WindsurfMcpSettings =
            serde_json::from_str(&raw).map_err(|e| AdapterError::McpConfigFailed(format!("parse failed: {e}")))?;
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
        let serialized =
            serde_json::to_string_pretty(&admin).map_err(|e| AdapterError::McpConfigFailed(e.to_string()))?;
        std::fs::write(&self.admin_settings_path, serialized)
            .map_err(|e| AdapterError::McpConfigFailed(e.to_string()))?;
        Ok(())
    }

    fn governance_level(&self) -> GovernanceLevel {
        GovernanceLevel::L2Enforce
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aa_devtool_contract::PolicyRule;
    use serde_json::Value;
    use std::sync::{Mutex, MutexGuard};
    use tempfile::TempDir;

    /// A `WINDSURF_BIN` value pointing at a binary that does not exist on disk.
    /// `detect()` and `build_launch_command()` use the env var verbatim with no
    /// existence check, so this is enough to drive the env-hook branch.
    const FAKE_BIN: &str = "/opt/aa-test/windsurf-fake-binary";

    /// Serializes tests that mutate process-global env vars so they cannot race
    /// when the test binary runs them in parallel.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    /// Run `f` with `key=value` set in the environment, restoring the previous
    /// value (or absence) afterwards. Holds [`ENV_LOCK`] for the duration.
    fn with_env<R>(key: &str, value: &str, f: impl FnOnce() -> R) -> R {
        let _guard: MutexGuard<'_, ()> = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let prev = std::env::var_os(key);
        // SAFETY: ENV_LOCK serializes all env mutation in this test binary.
        unsafe { std::env::set_var(key, value) };
        let out = f();
        unsafe {
            match prev {
                Some(v) => std::env::set_var(key, v),
                None => std::env::remove_var(key),
            }
        }
        out
    }

    fn rule(pattern: &str, decision: PolicyDecision) -> PolicyRule {
        PolicyRule {
            action_pattern: pattern.to_string(),
            decision,
        }
    }

    fn policy(rules: Vec<PolicyRule>) -> PolicyDocument {
        PolicyDocument {
            version: 1,
            name: "test-policy".to_string(),
            rules,
            enforcement_mode: Default::default(),
        }
    }

    /// Build an adapter rooted in a fresh temp dir, returning the dir guard so
    /// the caller controls its lifetime, plus the admin and mcp file paths.
    fn adapter_in_tempdir() -> (TempDir, WindsurfCascadeAdapter) {
        let dir = TempDir::new().expect("tempdir");
        let admin = dir.path().join("admin_settings.json");
        let mcp = dir.path().join("mcp_settings.json");
        let adapter = WindsurfCascadeAdapter::with_paths(admin, mcp);
        (dir, adapter)
    }

    #[test]
    fn default_paths_live_under_codeium_windsurf() {
        // The default paths are derived from $HOME; assert the stable suffix
        // rather than the absolute prefix so the test is host-independent.
        assert!(default_admin_settings_path().ends_with(".codeium/windsurf/admin_settings.json"));
        assert!(default_mcp_config_path().ends_with(".codeium/windsurf/mcp_settings.json"));
    }

    #[test]
    fn new_and_default_use_the_default_paths() {
        let a = WindsurfCascadeAdapter::new();
        assert_eq!(a.admin_settings_path(), default_admin_settings_path());
        assert_eq!(a.mcp_config_path(), default_mcp_config_path());
        let d = WindsurfCascadeAdapter::default();
        assert_eq!(d.admin_settings_path(), default_admin_settings_path());
    }

    #[test]
    fn governance_level_is_l2_enforce() {
        assert_eq!(
            WindsurfCascadeAdapter::new().governance_level(),
            GovernanceLevel::L2Enforce
        );
    }

    #[test]
    fn detect_via_env_var_reports_l2_enforce_with_mcp_support() {
        with_env(WINDSURF_BIN_ENV, FAKE_BIN, || {
            let info = WindsurfCascadeAdapter::new()
                .detect()
                .expect("env hook should yield DevToolInfo");
            assert_eq!(info.kind, DevToolKind::WindsurfCascade);
            assert_eq!(info.install_path, PathBuf::from(FAKE_BIN));
            assert_eq!(info.governance_level, GovernanceLevel::L2Enforce);
            assert!(info.supports_mcp);
            assert!(info.supports_managed_settings);
            // The fake binary cannot be executed, so version probing yields None.
            assert!(info.version.is_none());
        });
    }

    #[tokio::test]
    async fn generate_managed_settings_disables_denied_mcp_servers() {
        let adapter = WindsurfCascadeAdapter::new();
        let doc = policy(vec![
            rule("mcp_tool:filesystem", PolicyDecision::Deny),
            rule("mcp_tool:github:deny", PolicyDecision::Deny),
            rule("mcp_tool:allowed-server", PolicyDecision::Allow),
        ]);

        let json = adapter.generate_managed_settings(&doc).await.unwrap();
        let parsed: Value = serde_json::from_str(&json).unwrap();
        let disabled = parsed["mcp"]["disabled_servers"].as_array().unwrap();

        let names: Vec<&str> = disabled.iter().map(|v| v.as_str().unwrap()).collect();
        assert!(names.contains(&"filesystem"));
        // The defensive ":deny" suffix is stripped from the server name.
        assert!(names.contains(&"github"));
        // An Allow rule never disables a server.
        assert!(!names.contains(&"allowed-server"));
    }

    #[tokio::test]
    async fn generate_managed_settings_terminal_allowlist_built_from_allow_rules() {
        let adapter = WindsurfCascadeAdapter::new();
        let doc = policy(vec![
            rule("terminal_exec:git", PolicyDecision::Allow),
            rule("terminal_exec:ls", PolicyDecision::Allow),
        ]);

        let json = adapter.generate_managed_settings(&doc).await.unwrap();
        let parsed: Value = serde_json::from_str(&json).unwrap();
        let allow = parsed["terminal"]["command_allowlist"].as_array().unwrap();
        let cmds: Vec<&str> = allow.iter().map(|v| v.as_str().unwrap()).collect();
        assert_eq!(cmds, vec!["git", "ls"]);
    }

    #[tokio::test]
    async fn generate_managed_settings_terminal_deny_all_clears_allowlist() {
        let adapter = WindsurfCascadeAdapter::new();
        // A blanket `terminal_exec` deny must override any per-command allows:
        // the resulting allowlist is empty (deny-all wins).
        let doc = policy(vec![
            rule("terminal_exec:git", PolicyDecision::Allow),
            rule("terminal_exec", PolicyDecision::Deny),
        ]);

        let json = adapter.generate_managed_settings(&doc).await.unwrap();
        let parsed: Value = serde_json::from_str(&json).unwrap();
        let allow = parsed["terminal"]["command_allowlist"].as_array().unwrap();
        assert!(allow.is_empty(), "deny-all must clear the allowlist");
    }

    #[test]
    fn generate_managed_settings_registry_url_from_env_when_team_sync_allowed() {
        let adapter = WindsurfCascadeAdapter::new();
        let doc = policy(vec![rule("team_policy_sync", PolicyDecision::Allow)]);

        // The env var is read synchronously inside generate_managed_settings, so
        // drive the future to completion on a current-thread runtime while the
        // guard holds AA_GATEWAY_URL set.
        let json = with_env("AA_GATEWAY_URL", "https://gw.example.com", || {
            let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();
            rt.block_on(adapter.generate_managed_settings(&doc))
        })
        .unwrap();

        let parsed: Value = serde_json::from_str(&json).unwrap();
        assert_eq!(
            parsed["policy"]["registry_url"].as_str(),
            Some("https://gw.example.com")
        );
    }

    #[tokio::test]
    async fn generate_managed_settings_omits_policy_block_when_empty() {
        let adapter = WindsurfCascadeAdapter::new();
        let doc = policy(vec![]);

        let json = adapter.generate_managed_settings(&doc).await.unwrap();
        let parsed: Value = serde_json::from_str(&json).unwrap();
        // `WindsurfPolicyAdmin::is_empty()` skips serialization entirely.
        assert!(parsed.get("policy").is_none(), "empty policy block must be omitted");
    }

    #[tokio::test]
    async fn apply_settings_creates_parent_dirs_and_writes_file() {
        let dir = TempDir::new().unwrap();
        // Nest the admin path two levels deep to exercise create_dir_all.
        let admin = dir.path().join("nested/deeper/admin_settings.json");
        let adapter = WindsurfCascadeAdapter::with_paths(&admin, dir.path().join("mcp_settings.json"));

        adapter.apply_settings("{\"hello\":\"world\"}").await.unwrap();

        let written = std::fs::read_to_string(&admin).unwrap();
        assert_eq!(written, "{\"hello\":\"world\"}");
    }

    #[tokio::test]
    async fn generate_then_apply_round_trips_through_disk() {
        let (_dir, adapter) = adapter_in_tempdir();
        let doc = policy(vec![rule("mcp_tool:filesystem", PolicyDecision::Deny)]);

        let json = adapter.generate_managed_settings(&doc).await.unwrap();
        adapter.apply_settings(&json).await.unwrap();

        let back = std::fs::read_to_string(adapter.admin_settings_path()).unwrap();
        let parsed: Value = serde_json::from_str(&back).unwrap();
        assert_eq!(parsed["mcp"]["disabled_servers"][0].as_str(), Some("filesystem"));
    }

    #[tokio::test]
    async fn list_mcp_servers_parses_configured_entries() {
        let (_dir, adapter) = adapter_in_tempdir();
        std::fs::write(
            adapter.mcp_config_path(),
            r#"{ "mcpServers": {
                "filesystem": { "command": "mcp-fs", "args": ["--root", "/srv"] },
                "github": { "command": "mcp-gh" }
            } }"#,
        )
        .unwrap();

        let mut servers = adapter.list_mcp_servers().await.unwrap();
        // BTreeMap iteration is deterministic (sorted by name).
        servers.sort_by(|a, b| a.name.cmp(&b.name));
        assert_eq!(servers.len(), 2);
        assert_eq!(servers[0].name, "filesystem");
        assert_eq!(servers[0].command, "mcp-fs");
        assert_eq!(servers[0].args, vec!["--root", "/srv"]);
        assert_eq!(servers[1].name, "github");
        assert!(servers[1].args.is_empty(), "missing args default to empty");
    }

    #[tokio::test]
    async fn list_mcp_servers_errors_when_config_missing() {
        let (_dir, adapter) = adapter_in_tempdir();
        // No file written: read_to_string fails and surfaces as an error.
        let err = adapter.list_mcp_servers().await.unwrap_err();
        assert!(matches!(err, AdapterError::Io(_)));
    }

    #[tokio::test]
    async fn list_mcp_servers_errors_on_malformed_json() {
        let (_dir, adapter) = adapter_in_tempdir();
        std::fs::write(adapter.mcp_config_path(), "{ not valid json").unwrap();

        let err = adapter.list_mcp_servers().await.unwrap_err();
        assert!(matches!(err, AdapterError::McpConfigFailed(_)));
    }

    #[tokio::test]
    async fn apply_mcp_governance_disables_denied_and_non_allowed_configured() {
        let (_dir, adapter) = adapter_in_tempdir();
        // Three configured servers; only `keep` is allowed.
        std::fs::write(
            adapter.mcp_config_path(),
            r#"{ "mcpServers": {
                "keep": { "command": "a" },
                "drop": { "command": "b" },
                "also-drop": { "command": "c" }
            } }"#,
        )
        .unwrap();

        adapter
            .apply_mcp_governance(&["keep".to_string()], &["explicit-deny".to_string()])
            .await
            .unwrap();

        let admin: Value =
            serde_json::from_str(&std::fs::read_to_string(adapter.admin_settings_path()).unwrap()).unwrap();
        let disabled: Vec<String> = admin["mcp"]["disabled_servers"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect();

        // Explicit deny always present.
        assert!(disabled.contains(&"explicit-deny".to_string()));
        // Configured-but-not-allowed servers are disabled.
        assert!(disabled.contains(&"drop".to_string()));
        assert!(disabled.contains(&"also-drop".to_string()));
        // The allowed server is never disabled.
        assert!(!disabled.contains(&"keep".to_string()));
    }

    #[tokio::test]
    async fn apply_mcp_governance_works_without_existing_admin_or_config() {
        let (_dir, adapter) = adapter_in_tempdir();
        // Neither admin nor mcp config exists: only the explicit denies land.
        adapter
            .apply_mcp_governance(&[], &["only-deny".to_string()])
            .await
            .unwrap();

        let admin: Value =
            serde_json::from_str(&std::fs::read_to_string(adapter.admin_settings_path()).unwrap()).unwrap();
        let disabled: Vec<&str> = admin["mcp"]["disabled_servers"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert_eq!(disabled, vec!["only-deny"]);
    }

    #[test]
    fn build_launch_command_threads_governance_env() {
        with_env(WINDSURF_BIN_ENV, FAKE_BIN, || {
            let adapter = WindsurfCascadeAdapter::new();
            let cmd = adapter
                .build_launch_command(
                    &["--flag".to_string()],
                    "agent-7",
                    Some("team-x"),
                    Some("http://127.0.0.1:8888"),
                )
                .expect("env hook supplies the binary path");

            assert_eq!(cmd.get_program(), std::ffi::OsStr::new(FAKE_BIN));
            let args: Vec<_> = cmd.get_args().collect();
            assert_eq!(args, vec![std::ffi::OsStr::new("--flag")]);

            let envs: std::collections::HashMap<_, _> = cmd
                .get_envs()
                .filter_map(|(k, v)| v.map(|v| (k.to_owned(), v.to_owned())))
                .collect();
            assert_eq!(
                envs.get(std::ffi::OsStr::new("AA_AGENT_ID")).unwrap(),
                std::ffi::OsStr::new("agent-7")
            );
            assert_eq!(
                envs.get(std::ffi::OsStr::new("AA_TEAM_ID")).unwrap(),
                std::ffi::OsStr::new("team-x")
            );
            assert_eq!(
                envs.get(std::ffi::OsStr::new("HTTPS_PROXY")).unwrap(),
                std::ffi::OsStr::new("http://127.0.0.1:8888")
            );
        });
    }

    #[test]
    fn build_launch_command_omits_optional_env_when_absent() {
        with_env(WINDSURF_BIN_ENV, FAKE_BIN, || {
            let adapter = WindsurfCascadeAdapter::new();
            let cmd = adapter
                .build_launch_command(&[], "solo-agent", None, None)
                .expect("env hook supplies the binary path");

            let env_keys: Vec<_> = cmd.get_envs().map(|(k, _)| k.to_owned()).collect();
            assert!(env_keys.contains(&std::ffi::OsString::from("AA_AGENT_ID")));
            assert!(!env_keys.contains(&std::ffi::OsString::from("AA_TEAM_ID")));
            assert!(!env_keys.contains(&std::ffi::OsString::from("HTTPS_PROXY")));
        });
    }
}
