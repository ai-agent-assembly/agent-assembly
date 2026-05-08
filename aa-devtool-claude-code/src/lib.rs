//! [`DevToolAdapter`] for Anthropic Claude Code CLI.
//!
//! Claude Code is the Anthropic-developed CLI (`claude`) that wraps
//! their API in an agentic coding assistant. This adapter:
//!
//! * **Detects** the installation by probing `which claude` and
//!   validating the reported version against [`MIN_VERSION`].
//! * **Generates** managed settings (AAASM-952).
//! * **Applies** settings and MCP governance (AAASM-956).
//! * **Builds** the launch command wired for AA proxy and identity
//!   env vars (AAASM-959).
//!
//! [`DevToolAdapter`]: aa_core::DevToolAdapter

#![warn(missing_docs)]

mod apply;
mod settings;

use std::path::{Path, PathBuf};
use std::process::Command;

use aa_core::{AdapterError, DevToolAdapter, DevToolInfo, DevToolKind, GovernanceLevel, McpServerInfo, PolicyDocument};
use async_trait::async_trait;

/// Minimum Claude Code CLI version this adapter supports.
///
/// Claude Code 1.0.0 introduced stable `--permission-prompt-tool` wiring
/// and the `~/.claude/settings.json` MCP-server configuration surface
/// that this adapter governs. Installations reporting a lower version are
/// treated as absent to prevent half-functional governance.
pub const MIN_VERSION: &str = "1.0.0";

/// Name of the Claude Code CLI binary, used for PATH lookup and launch.
pub const CLAUDE_BIN: &str = "claude";

/// Hook a [`ClaudeCodeAdapter`] uses to read the Claude Code binary's
/// reported version.
///
/// The production implementation runs `<bin> --version` via
/// [`std::process::Command`]. Tests inject a deterministic stub so they
/// do not depend on a real Claude Code install or an executable tmpdir.
trait VersionProbe: Send + Sync {
    fn probe_version(&self, bin: &Path) -> Option<String>;
}

/// Production [`VersionProbe`] backed by [`std::process::Command`].
struct CommandVersionProbe;

impl VersionProbe for CommandVersionProbe {
    fn probe_version(&self, bin: &Path) -> Option<String> {
        let out = Command::new(bin).arg("--version").output().ok()?;
        let raw = std::str::from_utf8(&out.stdout).ok()?.trim().to_string();
        (!raw.is_empty()).then_some(raw)
    }
}

/// [`DevToolAdapter`] for the Anthropic Claude Code CLI.
///
/// Construct with [`ClaudeCodeAdapter::new`] for production use. In tests,
/// use [`ClaudeCodeAdapter::with_overrides`] to supply a stub binary path
/// and a temporary home directory so detection never touches the real
/// filesystem or spawns the real `claude` binary.
///
/// [`DevToolAdapter`]: aa_core::DevToolAdapter
pub struct ClaudeCodeAdapter {
    /// Optional override for the `claude` binary path. When set, skips the
    /// `which claude` PATH search and uses this path directly.
    binary_path_override: Option<PathBuf>,
    /// Optional override for the home directory used to locate `~/.claude/`.
    /// When set, replaces `$HOME` for all filesystem marker checks.
    home_dir_override: Option<PathBuf>,
    version_probe: Box<dyn VersionProbe>,
    settings_path_resolver: Box<dyn apply::SettingsPathResolver>,
}

impl std::fmt::Debug for ClaudeCodeAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClaudeCodeAdapter").finish_non_exhaustive()
    }
}

impl Default for ClaudeCodeAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl ClaudeCodeAdapter {
    /// Construct an adapter that detects Claude Code from the host's `PATH`
    /// and reads `$HOME/.claude/` for initialization-marker checks.
    pub fn new() -> Self {
        Self {
            binary_path_override: None,
            home_dir_override: None,
            version_probe: Box::new(CommandVersionProbe),
            settings_path_resolver: Box::new(apply::DefaultSettingsPathResolver { home_dir: None }),
        }
    }

    /// Construct with explicit overrides for the binary path and home
    /// directory. Intended for unit tests only.
    ///
    /// Pass `None` for either argument to retain the default lookup
    /// (`which` for the binary, `$HOME` for the home directory).
    #[doc(hidden)]
    pub fn with_overrides(binary_path: Option<PathBuf>, home_dir: Option<PathBuf>) -> Self {
        Self {
            binary_path_override: binary_path,
            home_dir_override: home_dir.clone(),
            version_probe: Box::new(CommandVersionProbe),
            settings_path_resolver: Box::new(apply::DefaultSettingsPathResolver { home_dir }),
        }
    }

    /// Override the version probe. Only used in tests to avoid spawning real
    /// subprocesses in environments where tmpdir may be noexec.
    #[cfg(test)]
    fn with_version_probe(mut self, probe: Box<dyn VersionProbe>) -> Self {
        self.version_probe = probe;
        self
    }

    /// Override the settings path resolver. Only used in tests to write to a
    /// temporary directory instead of the real `~/.claude/settings.json`.
    #[cfg(test)]
    fn with_settings_path_resolver(mut self, resolver: Box<dyn apply::SettingsPathResolver>) -> Self {
        self.settings_path_resolver = resolver;
        self
    }

    fn resolve_binary(&self) -> Option<PathBuf> {
        match &self.binary_path_override {
            Some(p) => p.exists().then(|| p.clone()),
            None => probe_which(CLAUDE_BIN),
        }
    }

    fn home_dir(&self) -> Option<PathBuf> {
        self.home_dir_override
            .clone()
            .or_else(|| std::env::var_os("HOME").map(PathBuf::from))
    }

    /// Check whether `~/.claude/` exists — confirms Claude Code has been
    /// initialized at least once on this host. Used as a secondary signal in
    /// [`detect`][Self::detect]; does not gate detection on its own.
    fn dot_claude_marker(&self) -> Option<PathBuf> {
        let marker = self.home_dir()?.join(".claude");
        marker.is_dir().then_some(marker)
    }
}

/// Locate a binary via the `which` command.
///
/// Returns `None` when the binary is not in `PATH` or the subprocess cannot
/// be spawned.
fn probe_which(bin: &str) -> Option<PathBuf> {
    let out = Command::new("which").arg(bin).output().ok()?;
    if out.status.success() {
        let s = std::str::from_utf8(&out.stdout).ok()?.trim();
        if !s.is_empty() {
            return Some(PathBuf::from(s));
        }
    }
    None
}

/// Extract the first `MAJOR.MINOR.PATCH` triple from an arbitrary string.
///
/// Claude Code reports version strings of the form `1.9.2` or
/// `claude 1.9.2`. Both formats are handled by scanning whitespace-delimited
/// tokens for a `\d+\.\d+\.\d+` pattern.
///
/// # Examples
///
/// ```
/// use aa_devtool_claude_code::extract_semver;
/// assert_eq!(extract_semver("1.9.2"),              Some((1, 9, 2)));
/// assert_eq!(extract_semver("claude 2.0.1"),       Some((2, 0, 1)));
/// assert_eq!(extract_semver("not a version"),      None);
/// ```
pub fn extract_semver(s: &str) -> Option<(u64, u64, u64)> {
    for token in s.split_whitespace() {
        // Strip leading/trailing chars that are neither digits nor dots so
        // prefixes like `v` or suffixes like `)` don't block parsing.
        let t = token.trim_matches(|c: char| !c.is_ascii_digit() && c != '.');
        let parts: Vec<&str> = t.splitn(3, '.').collect();
        if parts.len() != 3 {
            continue;
        }
        let (Ok(major), Ok(minor)) = (parts[0].parse::<u64>(), parts[1].parse::<u64>()) else {
            continue;
        };
        // Accept patch fields with pre-release suffixes (e.g. `3-rc1`).
        let patch_s: String = parts[2].chars().take_while(|c| c.is_ascii_digit()).collect();
        let Ok(patch) = patch_s.parse::<u64>() else {
            continue;
        };
        return Some((major, minor, patch));
    }
    None
}

/// Return `true` when `version_str` represents a semver ≥ `min`.
///
/// Both arguments must be parseable by [`extract_semver`]; returns `false`
/// when either cannot be parsed.
///
/// # Examples
///
/// ```
/// use aa_devtool_claude_code::{version_meets_minimum, MIN_VERSION};
/// assert!( version_meets_minimum("1.9.2", MIN_VERSION));
/// assert!(!version_meets_minimum("0.9.9", MIN_VERSION));
/// ```
pub fn version_meets_minimum(version_str: &str, min: &str) -> bool {
    let (Some(v), Some(m)) = (extract_semver(version_str), extract_semver(min)) else {
        return false;
    };
    v >= m
}

#[async_trait]
impl DevToolAdapter for ClaudeCodeAdapter {
    fn detect(&self) -> Option<DevToolInfo> {
        // 1. Locate the binary via which-probe or override path.
        let install_path = self.resolve_binary()?;

        // 2. Note ~/.claude/ presence — confirms prior initialization on this
        //    host. Not required: CI boxes may have claude in PATH before the
        //    first interactive run.
        let _marker = self.dot_claude_marker();

        // 3. Probe version string.
        let raw = self.version_probe.probe_version(&install_path)?;

        // 4. Minimum-version guard: reject installations too old to support
        //    the settings.json MCP configuration surface.
        if !version_meets_minimum(&raw, MIN_VERSION) {
            return None;
        }

        // Normalize to clean `MAJOR.MINOR.PATCH`; fall back to raw string if
        // the version output is unusual.
        let version = extract_semver(&raw)
            .map(|(ma, mi, pa)| format!("{ma}.{mi}.{pa}"))
            .or(Some(raw));

        Some(DevToolInfo {
            kind: DevToolKind::ClaudeCode,
            version,
            install_path,
            governance_level: GovernanceLevel::L2Enforce,
            supports_mcp: true,
            supports_managed_settings: true,
        })
    }

    async fn generate_managed_settings(&self, policy: &PolicyDocument) -> Result<String, AdapterError> {
        let s = settings::map_policy_to_settings(policy);
        serde_json::to_string_pretty(&s).map_err(|e| AdapterError::SettingsGenerationFailed(e.to_string()))
    }

    async fn apply_settings(&self, settings: &str) -> Result<(), AdapterError> {
        let path = self.settings_path_resolver.resolve()?;
        apply::apply_settings_at(&path, settings)
    }

    fn build_launch_command(
        &self,
        tool_args: &[String],
        agent_id: &str,
        team_id: Option<&str>,
        proxy_addr: Option<&str>,
    ) -> Result<Command, AdapterError> {
        let bin = self.resolve_binary().ok_or(AdapterError::ToolNotFound)?;
        let mut cmd = Command::new(bin);
        cmd.args(tool_args);
        cmd.env("AA_AGENT_ID", agent_id);
        if let Some(tid) = team_id {
            cmd.env("AA_TEAM_ID", tid);
        }
        if let Some(px) = proxy_addr {
            cmd.env("HTTPS_PROXY", px);
        }
        Ok(cmd)
    }

    async fn list_mcp_servers(&self) -> Result<Vec<McpServerInfo>, AdapterError> {
        // Primary source: resolved settings.json (global or project-scoped).
        let settings_path = self.settings_path_resolver.resolve()?;
        let mut servers = apply::read_mcp_servers_from(&settings_path)?;

        // Secondary source: <cwd>/.claude/.mcp.json when present.
        if let Ok(cwd) = std::env::current_dir() {
            let mcp_json = cwd.join(".claude").join(".mcp.json");
            let extra = apply::read_mcp_servers_from(&mcp_json)?;
            // Settings-file entries win on name collision.
            let existing: std::collections::HashSet<String> = servers.iter().map(|s| s.name.clone()).collect();
            for s in extra {
                if !existing.contains(&s.name) {
                    servers.push(s);
                }
            }
        }

        Ok(servers)
    }

    async fn apply_mcp_governance(&self, allowed: &[String], denied: &[String]) -> Result<(), AdapterError> {
        let path = self.settings_path_resolver.resolve()?;
        apply::apply_mcp_governance_at(&path, allowed, denied)
    }

    fn governance_level(&self) -> GovernanceLevel {
        GovernanceLevel::L2Enforce
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Stub [`VersionProbe`] returning a canned version string so detection
    /// tests don't depend on spawning a real executable (which fails in CI
    /// coverage environments where tmpdir may be noexec).
    struct StubVersionProbe(Option<String>);

    impl VersionProbe for StubVersionProbe {
        fn probe_version(&self, _bin: &Path) -> Option<String> {
            self.0.clone()
        }
    }

    // ── extract_semver ──────────────────────────────────────────────────────

    #[test]
    fn extract_semver_bare_version() {
        assert_eq!(extract_semver("1.9.2"), Some((1, 9, 2)));
    }

    #[test]
    fn extract_semver_prefixed_with_tool_name() {
        assert_eq!(extract_semver("claude 1.9.2"), Some((1, 9, 2)));
        assert_eq!(extract_semver("Claude Code 2.0.1"), Some((2, 0, 1)));
    }

    #[test]
    fn extract_semver_v_prefix() {
        assert_eq!(extract_semver("v1.0.0"), Some((1, 0, 0)));
    }

    #[test]
    fn extract_semver_patch_with_prerelease_suffix() {
        assert_eq!(extract_semver("1.0.0-rc1"), Some((1, 0, 0)));
    }

    #[test]
    fn extract_semver_non_version_string_returns_none() {
        assert_eq!(extract_semver("not a version"), None);
    }

    #[test]
    fn extract_semver_two_part_version_returns_none() {
        assert_eq!(extract_semver("1.0"), None);
    }

    #[test]
    fn extract_semver_empty_returns_none() {
        assert_eq!(extract_semver(""), None);
    }

    // ── version_meets_minimum ───────────────────────────────────────────────

    #[test]
    fn version_meets_minimum_equal_to_min() {
        assert!(version_meets_minimum(MIN_VERSION, MIN_VERSION));
    }

    #[test]
    fn version_meets_minimum_major_above() {
        assert!(version_meets_minimum("2.0.0", MIN_VERSION));
    }

    #[test]
    fn version_meets_minimum_minor_above() {
        assert!(version_meets_minimum("1.1.0", MIN_VERSION));
    }

    #[test]
    fn version_meets_minimum_patch_above() {
        assert!(version_meets_minimum("1.0.1", MIN_VERSION));
    }

    #[test]
    fn version_meets_minimum_below_min() {
        assert!(!version_meets_minimum("0.9.9", MIN_VERSION));
        assert!(!version_meets_minimum("0.0.1", MIN_VERSION));
    }

    #[test]
    fn version_meets_minimum_unparseable_returns_false() {
        assert!(!version_meets_minimum("not-a-version", MIN_VERSION));
        assert!(!version_meets_minimum(MIN_VERSION, "also-bad"));
    }

    // ── ClaudeCodeAdapter::detect ───────────────────────────────────────────

    #[test]
    fn detect_returns_none_for_nonexistent_binary_override() {
        let adapter = ClaudeCodeAdapter::with_overrides(Some(PathBuf::from("/no/such/binary")), None);
        assert!(adapter.detect().is_none());
    }

    #[test]
    fn governance_level_is_l2_enforce() {
        assert_eq!(ClaudeCodeAdapter::new().governance_level(), GovernanceLevel::L2Enforce);
    }

    #[test]
    fn default_equals_new() {
        let a = ClaudeCodeAdapter::new();
        let b = ClaudeCodeAdapter::default();
        // Both use the same code path; verifying they don't panic is sufficient.
        assert_eq!(a.governance_level(), b.governance_level());
    }

    #[test]
    fn detect_returns_none_for_version_below_minimum() {
        let tmp = tempfile::tempdir().unwrap();
        let stub = tmp.path().join("claude");
        std::fs::write(&stub, "").unwrap();
        let adapter = ClaudeCodeAdapter::with_overrides(Some(stub), None)
            .with_version_probe(Box::new(StubVersionProbe(Some("0.9.9".into()))));
        assert!(adapter.detect().is_none());
    }

    #[test]
    fn detect_returns_some_for_valid_version() {
        let tmp = tempfile::tempdir().unwrap();
        let stub = tmp.path().join("claude");
        std::fs::write(&stub, "").unwrap();
        let adapter = ClaudeCodeAdapter::with_overrides(Some(stub), None)
            .with_version_probe(Box::new(StubVersionProbe(Some("1.9.2".into()))));
        let info = adapter.detect().expect("should detect stub binary");
        assert_eq!(info.kind, DevToolKind::ClaudeCode);
        assert_eq!(info.version.as_deref(), Some("1.9.2"));
        assert_eq!(info.governance_level, GovernanceLevel::L2Enforce);
        assert!(info.supports_mcp);
        assert!(info.supports_managed_settings);
    }

    #[test]
    fn detect_normalizes_version_with_prefix() {
        let tmp = tempfile::tempdir().unwrap();
        let stub = tmp.path().join("claude");
        std::fs::write(&stub, "").unwrap();
        let adapter = ClaudeCodeAdapter::with_overrides(Some(stub), None)
            .with_version_probe(Box::new(StubVersionProbe(Some("claude 2.1.0".into()))));
        let info = adapter.detect().unwrap();
        assert_eq!(info.version.as_deref(), Some("2.1.0"));
    }

    #[test]
    fn detect_returns_none_when_probe_returns_none() {
        let tmp = tempfile::tempdir().unwrap();
        let stub = tmp.path().join("claude");
        std::fs::write(&stub, "").unwrap();
        let adapter =
            ClaudeCodeAdapter::with_overrides(Some(stub), None).with_version_probe(Box::new(StubVersionProbe(None)));
        assert!(adapter.detect().is_none());
    }

    #[cfg(unix)]
    #[test]
    fn dot_claude_marker_found_when_dir_exists() {
        let tmp = tempfile::tempdir().unwrap();
        let dot_claude = tmp.path().join(".claude");
        std::fs::create_dir(&dot_claude).unwrap();
        let adapter = ClaudeCodeAdapter::with_overrides(None, Some(tmp.path().to_path_buf()));
        assert_eq!(adapter.dot_claude_marker(), Some(dot_claude));
    }

    #[cfg(unix)]
    #[test]
    fn dot_claude_marker_absent_when_dir_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let adapter = ClaudeCodeAdapter::with_overrides(None, Some(tmp.path().to_path_buf()));
        assert!(adapter.dot_claude_marker().is_none());
    }

    // ── apply_settings / apply_mcp_governance (adapter wiring) ─────────────

    struct StubSettingsPathResolver(PathBuf);

    impl apply::SettingsPathResolver for StubSettingsPathResolver {
        fn resolve(&self) -> Result<PathBuf, AdapterError> {
            Ok(self.0.clone())
        }
    }

    #[tokio::test]
    async fn apply_settings_writes_to_resolved_path() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        let adapter =
            ClaudeCodeAdapter::new().with_settings_path_resolver(Box::new(StubSettingsPathResolver(path.clone())));
        let settings = r#"{"permissionMode":"acceptEdits","permissions":{"allow":["Bash"],"deny":[]},"enabledMcpjsonServers":[],"disabledMcpjsonServers":[]}"#;
        adapter.apply_settings(settings).await.unwrap();
        let v: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(v["permissionMode"], "acceptEdits");
    }

    #[tokio::test]
    async fn apply_mcp_governance_writes_to_resolved_path() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        let adapter =
            ClaudeCodeAdapter::new().with_settings_path_resolver(Box::new(StubSettingsPathResolver(path.clone())));
        adapter
            .apply_mcp_governance(&["filesystem".to_string()], &["search".to_string()])
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(v["enabledMcpjsonServers"], serde_json::json!(["filesystem"]));
        assert_eq!(v["disabledMcpjsonServers"], serde_json::json!(["search"]));
    }

    // ── build_launch_command ────────────────────────────────────────────────

    #[test]
    fn build_command_appends_args_and_env() {
        let tmp = tempfile::tempdir().unwrap();
        let stub = tmp.path().join("claude");
        std::fs::write(&stub, "").unwrap();
        let adapter = ClaudeCodeAdapter::with_overrides(Some(stub), None);
        let args = vec!["--print".to_string(), "hello".to_string()];
        let cmd = adapter
            .build_launch_command(&args, "agent-1", Some("team-a"), Some("127.0.0.1:8080"))
            .unwrap();
        let cmd_args: Vec<_> = cmd.get_args().collect();
        assert_eq!(cmd_args, ["--print", "hello"]);
        let envs: std::collections::HashMap<_, _> = cmd.get_envs().collect();
        assert_eq!(envs[std::ffi::OsStr::new("AA_AGENT_ID")], Some(std::ffi::OsStr::new("agent-1")));
        assert_eq!(envs[std::ffi::OsStr::new("AA_TEAM_ID")], Some(std::ffi::OsStr::new("team-a")));
        assert_eq!(envs[std::ffi::OsStr::new("HTTPS_PROXY")], Some(std::ffi::OsStr::new("127.0.0.1:8080")));
    }

    #[test]
    fn build_command_errors_when_binary_missing() {
        let adapter = ClaudeCodeAdapter::with_overrides(Some(PathBuf::from("/no/such/binary")), None);
        let result = adapter.build_launch_command(&[], "agent-1", None, None);
        assert!(matches!(result, Err(AdapterError::ToolNotFound)));
    }

    // ── list_mcp_servers ────────────────────────────────────────────────────

    #[tokio::test]
    async fn list_mcp_servers_returns_empty_when_no_config() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        let adapter =
            ClaudeCodeAdapter::new().with_settings_path_resolver(Box::new(StubSettingsPathResolver(path)));
        let servers = adapter.list_mcp_servers().await.unwrap();
        assert!(servers.is_empty());
    }

    #[tokio::test]
    async fn list_mcp_servers_parses_global_config() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        std::fs::write(
            &path,
            r#"{
                "mcpServers": {
                    "filesystem": {
                        "command": "npx",
                        "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]
                    },
                    "search": {
                        "command": "node",
                        "args": ["search-server.js"]
                    }
                }
            }"#,
        )
        .unwrap();
        let adapter =
            ClaudeCodeAdapter::new().with_settings_path_resolver(Box::new(StubSettingsPathResolver(path)));
        let mut servers = adapter.list_mcp_servers().await.unwrap();
        servers.sort_by(|a, b| a.name.cmp(&b.name));
        assert_eq!(servers.len(), 2);
        assert_eq!(servers[0].name, "filesystem");
        assert_eq!(servers[0].command, "npx");
        assert_eq!(servers[0].args, ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]);
        assert_eq!(servers[1].name, "search");
        assert_eq!(servers[1].command, "node");
        assert_eq!(servers[1].args, ["search-server.js"]);
    }
}
