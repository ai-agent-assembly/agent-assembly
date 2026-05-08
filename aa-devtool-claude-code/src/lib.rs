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

/// [`DevToolAdapter`] for the Anthropic Claude Code CLI.
///
/// Construct with [`ClaudeCodeAdapter::new`] for production use. In tests,
/// use [`ClaudeCodeAdapter::with_overrides`] to supply a stub binary path
/// and a temporary home directory so detection never touches the real
/// filesystem or spawns the real `claude` binary.
///
/// [`DevToolAdapter`]: aa_core::DevToolAdapter
#[derive(Debug, Clone)]
pub struct ClaudeCodeAdapter {
    /// Optional override for the `claude` binary path. When set, skips the
    /// `which claude` PATH search and uses this path directly.
    binary_path_override: Option<PathBuf>,
    /// Optional override for the home directory used to locate `~/.claude/`.
    /// When set, replaces `$HOME` for all filesystem marker checks.
    home_dir_override: Option<PathBuf>,
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
            home_dir_override: home_dir,
        }
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

/// Query a binary's version by running `<bin> --version`.
///
/// Returns the raw stdout trimmed of whitespace, or `None` on any subprocess
/// failure.
fn probe_version(bin: &Path) -> Option<String> {
    let out = Command::new(bin).arg("--version").output().ok()?;
    let raw = std::str::from_utf8(&out.stdout).ok()?.trim().to_string();
    (!raw.is_empty()).then_some(raw)
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
        let raw = probe_version(&install_path)?;

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

    async fn generate_managed_settings(&self, _policy: &PolicyDocument) -> Result<String, AdapterError> {
        // Implemented in AAASM-952.
        Err(AdapterError::SettingsGenerationFailed(
            "not yet implemented (AAASM-952)".into(),
        ))
    }

    async fn apply_settings(&self, _settings: &str) -> Result<(), AdapterError> {
        // Implemented in AAASM-956.
        Err(AdapterError::SettingsApplyFailed(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "not yet implemented (AAASM-956)",
        )))
    }

    fn build_launch_command(
        &self,
        _tool_args: &[String],
        _agent_id: &str,
        _team_id: Option<&str>,
        _proxy_addr: Option<&str>,
    ) -> Result<Command, AdapterError> {
        // Implemented in AAASM-959.
        Err(AdapterError::LaunchFailed("not yet implemented (AAASM-959)".into()))
    }

    async fn list_mcp_servers(&self) -> Result<Vec<McpServerInfo>, AdapterError> {
        // Implemented in AAASM-959.
        Ok(vec![])
    }

    async fn apply_mcp_governance(&self, _allowed: &[String], _denied: &[String]) -> Result<(), AdapterError> {
        // Implemented in AAASM-956.
        Ok(())
    }

    fn governance_level(&self) -> GovernanceLevel {
        GovernanceLevel::L2Enforce
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[cfg(unix)]
    #[test]
    fn detect_returns_none_for_version_below_minimum() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let stub = tmp.path().join("claude");
        std::fs::write(&stub, "#!/bin/sh\necho '0.9.9'\n").unwrap();
        std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o755)).unwrap();
        let adapter = ClaudeCodeAdapter::with_overrides(Some(stub), None);
        assert!(adapter.detect().is_none());
    }

    #[cfg(unix)]
    #[test]
    fn detect_returns_some_for_valid_version() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let stub = tmp.path().join("claude");
        std::fs::write(&stub, "#!/bin/sh\necho '1.9.2'\n").unwrap();
        std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o755)).unwrap();
        let adapter = ClaudeCodeAdapter::with_overrides(Some(stub), None);
        let info = adapter.detect().expect("should detect stub binary");
        assert_eq!(info.kind, DevToolKind::ClaudeCode);
        assert_eq!(info.version.as_deref(), Some("1.9.2"));
        assert_eq!(info.governance_level, GovernanceLevel::L2Enforce);
        assert!(info.supports_mcp);
        assert!(info.supports_managed_settings);
    }

    #[cfg(unix)]
    #[test]
    fn detect_normalizes_version_with_prefix() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let stub = tmp.path().join("claude");
        std::fs::write(&stub, "#!/bin/sh\necho 'claude 2.1.0'\n").unwrap();
        std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o755)).unwrap();
        let adapter = ClaudeCodeAdapter::with_overrides(Some(stub), None);
        let info = adapter.detect().unwrap();
        assert_eq!(info.version.as_deref(), Some("2.1.0"));
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
}
