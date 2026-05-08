//! `DevToolAdapter` implementation for the OpenAI Codex CLI.
//!
//! Tracks the F75 Story ([AAASM-202]).
//! * Detection — [`AAASM-971`]
//! * Sandbox-mode mapping — [`AAASM-978`] (this Subtask)
//! * Approval-policy alignment — `AAASM-983` (subsequent Subtask)
//! * `apply_settings` / `build_launch_command` — `AAASM-988` (subsequent Subtask)
//!
//! [AAASM-202]: https://lightning-dust-mite.atlassian.net/browse/AAASM-202
//! [`AAASM-971`]: https://lightning-dust-mite.atlassian.net/browse/AAASM-971
//! [`AAASM-978`]: https://lightning-dust-mite.atlassian.net/browse/AAASM-978

#![warn(missing_docs)]

use std::path::{Path, PathBuf};
use std::process::Command;

use aa_core::{AdapterError, DevToolAdapter, DevToolInfo, DevToolKind, GovernanceLevel, McpServerInfo, PolicyDocument};
use async_trait::async_trait;

mod approval;
mod sandbox;
use approval::map_policy_to_approval;
use sandbox::{map_policy_to_sandbox_mode, network_allow_list, network_block_list};

/// Hook a [`CodexAdapter`] uses to read the Codex binary's reported
/// version.
///
/// Concrete production implementation: [`CommandVersionProbe`], which
/// runs `<bin> --version` via [`std::process::Command`]. Tests inject a
/// deterministic stub instead so they don't depend on a real Codex
/// install.
pub trait VersionProbe: Send + Sync {
    /// Run the binary's "report version" entry point and return the
    /// parsed semver string (e.g. `"0.125.0"`), or `None` when the
    /// probe failed for any reason (binary missing, non-zero exit,
    /// unparseable output).
    fn probe_version(&self, bin: &Path) -> Option<String>;
}

/// Hook a [`CodexAdapter`] uses to discover the Codex binary on the host.
///
/// Two strategies are exposed independently so tests can verify the
/// "PATH succeeds, npm-fallback never consulted" and "PATH fails, npm-
/// fallback wins" cases without spawning real subprocesses or scrubbing
/// `$PATH`.
pub trait BinaryLocator: Send + Sync {
    /// Look up the Codex binary on `$PATH` (the primary discovery path).
    /// Returns the absolute install path or `None` if not on `$PATH`.
    fn locate_via_path(&self) -> Option<PathBuf>;

    /// Look up the Codex binary inside the npm-global install directory
    /// (the fallback discovery path). Returns the absolute install path
    /// or `None` when npm is not installed, `npm root -g` fails, or the
    /// expected `<npm-root>/@openai/codex/bin/codex` file does not
    /// exist.
    fn locate_via_npm_global(&self) -> Option<PathBuf>;
}

/// Production [`BinaryLocator`] consulting `$PATH` (via the `which`
/// crate) and the npm-global install directory (via `npm root -g`).
///
/// The npm fallback is only invoked when the `which` lookup misses,
/// matching the AAASM-971 AC's "fallback: check npm global install"
/// contract.
#[derive(Debug, Default, Clone, Copy)]
pub struct DefaultBinaryLocator;

impl BinaryLocator for DefaultBinaryLocator {
    fn locate_via_path(&self) -> Option<PathBuf> {
        which::which(CODEX_BIN).ok()
    }

    fn locate_via_npm_global(&self) -> Option<PathBuf> {
        let output = Command::new("npm").args(["root", "-g"]).output().ok()?;
        if !output.status.success() {
            return None;
        }
        let root = String::from_utf8(output.stdout).ok()?.trim().to_string();
        let candidate = PathBuf::from(root)
            .join(NPM_PACKAGE_NAME)
            .join(NPM_PACKAGE_BIN_RELATIVE);
        if candidate.is_file() {
            Some(candidate)
        } else {
            None
        }
    }
}

/// Production [`VersionProbe`] backed by [`std::process::Command`]. Runs
/// `<bin> --version`, captures stdout, and parses the version string via
/// [`parse_codex_version`].
///
/// Returns `None` when the binary cannot be spawned, exits non-zero, or
/// emits output the parser does not recognise. Detection treats `None`
/// as "version unknown" rather than "binary missing" so a Codex install
/// whose `--version` output the parser can't handle still produces a
/// `DevToolInfo` (with `version: None`).
#[derive(Debug, Default, Clone, Copy)]
pub struct CommandVersionProbe;

impl VersionProbe for CommandVersionProbe {
    fn probe_version(&self, bin: &Path) -> Option<String> {
        let output = Command::new(bin).arg("--version").output().ok()?;
        if !output.status.success() {
            return None;
        }
        let stdout = String::from_utf8(output.stdout).ok()?;
        parse_codex_version(&stdout)
    }
}

/// Extract a semver string from the Codex CLI's `--version` output.
///
/// Codex 0.34.0+ prints output like `codex-cli 0.125.0`; older 0.x
/// builds emit just the bare version (`0.5.1`). The parser is
/// permissive: it scans the first line for the first whitespace-
/// separated token that starts with an ASCII digit and returns it
/// verbatim. Returns `None` when the input is empty or no digit-leading
/// token is present.
pub fn parse_codex_version(output: &str) -> Option<String> {
    let line = output.lines().next()?.trim();
    line.split_whitespace()
        .find(|tok| tok.chars().next().is_some_and(|c| c.is_ascii_digit()))
        .map(|tok| tok.to_string())
}

/// Filename of the Codex CLI binary as installed by `npm install -g @openai/codex`
/// or by the standalone Homebrew formula.
pub const CODEX_BIN: &str = "codex";

/// npm package name shipping the Codex CLI. Consulted by the npm-global
/// fallback in [`DefaultBinaryLocator::locate_via_npm_global`].
pub const NPM_PACKAGE_NAME: &str = "@openai/codex";

/// Path of the Codex executable inside the npm package directory,
/// relative to `npm root -g`/`@openai/codex`.
pub const NPM_PACKAGE_BIN_RELATIVE: &str = "bin/codex";

/// `DevToolAdapter` for the OpenAI Codex CLI.
///
/// Construct via [`CodexAdapter::default`] for production use (uses the
/// shipped [`DefaultBinaryLocator`] and [`CommandVersionProbe`]); call
/// [`CodexAdapter::new`] in tests to inject stub implementations of the
/// two hooks.
pub struct CodexAdapter {
    locator: Box<dyn BinaryLocator>,
    probe: Box<dyn VersionProbe>,
    /// Overrides `$HOME` for config-path resolution. `None` → read `$HOME`.
    /// Set via [`Self::with_home_dir`]; intended for integration tests only.
    home_dir_override: Option<PathBuf>,
}

impl CodexAdapter {
    /// Build an adapter with custom hook implementations. Only useful
    /// in tests; production code should use [`Self::default`].
    pub fn new(locator: Box<dyn BinaryLocator>, probe: Box<dyn VersionProbe>) -> Self {
        Self {
            locator,
            probe,
            home_dir_override: None,
        }
    }

    /// Override the home directory used to locate `~/.codex/config.json`.
    /// Intended for integration tests; production code uses `$HOME`.
    #[doc(hidden)]
    pub fn with_home_dir(mut self, path: PathBuf) -> Self {
        self.home_dir_override = Some(path);
        self
    }

    fn home_dir(&self) -> Option<PathBuf> {
        self.home_dir_override
            .clone()
            .or_else(|| std::env::var_os("HOME").map(PathBuf::from))
    }
}

impl Default for CodexAdapter {
    fn default() -> Self {
        Self {
            locator: Box::new(DefaultBinaryLocator),
            probe: Box::new(CommandVersionProbe),
            home_dir_override: None,
        }
    }
}

impl std::fmt::Debug for CodexAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The trait-object hooks aren't `Debug`; surface the type name
        // instead so logs aren't cluttered with implementation pointers.
        f.debug_struct("CodexAdapter").finish_non_exhaustive()
    }
}

#[async_trait]
impl DevToolAdapter for CodexAdapter {
    fn detect(&self) -> Option<DevToolInfo> {
        let install_path = self
            .locator
            .locate_via_path()
            .or_else(|| self.locator.locate_via_npm_global())?;
        let version = self.probe.probe_version(&install_path);
        Some(DevToolInfo {
            kind: DevToolKind::Codex,
            version,
            install_path,
            governance_level: GovernanceLevel::L2Enforce,
            supports_mcp: false,
            supports_managed_settings: true,
        })
    }

    async fn generate_managed_settings(&self, policy: &PolicyDocument) -> Result<String, AdapterError> {
        let sandbox_mode = map_policy_to_sandbox_mode(policy);
        let allowed_domains = network_allow_list(policy);
        let blocked_domains = network_block_list(policy);
        let approval_policy = map_policy_to_approval(policy);

        let settings = serde_json::json!({
            "sandbox_mode": sandbox_mode,
            "allowed_domains": allowed_domains,
            "blocked_domains": blocked_domains,
            "approval_policy": approval_policy,
        });
        serde_json::to_string_pretty(&settings).map_err(|e| AdapterError::Serde(e.to_string()))
    }

    async fn apply_settings(&self, settings: &str) -> Result<(), AdapterError> {
        let home = self.home_dir().ok_or_else(|| {
            AdapterError::SettingsApplyFailed(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "HOME directory not found",
            ))
        })?;
        let config_path = home.join(".codex").join("config.json");

        // Parse incoming AA-managed settings.
        let new_val: serde_json::Value =
            serde_json::from_str(settings).map_err(|e| AdapterError::Serde(e.to_string()))?;

        // Load existing config (if any) so user-managed keys are preserved.
        let mut merged: serde_json::Map<String, serde_json::Value> = if config_path.exists() {
            let raw = std::fs::read_to_string(&config_path).map_err(AdapterError::SettingsApplyFailed)?;
            serde_json::from_str::<serde_json::Value>(&raw)
                .ok()
                .and_then(|v| match v {
                    serde_json::Value::Object(m) => Some(m),
                    _ => None,
                })
                .unwrap_or_default()
        } else {
            serde_json::Map::new()
        };

        // AA-managed keys win; user-managed keys not present in `settings` survive.
        if let serde_json::Value::Object(new_map) = new_val {
            merged.extend(new_map);
        }

        let content = serde_json::to_string_pretty(&merged).map_err(|e| AdapterError::Serde(e.to_string()))?;

        // Ensure ~/.codex/ exists.
        if let Some(parent) = config_path.parent() {
            std::fs::create_dir_all(parent).map_err(AdapterError::SettingsApplyFailed)?;
        }

        // Atomic write: write to a sibling tmp file then rename.
        let tmp_path = config_path.with_extension("tmp");
        std::fs::write(&tmp_path, content.as_bytes()).map_err(AdapterError::SettingsApplyFailed)?;
        std::fs::rename(&tmp_path, &config_path).map_err(AdapterError::SettingsApplyFailed)?;

        Ok(())
    }

    fn build_launch_command(
        &self,
        tool_args: &[String],
        agent_id: &str,
        team_id: Option<&str>,
        proxy_addr: Option<&str>,
    ) -> Result<Command, AdapterError> {
        let bin = self
            .locator
            .locate_via_path()
            .or_else(|| self.locator.locate_via_npm_global())
            .ok_or_else(|| AdapterError::LaunchFailed("codex binary not found on PATH or npm global".into()))?;

        let mut cmd = Command::new(bin);
        cmd.args(tool_args);
        cmd.env("AA_AGENT_ID", agent_id);
        if let Some(tid) = team_id {
            cmd.env("AA_TEAM_ID", tid);
        }
        if let Some(proxy) = proxy_addr {
            cmd.env("HTTPS_PROXY", proxy);
        }
        Ok(cmd)
    }

    async fn list_mcp_servers(&self) -> Result<Vec<McpServerInfo>, AdapterError> {
        // Codex does not expose an MCP server list (DevToolInfo::supports_mcp == false);
        // the trait contract for that case is to return an empty Vec.
        Ok(Vec::new())
    }

    async fn apply_mcp_governance(&self, _allowed: &[String], _denied: &[String]) -> Result<(), AdapterError> {
        // Codex does not expose MCP governance; the trait contract for tools
        // without MCP support is to return Ok(()) without performing any work.
        Ok(())
    }

    fn governance_level(&self) -> GovernanceLevel {
        GovernanceLevel::L2Enforce
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Stub locator returning canned PATH / npm-fallback results so
    /// `detect()` tests don't depend on a real Codex install.
    struct StubLocator {
        path_result: Option<PathBuf>,
        npm_result: Option<PathBuf>,
    }

    impl BinaryLocator for StubLocator {
        fn locate_via_path(&self) -> Option<PathBuf> {
            self.path_result.clone()
        }
        fn locate_via_npm_global(&self) -> Option<PathBuf> {
            self.npm_result.clone()
        }
    }

    /// Stub probe returning a canned version string.
    struct StubProbe(Option<String>);

    impl VersionProbe for StubProbe {
        fn probe_version(&self, _bin: &Path) -> Option<String> {
            self.0.clone()
        }
    }

    fn adapter(path_result: Option<PathBuf>, npm_result: Option<PathBuf>, version: Option<String>) -> CodexAdapter {
        CodexAdapter::new(
            Box::new(StubLocator {
                path_result,
                npm_result,
            }),
            Box::new(StubProbe(version)),
        )
    }

    #[test]
    fn detect_returns_none_when_locator_finds_nothing() {
        assert!(adapter(None, None, None).detect().is_none());
    }

    #[test]
    fn detect_finds_via_path_with_full_devtool_info() {
        let path = PathBuf::from("/usr/local/bin/codex");
        let info = adapter(Some(path.clone()), None, Some("0.125.0".into()))
            .detect()
            .expect("PATH hit should produce DevToolInfo");
        assert_eq!(info.kind, DevToolKind::Codex);
        assert_eq!(info.install_path, path);
        assert_eq!(info.version.as_deref(), Some("0.125.0"));
        assert_eq!(info.governance_level, GovernanceLevel::L2Enforce);
        assert!(info.supports_managed_settings);
        assert!(!info.supports_mcp);
    }

    #[test]
    fn detect_falls_back_to_npm_global_when_path_misses() {
        let path = PathBuf::from("/opt/npm/global/@openai/codex/bin/codex");
        let info = adapter(None, Some(path.clone()), Some("0.34.0".into()))
            .detect()
            .expect("npm fallback should produce DevToolInfo");
        assert_eq!(info.install_path, path);
        assert_eq!(info.version.as_deref(), Some("0.34.0"));
    }

    #[test]
    fn detect_handles_unknown_version() {
        let path = PathBuf::from("/usr/local/bin/codex");
        let info = adapter(Some(path.clone()), None, None)
            .detect()
            .expect("unparseable version is not a detection failure");
        assert_eq!(info.install_path, path);
        assert!(info.version.is_none());
    }

    #[test]
    fn parse_version_handles_codex_cli_prefix() {
        assert_eq!(parse_codex_version("codex-cli 0.125.0\n").as_deref(), Some("0.125.0"));
    }

    #[test]
    fn parse_version_handles_bare_semver() {
        assert_eq!(parse_codex_version("0.5.1").as_deref(), Some("0.5.1"));
    }

    #[test]
    fn parse_version_handles_arbitrary_prefix() {
        assert_eq!(
            parse_codex_version("Codex CLI version 0.34.0").as_deref(),
            Some("0.34.0")
        );
    }

    #[test]
    fn parse_version_returns_none_for_no_digit_token() {
        assert!(parse_codex_version("").is_none());
        assert!(parse_codex_version("not a version").is_none());
    }

    #[test]
    fn governance_level_is_l2_enforce() {
        assert_eq!(CodexAdapter::default().governance_level(), GovernanceLevel::L2Enforce);
    }

    #[test]
    fn debug_format_does_not_expose_internals() {
        let a = CodexAdapter::default();
        let s = format!("{a:?}");
        assert!(s.contains("CodexAdapter"));
    }

    // --- Production-implementation smoke tests ---
    //
    // These tests exercise DefaultBinaryLocator and CommandVersionProbe through
    // their real code paths without requiring Codex or npm to be installed on
    // the CI runner.  A missing binary is a valid result (None / non-zero exit)
    // — the tests only assert that no panic occurs.

    #[test]
    fn default_locator_path_lookup_does_not_panic() {
        let _ = DefaultBinaryLocator.locate_via_path();
    }

    #[test]
    fn default_locator_npm_global_lookup_does_not_panic() {
        let _ = DefaultBinaryLocator.locate_via_npm_global();
    }

    #[test]
    fn command_version_probe_returns_none_for_nonexistent_binary() {
        let result = CommandVersionProbe.probe_version(Path::new("/nonexistent/__codex_test__"));
        assert!(result.is_none());
    }
}
