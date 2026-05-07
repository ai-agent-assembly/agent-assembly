//! `DevToolAdapter` implementation for the OpenAI Codex CLI.
//!
//! Tracks the F75 Story ([AAASM-202]). This Subtask ([AAASM-971]) lands
//! detection only — `generate_managed_settings`, `apply_settings`, and
//! `build_launch_command` arrive in subsequent Subtasks.
//!
//! [AAASM-202]: https://lightning-dust-mite.atlassian.net/browse/AAASM-202
//! [AAASM-971]: https://lightning-dust-mite.atlassian.net/browse/AAASM-971

#![warn(missing_docs)]

use std::path::Path;
use std::process::Command;

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

/// Placeholder; the real `CodexAdapter` is added in subsequent commits
/// in this same Subtask.
pub struct CodexAdapter;
