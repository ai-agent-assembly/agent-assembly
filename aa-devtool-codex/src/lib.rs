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
