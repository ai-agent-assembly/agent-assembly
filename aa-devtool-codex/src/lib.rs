//! `DevToolAdapter` implementation for the OpenAI Codex CLI.
//!
//! Tracks the F75 Story ([AAASM-202]). This Subtask ([AAASM-971]) lands
//! detection only — `generate_managed_settings`, `apply_settings`, and
//! `build_launch_command` arrive in subsequent Subtasks.
//!
//! [AAASM-202]: https://lightning-dust-mite.atlassian.net/browse/AAASM-202
//! [AAASM-971]: https://lightning-dust-mite.atlassian.net/browse/AAASM-971

#![warn(missing_docs)]

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
