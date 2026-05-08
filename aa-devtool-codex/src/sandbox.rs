//! Codex sandbox-mode mapping from Agent Assembly policy.
//!
//! Provides [`CodexSandboxMode`] and pure functions that translate a
//! [`PolicyDocument`] into the three values Codex's native config accepts:
//! `full-auto`, `suggest`, and `ask`.
//!
//! No I/O is performed here — all functions are pure and deterministic.
//!
//! [AAASM-978]: https://lightning-dust-mite.atlassian.net/browse/AAASM-978

use serde::Serialize;

/// Codex sandbox mode, mapping to Codex's `sandbox_mode` config key.
///
/// Serializes to Codex's wire format via [`serde::Serialize`]:
/// - [`FullAuto`] → `"full-auto"`
/// - [`Suggest`] → `"suggest"`
/// - [`Ask`] → `"ask"`
///
/// [`FullAuto`]: CodexSandboxMode::FullAuto
/// [`Suggest`]: CodexSandboxMode::Suggest
/// [`Ask`]: CodexSandboxMode::Ask
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CodexSandboxMode {
    /// Permissive mode — Codex runs commands without prompting.
    /// Corresponds to AA enforcement level `log`.
    FullAuto,
    /// Suggestion mode — Codex proposes commands and waits for confirmation.
    /// Corresponds to AA enforcement level `alert`.
    Suggest,
    /// Approval mode — Codex requires explicit approval before each command.
    /// Corresponds to AA enforcement level `enforce`.
    Ask,
}
