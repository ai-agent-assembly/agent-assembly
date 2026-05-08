//! Codex sandbox-mode mapping from Agent Assembly policy.
//!
//! Provides [`CodexSandboxMode`] and pure functions that translate a
//! [`PolicyDocument`] into the three values Codex's native config accepts:
//! `full-auto`, `suggest`, and `ask`.
//!
//! No I/O is performed here — all functions are pure and deterministic.
//!
//! [AAASM-978]: https://lightning-dust-mite.atlassian.net/browse/AAASM-978

use aa_core::policy::{PolicyDecision, PolicyDocument};
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

/// Action-pattern prefix used in [`PolicyRule`]s to express an explicit
/// Codex sandbox-mode override.
///
/// A rule whose `action_pattern` starts with this prefix takes the form
/// `"dev_tools.codex.sandbox_mode:<mode>"` where `<mode>` is one of
/// `full-auto`, `suggest`, or `ask`. When such a rule is present it wins
/// over the enforcement-level inference, regardless of `decision`.
///
/// [`PolicyRule`]: aa_core::policy::PolicyRule
const CODEX_SANDBOX_OVERRIDE_PREFIX: &str = "dev_tools.codex.sandbox_mode:";

/// Translate a [`PolicyDocument`] into the [`CodexSandboxMode`] Codex
/// should use.
///
/// Resolution order (first match wins):
/// 1. A rule whose `action_pattern` is `"dev_tools.codex.sandbox_mode:<mode>"`
///    — explicit per-tool override, wins regardless of other rules.
/// 2. Most-restrictive [`PolicyDecision`] across all remaining rules:
///    - Any [`Deny`] → [`Ask`]
///    - Any [`RequireApproval`] (and no `Deny`) → [`Suggest`]
///    - All [`Allow`] → [`FullAuto`]
///
/// [`Deny`]: PolicyDecision::Deny
/// [`RequireApproval`]: PolicyDecision::RequireApproval
/// [`Allow`]: PolicyDecision::Allow
pub fn map_policy_to_sandbox_mode(policy: &PolicyDocument) -> CodexSandboxMode {
    if let Some(mode) = find_sandbox_override(policy) {
        return mode;
    }
    let has_deny = policy.rules.iter().any(|r| r.decision == PolicyDecision::Deny);
    if has_deny {
        return CodexSandboxMode::Ask;
    }
    let has_require_approval = policy.rules.iter().any(|r| r.decision == PolicyDecision::RequireApproval);
    if has_require_approval {
        return CodexSandboxMode::Suggest;
    }
    CodexSandboxMode::FullAuto
}

/// Scan `policy.rules` for a `dev_tools.codex.sandbox_mode:<mode>` override.
///
/// Returns `Some(CodexSandboxMode)` when a matching rule is found, `None`
/// otherwise. The `decision` field of the override rule is intentionally
/// ignored — only the `action_pattern` suffix encodes the desired mode.
fn find_sandbox_override(policy: &PolicyDocument) -> Option<CodexSandboxMode> {
    policy.rules.iter().find_map(|r| {
        let suffix = r.action_pattern.strip_prefix(CODEX_SANDBOX_OVERRIDE_PREFIX)?;
        match suffix {
            "full-auto" => Some(CodexSandboxMode::FullAuto),
            "suggest" => Some(CodexSandboxMode::Suggest),
            "ask" => Some(CodexSandboxMode::Ask),
            _ => None,
        }
    })
}
