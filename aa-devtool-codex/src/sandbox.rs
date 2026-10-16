//! Codex sandbox-mode mapping from Agent Assembly policy.
//!
//! Provides [`CodexSandboxMode`] and pure functions that translate a
//! [`PolicyDocument`] into the value Codex's `sandbox_mode` key accepts.
//! Agent Assembly keeps its own three-level vocabulary (`full-auto`, `suggest`,
//! `ask`, still accepted in policy overrides); the config file gets one of the
//! three values codex-cli 0.160.0 actually loads (AAASM-6319).
//!
//! No I/O is performed here — all functions are pure and deterministic.
//!
//! [AAASM-978]: https://lightning-dust-mite.atlassian.net/browse/AAASM-978

use aa_devtool_contract::{PolicyDecision, PolicyDocument};
use serde::Serialize;

/// Agent Assembly's three enforcement levels for a Codex install.
///
/// This is AA's own vocabulary, not Codex's. Codex's `sandbox_mode` key only
/// accepts `read-only`, `workspace-write` and `danger-full-access`
/// (measured against codex-cli 0.160.0 with `codex mcp list`; anything else,
/// including the old `full-auto`/`suggest`/`ask` names, makes Codex fail to
/// load its configuration). [`as_codex_value`] is therefore the only thing
/// that may be written to `config.toml`, and [`Serialize`] goes through it.
///
/// The levels keep their strictness order and never reach
/// `danger-full-access`: a permissive policy must not switch the sandbox off.
///
/// [`as_codex_value`]: CodexSandboxMode::as_codex_value
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodexSandboxMode {
    /// Permissive: AA enforcement level `log`. Codex still confines writes to
    /// the workspace (`workspace-write`).
    FullAuto,
    /// AA enforcement level `alert`. Codex gets a read-only sandbox.
    Suggest,
    /// AA enforcement level `enforce`. Codex gets a read-only sandbox; what
    /// separates it from [`Suggest`](CodexSandboxMode::Suggest) is the
    /// approval policy, which is derived separately.
    Ask,
}

impl CodexSandboxMode {
    /// The `sandbox_mode` value to write into Codex's `config.toml`.
    pub fn as_codex_value(self) -> &'static str {
        match self {
            CodexSandboxMode::FullAuto => "workspace-write",
            CodexSandboxMode::Suggest | CodexSandboxMode::Ask => "read-only",
        }
    }
}

impl Serialize for CodexSandboxMode {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_codex_value())
    }
}

/// Action-pattern prefix used in [`PolicyRule`]s to express an explicit
/// Codex sandbox-mode override.
///
/// A rule whose `action_pattern` starts with this prefix takes the form
/// `"dev_tools.codex.sandbox_mode:<mode>"` where `<mode>` is one of
/// `full-auto`, `suggest`, or `ask`. When such a rule is present it wins
/// over the enforcement-level inference, regardless of `decision`.
///
/// [`PolicyRule`]: aa_devtool_contract::PolicyRule
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
    let has_require_approval = policy
        .rules
        .iter()
        .any(|r| r.decision == PolicyDecision::RequireApproval);
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

#[cfg(test)]
mod tests {
    use super::*;
    use aa_devtool_contract::{EnforcementMode, PolicyDecision, PolicyDocument, PolicyRule};

    fn make_policy(rules: Vec<(&str, PolicyDecision)>) -> PolicyDocument {
        PolicyDocument {
            version: 1,
            name: "test".into(),
            rules: rules
                .into_iter()
                .map(|(pat, dec)| PolicyRule {
                    action_pattern: pat.into(),
                    decision: dec,
                })
                .collect(),
            enforcement_mode: EnforcementMode::default(),
        }
    }

    #[test]
    fn log_policy_maps_to_full_auto() {
        let policy = make_policy(vec![("*", PolicyDecision::Allow)]);
        assert_eq!(map_policy_to_sandbox_mode(&policy), CodexSandboxMode::FullAuto);
    }

    #[test]
    fn alert_policy_maps_to_suggest() {
        let policy = make_policy(vec![
            ("fs:read", PolicyDecision::Allow),
            ("fs:write", PolicyDecision::RequireApproval),
        ]);
        assert_eq!(map_policy_to_sandbox_mode(&policy), CodexSandboxMode::Suggest);
    }

    #[test]
    fn enforce_policy_maps_to_ask() {
        let policy = make_policy(vec![
            ("fs:read", PolicyDecision::Allow),
            ("shell:exec", PolicyDecision::Deny),
        ]);
        assert_eq!(map_policy_to_sandbox_mode(&policy), CodexSandboxMode::Ask);
    }

    #[test]
    fn deny_takes_precedence_over_require_approval() {
        let policy = make_policy(vec![
            ("fs:write", PolicyDecision::RequireApproval),
            ("shell:exec", PolicyDecision::Deny),
        ]);
        assert_eq!(map_policy_to_sandbox_mode(&policy), CodexSandboxMode::Ask);
    }

    #[test]
    fn explicit_override_wins() {
        let policy = make_policy(vec![
            ("dev_tools.codex.sandbox_mode:suggest", PolicyDecision::Allow),
            ("shell:exec", PolicyDecision::Deny),
        ]);
        assert_eq!(map_policy_to_sandbox_mode(&policy), CodexSandboxMode::Suggest);
    }

    #[test]
    fn explicit_override_full_auto_wins() {
        let policy = make_policy(vec![
            ("dev_tools.codex.sandbox_mode:full-auto", PolicyDecision::Allow),
            ("shell:exec", PolicyDecision::Deny),
        ]);
        assert_eq!(map_policy_to_sandbox_mode(&policy), CodexSandboxMode::FullAuto);
    }

    #[test]
    fn explicit_override_ask_wins() {
        let policy = make_policy(vec![("dev_tools.codex.sandbox_mode:ask", PolicyDecision::Allow)]);
        assert_eq!(map_policy_to_sandbox_mode(&policy), CodexSandboxMode::Ask);
    }

    #[test]
    fn empty_policy_maps_to_full_auto() {
        let policy = make_policy(vec![]);
        assert_eq!(map_policy_to_sandbox_mode(&policy), CodexSandboxMode::FullAuto);
    }

    #[test]
    fn sandbox_mode_serializes_to_values_codex_0_160_accepts() {
        // codex-cli 0.160.0 loads exactly read-only, workspace-write and
        // danger-full-access; the old full-auto/suggest/ask names make Codex
        // fail to load its config (AAASM-6319).
        assert_eq!(
            serde_json::to_string(&CodexSandboxMode::FullAuto).unwrap(),
            r#""workspace-write""#
        );
        assert_eq!(
            serde_json::to_string(&CodexSandboxMode::Suggest).unwrap(),
            r#""read-only""#
        );
        assert_eq!(serde_json::to_string(&CodexSandboxMode::Ask).unwrap(), r#""read-only""#);
    }

    #[test]
    fn no_level_ever_selects_the_unsandboxed_mode() {
        for mode in [
            CodexSandboxMode::FullAuto,
            CodexSandboxMode::Suggest,
            CodexSandboxMode::Ask,
        ] {
            assert_ne!(mode.as_codex_value(), "danger-full-access", "{mode:?}");
        }
    }
}
