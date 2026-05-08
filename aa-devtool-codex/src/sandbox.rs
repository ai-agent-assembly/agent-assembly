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

/// Action-pattern prefix that marks a network-domain rule.
///
/// Rules whose `action_pattern` starts with `"network:"` carry a domain
/// (or glob) immediately after the colon. The domain is extracted into
/// the allow list when `decision` is [`Allow`], or into the block list
/// when `decision` is [`Deny`].
///
/// [`Allow`]: PolicyDecision::Allow
/// [`Deny`]: PolicyDecision::Deny
const NETWORK_PREFIX: &str = "network:";

/// Extract network domains from policy rules that should be **allowed**.
///
/// Returns every domain (or glob) `D` where a rule with
/// `action_pattern = "network:<D>"` and `decision = Allow` exists.
pub fn network_allow_list(policy: &PolicyDocument) -> Vec<String> {
    policy
        .rules
        .iter()
        .filter(|r| r.action_pattern.starts_with(NETWORK_PREFIX) && r.decision == PolicyDecision::Allow)
        .map(|r| r.action_pattern[NETWORK_PREFIX.len()..].to_string())
        .collect()
}

/// Extract network domains from policy rules that should be **blocked**.
///
/// Returns every domain (or glob) `D` where a rule with
/// `action_pattern = "network:<D>"` and `decision = Deny` exists.
pub fn network_block_list(policy: &PolicyDocument) -> Vec<String> {
    policy
        .rules
        .iter()
        .filter(|r| r.action_pattern.starts_with(NETWORK_PREFIX) && r.decision == PolicyDecision::Deny)
        .map(|r| r.action_pattern[NETWORK_PREFIX.len()..].to_string())
        .collect()
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
    use aa_core::policy::{PolicyDecision, PolicyDocument, PolicyRule};

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
    fn network_allow_list_extracted() {
        let policy = make_policy(vec![
            ("network:api.openai.com", PolicyDecision::Allow),
            ("network:evil.example.com", PolicyDecision::Deny),
            ("network:cdn.example.com", PolicyDecision::Allow),
            ("fs:read", PolicyDecision::Allow),
        ]);
        let mut allow = network_allow_list(&policy);
        allow.sort();
        assert_eq!(allow, vec!["api.openai.com", "cdn.example.com"]);
    }

    #[test]
    fn network_block_list_extracted() {
        let policy = make_policy(vec![
            ("network:api.openai.com", PolicyDecision::Allow),
            ("network:evil.example.com", PolicyDecision::Deny),
            ("network:malware.io", PolicyDecision::Deny),
        ]);
        let mut block = network_block_list(&policy);
        block.sort();
        assert_eq!(block, vec!["evil.example.com", "malware.io"]);
    }

    #[test]
    fn empty_policy_maps_to_full_auto() {
        let policy = make_policy(vec![]);
        assert_eq!(map_policy_to_sandbox_mode(&policy), CodexSandboxMode::FullAuto);
    }

    #[test]
    fn sandbox_mode_serializes_to_wire_format() {
        assert_eq!(
            serde_json::to_string(&CodexSandboxMode::FullAuto).unwrap(),
            r#""full-auto""#
        );
        assert_eq!(
            serde_json::to_string(&CodexSandboxMode::Suggest).unwrap(),
            r#""suggest""#
        );
        assert_eq!(serde_json::to_string(&CodexSandboxMode::Ask).unwrap(), r#""ask""#);
    }

    #[test]
    fn generate_managed_settings_snapshot() {
        let policy = make_policy(vec![
            ("shell:exec", PolicyDecision::Deny),
            ("network:api.openai.com", PolicyDecision::Allow),
            ("network:evil.io", PolicyDecision::Deny),
        ]);
        let sandbox_mode = map_policy_to_sandbox_mode(&policy);
        let allowed = network_allow_list(&policy);
        let blocked = network_block_list(&policy);
        let settings = serde_json::json!({
            "sandbox_mode": sandbox_mode,
            "allowed_domains": allowed,
            "blocked_domains": blocked,
        });
        let json = serde_json::to_string_pretty(&settings).unwrap();
        assert!(json.contains(r#""sandbox_mode": "ask""#));
        assert!(json.contains("api.openai.com"));
        assert!(json.contains("evil.io"));
    }
}
