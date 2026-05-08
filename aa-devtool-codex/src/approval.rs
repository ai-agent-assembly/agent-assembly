//! Codex approval-policy mapping from Agent Assembly policy.
//!
//! Provides [`ApprovalLevel`], [`ApprovalPolicy`], and the pure function
//! [`map_policy_to_approval`] that translates a [`PolicyDocument`] into the
//! per-action approval settings Codex's native config accepts.
//!
//! No I/O is performed here — all functions are pure and deterministic.
//!
//! [AAASM-983]: https://lightning-dust-mite.atlassian.net/browse/AAASM-983

use aa_core::policy::{PolicyDecision, PolicyDocument};
use serde::{Deserialize, Serialize};

/// Per-action approval level for the Codex CLI.
///
/// Serializes to Codex's wire format via [`serde`]:
/// - [`Auto`][Self::Auto] → `"auto"`
/// - [`Prompt`][Self::Prompt] → `"prompt"`
/// - [`Deny`][Self::Deny] → `"deny"`
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ApprovalLevel {
    /// Codex performs the action without prompting.
    #[default]
    Auto,
    /// Codex asks the user before performing the action.
    Prompt,
    /// Codex refuses to perform the action entirely.
    Deny,
}

/// Approval policy applied per action category in the Codex CLI.
///
/// Maps directly to Codex's `approval_policy` config key. Construct via
/// [`map_policy_to_approval`]; the default (all `Auto`) is also available
/// through [`Default`].
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ApprovalPolicy {
    /// Approval level for file-write operations (e.g. `FileEdit`, `Write`).
    pub file_writes: ApprovalLevel,
    /// Approval level for shell / Bash execution.
    pub shell_exec: ApprovalLevel,
    /// Approval level for outbound network access.
    pub network: ApprovalLevel,
    /// Approval level for MCP tool calls.
    pub mcp_calls: ApprovalLevel,
}

/// Translate a [`PolicyDocument`] into an [`ApprovalPolicy`] for Codex.
///
/// Resolution per action category (first match wins per category):
/// 1. Any rule whose `action_pattern` matches the category with [`Deny`] → [`ApprovalLevel::Deny`]
/// 2. Any rule whose `action_pattern` matches the category with [`RequireApproval`] → [`ApprovalLevel::Prompt`]
/// 3. No matching rule → [`ApprovalLevel::Auto`]
///
/// Action-pattern matching per category:
/// - `shell_exec`: patterns starting with `"Bash"` or `"shell:"`
/// - `file_writes`: patterns starting with `"FileEdit"`, `"file_edit"`, or `"fs:write"`
/// - `network`:    patterns starting with `"network:"`
/// - `mcp_calls`:  patterns starting with `"mcp:"`
///
/// [`Deny`]: PolicyDecision::Deny
/// [`RequireApproval`]: PolicyDecision::RequireApproval
pub fn map_policy_to_approval(policy: &PolicyDocument) -> ApprovalPolicy {
    ApprovalPolicy {
        shell_exec: map_category(policy, is_shell_pattern),
        file_writes: map_category(policy, is_file_write_pattern),
        network: map_category(policy, is_network_pattern),
        mcp_calls: map_category(policy, is_mcp_pattern),
    }
}

fn map_category(policy: &PolicyDocument, matches: fn(&str) -> bool) -> ApprovalLevel {
    let has_deny = policy
        .rules
        .iter()
        .any(|r| matches(&r.action_pattern) && r.decision == PolicyDecision::Deny);
    if has_deny {
        return ApprovalLevel::Deny;
    }
    let has_prompt = policy
        .rules
        .iter()
        .any(|r| matches(&r.action_pattern) && r.decision == PolicyDecision::RequireApproval);
    if has_prompt {
        return ApprovalLevel::Prompt;
    }
    ApprovalLevel::Auto
}

fn is_shell_pattern(p: &str) -> bool {
    p.starts_with("Bash") || p.starts_with("shell:")
}

fn is_file_write_pattern(p: &str) -> bool {
    p.starts_with("FileEdit") || p.starts_with("file_edit") || p.starts_with("fs:write")
}

fn is_network_pattern(p: &str) -> bool {
    p.starts_with("network:")
}

fn is_mcp_pattern(p: &str) -> bool {
    p.starts_with("mcp:")
}

#[cfg(test)]
mod tests {
    use aa_core::policy::{PolicyDecision, PolicyDocument, PolicyRule};

    use super::*;

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
    fn bash_deny_maps_to_shell_exec_deny() {
        let policy = make_policy(vec![("Bash", PolicyDecision::Deny)]);
        let ap = map_policy_to_approval(&policy);
        assert_eq!(ap.shell_exec, ApprovalLevel::Deny);
    }

    #[test]
    fn file_edit_approval_maps_to_prompt() {
        let policy = make_policy(vec![("FileEdit", PolicyDecision::RequireApproval)]);
        let ap = map_policy_to_approval(&policy);
        assert_eq!(ap.file_writes, ApprovalLevel::Prompt);
    }

    #[test]
    fn unspecified_category_defaults_to_auto() {
        let policy = make_policy(vec![]);
        let ap = map_policy_to_approval(&policy);
        assert_eq!(ap.shell_exec, ApprovalLevel::Auto);
        assert_eq!(ap.file_writes, ApprovalLevel::Auto);
        assert_eq!(ap.network, ApprovalLevel::Auto);
        assert_eq!(ap.mcp_calls, ApprovalLevel::Auto);
    }

    #[test]
    fn combined_settings_roundtrip() {
        let policy = make_policy(vec![
            ("Bash", PolicyDecision::Deny),
            ("FileEdit", PolicyDecision::RequireApproval),
            ("network:evil.io", PolicyDecision::Deny),
        ]);
        let ap = map_policy_to_approval(&policy);

        let json = serde_json::to_string(&ap).expect("serialize");
        let restored: ApprovalPolicy = serde_json::from_str(&json).expect("deserialize");

        assert_eq!(restored.shell_exec, ApprovalLevel::Deny);
        assert_eq!(restored.file_writes, ApprovalLevel::Prompt);
        assert_eq!(restored.network, ApprovalLevel::Deny);
        assert_eq!(restored.mcp_calls, ApprovalLevel::Auto);
    }

    // --- additional edge cases ---

    #[test]
    fn deny_takes_precedence_over_require_approval_in_same_category() {
        let policy = make_policy(vec![
            ("Bash", PolicyDecision::RequireApproval),
            ("Bash", PolicyDecision::Deny),
        ]);
        let ap = map_policy_to_approval(&policy);
        assert_eq!(ap.shell_exec, ApprovalLevel::Deny);
    }

    #[test]
    fn shell_prefix_also_matches_shell_exec_pattern() {
        let policy = make_policy(vec![("shell:exec", PolicyDecision::Deny)]);
        let ap = map_policy_to_approval(&policy);
        assert_eq!(ap.shell_exec, ApprovalLevel::Deny);
    }

    #[test]
    fn fs_write_pattern_maps_to_file_writes() {
        let policy = make_policy(vec![("fs:write", PolicyDecision::RequireApproval)]);
        let ap = map_policy_to_approval(&policy);
        assert_eq!(ap.file_writes, ApprovalLevel::Prompt);
    }

    #[test]
    fn mcp_pattern_maps_to_mcp_calls() {
        let policy = make_policy(vec![("mcp:tool_call", PolicyDecision::Deny)]);
        let ap = map_policy_to_approval(&policy);
        assert_eq!(ap.mcp_calls, ApprovalLevel::Deny);
    }

    #[test]
    fn approval_level_serializes_to_wire_format() {
        assert_eq!(serde_json::to_string(&ApprovalLevel::Auto).unwrap(), r#""auto""#);
        assert_eq!(serde_json::to_string(&ApprovalLevel::Prompt).unwrap(), r#""prompt""#);
        assert_eq!(serde_json::to_string(&ApprovalLevel::Deny).unwrap(), r#""deny""#);
    }
}
