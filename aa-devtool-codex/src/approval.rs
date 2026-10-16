//! Codex approval-policy mapping from Agent Assembly policy.
//!
//! Provides [`ApprovalLevel`], [`ApprovalPolicy`], and the pure function
//! [`map_policy_to_approval`] that translates a [`PolicyDocument`] into the
//! per-action approval settings Codex's native config accepts.
//!
//! No I/O is performed here — all functions are pure and deterministic.
//!
//! [AAASM-983]: https://lightning-dust-mite.atlassian.net/browse/AAASM-983

use aa_devtool_contract::{PolicyDecision, PolicyDocument};
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
/// This is AA's per-category model; Codex's `approval_policy` key takes one
/// string, produced by [`ApprovalPolicy::as_codex_value`]. Construct via
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

impl ApprovalPolicy {
    /// The `approval_policy` value to write into Codex's `config.toml`.
    ///
    /// Codex's key is a single global string, not a per-category table
    /// (measured against codex-cli 0.160.0: a table is rejected with
    /// "unknown variant `level`", and `untrusted` is "no longer supported";
    /// `on-failure`, `on-request` and `never` load). The four per-category
    /// levels therefore collapse to one value: any category that needs a
    /// prompt or a refusal selects `on-request`, otherwise `on-failure`.
    /// This key only decides when Codex asks; it does not refuse. A refusal
    /// is never written as `never`, and the sandbox mode blocks writes but
    /// not shell or MCP execution (measured: `read-only` still ran
    /// `/bin/sh`), so a shell or MCP deny degrades to "ask" here and must be
    /// enforced by another layer.
    pub fn as_codex_value(&self) -> &'static str {
        let levels = [self.file_writes, self.shell_exec, self.network, self.mcp_calls];
        if levels.iter().any(|l| *l != ApprovalLevel::Auto) {
            "on-request"
        } else {
            "on-failure"
        }
    }
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
    use aa_devtool_contract::{PolicyDecision, PolicyDocument, PolicyRule};

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
            enforcement_mode: aa_devtool_contract::EnforcementMode::default(),
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

    #[test]
    fn approval_policy_is_one_string_codex_0_160_accepts() {
        // Codex loads on-failure / on-request / never; `untrusted` is "no
        // longer supported" and a table is rejected (AAASM-6319).
        let all_auto = ApprovalPolicy::default();
        assert_eq!(all_auto.as_codex_value(), "on-failure");
        for one in [
            ApprovalPolicy {
                file_writes: ApprovalLevel::Prompt,
                ..Default::default()
            },
            ApprovalPolicy {
                shell_exec: ApprovalLevel::Deny,
                ..Default::default()
            },
            ApprovalPolicy {
                network: ApprovalLevel::Prompt,
                ..Default::default()
            },
            ApprovalPolicy {
                mcp_calls: ApprovalLevel::Deny,
                ..Default::default()
            },
        ] {
            assert_eq!(one.as_codex_value(), "on-request", "{one:?}");
        }
    }

    #[test]
    fn approval_value_is_never_a_value_that_disables_asking() {
        let strict = ApprovalPolicy {
            file_writes: ApprovalLevel::Deny,
            shell_exec: ApprovalLevel::Deny,
            network: ApprovalLevel::Deny,
            mcp_calls: ApprovalLevel::Deny,
        };
        assert_ne!(strict.as_codex_value(), "never");
    }
}
