//! Deterministic lowering of the canonical [`PolicyDocument`] into the flat
//! rule set the eBPF maps consume (AAASM-3608).
//!
//! The kernel layer is *generated from* the same policy the gateway enforces,
//! never hand-maintained — this is the mechanism behind "one policy source →
//! gateway + eBPF rules with no detectable enforcement gap". The privileged
//! loader daemon (AAASM-3603/3604) pushes the produced [`EbpfRuleSet`] into the
//! `PATH_BLOCKLIST` / `PATH_ALLOWLIST` BPF maps over the control channel.
//!
//! # What is enforceable in-kernel vs L7-only
//!
//! The eBPF probes match on **filesystem paths** and (where wired) **egress
//! hosts**. The lowering therefore covers exactly:
//!
//! - **Filesystem path rules** derived from `tools.*.requires_approval_if`
//!   predicates of the form `path starts_with "<prefix>"` (each becomes a
//!   [`PathVerdict::Deny`] [`PathRule`]) and from a capability `file_write`
//!   deny (which seeds the well-known sensitive-path deny defaults).
//! - **Egress allowlist** copied verbatim from `network.allowlist`.
//!
//! Everything else is explicitly **L7-only** and documented in
//! [`L7_ONLY_DIMENSIONS`] so the cross-layer consistency test (AAASM-3609) can
//! assert the gap is intentional and reviewed, never silent:
//!
//! - Budget / spend limits (`budget`)
//! - Schedule / active-hours (`schedule`)
//! - Credential / PII scanning + redaction (`data`)
//! - Per-tool rate limits (`tools.*.limit_per_hour`)
//! - Non-path CEL predicates (`url contains`, `args.*`, `tool_result.*`)
//! - Capability categories with no path/host projection (`agent_spawn`,
//!   `model:*`, `mcp_tool:*`, `network_inbound`, `terminal_exec`)

use super::capability::Capability;
use super::document::PolicyDocument;

/// Policy dimensions that are structurally **not** enforceable by the eBPF
/// path/egress probes and are therefore enforced only at L7 by the gateway.
///
/// The cross-layer consistency test asserts every divergence between the two
/// layers falls under one of these documented carve-outs.
pub const L7_ONLY_DIMENSIONS: &[&str] = &[
    "budget",
    "schedule",
    "data.credential_scan",
    "tools.limit_per_hour",
    "tools.non_path_predicates",
    "capability.agent_spawn",
    "capability.model",
    "capability.mcp_tool",
    "capability.network_inbound",
    "capability.terminal_exec",
];

/// Whether matching a path rule allows or denies the operation in-kernel.
///
/// Mirrors `aa_ebpf::maps::PathVerdict`; kept here so the leaf crate has no
/// dependency on `aa-ebpf` (the dependency points the other way — the loader
/// daemon consumes this crate).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum PathVerdict {
    /// The path is allowed — no policy violation.
    Allow,
    /// The path is blocked — triggers a policy violation event.
    Deny,
}

/// A single lowered filesystem path rule destined for a BPF path map.
///
/// `pattern` is a path prefix (e.g. `/etc`); the kernel probe flags any access
/// whose path starts with it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PathRule {
    /// Path prefix to match.
    pub pattern: String,
    /// Verdict applied on match.
    pub verdict: PathVerdict,
}

/// The flat rule set produced by [`lower_to_ebpf`], consumed by the loader
/// daemon's map-update path.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct EbpfRuleSet {
    /// Filesystem path rules for `PATH_BLOCKLIST` / `PATH_ALLOWLIST`.
    pub path_rules: Vec<PathRule>,
    /// Egress host allowlist (empty means "no egress restriction").
    pub egress_allowlist: Vec<String>,
}

impl EbpfRuleSet {
    /// Convenience: the deny path patterns, in order.
    pub fn deny_paths(&self) -> impl Iterator<Item = &str> {
        self.path_rules
            .iter()
            .filter(|r| r.verdict == PathVerdict::Deny)
            .map(|r| r.pattern.as_str())
    }
}

/// Well-known sensitive paths denied in-kernel whenever the policy denies the
/// `file_write` capability. These mirror the kernel probe's sensitive-path
/// defaults so a "deny file_write" floor is reflected at the kernel boundary,
/// not just at L7.
const SENSITIVE_WRITE_DENY_DEFAULTS: &[&str] = &["/etc", "/root/.ssh", "/var/run/secrets"];

/// Lower a canonical [`PolicyDocument`] to its [`EbpfRuleSet`].
///
/// Deterministic and pure: the same document always lowers to the same rule
/// set (path rules are de-duplicated and order-stable).
pub fn lower_to_ebpf(doc: &PolicyDocument) -> EbpfRuleSet {
    let mut path_rules: Vec<PathRule> = Vec::new();

    // 1. Capability `file_write` deny → seed the sensitive-path deny defaults.
    let denies_file_write = doc
        .capabilities
        .as_ref()
        .map(|c| c.deny.contains(&Capability::FileWrite))
        .unwrap_or(false);
    if denies_file_write {
        for prefix in SENSITIVE_WRITE_DENY_DEFAULTS {
            push_unique(
                &mut path_rules,
                PathRule {
                    pattern: (*prefix).to_string(),
                    verdict: PathVerdict::Deny,
                },
            );
        }
    }

    // 2. Tool `requires_approval_if` path predicates → explicit deny rules.
    for tool in &doc.tools {
        if let Some(expr) = &tool.requires_approval_if {
            for prefix in extract_path_prefixes(expr) {
                push_unique(
                    &mut path_rules,
                    PathRule {
                        pattern: prefix,
                        verdict: PathVerdict::Deny,
                    },
                );
            }
        }
    }

    EbpfRuleSet {
        path_rules,
        egress_allowlist: doc.egress_allowlist().to_vec(),
    }
}

/// Push a rule only if no rule with the same pattern+verdict already exists,
/// preserving insertion order for determinism.
fn push_unique(rules: &mut Vec<PathRule>, rule: PathRule) {
    if !rules.contains(&rule) {
        rules.push(rule);
    }
}

/// Extract path prefixes from a `requires_approval_if` predicate of the form
/// `path starts_with "<prefix>"` (case-sensitive on the operator). Returns all
/// matches in the expression so compound `… AND path starts_with "…"` clauses
/// are covered. Non-path predicates yield nothing (they are L7-only).
fn extract_path_prefixes(expr: &str) -> Vec<String> {
    const NEEDLE: &str = "path starts_with";
    let mut out = Vec::new();
    let mut rest = expr;
    while let Some(idx) = rest.find(NEEDLE) {
        let after = &rest[idx + NEEDLE.len()..];
        if let Some(prefix) = first_quoted(after) {
            out.push(prefix);
        }
        rest = after;
    }
    out
}

/// Return the contents of the first double-quoted literal in `s`, if any.
fn first_quoted(s: &str) -> Option<String> {
    let start = s.find('"')? + 1;
    let end = s[start..].find('"')? + start;
    Some(s[start..end].to_string())
}
#[cfg(test)]
mod tests {
    use super::super::capability::CapabilitySet;
    use super::super::document::{NetworkPolicy, ToolRule};
    use super::*;

    fn doc_with(caps: Option<CapabilitySet>, tools: Vec<ToolRule>, allowlist: Vec<String>) -> PolicyDocument {
        PolicyDocument {
            name: None,
            network: (!allowlist.is_empty()).then_some(NetworkPolicy { allowlist }),
            capabilities: caps,
            tools,
        }
    }

    #[test]
    fn file_write_deny_seeds_sensitive_path_denies() {
        let mut caps = CapabilitySet::default();
        caps.deny.insert(Capability::FileWrite);
        let rules = lower_to_ebpf(&doc_with(Some(caps), vec![], vec![]));
        let deny: Vec<&str> = rules.deny_paths().collect();
        assert!(deny.contains(&"/etc"));
        assert!(deny.contains(&"/root/.ssh"));
    }

    #[test]
    fn no_file_write_deny_means_no_default_path_rules() {
        let rules = lower_to_ebpf(&doc_with(None, vec![], vec![]));
        assert!(rules.path_rules.is_empty());
    }

    #[test]
    fn tool_path_predicate_lowers_to_deny_rule() {
        let tools = vec![ToolRule {
            name: "write_file".to_string(),
            allow: true,
            requires_approval_if: Some("path starts_with \"/etc\"".to_string()),
        }];
        let rules = lower_to_ebpf(&doc_with(None, tools, vec![]));
        assert_eq!(
            rules.path_rules,
            vec![PathRule {
                pattern: "/etc".to_string(),
                verdict: PathVerdict::Deny,
            }]
        );
    }

    #[test]
    fn compound_predicate_extracts_all_path_prefixes() {
        let tools = vec![ToolRule {
            name: "x".to_string(),
            allow: true,
            requires_approval_if: Some("path starts_with \"/etc\" AND path starts_with \"/root\"".to_string()),
        }];
        let rules = lower_to_ebpf(&doc_with(None, tools, vec![]));
        let deny: Vec<&str> = rules.deny_paths().collect();
        assert!(deny.contains(&"/etc"));
        assert!(deny.contains(&"/root"));
    }

    #[test]
    fn non_path_predicate_is_l7_only_and_lowers_nothing() {
        let tools = vec![ToolRule {
            name: "http_get".to_string(),
            allow: true,
            requires_approval_if: Some("url contains \"internal\"".to_string()),
        }];
        let rules = lower_to_ebpf(&doc_with(None, tools, vec![]));
        assert!(rules.path_rules.is_empty());
    }

}
