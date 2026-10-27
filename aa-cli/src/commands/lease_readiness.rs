//! Authoring-time warnings for governed lease mode (AAASM-6386, ADR 0038).
//!
//! `aasm policy validate` and `aasm lease init --policy` both tell an operator
//! their policy is fine. Under governed lease mode (`AA_LEASE_POLICY`) the
//! runtime denies every call to a tool that declares no `capabilities`, and
//! every call to a tool whose capability has no matching `authority.leases`
//! entry, so "valid" was a promise the runtime then broke on the first call.
//!
//! # One decision function, not a second copy
//!
//! Each tool is judged by [`aa_runtime::lease::decide::decide`] against a
//! [`LeaseGovernance`] built by [`LeaseGovernance::from_resolution`], the same
//! pair the runtime's gate and the `aasm run --dry-run` lease plan use. This
//! module only builds the request a wrapped call would carry and words the
//! answer; it must not grow a rule of its own, or a warning could say "denied"
//! about a tool the gate admits.
//!
//! These are warnings, never errors: a policy that is not meant for governed
//! mode is still a valid policy.
//!
//! Lives in the `devtool` strip region with the gate it asks (`decide` is
//! removed from the crates.io build), so the published `aasm` prints none.

use std::collections::BTreeSet;
use std::path::Path;
use std::time::SystemTime;

use aa_policy::resolve::PolicyResolution;
use aa_proto::assembly::common::v1::ActionType;
use aa_proto::assembly::policy::v1::action_context::Action;
use aa_proto::assembly::policy::v1::{ActionContext, CheckActionRequest, ToolCallContext};
use aa_runtime::lease::decide::{decide, GovernedIssuance, LeaseGovernance};
use aa_runtime::lease::governed::DEFAULT_LEASE_TTL_SECONDS;
use aa_runtime::pipeline::LeaseVerdict;

use crate::sanitize::sanitize_terminal;

/// Subject used when the caller has no agent id (`policy validate`). Leases
/// are bound to a subject only for id derivation; the verdicts do not depend
/// on its value.
pub const VALIDATE_SUBJECT: &str = "aasm-policy-validate";

fn tool_call(name: &str) -> CheckActionRequest {
    CheckActionRequest {
        action_type: ActionType::ToolCall as i32,
        context: Some(ActionContext {
            action: Some(Action::ToolCall(ToolCallContext {
                tool_name: name.to_string(),
                ..Default::default()
            })),
        }),
        ..Default::default()
    }
}

/// Warnings for the policy file at `path`, as a governed runtime bound to
/// `subject` would experience it. Empty when the file does not resolve as an
/// enforced policy (nothing is governed then), is unreadable, or every tool is
/// admitted.
pub fn warnings_for_file(path: &Path, subject: &str) -> Vec<String> {
    let Ok(yaml) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    warnings_for_yaml(path, &yaml, subject)
}

/// [`warnings_for_file`] over already-read policy text.
pub fn warnings_for_yaml(source: &Path, yaml: &str, subject: &str) -> Vec<String> {
    let resolution = aa_policy::resolve::classify(source, yaml);
    if !matches!(resolution, PolicyResolution::Enforced { .. }) {
        return Vec::new();
    }
    // `classify` returned Enforced, so the same text validates.
    let Ok(output) = aa_policy::PolicyValidator::from_yaml(yaml) else {
        return Vec::new();
    };
    let now = SystemTime::now();
    let governance = match LeaseGovernance::from_resolution(
        &resolution,
        subject,
        &GovernedIssuance {
            issued_at: now,
            default_ttl_seconds: DEFAULT_LEASE_TTL_SECONDS,
            default_issuer: "aasm:lease-readiness".to_string(),
        },
        &|domain| Ok(format!("readiness:{domain}")),
    ) {
        Ok(g) => g,
        Err(e) => {
            return vec![format!(
                "a runtime started with AA_LEASE_POLICY would refuse to start with this policy: {}",
                sanitize_terminal(&e.to_string())
            )]
        }
    };

    let leased: BTreeSet<&str> = resolution.lease_grants().iter().map(|g| g.domain.as_str()).collect();
    let revoked: BTreeSet<String> = BTreeSet::new();

    // `tools` is a HashMap; sort so the output is stable.
    let mut tools: Vec<_> = output.document.tools.iter().collect();
    tools.sort_by(|a, b| a.0.cmp(b.0));

    let mut out = Vec::new();
    for (name, tool) in tools {
        // `allow: false` is the operator blocking the tool; the gate agreeing
        // is not a surprise to warn about.
        if !tool.allow {
            continue;
        }
        let LeaseVerdict::Deny { reason } = decide(&governance, &revoked, &tool_call(name), now) else {
            continue;
        };
        let shown = sanitize_terminal(name);
        let reason = sanitize_terminal(&reason);
        out.push(match &tool.capabilities {
            None => format!(
                "tool {shown:?} declares no `capabilities`, so a runtime started with AA_LEASE_POLICY denies every \
                 call to it ({reason}). Add `tools.{shown}.capabilities: [none]` if it needs no authority, or list \
                 the capability domains it uses together with a matching `authority.leases` entry for each."
            ),
            Some(caps) => {
                // Hint only: the verdict above is the gate's. A domain no lease
                // can ever cover (process_creation, syscall) is not suggested.
                let missing: Vec<&str> = caps
                    .iter()
                    .map(|c| c.as_str())
                    .filter(|w| !matches!(*w, "none" | "process_creation" | "syscall") && !leased.contains(w))
                    .collect();
                let words: Vec<&str> = caps.iter().map(|c| c.as_str()).collect();
                let fix = if missing.is_empty() {
                    String::new()
                } else {
                    format!(
                        " Add `authority.leases` entries (`- domain: <name>`, `scope: whole`, `reason: <why>`) for: {}.",
                        missing.join(", ")
                    )
                };
                format!(
                    "tool {shown:?} declares capabilities [{}] but a runtime started with AA_LEASE_POLICY would deny \
                     every call to it ({reason}).{fix}",
                    words.join(", ")
                )
            }
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn warn(yaml: &str) -> Vec<String> {
        warnings_for_yaml(Path::new("policy.yaml"), yaml, "agent-1")
    }

    #[test]
    fn a_capability_without_a_lease_is_named_with_what_to_add() {
        let w = warn("tools:\n  writer: { allow: true, capabilities: [filesystem_write] }\n");
        assert_eq!(w.len(), 1, "{w:?}");
        assert!(w[0].contains("\"writer\""), "{}", w[0]);
        assert!(w[0].contains("filesystem_write"), "{}", w[0]);
        assert!(w[0].contains("authority.leases"), "{}", w[0]);
    }

    #[test]
    fn a_tool_without_capabilities_says_to_declare_them() {
        let w = warn("tools:\n  x: { allow: true }\n");
        assert_eq!(w.len(), 1, "{w:?}");
        assert!(w[0].contains("declares no `capabilities`"), "{}", w[0]);
        assert!(w[0].contains("[none]"), "{}", w[0]);
    }

    #[test]
    fn a_leased_capability_and_a_none_tool_are_quiet() {
        let w = warn(
            "tools:\n  writer: { allow: true, capabilities: [filesystem_write] }\n  calc: { allow: true, capabilities: [none] }\n\
             authority:\n  leases:\n    - domain: filesystem_write\n      scope: whole\n      reason: test\n",
        );
        assert!(w.is_empty(), "{w:?}");
    }

    #[test]
    fn a_blocked_tool_is_not_warned_about() {
        assert!(warn("tools:\n  x: { allow: false }\n").is_empty());
    }

    #[test]
    fn a_domain_no_lease_can_cover_is_not_offered_as_a_fix() {
        let w = warn("tools:\n  sh: { allow: true, capabilities: [process_creation] }\n");
        assert_eq!(w.len(), 1, "{w:?}");
        assert!(!w[0].contains("Add `authority.leases`"), "{}", w[0]);
        assert!(w[0].contains("process_creation"), "{}", w[0]);
    }

    #[test]
    fn a_policy_that_is_not_enforced_has_nothing_to_warn_about() {
        assert!(warn("budget:\n  daily_limit_usd: 100.0\n").is_empty());
    }

    #[test]
    fn warnings_are_stable_and_sorted_by_tool_name() {
        let w = warn("tools:\n  b: { allow: true }\n  a: { allow: true }\n");
        assert!(w[0].contains("\"a\"") && w[1].contains("\"b\""), "{w:?}");
    }

    /// Parity: a warning exists exactly when the gate denies. The expectation
    /// is computed by the runtime's own `decide`, not restated here, so this
    /// fails if the module ever grows a rule of its own.
    #[test]
    fn warnings_match_the_gates_denials_for_every_tool() {
        let yaml = "tools:\n  a: { allow: true, capabilities: [none] }\n  b: { allow: true, capabilities: [filesystem_read] }\n  c: { allow: true }\n  d: { allow: true, capabilities: [network_egress] }\n\
                    authority:\n  leases:\n    - domain: filesystem_read\n      scope: whole\n      reason: test\n";
        let resolution = aa_policy::resolve::classify(Path::new("p.yaml"), yaml);
        let now = SystemTime::now();
        let g = LeaseGovernance::from_resolution(
            &resolution,
            "agent-1",
            &GovernedIssuance {
                issued_at: now,
                default_ttl_seconds: DEFAULT_LEASE_TTL_SECONDS,
                default_issuer: "t".into(),
            },
            &|d| Ok(format!("t:{d}")),
        )
        .unwrap();
        let revoked: BTreeSet<String> = BTreeSet::new();
        let denied: Vec<&str> = ["a", "b", "c", "d"]
            .into_iter()
            .filter(|t| matches!(decide(&g, &revoked, &tool_call(t), now), LeaseVerdict::Deny { .. }))
            .collect();
        let warned: Vec<String> = warn(yaml);
        assert_eq!(denied, ["c", "d"]);
        assert_eq!(warned.len(), denied.len(), "{warned:?}");
        for t in denied {
            assert!(warned.iter().any(|w| w.contains(&format!("{t:?}"))), "{t}: {warned:?}");
        }
    }
}
