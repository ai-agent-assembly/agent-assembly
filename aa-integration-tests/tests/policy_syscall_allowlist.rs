//! End-to-end round trip for the syscall-allowlist node (AAASM-5753).
//!
//! The unit tests inside `aa-security`, `aa-policy` and `aa-isolation` each pin
//! one arrow of the chain. This file pins the **whole** chain in one test,
//! because the arrows are owned by three crates that cannot see each other:
//!
//! ```text
//! authored YAML
//!   → aa_policy::raw   (serde deserialization)
//!   → aa_policy::PolicyValidator            (validation)
//!   → aa_policy::PolicyDocument::to_canonical (canonical AST)
//!   → aa_isolation::lower_policy            (execution requirement)
//! ```
//!
//! That is the defect this ticket records, stated as a test. `to_canonical`
//! hard-coded `syscall_allowlist: None`, so an authored allowlist was dropped
//! between the second and third arrows. Each crate's own tests passed
//! throughout: the validator had no field to lose, the projection compiled, and
//! the lowering handled the populated node correctly when handed one directly.
//! The loss was visible only from a test that starts at the YAML and ends at
//! the requirement — which is why the AAASM-5707 lowering is exercised here
//! **through the projection** rather than by constructing the AST.
//!
//! Each positive assertion here carries the control that makes it move.

use aa_gateway::policy::PolicyValidator;
use aa_isolation::{
    lower_policy, permitted_selector, CapabilityDomain, DomainCoverage, ExecutionSpec, IdentityRef, LoweringOptions,
    PolicyLowering, RequirementScope, ScopeGranularity,
};

/// An authored policy naming the calls a sandboxed workload may issue.
const ENUMERATED: &str = r#"
apiVersion: agent-assembly/v1
kind: Policy
metadata:
  name: syscall-scoped
spec:
  syscalls:
    allow:
      - read
      - write
      - exit_group
"#;

/// The same policy with the syscall node removed. Everything else is identical,
/// so a difference in the lowering is attributable to that node alone.
const SILENT: &str = r#"
apiVersion: agent-assembly/v1
kind: Policy
metadata:
  name: syscall-scoped
spec:
  tools:
    "*":
      allow: true
"#;

/// A `syscalls:` key with no `allow:` under it — a restriction in force that
/// permits no call, which is a different authored fact from the node's absence.
const DENY_ALL: &str = r#"
apiVersion: agent-assembly/v1
kind: Policy
metadata:
  name: syscall-scoped
spec:
  syscalls: {}
"#;

/// Drive the full chain: YAML → raw → validation → canonical AST → lowering.
///
/// `to_canonical` is deliberately in the path. Building the canonical AST
/// directly would skip the arrow this ticket exists to fix.
fn lower_yaml(yaml: &str) -> PolicyLowering {
    let validated = PolicyValidator::from_yaml(yaml)
        .unwrap_or_else(|errors| panic!("the fixture must validate, got {errors:?}"))
        .document;
    lower_policy(&validated.to_canonical(), &LoweringOptions::strict())
}

fn coverage(lowering: &PolicyLowering, domain: CapabilityDomain) -> &DomainCoverage {
    &lowering
        .coverage(domain)
        .expect("every domain in CapabilityDomain::ALL has a lowering")
        .coverage
}

fn scope_of(lowering: &PolicyLowering, domain: CapabilityDomain) -> Option<&RequirementScope> {
    lowering
        .requirements()
        .iter()
        .find(|r| r.domain() == domain)
        .map(|r| r.scope())
}

/// The round trip. An operator writes three syscall names; the execution
/// boundary asks for exactly those three, at enumerated granularity, having
/// crossed three crates.
///
/// The assertion is the **set**, not `is_some()`: a projection that
/// manufactured an allowlist would satisfy `is_some()` and is a different bug
/// with the same shape as the one this ticket fixes.
#[test]
fn an_authored_syscall_allowlist_reaches_the_execution_requirement() {
    let lowering = lower_yaml(ENUMERATED);

    assert_eq!(
        scope_of(&lowering, CapabilityDomain::Syscall),
        Some(&RequirementScope::Selectors(vec![
            "permit-only:read".to_string(),
            "permit-only:write".to_string(),
            "permit-only:exit_group".to_string(),
        ])),
        "the authored syscall names did not reach the requirement"
    );

    assert!(
        matches!(
            coverage(&lowering, CapabilityDomain::Syscall),
            DomainCoverage::Lowered {
                granularity: ScopeGranularity::Enumerated,
                ..
            }
        ),
        "Syscall did not reach enumerated granularity: {:?}",
        coverage(&lowering, CapabilityDomain::Syscall)
    );

    // The selectors read back through the shared polarity convention, so a
    // backend consumes them with no syscall-specific branch — and the read-back
    // is the set assertion in the other direction, naming a member of the
    // vocabulary the author did **not** write.
    let RequirementScope::Selectors(selectors) = scope_of(&lowering, CapabilityDomain::Syscall).unwrap() else {
        unreachable!("asserted above");
    };
    let permitted: Vec<&str> = selectors.iter().filter_map(|s| permitted_selector(s)).collect();
    assert_eq!(permitted, vec!["read", "write", "exit_group"]);
    assert!(
        !permitted.contains(&"openat"),
        "the projection widened the authored set"
    );

    // The chain produces a launchable spec rather than a refusal.
    let spec = lowering
        .apply_to(ExecutionSpec::new("python", IdentityRef::root("agent-1")))
        .expect("an authored syscall allowlist is an expressible restriction");
    assert_eq!(spec.requirements().len(), 1);
}

/// The control that makes the test above move: the same chain, the same
/// fixture minus the `syscalls:` node.
///
/// Without this half, the positive test would pass for a lowering that emitted
/// an enumerated syscall requirement for whatever document it is handed —
/// including one that hard-coded the requirement instead of reading the policy.
#[test]
fn removing_the_syscall_node_yields_no_requirement_and_no_silent_allow() {
    let lowering = lower_yaml(SILENT);

    assert_eq!(
        scope_of(&lowering, CapabilityDomain::Syscall),
        None,
        "Syscall lowered a requirement from a document that names no call"
    );
    assert_eq!(
        coverage(&lowering, CapabilityDomain::Syscall).as_str(),
        "not_stated",
        "Syscall must be reported as unstated, not omitted"
    );

    let DomainCoverage::NotStated { node, schema_default } = coverage(&lowering, CapabilityDomain::Syscall) else {
        unreachable!("asserted immediately above");
    };
    assert!(
        node.contains("syscalls."),
        "Syscall must name the node an operator could have written: {node}"
    );
    assert!(
        !schema_default.to_lowercase().contains("unrestricted")
            && !schema_default.to_lowercase().contains("is permitted"),
        "Syscall's absent-node meaning must not read as a grant: {schema_default}"
    );
    // The stale-claim guard. Until AAASM-5753 this text told readers the
    // gateway projection discarded the node, which is what the ticket fixed. A
    // reintroduced claim of that shape would mean the projection regressed, or
    // that the prose outlived the code.
    assert!(
        !schema_default.contains("to_canonical"),
        "the absent-node meaning still claims the projection drops this node: {schema_default}"
    );
}

/// An **absent** allowlist and an **empty** one are two authored facts, and the
/// distinction survives the whole chain.
///
/// The schema's answer, stated: absent is the operator having said nothing;
/// empty is a restriction in force that permits no call — the strictest posture
/// authorable here, and the reading `aa_security::policy::FilesystemPolicy`
/// documents for an empty `PathScope`. Enforced end to end: the empty document
/// yields a requirement covering the whole domain, where the absent one yields
/// no requirement and the coverage token `not_stated`.
#[test]
fn an_empty_allowlist_is_a_restriction_where_an_absent_one_is_silence() {
    let empty = lower_yaml(DENY_ALL);
    let absent = lower_yaml(SILENT);

    assert_eq!(
        scope_of(&empty, CapabilityDomain::Syscall),
        Some(&RequirementScope::Whole),
        "a stated allowlist permitting no call must lower to whole-domain prevention"
    );
    assert_eq!(
        coverage(&empty, CapabilityDomain::Syscall).as_str(),
        "lowered",
        "an in-force deny-all was reported as something other than lowered"
    );
    assert!(
        matches!(
            coverage(&empty, CapabilityDomain::Syscall),
            DomainCoverage::Lowered {
                granularity: ScopeGranularity::WholeDomainOnly,
                ..
            }
        ),
        "{:?}",
        coverage(&empty, CapabilityDomain::Syscall)
    );

    // The control beside it: the absent document, through the same chain.
    assert_eq!(scope_of(&absent, CapabilityDomain::Syscall), None);
    assert_ne!(
        coverage(&empty, CapabilityDomain::Syscall).as_str(),
        coverage(&absent, CapabilityDomain::Syscall).as_str(),
        "an in-force deny-all collapsed onto silence"
    );

    // And the enumerated document, so "whole domain" is attributable to the
    // allowlist being empty rather than to the domain lowering that way for
    // whatever a document says.
    assert!(matches!(
        scope_of(&lower_yaml(ENUMERATED), CapabilityDomain::Syscall),
        Some(RequirementScope::Selectors(_))
    ));
}

/// The AAASM-4330 fail-closed rule, driven from the YAML end.
///
/// A name outside the closed 15-name vocabulary is refused rather than dropped,
/// so a typo cannot silently shrink the allowlist to a posture nobody wrote —
/// and the refusal names the offending index.
#[test]
fn an_unknown_syscall_name_is_refused_at_the_gateway_rather_than_dropped() {
    let yaml = "spec:\n  syscalls:\n    allow:\n      - read\n      - ptrace\n";
    let errors = PolicyValidator::from_yaml(yaml).expect_err("an unknown syscall name must be refused");
    assert!(
        errors.iter().any(|e| e.field == "syscalls.allow[1]"),
        "expected the offending index to be named, got {errors:?}"
    );

    // The control: the same document with the offending name removed loads and
    // reaches the requirement, so the refusal is attributable to that name
    // rather than to the section being rejected wholesale.
    let ok = "spec:\n  syscalls:\n    allow:\n      - read\n";
    assert_eq!(
        scope_of(&lower_yaml(ok), CapabilityDomain::Syscall),
        Some(&RequirementScope::Selectors(vec!["permit-only:read".to_string()]))
    );
}
