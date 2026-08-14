//! End-to-end round trip for the filesystem path-scope node (AAASM-5751).
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
//! A per-crate test cannot fail when the *join* between two crates breaks, and
//! a broken join is exactly the defect AAASM-5753 records for the syscall node:
//! `to_canonical` compiles, validates and ships while silently dropping a node
//! an operator authored. Only a test that starts at the YAML and ends at the
//! requirement can catch that.
//!
//! Every positive assertion here carries the control that makes it move.

use aa_gateway::policy::{merge_filesystem_cascade, CascadeFilesystemScope, PolicyValidator};
use aa_isolation::{
    lower_policy, permitted_selector, CapabilityDomain, DomainCoverage, ExecutionSpec, IdentityRef, LoweringOptions,
    PolicyLowering, RequirementScope, ScopeGranularity,
};

/// An authored policy that scopes both filesystem verbs by path.
const SCOPED: &str = r#"
apiVersion: agent-assembly/v1
kind: Policy
metadata:
  name: workspace-scoped
spec:
  filesystem:
    read:
      allow:
        - /workspace
        - /usr/share/dict
    write:
      allow:
        - /workspace/build
"#;

/// The same policy with the path node removed. Everything else is identical,
/// so any difference in the lowering is attributable to that node alone.
const UNSCOPED: &str = r#"
apiVersion: agent-assembly/v1
kind: Policy
metadata:
  name: workspace-scoped
spec:
  tools:
    "*":
      allow: true
"#;

/// Drive the full chain: YAML → raw → validation → canonical AST → lowering.
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

/// The round trip. An operator writes path prefixes; the execution boundary
/// asks for exactly those prefixes, at enumerated granularity, having crossed
/// three crates.
#[test]
fn an_authored_path_scope_reaches_the_execution_requirement() {
    let lowering = lower_yaml(SCOPED);

    assert_eq!(
        scope_of(&lowering, CapabilityDomain::FilesystemRead),
        Some(&RequirementScope::Selectors(vec![
            "permit-only:/usr/share/dict".to_string(),
            "permit-only:/workspace".to_string(),
        ])),
        "the authored read prefixes did not reach the requirement"
    );
    assert_eq!(
        scope_of(&lowering, CapabilityDomain::FilesystemWrite),
        Some(&RequirementScope::Selectors(vec![
            "permit-only:/workspace/build".to_string()
        ])),
        "the authored write prefixes did not reach the requirement"
    );

    for domain in [CapabilityDomain::FilesystemRead, CapabilityDomain::FilesystemWrite] {
        assert!(
            matches!(
                coverage(&lowering, domain),
                DomainCoverage::Lowered {
                    granularity: ScopeGranularity::Enumerated,
                    ..
                }
            ),
            "{domain} did not reach enumerated granularity: {:?}",
            coverage(&lowering, domain)
        );
    }

    // The selectors read back through the shared polarity convention, so a
    // backend consumes them with no filesystem-specific branch.
    let RequirementScope::Selectors(read_selectors) = scope_of(&lowering, CapabilityDomain::FilesystemRead).unwrap()
    else {
        unreachable!("asserted above");
    };
    assert_eq!(
        read_selectors
            .iter()
            .filter_map(|s| permitted_selector(s))
            .collect::<Vec<_>>(),
        vec!["/usr/share/dict", "/workspace"]
    );

    // The chain produces a launchable spec rather than a refusal.
    let spec = lowering
        .apply_to(ExecutionSpec::new("python", IdentityRef::root("agent-1")))
        .expect("an authored path scope is an expressible restriction");
    assert_eq!(spec.requirements().len(), 2);
}

/// The negative control the ticket names, driven through the same chain.
///
/// With the `filesystem:` node removed, both filesystem domains must report
/// `not_stated` and emit **no** requirement — never a silent allow, and never a
/// domain quietly missing from the report. Asserting only the positive case
/// above would pass for a lowering that emitted an enumerated filesystem
/// requirement for every document.
#[test]
fn removing_the_path_node_yields_no_requirement_and_no_silent_allow() {
    let lowering = lower_yaml(UNSCOPED);

    for domain in [CapabilityDomain::FilesystemRead, CapabilityDomain::FilesystemWrite] {
        assert_eq!(
            scope_of(&lowering, domain),
            None,
            "{domain} lowered a requirement from a document that scopes no path"
        );
        assert_eq!(
            coverage(&lowering, domain).as_str(),
            "not_stated",
            "{domain} must be reported as unstated, not omitted"
        );
        let DomainCoverage::NotStated { node, schema_default } = coverage(&lowering, domain) else {
            unreachable!("asserted immediately above");
        };
        assert!(
            node.contains("filesystem."),
            "{domain} must name the node an operator could have written: {node}"
        );
        assert!(
            !schema_default.to_lowercase().contains("unrestricted")
                && !schema_default.to_lowercase().contains("is permitted"),
            "{domain}'s absent-node meaning must not read as a grant: {schema_default}"
        );
    }

    // The domains the schema still cannot reach at all keep saying so, under
    // both documents. Closing one gap must not silently reclassify the others.
    for domain in [
        CapabilityDomain::NameResolution,
        CapabilityDomain::Ipc,
        CapabilityDomain::Credential,
        CapabilityDomain::Resource,
    ] {
        assert_eq!(coverage(&lowering, domain).as_str(), "policy_cannot_express");
        assert_eq!(coverage(&lower_yaml(SCOPED), domain).as_str(), "policy_cannot_express");
    }
    assert_eq!(lowering.unrepresentable().count(), 4);
    assert_eq!(lower_yaml(SCOPED).unrepresentable().count(), 4);
}

/// A document whose only enforcement statement is a path scope must still
/// refuse to become a spec when it scopes *nothing* — the fail-closed floor
/// applies to the new node too.
#[test]
fn a_scope_that_permits_nothing_crosses_the_chain_as_whole_domain_prevention() {
    let lowering = lower_yaml(
        r#"
spec:
  filesystem:
    write:
      allow: []
"#,
    );
    assert_eq!(
        scope_of(&lowering, CapabilityDomain::FilesystemWrite),
        Some(&RequirementScope::Whole),
        "an in-force scope permitting nothing must prevent the whole domain"
    );

    // The control: the same document with one prefix lowers to that prefix
    // rather than to the whole domain, so `Whole` above is attributable to the
    // empty list and not to the lowering ignoring the node.
    let one = lower_yaml(
        r#"
spec:
  filesystem:
    write:
      allow: [/workspace]
"#,
    );
    assert_eq!(
        scope_of(&one, CapabilityDomain::FilesystemWrite),
        Some(&RequirementScope::Selectors(vec!["permit-only:/workspace".to_string()]))
    );
}

/// A malformed prefix must fail the load rather than silently narrowing or
/// widening the authored scope.
#[test]
fn a_malformed_prefix_fails_validation_at_the_front_of_the_chain() {
    let errors = PolicyValidator::from_yaml(
        r#"
spec:
  filesystem:
    read:
      allow: [/workspace/../etc]
"#,
    )
    .expect_err("a traversing prefix must not validate");
    assert!(
        errors.iter().any(|e| e.field.starts_with("filesystem.read.allow")),
        "the error must point at the line the operator wrote: {errors:?}"
    );

    // The control: the directory it would have resolved to validates when
    // written out, so the rejection is about the notation, not about `/etc`.
    assert!(PolicyValidator::from_yaml(
        r#"
spec:
  filesystem:
    read:
      allow: [/etc]
"#
    )
    .is_ok());
}

/// The cascade, through the same validated documents the gateway holds.
///
/// Most-restrictive-wins: a narrower tier shrinks a broader one and can never
/// add to it. The fixture is chosen so the candidate merges disagree — a union
/// would permit `/workspace/docs`, keeping the last tier would permit `/tmp`,
/// and only the intersection permits neither.
#[test]
fn the_cascade_merges_most_restrictive_wins_and_an_empty_one_refuses() {
    let global = PolicyValidator::from_yaml("spec:\n  filesystem:\n    read:\n      allow: [/workspace]\n")
        .expect("valid")
        .document;
    let team = PolicyValidator::from_yaml("spec:\n  filesystem:\n    read:\n      allow: [/workspace/src, /tmp]\n")
        .expect("valid")
        .document;

    let CascadeFilesystemScope::Stated(merged) = merge_filesystem_cascade([&global, &team]) else {
        panic!("two stated tiers merge to a stated scope");
    };
    let read = merged.read.as_ref().expect("the read verb was stated");
    assert!(read.permits("/workspace/src/main.rs"));
    assert!(!read.permits("/workspace/docs/readme.md"), "a union would permit this");
    assert!(!read.permits("/tmp/scratch"), "keeping the last tier would permit this");

    // The empty cascade is a refusal, not an empty intersection (ADR 0024).
    let empty = merge_filesystem_cascade(std::iter::empty());
    assert!(empty.is_fail_closed());
    assert!(empty.into_effective().is_err());

    // The control: a cascade of one document that scopes nothing resolves —
    // it does not refuse — so the refusal above is attributable to the absent
    // cascade rather than to `into_effective` refusing whenever no scope
    // resulted.
    let silent = PolicyValidator::from_yaml("spec:\n  tools:\n    \"*\":\n      allow: true\n")
        .expect("valid")
        .document;
    let resolved = merge_filesystem_cascade([&silent]);
    assert!(!resolved.is_fail_closed());
    assert_eq!(resolved.into_effective().expect("a populated cascade resolves"), None);
}

/// The two ingest paths into the canonical AST must agree about this node.
///
/// `aa_security::policy::PolicyDocument::from_yaml` and
/// `aa_policy::PolicyValidator` + `to_canonical` are two independent parsers of
/// the same on-disk contract, and they already disagree about the syscall node
/// (AAASM-5753). This pins that the path node does not join it — and the
/// syscall assertion beside it is the control that proves the test can see a
/// disagreement when there is one.
#[test]
fn both_ingest_paths_agree_about_the_path_node() {
    let via_gateway = PolicyValidator::from_yaml(SCOPED)
        .expect("valid")
        .document
        .to_canonical();
    let via_canonical = aa_security::policy::PolicyDocument::from_yaml(SCOPED).expect("valid");

    assert_eq!(
        via_gateway.filesystem, via_canonical.filesystem,
        "the two ingest paths produced different path scopes"
    );
    assert!(via_gateway.filesystem.is_some(), "both dropped the node entirely");

    // The control: a node the two paths genuinely disagree about, so this test
    // is not passing because both sides are trivially `None`. `syscalls:` is
    // accepted and populated by the canonical parser and **rejected outright**
    // by the gateway validator, which has no field for it — the AAASM-5753
    // divergence, demonstrated rather than assumed. If this half ever starts
    // failing, the two paths have converged and this control needs replacing.
    let with_syscalls = "spec:\n  syscalls:\n    allow: [read]\n";
    assert!(
        aa_security::policy::PolicyDocument::from_yaml(with_syscalls)
            .expect("the canonical parser accepts syscalls:")
            .syscall_allowlist
            .is_some(),
        "the canonical parser stopped populating the syscall node"
    );
    let rejected = PolicyValidator::from_yaml(with_syscalls)
        .expect_err("the gateway validator has no syscalls field and must reject it");
    assert!(
        rejected.iter().any(|e| e.field == "syscalls"),
        "expected the gateway validator to reject `syscalls:` as an unknown key, got {rejected:?}"
    );
}
