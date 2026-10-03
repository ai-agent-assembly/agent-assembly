//! AAASM-6174 live/adversarial verification for J81 (AAASM-6160, capability
//! leases / explicit-authority contract) and J82 (AAASM-6161, monotonic
//! capability attenuation).
//!
//! # Why this is the honest shape for in-process decision logic
//!
//! `authority_gate` and the attenuation it composes with are pure Rust
//! decision logic with no kernel/OS boundary — unlike the Linux
//! Landlock/eBPF adversarial tests elsewhere in this repo
//! (`aa-isolation-native/tests/adversarial_boundary_native_linux.rs`), there
//! is no process to confine and no filesystem side effect to observe. The
//! equivalent of "prove the adversarial action would succeed without the
//! boundary" here is: call the same production entry point
//! (`MockBackend::plan`, which is the exact `backend.plan(&spec)` call
//! `aa-cli` makes) with the boundary (`authority_gate`) simply never having
//! been consulted, and show it admits and fully plans an ungranted domain.
//! The measured artifact is the launch-authorizing [`EnforcementPlan`]
//! itself: a `Ready` plan with the ungranted domain recorded as prevented is
//! the "the adversarial action succeeded" evidence, because that plan is
//! what a caller would hand to `prepare`/`spawn` next.
//!
//! # What this does NOT claim
//!
//! `authority_gate` is wired at the one production call site in
//! `aa-cli::commands::run::resolve_boundary`, before backend dispatch, and
//! runs by default on every `aasm run`. But every real launch today
//! constructs `leases: Vec::new()` and `Ancestry::Root` (see
//! `aa-cli/src/commands/run.rs`'s own doc comments on those fields) — no
//! policy path issues a lease or resolves a parent yet. So every real launch
//! lands on the rc.7 compatibility residual and the gate is a guaranteed
//! pass in the shipped binary. That is not a trust-boundary bypass in the
//! product (do not read it as one) — it is why the refusing behavior can
//! currently only be exercised through this crate's public library API, and
//! exactly why this live verification belongs here rather than in a CLI
//! integration test.

use std::time::{Duration, SystemTime};

use aa_isolation::mock::MockBackend;
use aa_isolation::{
    authority_gate, permit_only_selector, scope_order, Ancestry, AuthorityRefusal, CapabilityDomain, CapabilityLease,
    ControlRequirement, DelegationRule, EffectiveAuthority, ExecutionSpec, IdentityRef, IsolationBackend,
    LaunchPosture, LeaseBasis, LeaseId, ParentAuthority, RequirementOutcome, RequirementScope, ScopeOrdering,
};

fn t(secs: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(secs)
}

// ---------------------------------------------------------------------
// J81 — capability leases / explicit-authority contract (AAASM-6160)
// ---------------------------------------------------------------------

/// The decisive adversarial check for J81: a domain the spec never leased is
/// refused by `authority_gate`, while the exact same spec, run through the
/// real `negotiate` with no gate in front of it (via `MockBackend::plan`,
/// the same entry point `aa-cli` calls), is admitted and fully planned.
///
/// This is one spec value, exercised two ways — the gate's presence is the
/// only variable that moves.
#[test]
fn an_ungranted_domain_is_refused_by_the_gate_while_negotiate_alone_admits_it() {
    let now = t(1_500);

    // Lease-aware (so the rc.7 compatibility residual does not apply) via a
    // lease for a *different* domain. `Credential` deliberately has no
    // lease at all — the ungranted domain under test.
    let network_lease = CapabilityLease::new(
        LeaseId::new("network-lease"),
        IdentityRef::root("agent-under-test"),
        CapabilityDomain::NetworkEgress,
        RequirementScope::Whole,
        t(1_000),
        t(2_000),
        LeaseBasis::new(IdentityRef::root("issuer"), "test fixture: unrelated domain"),
    );

    let spec = ExecutionSpec::new("echo", IdentityRef::root("agent-under-test"))
        .with_requirement(ControlRequirement::prevent(CapabilityDomain::Credential))
        .with_lease(network_lease);

    let backend = MockBackend::preventing(&[CapabilityDomain::Credential]);

    // (a) Fixture-honesty precondition: the backend really can prevent this
    // domain, and the spec is really lease-aware with Credential denied —
    // so a refusal below can only be attributed to the gate, not to the
    // backend being unable to help or to the compatibility residual quietly
    // granting it anyway.
    assert!(
        backend
            .capabilities()
            .report_for(CapabilityDomain::Credential)
            .expect("backend declared this domain")
            .can_prevent(),
        "fixture-honesty: the backend must genuinely support preventing Credential"
    );
    assert!(
        EffectiveAuthority::is_lease_aware(&spec),
        "fixture-honesty: the spec must be lease-aware, or the rc.7 compatibility \
         residual (not the gate) would be what grants Credential"
    );
    let authority = EffectiveAuthority::from_spec(&spec).expect("well-formed spec");
    assert_eq!(
        authority.state(CapabilityDomain::Credential),
        &aa_isolation::AuthorityState::Denied,
        "fixture-honesty: Credential must be Denied, not already satisfied some other way"
    );

    // (b) Adversarial assertion: the real gate refuses the ungranted domain.
    let refusal = authority_gate(&spec, &Ancestry::Root, now).expect_err("ungranted domain must be refused");
    assert_eq!(
        refusal,
        AuthorityRefusal::NoExplicitGrant {
            domain: CapabilityDomain::Credential
        }
    );

    // (c) Mandatory unscoped positive control: the identical spec, through
    // the real `negotiate` via the same `backend.plan(&spec)` entry point
    // `aa-cli` uses, with the gate never consulted — admitted and fully
    // planned. This is the artifact that proves the adversarial action
    // (treating an ungranted domain as authorized) succeeds whenever this
    // boundary is absent from the call chain.
    let plan = backend
        .plan(&spec)
        .expect("negotiate alone, with no authority gate in front of it, must admit the ungranted domain");
    assert_eq!(plan.posture(), LaunchPosture::Ready);
    assert!(
        plan.prevented_domains().contains(&CapabilityDomain::Credential),
        "the unscoped path plans Credential as fully prevented and launch-ready — \
         proving the refusal in (b) is attributable to authority_gate, not to \
         negotiate or the backend being unable to serve this domain at all"
    );
    assert!(matches!(plan.planned()[0].outcome, RequirementOutcome::Enforced { .. }));
}

/// Discrimination control for the test above: a spec that DOES carry a
/// covering lease for the same domain passes the gate too. Without this,
/// the refusal above would be equally consistent with a gate that refuses
/// every domain unconditionally — this proves the gate actually
/// discriminates on grant coverage.
#[test]
fn a_covering_lease_for_the_same_domain_passes_the_gate_and_still_negotiates() {
    let now = t(1_500);
    let lease = CapabilityLease::new(
        LeaseId::new("credential-lease"),
        IdentityRef::root("agent-under-test"),
        CapabilityDomain::Credential,
        RequirementScope::Whole,
        t(1_000),
        t(2_000),
        LeaseBasis::new(IdentityRef::root("issuer"), "test fixture: covering lease"),
    );
    let spec = ExecutionSpec::new("echo", IdentityRef::root("agent-under-test"))
        .with_requirement(ControlRequirement::prevent(CapabilityDomain::Credential))
        .with_lease(lease);
    let backend = MockBackend::preventing(&[CapabilityDomain::Credential]);

    assert!(authority_gate(&spec, &Ancestry::Root, now).is_ok());
    assert!(backend.plan(&spec).is_ok());
}

// ---------------------------------------------------------------------
// J82 — monotonic capability attenuation across sub-agent trees (AAASM-6161)
// ---------------------------------------------------------------------

/// The decisive adversarial check for J82: a child lease that claims a
/// *wider* scope than its parent ever held is refused by the gate, while
/// the identical lease value — the exact same attack artifact — is
/// otherwise a perfectly valid, coverage-correct lease, and the same
/// refusal does not occur when there is no ancestry relationship in play at
/// all (the control that isolates attenuation, specifically, as the cause).
#[test]
fn a_child_lease_wider_than_its_parents_is_refused_and_is_otherwise_a_valid_lease() {
    let now = t(1_500);

    let parent_scope = RequirementScope::Selectors(vec![permit_only_selector("/workspace")]);
    let parent_lease = CapabilityLease::new(
        LeaseId::new("parent-fs-lease"),
        IdentityRef::root("parent-agent"),
        CapabilityDomain::FilesystemWrite,
        parent_scope.clone(),
        t(1_000),
        t(5_000),
        LeaseBasis::new(IdentityRef::root("issuer"), "test fixture: parent grant"),
    )
    .with_delegation(DelegationRule::DelegableWithNarrowerScope);

    let parent_spec = ExecutionSpec::new("echo", IdentityRef::root("parent-agent"))
        .with_requirement(
            ControlRequirement::prevent(CapabilityDomain::FilesystemWrite).with_scope(parent_scope.clone()),
        )
        .with_lease(parent_lease.clone());
    let parent_witness =
        authority_gate(&parent_spec, &Ancestry::Root, now).expect("parent's own launch must be authorized first");
    let ancestry = Ancestry::Parent(Box::new(ParentAuthority::from_gated_spec(
        &parent_spec,
        &parent_witness,
    )));

    // The attack: a hand-built child lease claiming a scope the parent never
    // held at all (outside /workspace entirely), with no attempted
    // independent attribution (no approval_ref/policy_rule), so this is
    // read as a plain escalation attempt, not a differently-authorized
    // grant.
    let widened_scope = RequirementScope::Selectors(vec![permit_only_selector("/etc")]);
    let widened_child = CapabilityLease::new(
        LeaseId::new("child-fs-lease"),
        IdentityRef::root("child-agent").with_ancestor("parent-agent"),
        CapabilityDomain::FilesystemWrite,
        widened_scope.clone(),
        t(1_000),
        t(2_000),
        LeaseBasis::new(IdentityRef::root("issuer"), "test fixture: hand-built, not derived"),
    );

    // (a) The attack artifact is, on its own terms, a perfectly valid and
    // covering lease, and really is a scope escalation relative to the
    // parent — so a refusal below is attributable to attenuation, not to
    // the lease being malformed or the scopes being incomparable by
    // accident.
    assert_eq!(widened_child.validate_at(t(1_500)), Ok(()));
    assert!(widened_child.covers(&widened_scope));
    assert_eq!(
        scope_order::order_for(CapabilityDomain::FilesystemWrite).compare(&parent_scope, &widened_scope),
        ScopeOrdering::Wider,
        "fixture-honesty: the attack scope must really be wider than the parent's, \
         not merely different"
    );

    // (b) Adversarial assertion: the gate refuses the widened child when a
    // real resolved parent authority is in play.
    let child_spec = ExecutionSpec::new("echo", IdentityRef::root("child-agent").with_ancestor("parent-agent"))
        .with_requirement(
            ControlRequirement::prevent(CapabilityDomain::FilesystemWrite).with_scope(widened_scope.clone()),
        )
        .with_lease(widened_child.clone());
    assert_eq!(
        authority_gate(&child_spec, &ancestry, now),
        Err(AuthorityRefusal::ChildExceedsParent {
            domain: CapabilityDomain::FilesystemWrite
        })
    );

    // (c) Mandatory unscoped positive control: the identical lease value,
    // on a spec with no claimed ancestry at all (so attenuation never
    // engages), gates successfully. The only variable that moved between
    // (b) and (c) is whether an ancestry relationship is asserted —
    // isolating attenuation, specifically, as what refused the escalation
    // in (b).
    let unparented_spec = ExecutionSpec::new("echo", IdentityRef::root("child-agent"))
        .with_requirement(ControlRequirement::prevent(CapabilityDomain::FilesystemWrite).with_scope(widened_scope))
        .with_lease(widened_child);
    assert!(
        authority_gate(&unparented_spec, &Ancestry::Root, now).is_ok(),
        "unscoped control: the identical lease value must be accepted once no ancestry \
         relationship is claimed at all — proving (b)'s refusal is attributable to \
         attenuation, not to the lease itself"
    );
}

/// Discrimination control: a child lease genuinely derived as narrower than
/// its parent, via the real `derive_child`/`PathPrefixOrder` machinery,
/// passes the same gate against the same parent. Without this, the refusal
/// above would be equally consistent with attenuation refusing every child
/// unconditionally.
#[test]
fn a_narrower_derived_child_passes_the_same_gate_against_the_same_parent() {
    let now = t(1_500);

    let parent_scope = RequirementScope::Selectors(vec![permit_only_selector("/workspace")]);
    let parent_lease = CapabilityLease::new(
        LeaseId::new("parent-fs-lease-2"),
        IdentityRef::root("parent-agent-2"),
        CapabilityDomain::FilesystemWrite,
        parent_scope.clone(),
        t(1_000),
        t(5_000),
        LeaseBasis::new(IdentityRef::root("issuer"), "test fixture: parent grant"),
    )
    .with_delegation(DelegationRule::DelegableWithNarrowerScope);

    let parent_spec = ExecutionSpec::new("echo", IdentityRef::root("parent-agent-2"))
        .with_requirement(
            ControlRequirement::prevent(CapabilityDomain::FilesystemWrite).with_scope(parent_scope.clone()),
        )
        .with_lease(parent_lease.clone());
    let parent_witness =
        authority_gate(&parent_spec, &Ancestry::Root, now).expect("parent's own launch must be authorized first");
    let ancestry = Ancestry::Parent(Box::new(ParentAuthority::from_gated_spec(
        &parent_spec,
        &parent_witness,
    )));

    let narrower_scope = RequirementScope::Selectors(vec![permit_only_selector("/workspace/sub")]);
    let child_request = aa_isolation::ChildLeaseRequest {
        child_id: LeaseId::new("child-fs-lease-2"),
        child_subject: IdentityRef::root("child-agent-2").with_ancestor("parent-agent-2"),
        child_scope: narrower_scope.clone(),
        child_expires_at: t(2_000),
        mode: aa_isolation::InheritanceMode::Narrower,
        child_delegation: DelegationRule::NotDelegable,
        child_limits: None,
    };
    let narrower_child = parent_lease
        .derive_child(
            child_request,
            scope_order::order_for(CapabilityDomain::FilesystemWrite),
            t(1_100),
        )
        .expect("a genuinely narrower child must be derivable from a delegable parent");

    let child_spec = ExecutionSpec::new(
        "echo",
        IdentityRef::root("child-agent-2").with_ancestor("parent-agent-2"),
    )
    .with_requirement(ControlRequirement::prevent(CapabilityDomain::FilesystemWrite).with_scope(narrower_scope))
    .with_lease(narrower_child);

    assert!(authority_gate(&child_spec, &ancestry, now).is_ok());
}
