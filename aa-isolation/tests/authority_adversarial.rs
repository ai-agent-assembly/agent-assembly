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
    ChildLeaseRequest, ControlRequirement, DelegationDenied, DelegationLedger, DelegationRule, EffectiveAuthority,
    ExecutionSpec, IdentityRef, InheritanceMode, IsolationBackend, LaunchPosture, LeaseBasis, LeaseId, LeaseInvalid,
    ParentAuthority, RequirementOutcome, RequirementScope, RevocationState, ScopeOrdering,
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

// ---------------------------------------------------------------------
// AAASM-6290 (ST-3): a real 3-generation chain -- root -> child ->
// grandchild -- rather than the 2-generation (parent/child) fixtures above.
// ---------------------------------------------------------------------

/// A real 3-generation attenuation chain, built end to end through the
/// production machinery (`DelegationLedger::derive_child`, not a hand-built
/// lease) at every hop: root -> child -> grandchild.
///
/// (a) a grandchild trying to claim a scope wider than its own parent (the
///     child, scoped to `/workspace/a`) ever held -- `/workspace/b`, a
///     *sibling* of the child's own grant and therefore still well inside
///     the root's `/workspace` grant -- is refused relative to the
///     immediate parent specifically. The positive control re-gates the
///     identical hand-built lease directly against the root ancestry
///     (skipping the child), where it is narrower than the root's own
///     grant and admits: a 2-generation fixture cannot isolate "refused
///     because it exceeds the immediate parent" from "refused because it
///     exceeds the root", since there both parents are the same node; this
///     one can, and does.
/// (b) revoking the root's lease: the immediate child is refused when
///     re-gated against a `ParentAuthority` snapshot carrying the root's
///     now-revoked lease, and the ledger refuses to mint any *fresh* child
///     from the revoked root lease. Verified empirically (not asserted)
///     against this crate's real production entry points and recorded
///     honestly below is the limit of that cascade: revocation reaches
///     only the hop derived directly from the revoked lease. An
///     already-minted, already-held grandchild `ParentAuthority` whose own
///     immediate parent (the child) was never itself revoked is
///     unaffected -- the grandchild still gates cleanly, and a *fresh*
///     grandchild can still be minted from the still-active child lease,
///     because `RevocationState` lives on each lease object independently
///     (see that type's own doc comment) and nothing in `check_attenuation`
///     looks past the immediate parent to ask whether its own ancestors
///     are still valid. This is the documented, pinned gap this test
///     exists to make checkable rather than merely asserted: "revocation
///     isn't accidentally scoped to only the immediate child" does NOT
///     hold for an already-resolved deeper ancestry snapshot -- it holds
///     only for whichever hop is re-gated directly against the revoked
///     lease. A target-contract test below (`#[ignore]`d) pins the
///     property this ticket's AC literally asks for, for a future fix;
///     per AAASM-6290's scope this subtask documents the gap and does not
///     change `authority_gate` or `DelegationLedger` to close it.
#[test]
fn a_three_generation_chain_refuses_widening_at_generation_two_and_characterizes_root_revocation_reach() {
    let now = t(1_500);

    let root_scope = RequirementScope::Selectors(vec![permit_only_selector("/workspace")]);
    let root_lease = CapabilityLease::new(
        LeaseId::new("root-fs-lease"),
        IdentityRef::root("root-agent"),
        CapabilityDomain::FilesystemRead,
        root_scope.clone(),
        t(1_000),
        t(9_000),
        LeaseBasis::new(IdentityRef::root("issuer"), "test fixture: root grant"),
    )
    .with_delegation(DelegationRule::DelegableWithNarrowerScope);

    let root_spec = ExecutionSpec::new("echo", IdentityRef::root("root-agent"))
        .with_requirement(ControlRequirement::observe(CapabilityDomain::FilesystemRead).with_scope(root_scope.clone()))
        .with_lease(root_lease.clone());
    let root_witness = authority_gate(&root_spec, &Ancestry::Root, now).expect("root's own launch must gate");
    let root_ancestry = Ancestry::Parent(Box::new(ParentAuthority::from_gated_spec(&root_spec, &root_witness)));

    // Generation 1 (child): derived through the real ledger, so its
    // provenance carries the root's actual revocation generation rather
    // than a hand-asserted one.
    let ledger = DelegationLedger::new();
    ledger.register_parent(&root_lease);

    let child_scope = RequirementScope::Selectors(vec![permit_only_selector("/workspace/a")]);
    let child_lease = ledger
        .derive_child(
            &root_lease,
            ChildLeaseRequest {
                child_id: LeaseId::new("child-fs-lease"),
                child_subject: IdentityRef::root("child-agent").with_ancestor("root-agent"),
                child_scope: child_scope.clone(),
                child_expires_at: t(8_000),
                mode: InheritanceMode::Narrower,
                child_delegation: DelegationRule::DelegableWithNarrowerScope,
                child_limits: None,
            },
            t(1_100),
        )
        .expect("a narrower child must derive from the root through the ledger");

    let child_spec = ExecutionSpec::new("echo", IdentityRef::root("child-agent").with_ancestor("root-agent"))
        .with_requirement(ControlRequirement::observe(CapabilityDomain::FilesystemRead).with_scope(child_scope.clone()))
        .with_lease(child_lease.clone());
    let child_witness = authority_gate(&child_spec, &root_ancestry, now).expect("child must gate against root");
    let child_ancestry = Ancestry::Parent(Box::new(ParentAuthority::from_gated_spec(&child_spec, &child_witness)));

    // Generation 2 (grandchild), still through the ledger, narrower again.
    let grandchild_scope = RequirementScope::Selectors(vec![permit_only_selector("/workspace/a/sub")]);
    let grandchild_lease = ledger
        .derive_child(
            &child_lease,
            ChildLeaseRequest {
                child_id: LeaseId::new("grandchild-fs-lease"),
                child_subject: IdentityRef::root("grandchild-agent")
                    .with_ancestor("root-agent")
                    .with_ancestor("child-agent"),
                child_scope: grandchild_scope.clone(),
                child_expires_at: t(7_000),
                mode: InheritanceMode::Narrower,
                child_delegation: DelegationRule::NotDelegable,
                child_limits: None,
            },
            t(1_200),
        )
        .expect("a narrower grandchild must derive from the child through the ledger");

    let grandchild_identity = IdentityRef::root("grandchild-agent")
        .with_ancestor("root-agent")
        .with_ancestor("child-agent");
    let grandchild_spec = ExecutionSpec::new("echo", grandchild_identity.clone())
        .with_requirement(
            ControlRequirement::observe(CapabilityDomain::FilesystemRead).with_scope(grandchild_scope.clone()),
        )
        .with_lease(grandchild_lease.clone());

    // Sanity (positive control): the genuinely-narrower 3-generation chain
    // gates cleanly before either adversarial step below -- without this,
    // (a) and (b) would be equally well explained by a gate that refuses
    // every grandchild unconditionally.
    assert!(
        authority_gate(&grandchild_spec, &child_ancestry, now).is_ok(),
        "a genuinely narrower 3-generation chain must gate cleanly"
    );

    // -----------------------------------------------------------------
    // (a) Widening at generation 2, isolated from "wider than the root":
    // /workspace/b is a sibling of the child's own /workspace/a grant, so
    // it is outside the *immediate parent*'s ceiling while still squarely
    // inside the root's /workspace grant.
    // -----------------------------------------------------------------
    let widened_scope = RequirementScope::Selectors(vec![permit_only_selector("/workspace/b")]);
    assert_eq!(
        scope_order::order_for(CapabilityDomain::FilesystemRead).compare(&child_scope, &widened_scope),
        ScopeOrdering::Wider,
        "fixture-honesty: /workspace/b is a sibling of /workspace/a, not a sub-path of it, so this \
         attack scope really does exceed the immediate parent's grant"
    );
    assert_eq!(
        scope_order::order_for(CapabilityDomain::FilesystemRead).compare(&root_scope, &widened_scope),
        ScopeOrdering::Narrower,
        "fixture-honesty: /workspace/b is still inside the root's own /workspace grant -- this \
         scope is wide relative to the child specifically, not invalid in general"
    );

    let widened_grandchild_lease = CapabilityLease::new(
        LeaseId::new("grandchild-fs-lease-widened"),
        grandchild_identity.clone(),
        CapabilityDomain::FilesystemRead,
        widened_scope.clone(),
        t(1_000),
        t(2_000),
        LeaseBasis::new(IdentityRef::root("issuer"), "test fixture: hand-built, not derived"),
    );
    let widened_spec = ExecutionSpec::new("echo", grandchild_identity.clone())
        .with_requirement(
            ControlRequirement::observe(CapabilityDomain::FilesystemRead).with_scope(widened_scope.clone()),
        )
        .with_lease(widened_grandchild_lease.clone());
    assert_eq!(
        authority_gate(&widened_spec, &child_ancestry, now),
        Err(AuthorityRefusal::ChildExceedsParent {
            domain: CapabilityDomain::FilesystemRead
        }),
        "widening at generation 2 must be refused as ChildExceedsParent against the immediate parent"
    );

    // Positive control: the identical hand-built lease, gated directly
    // against the root ancestry (the child hop skipped entirely), admits
    // -- it is narrower than the root's own grant and carries no
    // provenance claiming a derivation this skip would falsify. This is
    // the control a 2-generation fixture cannot express: it proves (a)'s
    // refusal is attributable to the *immediate* parent's ceiling, not to
    // the scope being wide in any absolute sense.
    assert!(
        authority_gate(&widened_spec, &root_ancestry, now).is_ok(),
        "unscoped control: the identical lease, checked directly against the root (which really \
         does cover /workspace/b), must admit -- isolating (a)'s refusal as specific to the \
         immediate parent's ceiling"
    );

    // -----------------------------------------------------------------
    // (b) Revoking the root.
    // -----------------------------------------------------------------
    ledger.revoke(root_lease.id(), 1, "operator revoked the root lease");

    // (b-i) The immediate child is refused when re-gated against a fresh
    // `ParentAuthority` snapshot carrying the root's now-revoked lease
    // value -- the same mechanism the existing single-hop tests already
    // pin. An empty-requirement spec always gates (mirrors
    // `attenuation.rs`'s own `concurrent_child_derivation_...` test) --
    // this is how the post-revocation snapshot is produced here without
    // depending on the production orchestrator's own re-resolution path.
    let root_spec_revoked = ExecutionSpec::new("echo", IdentityRef::root("root-agent")).with_lease(
        root_lease.clone().with_revocation(RevocationState::Revoked {
            generation: 1,
            reason: "operator revoked the root lease".to_string(),
        }),
    );
    let root_witness_post_revoke = authority_gate(&root_spec_revoked, &Ancestry::Root, now)
        .expect("an empty-requirement spec always gates, even carrying a revoked lease");
    let root_ancestry_post_revoke = Ancestry::Parent(Box::new(ParentAuthority::from_gated_spec(
        &root_spec_revoked,
        &root_witness_post_revoke,
    )));

    let child_refusal_after_revoke = authority_gate(&child_spec, &root_ancestry_post_revoke, now)
        .expect_err("the child must be refused once the root's lease is observed as revoked");
    assert!(
        matches!(
            child_refusal_after_revoke,
            AuthorityRefusal::LeaseInvalid {
                domain: CapabilityDomain::FilesystemRead,
                reason: LeaseInvalid::Revoked { .. }
            }
        ),
        "the immediate child must be refused with LeaseInvalid::Revoked, got: {child_refusal_after_revoke:?}"
    );

    // (b-ii) The ledger itself refuses to mint any *fresh* child from the
    // now-revoked root lease.
    let fresh_child_attempt = ledger.derive_child(
        &root_lease,
        ChildLeaseRequest {
            child_id: LeaseId::new("child-fs-lease-post-revoke"),
            child_subject: IdentityRef::root("child-agent").with_ancestor("root-agent"),
            child_scope: child_scope.clone(),
            child_expires_at: t(8_000),
            mode: InheritanceMode::Narrower,
            child_delegation: DelegationRule::DelegableWithNarrowerScope,
            child_limits: None,
        },
        t(1_600),
    );
    assert_eq!(
        fresh_child_attempt,
        Err(DelegationDenied::ParentRevoked),
        "the ledger must refuse to mint a fresh child directly from a revoked parent lease"
    );

    // (b-iii) Documented, pinned gap -- the limit of (b-i)/(b-ii)'s reach,
    // verified empirically rather than assumed: an already-minted
    // grandchild `ParentAuthority`, whose own immediate parent (the child
    // lease) was never itself revoked, is unaffected by the root's
    // revocation. The grandchild still gates cleanly against the
    // already-held `child_ancestry` ...
    assert!(
        authority_gate(&grandchild_spec, &child_ancestry, now).is_ok(),
        "documented gap: an already-held child ancestry snapshot is not retroactively invalidated \
         by a revocation of ITS OWN parent (the root) -- only the hop re-gated directly against \
         the revoked lease is caught. If this assertion starts failing, the gap has been closed \
         and this test (plus J82's recorded finding) needs to be revisited deliberately, not \
         silently."
    );
    // ... and a *fresh* grandchild can still be minted from the
    // still-active child lease through the very same ledger that just
    // refused a fresh child from the revoked root -- the ledger's
    // `register_parent`/`revoke` state is keyed per lease id, not
    // transitively across a derivation chain.
    let fresh_grandchild_attempt = ledger.derive_child(
        &child_lease,
        ChildLeaseRequest {
            child_id: LeaseId::new("grandchild-fs-lease-post-root-revoke"),
            child_subject: grandchild_identity.clone(),
            child_scope: grandchild_scope.clone(),
            child_expires_at: t(7_000),
            mode: InheritanceMode::Narrower,
            child_delegation: DelegationRule::NotDelegable,
            child_limits: None,
        },
        t(1_700),
    );
    assert!(
        fresh_grandchild_attempt.is_ok(),
        "documented gap: a fresh grandchild derived from the still-active child lease is not \
         blocked by the root's revocation -- the ledger tracks revocation per lease id, not \
         transitively up the ancestry chain"
    );
}

/// Target-contract pin (per AAASM-6290's "document, don't fix" scope): the
/// property the ticket's own AC literally asks for -- revoking the root's
/// authority reaches the grandchild even through an already-held,
/// already-minted `ParentAuthority` snapshot whose immediate parent was
/// never itself revoked. The test above shows this does **not** currently
/// hold; this one pins the desired behavior as a known-failing target so a
/// future fix (transitively re-validating the whole ancestry chain, not
/// just the immediate parent, inside `check_attenuation`) has a concrete
/// regression test to turn green, without this QA subtask touching
/// `authority_gate` or `DelegationLedger` itself.
#[test]
#[ignore = "AAASM-6290 ST-3 documented gap: revocation does not transitively reach a grandchild \
            through an already-held, unaffected intermediate ParentAuthority snapshot -- see the \
            passing characterization test above for the current (gap) behavior. Run with \
            --ignored to reproduce; candidate Bug not yet filed."]
fn a_grandchild_is_refused_once_any_ancestor_up_to_the_root_is_revoked_target_contract() {
    let now = t(1_500);

    let root_scope = RequirementScope::Selectors(vec![permit_only_selector("/workspace")]);
    let root_lease = CapabilityLease::new(
        LeaseId::new("root-fs-lease-target"),
        IdentityRef::root("root-agent"),
        CapabilityDomain::FilesystemRead,
        root_scope,
        t(1_000),
        t(9_000),
        LeaseBasis::new(IdentityRef::root("issuer"), "test fixture: root grant"),
    )
    .with_delegation(DelegationRule::DelegableWithNarrowerScope);

    let ledger = DelegationLedger::new();
    ledger.register_parent(&root_lease);

    let child_scope = RequirementScope::Selectors(vec![permit_only_selector("/workspace/a")]);
    let child_lease = ledger
        .derive_child(
            &root_lease,
            ChildLeaseRequest {
                child_id: LeaseId::new("child-fs-lease-target"),
                child_subject: IdentityRef::root("child-agent").with_ancestor("root-agent"),
                child_scope: child_scope.clone(),
                child_expires_at: t(8_000),
                mode: InheritanceMode::Narrower,
                child_delegation: DelegationRule::DelegableWithNarrowerScope,
                child_limits: None,
            },
            t(1_100),
        )
        .expect("a narrower child must derive from the root through the ledger");

    let child_spec = ExecutionSpec::new("echo", IdentityRef::root("child-agent").with_ancestor("root-agent"))
        .with_requirement(ControlRequirement::observe(CapabilityDomain::FilesystemRead).with_scope(child_scope.clone()))
        .with_lease(child_lease.clone());
    let root_spec = ExecutionSpec::new("echo", IdentityRef::root("root-agent")).with_lease(root_lease.clone());
    let root_witness = authority_gate(&root_spec, &Ancestry::Root, now).expect("root's own launch must gate");
    let root_ancestry = Ancestry::Parent(Box::new(ParentAuthority::from_gated_spec(&root_spec, &root_witness)));
    let child_witness = authority_gate(&child_spec, &root_ancestry, now).expect("child must gate against root");
    let child_ancestry = Ancestry::Parent(Box::new(ParentAuthority::from_gated_spec(&child_spec, &child_witness)));

    let grandchild_scope = RequirementScope::Selectors(vec![permit_only_selector("/workspace/a/sub")]);
    let grandchild_lease = ledger
        .derive_child(
            &child_lease,
            ChildLeaseRequest {
                child_id: LeaseId::new("grandchild-fs-lease-target"),
                child_subject: IdentityRef::root("grandchild-agent")
                    .with_ancestor("root-agent")
                    .with_ancestor("child-agent"),
                child_scope: grandchild_scope.clone(),
                child_expires_at: t(7_000),
                mode: InheritanceMode::Narrower,
                child_delegation: DelegationRule::NotDelegable,
                child_limits: None,
            },
            t(1_200),
        )
        .expect("a narrower grandchild must derive from the child through the ledger");
    let grandchild_spec = ExecutionSpec::new(
        "echo",
        IdentityRef::root("grandchild-agent")
            .with_ancestor("root-agent")
            .with_ancestor("child-agent"),
    )
    .with_requirement(ControlRequirement::observe(CapabilityDomain::FilesystemRead).with_scope(grandchild_scope))
    .with_lease(grandchild_lease);

    ledger.revoke(root_lease.id(), 1, "operator revoked the root lease");

    // Target behavior: this should be refused once the root -- two hops
    // up -- is revoked, even though `child_ancestry`'s own immediate
    // parent lease (the child's) was never itself revoked.
    assert!(
        authority_gate(&grandchild_spec, &child_ancestry, now).is_err(),
        "target contract: a grandchild must be refused once ANY ancestor up to the root is \
         revoked, not only its own immediate parent"
    );
}
