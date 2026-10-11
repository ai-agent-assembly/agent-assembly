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

use std::sync::Arc;
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
    let parent_ledger = Arc::new(DelegationLedger::new());
    parent_ledger
        .register_parent(&parent_lease)
        .expect("a provenance-free parent lease registers as a root");
    let ancestry = Ancestry::Parent(Box::new(ParentAuthority::from_gated_spec(
        &parent_spec,
        &parent_witness,
        parent_ledger,
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
    let parent_ledger = Arc::new(DelegationLedger::new());
    parent_ledger
        .register_parent(&parent_lease)
        .expect("a provenance-free parent lease registers as a root");
    let ancestry = Ancestry::Parent(Box::new(ParentAuthority::from_gated_spec(
        &parent_spec,
        &parent_witness,
        parent_ledger,
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
/// (b) revoking the root's lease reaches every descendant: the immediate
///     child is refused when re-gated against a `ParentAuthority` snapshot
///     carrying the root's now-revoked lease, the ledger refuses to mint any
///     *fresh* child from the revoked root, an already-held grandchild
///     ancestry whose immediate parent was never itself revoked is refused
///     with `RevokedInLedger` naming the root, and a *fresh* grandchild
///     under the still-active child lease is refused with `ParentRevoked`.
///     Before AAASM-6307 the last two held (the documented gap); they are now
///     asserted as refusals.
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
    let ledger = Arc::new(DelegationLedger::new());
    ledger
        .register_parent(&root_lease)
        .expect("a provenance-free root lease registers");
    let root_ancestry = Ancestry::Parent(Box::new(ParentAuthority::from_gated_spec(
        &root_spec,
        &root_witness,
        Arc::clone(&ledger),
    )));

    // Generation 1 (child): derived through the real ledger, so its
    // provenance carries the root's actual revocation generation rather
    // than a hand-asserted one.

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
    let child_ancestry = Ancestry::Parent(Box::new(ParentAuthority::from_gated_spec(
        &child_spec,
        &child_witness,
        Arc::clone(&ledger),
    )));

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
        Arc::clone(&ledger),
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

    // (b-iii) Transitive reach (AAASM-6307): an already-minted grandchild
    // `ParentAuthority` whose own immediate parent (the child lease) was
    // never itself revoked is refused once the root is revoked, because the
    // gate re-reads the live ledger and walks the whole chain. (Before
    // AAASM-6307 this gated cleanly -- the gap this test used to pin.)
    assert_eq!(
        authority_gate(&grandchild_spec, &child_ancestry, now),
        Err(AuthorityRefusal::RevokedInLedger {
            domain: CapabilityDomain::FilesystemRead,
            lease: root_lease.id().clone(),
            reason: "operator revoked the root lease".to_string(),
        }),
        "an already-held descendant ancestry must be refused once ANY ancestor up to the root is revoked"
    );
    // ... but a *fresh* grandchild can no longer be minted from the
    // still-active child lease: AAASM-6307 made the ledger record parent
    // edges, so revoking the root reaches every descendant derivation.
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
    assert_eq!(
        fresh_grandchild_attempt,
        Err(DelegationDenied::ParentRevoked),
        "a fresh grandchild derived under a revoked root must be refused (transitive revocation)"
    );
}

/// The property AAASM-6307's acceptance criteria ask for, which used to be an
/// `#[ignore]`d target: revoking the root's authority reaches the grandchild
/// even through an already-held, already-minted `ParentAuthority` snapshot
/// whose immediate parent was never itself revoked.
#[test]
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

    let ledger = Arc::new(DelegationLedger::new());
    ledger
        .register_parent(&root_lease)
        .expect("a provenance-free root lease registers");

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
    let root_ancestry = Ancestry::Parent(Box::new(ParentAuthority::from_gated_spec(
        &root_spec,
        &root_witness,
        Arc::clone(&ledger),
    )));
    let child_witness = authority_gate(&child_spec, &root_ancestry, now).expect("child must gate against root");
    let child_ancestry = Ancestry::Parent(Box::new(ParentAuthority::from_gated_spec(
        &child_spec,
        &child_witness,
        Arc::clone(&ledger),
    )));

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

    // Positive control: before the revocation the same held ancestry admits
    // the grandchild, so the refusal below is attributable to the revocation.
    assert!(authority_gate(&grandchild_spec, &child_ancestry, now).is_ok());

    ledger.revoke(root_lease.id(), 1, "operator revoked the root lease");

    // Two hops up, while `child_ancestry`'s own immediate parent lease (the
    // child's) was never itself revoked.
    assert_eq!(
        authority_gate(&grandchild_spec, &child_ancestry, now),
        Err(AuthorityRefusal::RevokedInLedger {
            domain: CapabilityDomain::FilesystemRead,
            lease: root_lease.id().clone(),
            reason: "operator revoked the root lease".to_string(),
        })
    );
}

// ---------------------------------------------------------------------
// AAASM-6307: transitive revocation matrix. Every chain is built through the
// production `DelegationLedger::derive_child` and gated through held
// `ParentAuthority` snapshots taken BEFORE the revocation, because a snapshot
// that still reads as active is exactly what the old gate trusted.
// ---------------------------------------------------------------------

const NOW: u64 = 1_500;

fn identity_at(i: usize) -> IdentityRef {
    let mut identity = IdentityRef::root(format!("chain-agent-{i}"));
    for ancestor in 0..i {
        identity = identity.with_ancestor(format!("chain-agent-{ancestor}"));
    }
    identity
}

fn path_at(i: usize) -> String {
    let mut path = "/workspace".to_string();
    for level in 1..=i {
        path.push_str(&format!("/d{level}"));
    }
    path
}

fn request_for(id: &str, subject: IdentityRef, path: &str, expires: u64) -> ChildLeaseRequest {
    ChildLeaseRequest {
        child_id: LeaseId::new(id),
        child_subject: subject,
        child_scope: RequirementScope::Selectors(vec![permit_only_selector(path)]),
        child_expires_at: t(expires),
        mode: InheritanceMode::Narrower,
        child_delegation: DelegationRule::DelegableWithNarrowerScope,
        child_limits: None,
    }
}

fn spec_for(lease: &CapabilityLease) -> ExecutionSpec {
    ExecutionSpec::new("echo", lease.subject().clone())
        .with_requirement(
            ControlRequirement::observe(CapabilityDomain::FilesystemRead).with_scope(lease.scope().clone()),
        )
        .with_lease(lease.clone())
}

/// A delegation chain `leases[0] -> leases[1] -> ...`, each hop derived through
/// the shared ledger and each hop's `ParentAuthority` held from before any
/// revocation.
struct Chain {
    ledger: Arc<DelegationLedger>,
    leases: Vec<CapabilityLease>,
    specs: Vec<ExecutionSpec>,
    /// `ancestries[i]` is node `i`'s authority as a parent.
    ancestries: Vec<Ancestry>,
}

impl Chain {
    fn build(tag: &str, depth: usize) -> Self {
        assert!(depth >= 2);
        let ledger = Arc::new(DelegationLedger::new());
        let root = CapabilityLease::new(
            LeaseId::new(format!("{tag}-lease-0")),
            identity_at(0),
            CapabilityDomain::FilesystemRead,
            RequirementScope::Selectors(vec![permit_only_selector(&path_at(0))]),
            t(1_000),
            t(9_000),
            LeaseBasis::new(IdentityRef::root("issuer"), "test fixture: root grant"),
        )
        .with_delegation(DelegationRule::DelegableWithNarrowerScope);
        ledger
            .register_parent(&root)
            .expect("a provenance-free root lease registers");
        let root_spec = spec_for(&root);
        let root_witness = authority_gate(&root_spec, &Ancestry::Root, t(NOW)).expect("root gates");
        let mut chain = Chain {
            ancestries: vec![Ancestry::Parent(Box::new(ParentAuthority::from_gated_spec(
                &root_spec,
                &root_witness,
                Arc::clone(&ledger),
            )))],
            specs: vec![root_spec],
            leases: vec![root],
            ledger,
        };
        for i in 1..depth {
            let lease = chain
                .ledger
                .derive_child(
                    &chain.leases[i - 1],
                    request_for(
                        &format!("{tag}-lease-{i}"),
                        identity_at(i),
                        &path_at(i),
                        9_000 - 100 * i as u64,
                    ),
                    t(1_100),
                )
                .expect("a narrower hop derives while every ancestor is active");
            let spec = spec_for(&lease);
            let witness = authority_gate(&spec, &chain.ancestries[i - 1], t(NOW)).expect("hop gates");
            chain
                .ancestries
                .push(Ancestry::Parent(Box::new(ParentAuthority::from_gated_spec(
                    &spec,
                    &witness,
                    Arc::clone(&chain.ledger),
                ))));
            chain.specs.push(spec);
            chain.leases.push(lease);
        }
        chain
    }

    /// Gate node `j` against the held authority of node `j - 1`.
    fn gate(&self, j: usize) -> Result<(), AuthorityRefusal> {
        authority_gate(&self.specs[j], &self.ancestries[j - 1], t(NOW)).map(|_| ())
    }

    fn revoke(&self, i: usize) {
        self.ledger
            .revoke(self.leases[i].id(), 1, format!("operator revoked lease {i}"));
    }

    fn revoked_in_ledger(&self, i: usize) -> AuthorityRefusal {
        AuthorityRefusal::RevokedInLedger {
            domain: CapabilityDomain::FilesystemRead,
            lease: self.leases[i].id().clone(),
            reason: format!("operator revoked lease {i}"),
        }
    }

    fn derive_from(&self, parent: usize, id: &str) -> Result<CapabilityLease, DelegationDenied> {
        self.ledger.derive_child(
            &self.leases[parent],
            request_for(id, identity_at(parent + 1), &path_at(parent + 1), 7_000),
            t(1_200),
        )
    }
}

/// One hop, held snapshot: the root's `ParentAuthority` was taken while the
/// root was active and is still held; revoking the root in the ledger must
/// refuse the child gated against it. The old gate compared only against the
/// snapshot's own (still `Active`) lease value and admitted it.
#[test]
fn a_held_root_snapshot_is_refused_once_the_ledger_revokes_the_root() {
    let chain = Chain::build("single-hop", 2);
    assert_eq!(chain.gate(1), Ok(()), "positive control: admitted before the revoke");
    chain.revoke(0);
    assert_eq!(chain.gate(1), Err(chain.revoked_in_ledger(0)));
}

#[test]
fn revoking_the_root_refuses_every_descendant_at_depth_three_and_four() {
    for depth in [3, 4] {
        let chain = Chain::build(&format!("root-revoke-{depth}"), depth);
        for j in 1..depth {
            assert_eq!(
                chain.gate(j),
                Ok(()),
                "positive control: hop {j} of depth {depth} admits"
            );
        }
        chain.revoke(0);
        for j in 1..depth {
            assert_eq!(
                chain.gate(j),
                Err(chain.revoked_in_ledger(0)),
                "hop {j} of a depth-{depth} chain must be refused once the root is revoked"
            );
        }
    }
}

#[test]
fn revoking_the_middle_refuses_its_descendants_and_leaves_the_root_gating() {
    let chain = Chain::build("middle", 4);
    for j in 1..4 {
        assert_eq!(chain.gate(j), Ok(()), "positive control: hop {j} admits");
    }
    chain.revoke(1);

    assert_eq!(
        chain.gate(1),
        Err(chain.revoked_in_ledger(1)),
        "the revoked lease itself"
    );
    assert_eq!(chain.gate(2), Err(chain.revoked_in_ledger(1)), "its child");
    assert_eq!(chain.gate(3), Err(chain.revoked_in_ledger(1)), "its grandchild");

    // The root is unaffected: it still derives, and a sibling of the revoked
    // lease still gates against the root's held authority.
    let sibling = chain
        .ledger
        .derive_child(
            &chain.leases[0],
            request_for("middle-sibling", identity_at(1), "/workspace/sibling", 7_000),
            t(1_200),
        )
        .expect("the root is still active, so it still derives");
    assert_eq!(
        authority_gate(&spec_for(&sibling), &chain.ancestries[0], t(NOW)).map(|_| ()),
        Ok(())
    );
}

#[test]
fn revoking_one_leaf_leaves_its_sibling_and_its_parent_admitted() {
    let chain = Chain::build("leaf", 3);
    let sibling = chain
        .derive_from(1, "leaf-sibling")
        .expect("a sibling of the leaf derives from the same parent");
    // The sibling reuses the leaf's path, so it is a sibling in the tree, not
    // a different scope.
    let sibling_spec = spec_for(&sibling);
    assert!(authority_gate(&sibling_spec, &chain.ancestries[1], t(NOW)).is_ok());
    assert_eq!(chain.gate(2), Ok(()), "positive control: the leaf admits");

    chain.revoke(2);

    assert_eq!(chain.gate(2), Err(chain.revoked_in_ledger(2)), "the revoked leaf");
    assert!(
        authority_gate(&sibling_spec, &chain.ancestries[1], t(NOW)).is_ok(),
        "the sibling must still be admitted"
    );
    assert_eq!(chain.gate(1), Ok(()), "the leaf's parent must still be admitted");
}

#[test]
fn a_parent_the_ledger_cannot_place_is_refused_rather_than_read_as_unrevoked() {
    let order = scope_order::order_for(CapabilityDomain::FilesystemRead);

    // (a) A ledger that never saw the parent lease at all.
    let root = CapabilityLease::new(
        LeaseId::new("unknown-root"),
        identity_at(0),
        CapabilityDomain::FilesystemRead,
        RequirementScope::Selectors(vec![permit_only_selector("/workspace")]),
        t(1_000),
        t(9_000),
        LeaseBasis::new(IdentityRef::root("issuer"), "test fixture"),
    )
    .with_delegation(DelegationRule::DelegableWithNarrowerScope);
    let root_spec = spec_for(&root);
    let root_witness = authority_gate(&root_spec, &Ancestry::Root, t(NOW)).expect("root gates");
    let child = root
        .derive_child(
            request_for("unknown-child", identity_at(1), "/workspace/d1", 8_000),
            order,
            t(1_100),
        )
        .expect("bare derivation");
    let child_spec = spec_for(&child);

    let empty_ledger = Arc::new(DelegationLedger::new());
    let against_empty = Ancestry::Parent(Box::new(ParentAuthority::from_gated_spec(
        &root_spec,
        &root_witness,
        empty_ledger,
    )));
    assert_eq!(
        authority_gate(&child_spec, &against_empty, t(NOW)).map(|_| ()),
        Err(AuthorityRefusal::LedgerUnverifiable {
            domain: CapabilityDomain::FilesystemRead,
            lease: LeaseId::new("unknown-root"),
        })
    );

    // Control: the identical specs against a ledger that registered the root.
    let known = Arc::new(DelegationLedger::new());
    known.register_parent(&root).expect("registers");
    let against_known = Ancestry::Parent(Box::new(ParentAuthority::from_gated_spec(
        &root_spec,
        &root_witness,
        known,
    )));
    assert!(authority_gate(&child_spec, &against_known, t(NOW)).is_ok());

    // (b) A parent derived by the bare `CapabilityLease::derive_child`, which
    // bypasses the ledger: the root is registered, the middle lease is not.
    let ledger = Arc::new(DelegationLedger::new());
    ledger.register_parent(&root).expect("registers");
    let bare_middle = child;
    let bare_middle_spec = spec_for(&bare_middle);
    let middle_witness =
        authority_gate(&bare_middle_spec, &against_known, t(NOW)).expect("middle gates against its parent");
    let held_middle = Ancestry::Parent(Box::new(ParentAuthority::from_gated_spec(
        &bare_middle_spec,
        &middle_witness,
        Arc::clone(&ledger),
    )));
    let grandchild = bare_middle
        .derive_child(
            request_for("unknown-grandchild", identity_at(2), "/workspace/d1/d2", 7_000),
            order,
            t(1_200),
        )
        .expect("bare derivation");
    assert_eq!(
        authority_gate(&spec_for(&grandchild), &held_middle, t(NOW)).map(|_| ()),
        Err(AuthorityRefusal::LedgerUnverifiable {
            domain: CapabilityDomain::FilesystemRead,
            lease: LeaseId::new("unknown-child"),
        }),
        "a bare-derived parent the ledger never recorded must not be trusted"
    );
}

/// A mid-chain lease must not be registrable as a root: that would sever its
/// link to the ancestors above it, so revoking them would no longer reach it.
#[test]
fn a_mid_chain_lease_cannot_be_registered_as_a_root_to_sever_the_chain() {
    let chain = Chain::build("sever", 3);

    assert_eq!(
        chain.ledger.register_parent(&chain.leases[1]),
        Err(DelegationDenied::DuplicateLeaseId),
        "re-registering a known mid-chain lease must be refused, not re-seeded as a root"
    );
    let fresh_ledger = DelegationLedger::new();
    assert_eq!(
        fresh_ledger.register_parent(&chain.leases[1]),
        Err(DelegationDenied::AncestryUnverifiable),
        "a lease carrying provenance can never be a root in any ledger"
    );

    chain.revoke(0);
    assert_eq!(
        chain.gate(2),
        Err(chain.revoked_in_ledger(0)),
        "the chain is still intact"
    );
}

#[test]
fn a_known_lease_id_cannot_be_resurrected_by_rederiving_or_reregistering() {
    let chain = Chain::build("resurrect", 2);
    chain.revoke(1);
    let revoked_id = chain.leases[1].id().clone();

    assert_eq!(
        chain.derive_from(0, "resurrect-lease-1"),
        Err(DelegationDenied::DuplicateLeaseId),
        "re-deriving a revoked child id must be refused"
    );
    let same_id_root = CapabilityLease::new(
        revoked_id,
        identity_at(1),
        CapabilityDomain::FilesystemRead,
        RequirementScope::Selectors(vec![permit_only_selector("/workspace/d1")]),
        t(1_000),
        t(9_000),
        LeaseBasis::new(IdentityRef::root("issuer"), "test fixture"),
    );
    assert_eq!(
        chain.ledger.register_parent(&same_id_root),
        Err(DelegationDenied::DuplicateLeaseId),
        "re-registering a revoked id with a fresh Active clone must be refused"
    );
    assert_eq!(chain.gate(1), Err(chain.revoked_in_ledger(1)), "and it stays revoked");

    // A revocation recorded before the lease was ever registered is honored
    // too: the id is known (unlinked), so it can no longer be registered.
    let ghost = LeaseId::new("ghost");
    chain.ledger.revoke(&ghost, 1, "revoked before registration");
    let ghost_lease = CapabilityLease::new(
        ghost,
        identity_at(0),
        CapabilityDomain::FilesystemRead,
        RequirementScope::Selectors(vec![permit_only_selector("/workspace")]),
        t(1_000),
        t(9_000),
        LeaseBasis::new(IdentityRef::root("issuer"), "test fixture"),
    );
    assert_eq!(
        chain.ledger.register_parent(&ghost_lease),
        Err(DelegationDenied::DuplicateLeaseId)
    );
}

#[test]
fn a_fresh_derivation_under_a_revoked_ancestor_is_refused_at_every_depth() {
    let chain = Chain::build("derive-time", 3);
    // Positive control: both the root and the middle still derive.
    chain
        .derive_from(0, "derive-time-ok-0")
        .expect("derives under an active root");
    chain
        .derive_from(1, "derive-time-ok-1")
        .expect("derives under an active chain");

    chain.revoke(0);
    assert_eq!(
        chain.derive_from(1, "derive-time-g1"),
        Err(DelegationDenied::ParentRevoked)
    );
    assert_eq!(
        chain.derive_from(2, "derive-time-g2"),
        Err(DelegationDenied::ParentRevoked)
    );
    assert_eq!(
        chain.derive_from(0, "derive-time-g0"),
        Err(DelegationDenied::ParentRevoked)
    );
}
