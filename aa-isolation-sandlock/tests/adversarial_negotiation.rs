//! Adversarial scenarios that need no kernel and no mechanism (AAASM-5712).
//!
//! # Why this file is separate from `adversarial_boundary_linux.rs`
//!
//! Every scenario here runs on **any** host, and none of them declines. They
//! attack the part of the boundary that is a decision rather than a mechanism:
//! what a backend refuses, what it may claim, and whether *blocked*,
//! *unsupported* and *unmeasured* stay three different answers. A green run of
//! this file says nothing about whether a kernel confines anything — that is
//! `adversarial_boundary_linux.rs`, which declines with a recorded reason
//! everywhere the mechanism is absent.
//!
//! Splitting them is the acceptance criterion about CI legibility, held as a
//! file boundary rather than a comment: a reader of a CI log can see which
//! binary ran and therefore which half of the suite a green result covers.
//!
//! # Both backends, one interface
//!
//! The scenarios below drive `aa_isolation::mock::MockBackend` and
//! `SandlockBackend` through `AdversarialTarget`, which exposes nothing beyond
//! the contract's own `plan`/`prepare`/`spawn`/`evidence`. A refusal rule that
//! held for only one of them would fail here.

use std::collections::BTreeSet;

use aa_isolation::mock::MockBackend;
use aa_isolation::{
    negotiate, BackendCapabilities, BackendIdentity, CapabilityDomain, ControlRequirement, EnforcementEvidence,
    EnforcementPlan, IdentityRef, IsolationBackend, LaunchPosture, Lowering, PlanRefusal, Provenance, RefusalReason,
    RequirementScope, ResourceLimits, SupportLevel,
};
use aa_isolation_sandlock::capability::{ABSTRACT_UNIX_SOCKET_SCOPE, SIGNAL_SCOPE};
use aa_isolation_sandlock::host::{BackendLookupError, HostFacts};
use aa_isolation_sandlock::probe::{ConfinementProbe, Observation};
use aa_isolation_sandlock::{capability, SandlockBackend};

mod adversarial;

use adversarial::{
    assert_blocked_unsupported_and_unmeasured_stay_distinct, assert_claim_is_promoted_only_by_a_decision_record,
    assert_observation_is_never_promoted_to_prevention, assert_required_prevention_refused_by_every_uncapable_backend,
    measured, prevention_claims, quote, required_prevention_spec, AdversarialTarget, AttackFamily, MockTarget,
    SandlockTarget, Scratch,
};

// ---------------------------------------------------------------------------
// Backend posture: missing, disabled, partially configured, observe-only.
// ---------------------------------------------------------------------------

/// AC: a required prevention requirement is refused by every backend that
/// cannot enforce it, and the refusal is a property of the contract rather than
/// of one mechanism.
///
/// The control is `MockBackend::preventing`, which differs from
/// `MockBackend::observing` in exactly one field — mediation — so the refusal
/// below cannot be attributed to some other weakened axis. Body shared with the
/// native lane (AAASM-5805) via `adversarial::
/// assert_required_prevention_refused_by_every_uncapable_backend` — nothing in
/// it is Sandlock-specific beyond which backend stands in for "absent".
#[test]
fn a_required_prevention_is_refused_by_every_backend_that_cannot_enforce_it() {
    let scenario = "adversarial: required prevention refused by every backend that cannot enforce it";

    let inert = MockTarget {
        backend: MockBackend::inert(),
        label: "mock/inert",
    };
    let observing = MockTarget {
        backend: MockBackend::observing(CapabilityDomain::ALL),
        label: "mock/observe-only",
    };
    let absent = SandlockTarget(SandlockBackend::unavailable(&BackendLookupError::NotOnPath));
    let preventing = MockTarget {
        backend: MockBackend::preventing(CapabilityDomain::ALL),
        label: "mock/preventing",
    };

    assert_required_prevention_refused_by_every_uncapable_backend(
        scenario,
        &[&inert as &dyn AdversarialTarget, &observing, &absent],
        &preventing,
    );
}

/// AC: observation is never promoted to enforcement, on any backend. Body
/// shared with the native lane: both sides of the comparison are `MockBackend`
/// configurations, so nothing here is Sandlock-specific.
#[test]
fn observation_is_never_promoted_to_prevention_on_any_backend() {
    assert_observation_is_never_promoted_to_prevention("adversarial: observation is never promoted to prevention");
}

/// AC: audit/evidence assertions confirm blocked, unsupported and unmeasured
/// are not conflated. Body shared with the native lane: the report's
/// vocabulary for "nothing is known" is a property of
/// `aa_isolation::IsolationReport`, not of any one mechanism.
#[test]
fn blocked_unsupported_and_unmeasured_stay_three_distinct_report_states() {
    assert_blocked_unsupported_and_unmeasured_stay_distinct(
        "adversarial: blocked, unsupported and unmeasured are distinct report states",
    );
}

/// AC: a claim is promoted only by a decision record, and corroboration is not
/// a decision. Body shared with the native lane: the promotion rule lives in
/// `aa_isolation::EnforcementEvidence`, not in any one mechanism.
#[test]
fn a_claim_is_promoted_only_by_a_decision_record() {
    assert_claim_is_promoted_only_by_a_decision_record("adversarial: only a decision record promotes a claim");
}

// ---------------------------------------------------------------------------
// The first capability set: what it refuses rather than approximates.
// ---------------------------------------------------------------------------

/// The backend's own capability logic, driven with a host it does not have.
///
/// `SandlockBackend::from_measured` is `pub(crate)` on purpose — a public
/// constructor taking a probe would let a caller hand in "denied" without
/// anything having been denied. So this file assembles the same two steps
/// `SandlockBackend::plan` performs, from the public pieces:
/// `capability::discover` for the report and `capability::narrow_for` plus
/// `negotiate` for the decision. Every artifact that *decides* is the real one;
/// only the host facts and the probe are supplied, which is the whole point —
/// the question here is what the contract does with a measurement, not whether
/// a kernel took one.
fn measured_capabilities(degraded: &[String]) -> BackendCapabilities {
    let facts = HostFacts::for_test("/usr/bin/sandlock", "sandlock 0.8.6", None);
    let probe = ConfinementProbe {
        filesystem_read: Observation::Denied,
        filesystem_write: Observation::Denied,
        process_ceiling: Observation::Denied,
        network_egress: Observation::Denied,
    };
    capability::discover(&facts, &probe, degraded)
}

/// The identity the negotiations below run under.
fn sandlock_identity() -> BackendIdentity {
    BackendIdentity {
        id: aa_isolation_sandlock::BACKEND_ID.to_string(),
        version: "0.8.6".to_string(),
        provenance: Provenance {
            source: aa_isolation_sandlock::SOURCE_URL.to_string(),
            license: aa_isolation_sandlock::SPDX_LICENSE.to_string(),
            modified: false,
        },
    }
}

/// Mirror `SandlockBackend::plan`'s two steps against a supplied capability set.
#[allow(clippy::result_large_err)]
fn plan_against(
    capabilities: &BackendCapabilities,
    spec: &aa_isolation::ExecutionSpec,
) -> Result<EnforcementPlan, PlanRefusal> {
    let narrowed = capability::narrow_for(capabilities, spec);
    negotiate(spec, &sandlock_identity(), &narrowed, &|_, _| Lowering::none())
}

/// A spec asking for one resource ceiling.
fn ceiling_spec(limits: ResourceLimits) -> aa_isolation::ExecutionSpec {
    aa_isolation::ExecutionSpec::new("/bin/true", IdentityRef::root("adversary")).with_requirement(
        ControlRequirement::prevent(CapabilityDomain::Resource).with_scope(RequirementScope::Limits(limits)),
    )
}

/// AC: attempts to invoke disallowed resources represented by the first
/// capability set are refused rather than approximated.
///
/// The adversarial reading of a resource ceiling is that an unenforceable one
/// gets quietly dropped, leaving a launch that asked for a limit and got none
/// while reporting success. Every ceiling the mechanism cannot decide *before*
/// the effect must therefore refuse — including the wall-clock one, which it
/// could enforce by killing a process that has already run, and which is
/// detection rather than prevention.
///
/// Asserted as two sets, so a ceiling moving from one to the other fails here
/// whichever direction it moves in.
#[test]
fn every_resource_ceiling_the_mechanism_cannot_decide_before_the_effect_is_refused() {
    let scenario = "adversarial: unenforceable resource ceilings are refused, not approximated";
    let capabilities = measured_capabilities(&[]);

    let cases: [(&str, ResourceLimits); 6] = [
        (
            "memory",
            ResourceLimits {
                max_memory_bytes: Some(64 << 20),
                ..ResourceLimits::default()
            },
        ),
        (
            "processes",
            ResourceLimits {
                max_pids: Some(2),
                ..ResourceLimits::default()
            },
        ),
        (
            "cpu seconds",
            ResourceLimits {
                max_cpu_seconds: Some(5),
                ..ResourceLimits::default()
            },
        ),
        (
            "file size",
            ResourceLimits {
                max_file_size_bytes: Some(1 << 20),
                ..ResourceLimits::default()
            },
        ),
        (
            "open files",
            ResourceLimits {
                max_open_files: Some(16),
                ..ResourceLimits::default()
            },
        ),
        (
            "wall clock",
            ResourceLimits {
                max_wall_clock_seconds: Some(30),
                ..ResourceLimits::default()
            },
        ),
    ];

    let mut accepted: BTreeSet<&str> = BTreeSet::new();
    let mut refused: BTreeSet<&str> = BTreeSet::new();
    for (name, limits) in cases {
        match plan_against(&capabilities, &ceiling_spec(limits)) {
            Ok(_) => {
                accepted.insert(name);
            }
            Err(refusal) => {
                assert!(
                    refusal
                        .unmet()
                        .iter()
                        .any(|(r, _)| r.domain() == CapabilityDomain::Resource),
                    "a resource ceiling refused without naming the resource domain: {refusal:?}"
                );
                refused.insert(name);
            }
        }
    }

    assert_eq!(
        accepted,
        ["memory", "processes"].into_iter().collect::<BTreeSet<&str>>(),
        "the set of ceilings this mechanism accepts changed"
    );
    assert_eq!(
        refused,
        ["cpu seconds", "file size", "open files", "wall clock"]
            .into_iter()
            .collect::<BTreeSet<&str>>(),
        "a ceiling the mechanism cannot decide before the effect stopped being refused"
    );

    measured(
        scenario,
        AttackFamily::SyscallAndResource,
        "two expressible ceilings planned and four unexpressible ones were refused, including the \
         wall-clock ceiling that could only be enforced after the effect",
    );
}

/// AC: a syscall permitted-set requirement is refused rather than met by a
/// denied list, and the refusal is distinguishable from an unmeasured domain.
///
/// Three refusal reasons, one sweep. `unsupported` and `unmeasured` are the pair
/// this whole Epic exists to keep apart, and the negotiation layer is where they
/// first become different words.
#[test]
fn unsupported_and_unmeasured_domains_refuse_for_different_reasons() {
    let scenario = "adversarial: unsupported and unmeasured domains refuse for different reasons";
    let capabilities = measured_capabilities(&[]);

    let mut reasons: Vec<(CapabilityDomain, &'static str)> = Vec::new();
    for domain in [
        CapabilityDomain::Syscall,
        CapabilityDomain::NameResolution,
        CapabilityDomain::Ipc,
        CapabilityDomain::Credential,
    ] {
        let refusal = plan_against(&capabilities, &required_prevention_spec(domain))
            .expect_err("this domain cannot meet a required prevention requirement on any host");
        let (_, reason) = refusal
            .unmet()
            .iter()
            .find(|(r, _)| r.domain() == domain)
            .unwrap_or_else(|| panic!("{domain} refused without naming itself: {refusal:?}"));
        reasons.push((
            domain,
            match reason {
                RefusalReason::DomainUnsupported { .. } => "unsupported",
                RefusalReason::PrerequisiteUnsatisfied { .. } => "unmeasured_prerequisite",
                other => panic!("{domain} refused for an unexpected reason: {other:?}"),
            },
        ));
    }

    assert_eq!(
        reasons,
        vec![
            (CapabilityDomain::Syscall, "unsupported"),
            (CapabilityDomain::NameResolution, "unsupported"),
            (CapabilityDomain::Ipc, "unmeasured_prerequisite"),
            (CapabilityDomain::Credential, "unmeasured_prerequisite"),
        ],
        "a domain that cannot be asked and a domain nobody measured stopped being different refusals"
    );

    // The control: on the same capability set, the four measured domains do
    // accept a whole-domain prevention requirement. Without this the four
    // refusals above would be consistent with a capability set that refuses
    // everything.
    assert_eq!(
        domains_accepting_whole_domain_prevention(&capabilities),
        [
            CapabilityDomain::FilesystemRead,
            CapabilityDomain::FilesystemWrite,
            CapabilityDomain::NetworkEgress,
            CapabilityDomain::ProcessCreation,
        ]
        .into_iter()
        .collect::<BTreeSet<_>>(),
        "the set of domains a measured host accepts a whole-domain prevention requirement for changed"
    );

    measured(
        scenario,
        AttackFamily::SyscallAndResource,
        "syscall and name resolution refused as unsupported while ipc and credential refused as \
         unmeasured, and four measured domains accepted the same requirement shape",
    );
}

/// The domains a capability set accepts a whole-domain prevention requirement
/// for, as a set.
fn domains_accepting_whole_domain_prevention(capabilities: &BackendCapabilities) -> BTreeSet<CapabilityDomain> {
    CapabilityDomain::ALL
        .iter()
        .copied()
        .filter(|domain| plan_against(capabilities, &required_prevention_spec(*domain)).is_ok())
        .collect()
}

/// AC: a partially configured backend is reported as a *removed* control rather
/// than a weaker one.
///
/// The mechanism can be authorised to waive a protection the host kernel cannot
/// provide, and it applies the waiver silently. The adversarial reading is that
/// a waived launch looks exactly like a fully confined one. It must not: the
/// domain the waiver removes has to become `unsupported`, so a requirement that
/// needed it refuses rather than being silently unmet.
///
/// The control is a waiver of a **different** protection — one that covers no
/// domain this contract reports — which must leave the report untouched. That is
/// what makes the change below attributable to the waived protection rather than
/// to the presence of any waiver at all.
#[test]
fn a_waived_protection_removes_the_domain_it_covers_rather_than_weakening_it() {
    let scenario = "adversarial: a waived protection removes its domain rather than weakening it";

    let strict = measured_capabilities(&[]);
    let waived = measured_capabilities(&[ABSTRACT_UNIX_SOCKET_SCOPE.to_string()]);
    let unrelated = measured_capabilities(&[SIGNAL_SCOPE.to_string()]);

    let strict_ipc = strict.report_for(CapabilityDomain::Ipc).expect("reported");
    let waived_ipc = waived.report_for(CapabilityDomain::Ipc).expect("reported");
    let unrelated_ipc = unrelated.report_for(CapabilityDomain::Ipc).expect("reported");

    assert!(
        matches!(strict_ipc.support(), SupportLevel::Partial { .. }),
        "the strict configuration does not report ipc as partially supported: {strict_ipc:?}"
    );
    assert!(
        matches!(waived_ipc.support(), SupportLevel::Unsupported { .. }),
        "a waived protection left its domain looking merely weaker: {waived_ipc:?}"
    );
    assert_eq!(
        unrelated_ipc.support(),
        strict_ipc.support(),
        "waiving a protection that covers no reported domain still changed the ipc report, so the \
         change above is not attributable to the waived protection"
    );

    // Both refuse a required ipc prevention requirement — and for different
    // reasons, which is the distinction an operator acts on: one says the
    // control is not installed, the other says nobody measured it.
    let waived_reason = refusal_reason(&waived, CapabilityDomain::Ipc);
    let strict_reason = refusal_reason(&strict, CapabilityDomain::Ipc);
    assert!(
        matches!(waived_reason, RefusalReason::DomainUnsupported { .. }),
        "{waived_reason:?}"
    );
    assert!(
        matches!(strict_reason, RefusalReason::PrerequisiteUnsatisfied { .. }),
        "{strict_reason:?}"
    );

    measured(
        scenario,
        AttackFamily::BackendPosture,
        "waiving the unix-socket scoping made its domain unsupported while waiving an unrelated \
         protection changed nothing, and the two configurations refuse for different reasons",
    );
}

/// The reason a capability set refuses a required prevention requirement.
fn refusal_reason(capabilities: &BackendCapabilities, domain: CapabilityDomain) -> RefusalReason {
    let refusal = plan_against(capabilities, &required_prevention_spec(domain)).expect_err("this domain must refuse");
    refusal
        .unmet()
        .iter()
        .find(|(r, _)| r.domain() == domain)
        .map(|(_, reason)| reason.clone())
        .unwrap_or_else(|| panic!("{domain} refused without naming itself: {refusal:?}"))
}

/// AC: missing, disabled and partially configured backends are three
/// distinguishable states, and none of them runs the program.
///
/// The effect assertion is the load-bearing one: a refusal that still ran the
/// program would be a refusal in name only, and the exit status of a launch that
/// never happened looks exactly like the exit status of one that was stopped.
#[test]
fn missing_disabled_and_partially_configured_backends_are_three_distinct_states() {
    let scenario = "adversarial: missing, disabled and partially configured backends are distinct";

    let scratch = Scratch::new("posture");
    let target_file = scratch.permitted().join("should-never-exist");
    let spec = aa_isolation::ExecutionSpec::new("/bin/sh", IdentityRef::root("agent-under-test"))
        .with_args(["-c", &format!("printf x > {}", quote(&target_file.to_string_lossy()))])
        .with_requirement(
            ControlRequirement::prevent(CapabilityDomain::FilesystemWrite)
                .with_scope(RequirementScope::Selectors(vec![scratch.permitted_selector()])),
        );

    // Missing: nothing named the mechanism was found.
    let missing = SandlockBackend::unavailable(&BackendLookupError::NotOnPath);
    let missing_refusal = missing.plan(&spec).expect_err("an absent mechanism must refuse");

    // Disabled: an operator pointed the backend at a path that is not there.
    // A different fact with a different fix, and it must not read as the first.
    let disabled = SandlockBackend::unavailable(&BackendLookupError::OverrideMissing {
        path: std::path::PathBuf::from("/nonexistent/sandlock"),
    });
    let disabled_refusal = disabled.plan(&spec).expect_err("a mispointed override must refuse");

    let missing_reason = missing_refusal
        .backend_unavailable()
        .expect("a host-level refusal names the host-level reason");
    let disabled_reason = disabled_refusal
        .backend_unavailable()
        .expect("a host-level refusal names the host-level reason");
    assert_ne!(
        missing_reason, disabled_reason,
        "an absent mechanism and a mispointed one produced the same reason"
    );
    assert!(disabled_reason.contains("/nonexistent/sandlock"), "{disabled_reason}");

    // Partially configured: the backend is available and one domain is not.
    // The refusal is per-requirement, and there is no host-level reason at all.
    let partial = measured_capabilities(&[ABSTRACT_UNIX_SOCKET_SCOPE.to_string()]);
    let partial_refusal = plan_against(&partial, &required_prevention_spec(CapabilityDomain::Ipc))
        .expect_err("a removed control must refuse the requirement that needed it");
    assert!(
        partial_refusal.backend_unavailable().is_none(),
        "a partially configured backend reported itself unavailable, collapsing two states into one"
    );
    assert_eq!(
        partial_refusal
            .unmet()
            .iter()
            .map(|(r, _)| r.domain())
            .collect::<BTreeSet<_>>(),
        [CapabilityDomain::Ipc].into_iter().collect::<BTreeSet<_>>()
    );

    // None of the three ran the program.
    assert!(
        !target_file.exists(),
        "a refused launch still ran the program: {} exists",
        target_file.display()
    );

    // The control for that absence: the identical command outside any boundary
    // does create the file, so its absence above is the refusal and not a
    // command that never worked.
    adversarial::unconfined(&format!("printf x > {}", quote(&target_file.to_string_lossy())));
    assert!(
        target_file.exists(),
        "the same command outside the boundary produced nothing either, so the assertion above proves \
         nothing"
    );

    // And each refusal is evidenced as a refusal rather than as an absence.
    for refusal in [&missing_refusal, &disabled_refusal, &partial_refusal] {
        let evidence = EnforcementEvidence::from_refusal(refusal);
        assert_eq!(evidence.posture(), LaunchPosture::Refused);
        assert!(prevention_claims(&evidence).is_empty());
    }

    measured(
        scenario,
        AttackFamily::BackendPosture,
        "an absent mechanism, a mispointed override and a partially configured backend each refused \
         with a distinguishable reason and none ran the program, while the same command outside the \
         boundary did",
    );
}
