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

use aa_core::attestation::ClaimTerm;
use aa_isolation::mock::MockBackend;
use aa_isolation::{
    negotiate, BackendCapabilities, BackendIdentity, CapabilityDomain, ControlRequirement, EnforcementEvidence,
    EnforcementPlan, EvidenceKind, EvidenceRecord, IdentityRef, IsolationBackend, IsolationReport, LaunchPosture,
    Lowering, PlanRefusal, Provenance, RefusalReason, RequirementPosture, RequirementScope, ResourceLimits, SessionRef,
    SupportLevel,
};
use aa_isolation_sandlock::capability::{ABSTRACT_UNIX_SOCKET_SCOPE, SIGNAL_SCOPE};
use aa_isolation_sandlock::host::{BackendLookupError, HostFacts};
use aa_isolation_sandlock::probe::{ConfinementProbe, Observation};
use aa_isolation_sandlock::{capability, SandlockBackend};

mod adversarial;

use adversarial::{
    all_domains, assert_no_prevention_claim, control_states, domains_accepting_required_observation,
    domains_accepting_required_prevention, domains_refusing_required_prevention, evidence_bases, measured,
    prevention_claims, quote, required_prevention_spec, AdversarialTarget, AttackFamily, MockTarget, SandlockTarget,
    Scratch,
};

/// A session reference for a report. The values are correlation ids and carry
/// no authority; nothing in this file depends on their content.
fn session() -> SessionRef {
    SessionRef::new("adversarial-session", "adversarial-trace")
}

// ---------------------------------------------------------------------------
// Backend posture: missing, disabled, partially configured, observe-only.
// ---------------------------------------------------------------------------

/// AC: a required prevention requirement is refused by every backend that
/// cannot enforce it, and the refusal is a property of the contract rather than
/// of one mechanism.
///
/// The assertion is over the **set** of refused domains, never a count. "Nine
/// domains refused" is equally consistent with the nine that should have and
/// with eight that should plus one that should not.
///
/// The control is `MockBackend::preventing`, which differs from
/// `MockBackend::observing` in exactly one field — mediation — so the refusal
/// below cannot be attributed to some other weakened axis.
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

    for target in [&inert as &dyn AdversarialTarget, &observing, &absent] {
        assert_eq!(
            domains_refusing_required_prevention(target.backend()),
            all_domains(),
            "`{}` accepted a required prevention requirement for a domain it cannot enforce",
            target.label()
        );
    }

    // The control. One field of the capability report moved, and every refusal
    // above turns into an acceptance — so those refusals are attributable to
    // mediation and not to the requirement being malformed.
    let preventing = MockTarget {
        backend: MockBackend::preventing(CapabilityDomain::ALL),
        label: "mock/preventing",
    };
    assert_eq!(
        domains_refusing_required_prevention(preventing.backend()),
        BTreeSet::new(),
        "the control backend refused something too, so the refusals above prove nothing"
    );
    assert_eq!(
        domains_accepting_required_prevention(preventing.backend()),
        all_domains(),
        "the control backend did not accept every domain"
    );

    measured(
        scenario,
        AttackFamily::BackendPosture,
        "an inert backend, an observe-only backend and an absent backend each refused a required \
         prevention requirement for all nine domains, while a backend differing only in mediation \
         accepted all nine",
    );
}

/// AC: observation is never promoted to enforcement, on any backend.
///
/// Two directions, because "an observe-only backend refuses a prevention
/// requirement" is only half of it. The other half is that a backend which
/// *does* report prevention still produces no prevention **claim** from a run —
/// the capability report says what a control could do, and the evidence says
/// what it did.
#[test]
fn observation_is_never_promoted_to_prevention_on_any_backend() {
    let scenario = "adversarial: observation is never promoted to prevention";

    let observing = MockTarget {
        backend: MockBackend::observing(CapabilityDomain::ALL),
        label: "mock/observe-only",
    };
    let preventing = MockTarget {
        backend: MockBackend::preventing(CapabilityDomain::ALL),
        label: "mock/preventing",
    };

    // Both accept an *observation* requirement. That is what makes the pair a
    // control: the observe-only backend is not simply broken.
    for target in [&observing, &preventing] {
        assert_eq!(
            domains_accepting_required_observation(target.backend()),
            all_domains(),
            "`{}` refused an observation requirement it can meet",
            target.label()
        );
    }

    let spec = adversarial::required_observation_spec(CapabilityDomain::FilesystemWrite);
    for target in [&observing, &preventing] {
        let outcome = target
            .launch(&spec)
            .unwrap_or_else(|refusal| panic!("`{}` refused an observation it accepts: {refusal:?}", target.label()));
        assert_eq!(outcome.posture, LaunchPosture::Ready);
        assert_no_prevention_claim(target.label(), &outcome.evidence);
        assert!(
            !outcome
                .evidence
                .claim_for(CapabilityDomain::FilesystemWrite)
                .is_prevention(),
            "`{}` derived a prevention term from a run that recorded no decision",
            target.label()
        );
    }

    // And the states the two plans project are different words, so a reader
    // cannot mistake one for the other.
    let observed_state = state_for(&observing, CapabilityDomain::FilesystemWrite, &spec);
    let prevented_state = state_for(
        &preventing,
        CapabilityDomain::FilesystemWrite,
        &required_prevention_spec(CapabilityDomain::FilesystemWrite),
    );
    assert_eq!(observed_state, "observe_only");
    assert_eq!(prevented_state, "prevention");

    measured(
        scenario,
        AttackFamily::ObserveAndDegradedTruthfulness,
        "an observe-only backend met every observation requirement and no prevention requirement; a \
         backend that reports prevention still produced no prevention claim from a run",
    );
}

/// The control state one target projects for one domain.
fn state_for(target: &MockTarget, domain: CapabilityDomain, spec: &aa_isolation::ExecutionSpec) -> &'static str {
    let plan = target.backend().plan(spec).expect("planned");
    let report = IsolationReport::from_plan(session(), &plan);
    report
        .domains()
        .iter()
        .find(|d| d.domain == domain)
        .expect("every domain is projected")
        .state
        .as_str()
}

/// AC: audit/evidence assertions confirm blocked, unsupported and unmeasured are
/// not conflated.
///
/// Four silences and one denial, in one sweep. The report has three ways to say
/// "nothing is known" and they mean different things to whoever reads them:
/// nobody asked, no backend was consulted, or something looked and could not
/// resolve it. A reader who cannot tell them apart reads all three as safety.
#[test]
fn blocked_unsupported_and_unmeasured_stay_three_distinct_report_states() {
    let scenario = "adversarial: blocked, unsupported and unmeasured are distinct report states";

    // A backend that covers one domain and reports nothing at all about the
    // rest, so the spec below can land a requirement in each state.
    let backend = MockBackend::preventing(&[CapabilityDomain::FilesystemWrite]);
    let spec = aa_isolation::ExecutionSpec::new("/bin/true", IdentityRef::root("adversary"))
        .with_requirement(ControlRequirement::prevent(CapabilityDomain::FilesystemWrite))
        .with_requirement(
            ControlRequirement::prevent(CapabilityDomain::NetworkEgress)
                .with_posture(RequirementPosture::DegradeIfUnavailable),
        );
    let plan = backend.plan(&spec).expect("the degrading requirement permits a plan");
    let planned = IsolationReport::from_plan(session(), &plan);
    let states: Vec<(CapabilityDomain, &str)> = control_states(&planned);

    assert!(
        states.contains(&(CapabilityDomain::FilesystemWrite, "prevention")),
        "{states:?}"
    );
    assert!(
        states.contains(&(CapabilityDomain::NetworkEgress, "degraded")),
        "a requirement that fell short is not reported as degraded: {states:?}"
    );
    assert!(
        states.contains(&(CapabilityDomain::Ipc, "unmeasured")),
        "a domain nobody asked about is not reported as unmeasured: {states:?}"
    );

    // A refusal projects the domain that could not be met as `unsupported`, and
    // the domain that was requested but never resolved as `unmeasured` — two
    // different words for two different facts about the same refused launch.
    let refused_spec = spec
        .clone()
        .with_requirement(ControlRequirement::prevent(CapabilityDomain::Syscall));
    let refusal = backend
        .plan(&refused_spec)
        .expect_err("a required requirement for an unreported domain must refuse");
    let refused = IsolationReport::from_refusal(session(), &refused_spec, &refusal);
    let refused_states: Vec<(CapabilityDomain, &str)> = control_states(&refused);
    assert!(
        refused_states.contains(&(CapabilityDomain::Syscall, "unsupported")),
        "{refused_states:?}"
    );
    assert!(
        refused_states.contains(&(CapabilityDomain::FilesystemWrite, "unmeasured")),
        "a requirement whose outcome was never reported is not reported as unmeasured: {refused_states:?}"
    );

    // The three silences carry three different reasons.
    let no_boundary = IsolationReport::no_boundary(
        session(),
        IdentityRef::root("adversary"),
        aa_isolation::TargetRef::of(&spec),
        aa_isolation::CredentialPosture::default(),
        "no backend was selected for this launch",
    );
    let reasons: BTreeSet<&str> = [
        unmeasured_reason(&planned, CapabilityDomain::Ipc),
        unmeasured_reason(&refused, CapabilityDomain::FilesystemWrite),
        unmeasured_reason(&no_boundary, CapabilityDomain::FilesystemWrite),
    ]
    .into_iter()
    .collect();
    assert_eq!(
        reasons,
        ["inconclusive", "no_backend_selected", "no_control_requested"]
            .into_iter()
            .collect::<BTreeSet<&str>>(),
        "the three silences collapsed into fewer than three reasons"
    );
    assert_eq!(no_boundary.posture().as_str(), "no_boundary");

    measured(
        scenario,
        AttackFamily::ObserveAndDegradedTruthfulness,
        "one sweep produced prevention, degraded, unsupported and unmeasured states, and the three \
         unmeasured reasons stayed distinct",
    );
}

/// The unmeasured reason a report gives for one domain.
fn unmeasured_reason(report: &IsolationReport, domain: CapabilityDomain) -> &'static str {
    match &report
        .domains()
        .iter()
        .find(|d| d.domain == domain)
        .expect("every domain is projected")
        .state
    {
        aa_isolation::ControlState::Unmeasured { reason } => reason.as_str(),
        other => panic!("{domain} is `{}`, not unmeasured", other.as_str()),
    }
}

/// AC: a claim is promoted only by a decision record, and corroboration is not
/// a decision.
///
/// Three points on one axis, which is what makes this a control rather than a
/// restatement of the predicate:
///
/// 1. a real run of a backend that *reports* prevention yields `setup_only` and
///    no prevention claim;
/// 2. an `IndependentVerification` record carrying a prevention term still
///    yields no prevention claim — the claim is downgraded to `observed`;
/// 3. a `Decision` record carrying the same term does yield one.
///
/// Without (3) the predicate could be false for every input and every assertion
/// here would still pass.
#[test]
fn a_claim_is_promoted_only_by_a_decision_record() {
    let scenario = "adversarial: only a decision record promotes a claim";

    let target = MockTarget {
        backend: MockBackend::preventing(CapabilityDomain::ALL),
        label: "mock/preventing",
    };
    let spec = required_prevention_spec(CapabilityDomain::FilesystemWrite);
    let plan = target.backend().plan(&spec).expect("planned");
    let outcome = target.launch(&spec).expect("the mock always launches");

    let run_report = IsolationReport::from_plan(session(), &plan).with_evidence(&outcome.evidence);
    assert!(
        evidence_bases(&run_report).contains(&(CapabilityDomain::FilesystemWrite, "setup_only")),
        "a run with only setup-time records reported a stronger basis: {:?}",
        evidence_bases(&run_report)
    );
    assert_no_prevention_claim("mock/preventing", &outcome.evidence);

    // (2) corroboration.
    let corroborated = evidence_with(&plan, EvidenceKind::IndependentVerification);
    assert!(
        prevention_claims(&corroborated).is_empty(),
        "an out-of-band probe was treated as the enforcing control's own decision"
    );
    let corroborated_report = IsolationReport::from_plan(session(), &plan).with_evidence(&corroborated);
    assert_eq!(
        claim_for(&corroborated_report, CapabilityDomain::FilesystemWrite),
        ClaimTerm::Observed,
        "a prevention term arrived with no decision behind it and was not downgraded"
    );

    // (3) the direction that makes the other two mean something.
    let decided = evidence_with(&plan, EvidenceKind::Decision);
    assert_eq!(
        prevention_claims(&decided),
        [CapabilityDomain::FilesystemWrite].into_iter().collect::<BTreeSet<_>>(),
        "a decision record carrying a prevention term did not support a prevention claim, so the \
         assertions above hold vacuously"
    );
    let decided_report = IsolationReport::from_plan(session(), &plan).with_evidence(&decided);
    assert_eq!(
        claim_for(&decided_report, CapabilityDomain::FilesystemWrite),
        ClaimTerm::DeniedBeforeExecution
    );
    assert!(evidence_bases(&decided_report).contains(&(CapabilityDomain::FilesystemWrite, "decision")));

    measured(
        scenario,
        AttackFamily::ObserveAndDegradedTruthfulness,
        "a setup-only run and an independently corroborated run both yielded no prevention claim, \
         while the same evidence graded as a decision did",
    );
}

/// Evidence for `plan` carrying one extra record of the given grade with a
/// prevention term, so the grade is the only variable.
fn evidence_with(plan: &EnforcementPlan, kind: EvidenceKind) -> EnforcementEvidence {
    EnforcementEvidence::from_plan(plan).with_record(EvidenceRecord::new(
        kind,
        CapabilityDomain::FilesystemWrite,
        ClaimTerm::DeniedBeforeExecution,
        "a forbidden write did not take effect",
    ))
}

/// The claim a report states for one domain.
fn claim_for(report: &IsolationReport, domain: CapabilityDomain) -> ClaimTerm {
    report
        .domains()
        .iter()
        .find(|d| d.domain == domain)
        .expect("every domain is projected")
        .claim
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
