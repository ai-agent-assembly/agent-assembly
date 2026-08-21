//! The semantics that must hold before an untrusted process is allowed to
//! start.
//!
//! Every test here is a statement from ADR 0035 §4 or §6 turned into an
//! assertion. Where a test compares two backends, they differ in exactly one
//! field, so a passing assertion attributes the outcome to that field and not
//! to an incidental difference.

use aa_core::attestation::ClaimTerm;
use aa_isolation::{
    negotiate, AchievedControl, BackendAvailability, BackendCapabilities, BackendIdentity, CapabilityDomain,
    CapabilityReport, ControlRequirement, DecisionTiming, DescendantCoverage, DescendantRequirement, ExecutionSpec,
    IdentityRef, LaunchPosture, Lowering, Mediation, PlanRefusal, PlatformBoundary, Prerequisite, PrerequisiteStatus,
    Provenance, RefusalReason, RequirementIntent, RequirementOutcome, RequirementPosture, SupportLevel, Synchrony,
};

fn identity(id: &str) -> BackendIdentity {
    BackendIdentity {
        id: id.to_string(),
        version: "1.0".to_string(),
        provenance: Provenance {
            source: "test".to_string(),
            license: "Apache-2.0".to_string(),
            modified: false,
        },
    }
}

fn capabilities(reports: Vec<CapabilityReport>) -> BackendCapabilities {
    BackendCapabilities::new(
        BackendAvailability::Available,
        PlatformBoundary::SharedHostKernel,
        reports,
    )
    .expect("unique domains")
}

/// A report that satisfies every prevention axis, so tests can weaken exactly
/// one of them.
fn preventing(domain: CapabilityDomain) -> CapabilityReport {
    CapabilityReport::new(domain, Mediation::Enforce, DecisionTiming::Pre, Synchrony::Sync)
        .with_descendants(DescendantCoverage::ProcessTree)
}

fn spec(requirements: Vec<ControlRequirement>) -> ExecutionSpec {
    let mut spec = ExecutionSpec::new("python", IdentityRef::root("agent-1")).with_args(["ai_agent_main.py"]);
    for requirement in requirements {
        spec = spec.with_requirement(requirement);
    }
    spec
}

fn no_lowering() -> impl Fn(&ControlRequirement, &RequirementOutcome) -> Lowering {
    |_, _| Lowering::none()
}

// ---------------------------------------------------------------------------
// An observe-only capability cannot satisfy a prevention requirement.
// ---------------------------------------------------------------------------

/// The controlled comparison. Both backends report `Pre` timing, `Sync`
/// synchrony, `Full` support and `ProcessTree` coverage; only `mediation`
/// differs. The enforcing one is accepted and the observing one is refused, so
/// the refusal is attributable to mediation alone.
#[test]
fn observe_only_capability_cannot_satisfy_a_prevention_requirement() {
    let requirement = ControlRequirement::prevent(CapabilityDomain::NetworkEgress);
    let spec = spec(vec![requirement]);
    let backend = identity("test");

    let enforcing = capabilities(vec![preventing(CapabilityDomain::NetworkEgress)]);
    let plan = negotiate(&spec, &backend, &enforcing, &no_lowering())
        .expect("an enforcing pre-effect synchronous capability satisfies a prevention requirement");
    assert!(plan.planned()[0].outcome.is_prevention());

    let observing = capabilities(vec![CapabilityReport::new(
        CapabilityDomain::NetworkEgress,
        // The single changed field.
        Mediation::Observe,
        DecisionTiming::Pre,
        Synchrony::Sync,
    )
    .with_descendants(DescendantCoverage::ProcessTree)]);
    let refusal = negotiate(&spec, &backend, &observing, &no_lowering())
        .expect_err("an observe-only capability must not satisfy a prevention requirement");

    assert_eq!(refusal.unmet().len(), 1);
    assert_eq!(
        refusal.unmet()[0].1,
        RefusalReason::ObserveOnlyForPreventionRequirement {
            domain: CapabilityDomain::NetworkEgress,
            mediation: Mediation::Observe,
        }
    );
}

/// The same requirement, weakened one axis at a time, must be refused with the
/// reason naming that axis. A single "could not enforce" reason would pass this
/// test only by accident of wording; naming the axis is what makes the refusal
/// actionable.
#[test]
fn each_weakened_axis_refuses_with_its_own_reason() {
    let domain = CapabilityDomain::FilesystemWrite;
    let spec = spec(vec![ControlRequirement::prevent(domain)]);
    let backend = identity("test");

    let cases: Vec<(CapabilityReport, RefusalReason)> = vec![
        (
            CapabilityReport::new(domain, Mediation::Enforce, DecisionTiming::Post, Synchrony::Sync)
                .with_descendants(DescendantCoverage::ProcessTree),
            RefusalReason::DecisionTooLate {
                domain,
                timing: DecisionTiming::Post,
            },
        ),
        (
            CapabilityReport::new(domain, Mediation::Enforce, DecisionTiming::Pre, Synchrony::BestEffort)
                .with_descendants(DescendantCoverage::ProcessTree),
            RefusalReason::DecisionNotSynchronous {
                domain,
                synchrony: Synchrony::BestEffort,
            },
        ),
        (
            preventing(domain).with_support(SupportLevel::Unsupported {
                reason: "no mechanism on this host".into(),
            }),
            RefusalReason::DomainUnsupported {
                domain,
                reason: "no mechanism on this host".into(),
            },
        ),
        (
            preventing(domain).with_prerequisite(Prerequisite::unsatisfied(
                "kernel supports per-process filesystem restriction",
                "not present",
            )),
            RefusalReason::PrerequisiteUnsatisfied {
                domain,
                requirement: "kernel supports per-process filesystem restriction".into(),
            },
        ),
        (
            preventing(domain).with_prerequisite(Prerequisite {
                requirement: "kernel feature".into(),
                status: PrerequisiteStatus::Unchecked,
            }),
            RefusalReason::PrerequisiteUnsatisfied {
                domain,
                requirement: "kernel feature".into(),
            },
        ),
    ];

    for (report, expected) in cases {
        let refusal = negotiate(&spec, &backend, &capabilities(vec![report]), &no_lowering())
            .expect_err("weakened capability must refuse");
        assert_eq!(refusal.unmet()[0].1, expected);
    }
}

/// Silence about a domain refuses, and refuses with a reason distinct from a
/// stated absence of mechanism.
#[test]
fn an_unreported_domain_refuses_a_required_prevention() {
    let spec = spec(vec![ControlRequirement::prevent(CapabilityDomain::Syscall)]);
    let refusal = negotiate(
        &spec,
        &identity("test"),
        &capabilities(vec![preventing(CapabilityDomain::FilesystemWrite)]),
        &no_lowering(),
    )
    .expect_err("a domain the backend said nothing about cannot satisfy a requirement");
    assert_eq!(
        refusal.unmet()[0].1,
        RefusalReason::NoCapabilityReported {
            domain: CapabilityDomain::Syscall
        }
    );
}

// ---------------------------------------------------------------------------
// A required capability the backend cannot enforce refuses before spawn.
// ---------------------------------------------------------------------------

/// Refusal is the `Err` arm, so no `EnforcementPlan` exists to be prepared or
/// spawned. This is the structural form of "refuse before spawn": a caller
/// cannot proceed by ignoring a status field, because there is no value to
/// proceed with.
#[test]
fn a_required_unmet_capability_yields_no_plan_at_all() {
    let spec = spec(vec![ControlRequirement::prevent(CapabilityDomain::NetworkEgress)]);
    let result = negotiate(
        &spec,
        &identity("test"),
        &capabilities(vec![CapabilityReport::unsupported(
            CapabilityDomain::NetworkEgress,
            "no mechanism",
        )]),
        &no_lowering(),
    );
    assert!(result.is_err());
}

/// `Required` is the default posture for both requirement constructors, so a
/// caller who states a requirement and nothing else gets refusal rather than
/// silent degradation.
#[test]
fn required_is_the_default_posture() {
    assert_eq!(
        ControlRequirement::prevent(CapabilityDomain::Ipc).posture(),
        RequirementPosture::Required
    );
    assert_eq!(
        ControlRequirement::observe(CapabilityDomain::Ipc).posture(),
        RequirementPosture::Required
    );
}

/// Every unmet required requirement is reported, not only the first, so an
/// operator does not discover them one re-run at a time.
#[test]
fn refusal_reports_every_unmet_requirement() {
    let spec = spec(vec![
        ControlRequirement::prevent(CapabilityDomain::NetworkEgress),
        ControlRequirement::prevent(CapabilityDomain::FilesystemWrite),
        ControlRequirement::prevent(CapabilityDomain::Syscall),
    ]);
    let refusal = negotiate(
        &spec,
        &identity("test"),
        &capabilities(vec![preventing(CapabilityDomain::FilesystemWrite)]),
        &no_lowering(),
    )
    .expect_err("two of three requirements are unmet");
    assert_eq!(refusal.unmet().len(), 2);
    let domains: Vec<_> = refusal.unmet().iter().filter_map(|(_, r)| r.domain()).collect();
    assert!(domains.contains(&CapabilityDomain::NetworkEgress));
    assert!(domains.contains(&CapabilityDomain::Syscall));
}

/// An unavailable backend refuses without reaching any requirement, and says so
/// at the backend level rather than blaming an individual control.
#[test]
fn an_unavailable_backend_refuses_before_evaluating_requirements() {
    let spec = spec(vec![ControlRequirement::prevent(CapabilityDomain::FilesystemWrite)]);
    let unavailable = BackendCapabilities::new(
        BackendAvailability::Unavailable {
            reason: "kernel too old".into(),
        },
        PlatformBoundary::SharedHostKernel,
        vec![preventing(CapabilityDomain::FilesystemWrite)],
    )
    .expect("unique");
    let refusal = negotiate(&spec, &identity("test"), &unavailable, &no_lowering())
        .expect_err("an unavailable backend cannot plan");
    assert_eq!(refusal.backend_unavailable(), Some("kernel too old"));
    assert!(refusal.unmet().is_empty());
}

// ---------------------------------------------------------------------------
// Degradation is representable and is never enforcement.
// ---------------------------------------------------------------------------

/// A degraded prevention requirement carries what it *planned* alongside what it
/// *achieved*, and none of the prevention predicates become true.
#[test]
fn explicit_degradation_is_recorded_and_is_not_enforcement() {
    let domain = CapabilityDomain::NetworkEgress;
    let spec = spec(vec![
        ControlRequirement::prevent(domain).with_posture(RequirementPosture::DegradeIfUnavailable)
    ]);
    let observing = capabilities(vec![CapabilityReport::new(
        domain,
        Mediation::Observe,
        DecisionTiming::Pre,
        Synchrony::Sync,
    )
    .with_descendants(DescendantCoverage::ProcessTree)]);

    let plan = negotiate(&spec, &identity("test"), &observing, &no_lowering())
        .expect("degradation was explicitly permitted for this requirement");

    assert_eq!(plan.posture(), LaunchPosture::Degraded);
    assert_eq!(plan.prevented_domains(), Vec::<CapabilityDomain>::new());
    assert_eq!(plan.shortfalls().count(), 1);

    let outcome = &plan.planned()[0].outcome;
    assert!(!outcome.is_prevention(), "degradation is never prevention");
    assert!(outcome.is_shortfall());
    assert_eq!(outcome.claim_ceiling(), ClaimTerm::Degraded);
    assert!(!outcome.claim_ceiling().is_prevention());

    match outcome {
        RequirementOutcome::Degraded { planned, achieved, .. } => {
            assert_eq!(*planned, RequirementIntent::PreventBeforeEffect);
            assert_eq!(
                *achieved,
                AchievedControl::Observed {
                    timing: DecisionTiming::Pre,
                    descendants: DescendantCoverage::ProcessTree,
                }
            );
        }
        other => panic!("expected Degraded, got {other:?}"),
    }
}

/// Degradation must be chosen for that specific requirement. Permitting it on
/// one requirement does not soften another in the same spec.
#[test]
fn degradation_permission_does_not_leak_between_requirements() {
    let spec = spec(vec![
        ControlRequirement::prevent(CapabilityDomain::NetworkEgress)
            .with_posture(RequirementPosture::DegradeIfUnavailable),
        ControlRequirement::prevent(CapabilityDomain::FilesystemWrite),
    ]);
    let refusal = negotiate(
        &spec,
        &identity("test"),
        &capabilities(vec![
            CapabilityReport::unsupported(CapabilityDomain::NetworkEgress, "none"),
            CapabilityReport::unsupported(CapabilityDomain::FilesystemWrite, "none"),
        ]),
        &no_lowering(),
    )
    .expect_err("the second requirement is Required and unmet");
    assert_eq!(refusal.unmet().len(), 1);
    assert_eq!(refusal.unmet()[0].1.domain(), Some(CapabilityDomain::FilesystemWrite));
}

/// A degraded requirement against a backend that cannot even watch the domain
/// achieves nothing, and says so.
#[test]
fn degradation_to_nothing_is_representable() {
    let domain = CapabilityDomain::Ipc;
    let spec = spec(vec![
        ControlRequirement::prevent(domain).with_posture(RequirementPosture::DegradeIfUnavailable)
    ]);
    let plan = negotiate(
        &spec,
        &identity("test"),
        &capabilities(vec![CapabilityReport::unsupported(domain, "none")]),
        &no_lowering(),
    )
    .expect("degradation permitted");
    match &plan.planned()[0].outcome {
        RequirementOutcome::Degraded { achieved, .. } => {
            assert_eq!(*achieved, AchievedControl::None);
        }
        other => panic!("expected Degraded, got {other:?}"),
    }
}

/// An optional requirement that cannot be met leaves the domain uncovered and
/// the launch proceeding — but never reads as coverage.
#[test]
fn an_optional_requirement_does_not_refuse_and_does_not_claim_coverage() {
    let domain = CapabilityDomain::Resource;
    let spec = spec(vec![
        ControlRequirement::prevent(domain).with_posture(RequirementPosture::Optional)
    ]);
    let plan = negotiate(
        &spec,
        &identity("test"),
        &capabilities(vec![CapabilityReport::unsupported(domain, "none")]),
        &no_lowering(),
    )
    .expect("an optional requirement does not refuse");
    assert_eq!(plan.posture(), LaunchPosture::Degraded);
    let outcome = &plan.planned()[0].outcome;
    assert!(matches!(outcome, RequirementOutcome::Unmet { .. }));
    assert_eq!(outcome.claim_ceiling(), ClaimTerm::Unmeasured);
    assert!(!outcome.claim_ceiling().asserts_coverage());
}

// ---------------------------------------------------------------------------
// Descendant coverage is per capability, not global.
// ---------------------------------------------------------------------------

/// One backend, two domains, two different coverages, two different outcomes
/// for the same requirement shape. A global tree-coverage flag could not
/// produce this result.
#[test]
fn descendant_coverage_is_evaluated_per_capability() {
    let spec = spec(vec![
        ControlRequirement::prevent(CapabilityDomain::FilesystemWrite)
            .with_descendants(DescendantRequirement::ProcessTree),
        ControlRequirement::prevent(CapabilityDomain::NetworkEgress)
            .with_descendants(DescendantRequirement::ProcessTree),
    ]);
    let mixed = capabilities(vec![
        preventing(CapabilityDomain::FilesystemWrite).with_descendants(DescendantCoverage::ProcessTree),
        preventing(CapabilityDomain::NetworkEgress).with_descendants(DescendantCoverage::TargetProcessOnly),
    ]);

    let refusal = negotiate(&spec, &identity("test"), &mixed, &no_lowering())
        .expect_err("the network capability does not cover descendants");
    assert_eq!(refusal.unmet().len(), 1, "only the network requirement fails");
    assert_eq!(
        refusal.unmet()[0].1,
        RefusalReason::DescendantCoverageInsufficient {
            domain: CapabilityDomain::NetworkEgress,
            offered: DescendantCoverage::TargetProcessOnly,
        }
    );
}

/// Unmeasured coverage is refused alongside known-absent coverage: a backend
/// must not be able to meet a process-tree requirement by declining to look.
#[test]
fn unmeasured_descendant_coverage_does_not_satisfy_a_tree_requirement() {
    let domain = CapabilityDomain::FilesystemWrite;
    let spec = spec(vec![ControlRequirement::prevent(domain)]);
    let refusal = negotiate(
        &spec,
        &identity("test"),
        &capabilities(vec![preventing(domain).with_descendants(DescendantCoverage::Unmeasured)]),
        &no_lowering(),
    )
    .expect_err("unmeasured coverage cannot satisfy a process-tree requirement");
    assert_eq!(
        refusal.unmet()[0].1,
        RefusalReason::DescendantCoverageInsufficient {
            domain,
            offered: DescendantCoverage::Unmeasured,
        }
    );
}

/// A requirement that explicitly asks only for the launched process is met by
/// target-only coverage — the requirement side of the same axis.
#[test]
fn a_target_only_requirement_accepts_target_only_coverage() {
    let domain = CapabilityDomain::FilesystemWrite;
    let spec = spec(vec![
        ControlRequirement::prevent(domain).with_descendants(DescendantRequirement::TargetProcessOnly)
    ]);
    let plan = negotiate(
        &spec,
        &identity("test"),
        &capabilities(vec![
            preventing(domain).with_descendants(DescendantCoverage::TargetProcessOnly)
        ]),
        &no_lowering(),
    )
    .expect("a target-only requirement is met by target-only coverage");
    assert!(plan.planned()[0].outcome.is_prevention());
}

/// Requirements default to process-tree coverage, so omitting the field asks for
/// the strict answer rather than the lenient one.
#[test]
fn requirements_default_to_process_tree_coverage() {
    assert_eq!(
        ControlRequirement::prevent(CapabilityDomain::Ipc).descendants(),
        DescendantRequirement::ProcessTree
    );
}

// ---------------------------------------------------------------------------
// Backend provenance rides in the plan without entering policy vocabulary.
// ---------------------------------------------------------------------------

/// The spec that comes out of a plan is byte-identical to the one that went in,
/// for two backends whose identities differ. Nothing about which backend
/// answered has been written back into policy.
#[test]
fn backend_identity_does_not_enter_the_spec() {
    let spec = spec(vec![ControlRequirement::prevent(CapabilityDomain::FilesystemWrite)]);
    let caps = capabilities(vec![preventing(CapabilityDomain::FilesystemWrite)]);

    let one = negotiate(&spec, &identity("alpha"), &caps, &no_lowering()).expect("plans");
    let two = negotiate(&spec, &identity("beta"), &caps, &no_lowering()).expect("plans");

    assert_eq!(one.spec(), &spec);
    assert_eq!(two.spec(), &spec);
    assert_eq!(one.spec(), two.spec());
    assert_ne!(one.backend().id, two.backend().id);
}

/// Provenance travels with the plan so a release review has something to read.
#[test]
fn provenance_travels_with_the_plan() {
    let spec = spec(vec![]);
    let plan = negotiate(&spec, &identity("alpha"), &capabilities(vec![]), &no_lowering())
        .expect("a spec with no requirements plans trivially");
    assert_eq!(plan.posture(), LaunchPosture::Ready);
    assert_eq!(plan.backend().provenance.license, "Apache-2.0");
    assert!(!plan.backend().provenance.modified);
}

/// The lowering callback is invoked for shortfalls too, so evidence can show
/// what a degraded requirement actually got.
#[test]
fn lowering_is_recorded_for_shortfalls_as_well_as_successes() {
    let domain = CapabilityDomain::NetworkEgress;
    let spec = spec(vec![
        ControlRequirement::prevent(domain).with_posture(RequirementPosture::DegradeIfUnavailable)
    ]);
    let plan = negotiate(
        &spec,
        &identity("test"),
        &capabilities(vec![CapabilityReport::unsupported(domain, "none")]),
        &|requirement, _| Lowering::new([format!("noted {}", requirement.domain())]),
    )
    .expect("degradation permitted");
    assert_eq!(plan.planned()[0].lowering.steps(), ["noted network_egress"]);
}

// ---------------------------------------------------------------------------
// Capability-aware auto-selection (AAASM-5808).
//
// `aa-isolation` has no access to the real `SandlockBackend` / `NativeBackend`
// types — those live in their own crates, downstream of this one — so these
// tests exercise the premise `aa_cli::commands::run::plan::auto_select` is
// built on, using fixture `BackendCapabilities` shaped like each real
// backend's measured coverage (see the ticket's approved design): sandlock
// covers every domain except `Syscall`; the native backend covers exactly
// `FilesystemRead`, `FilesystemWrite` and `Syscall`. The two gaps are
// complementary, not nested, which is why a fixed-order eligibility walk
// against real `plan()`/`negotiate()` verdicts is the only correct selector —
// a hand-written domain-subset comparison would have to reimplement this
// logic and could drift from it.
// ---------------------------------------------------------------------------

/// Capabilities shaped like the sandlock backend's measured coverage: every
/// domain this crate defines requirements for, except `Syscall`.
fn sandlock_shaped() -> BackendCapabilities {
    capabilities(vec![
        preventing(CapabilityDomain::FilesystemRead),
        preventing(CapabilityDomain::FilesystemWrite),
        preventing(CapabilityDomain::NetworkEgress),
        preventing(CapabilityDomain::ProcessCreation),
        preventing(CapabilityDomain::Resource),
        preventing(CapabilityDomain::Ipc),
        preventing(CapabilityDomain::Credential),
        CapabilityReport::unsupported(CapabilityDomain::Syscall, "no seccomp-equivalent mechanism"),
    ])
}

/// Capabilities shaped like the native backend's measured coverage: exactly
/// `FilesystemRead`, `FilesystemWrite` and `Syscall`, and silence — not a
/// stated absence — about everything else.
fn native_shaped() -> BackendCapabilities {
    capabilities(vec![
        preventing(CapabilityDomain::FilesystemRead),
        preventing(CapabilityDomain::FilesystemWrite),
        preventing(CapabilityDomain::Syscall),
    ])
}

/// One candidate's id and the verdict `negotiate()` reached for it.
type ConsideredVerdict<'a> = (&'a str, Result<(), PlanRefusal>);

/// Walk `candidates` in the given fixed order and return the first whose
/// `negotiate()` verdict is `Ok`, alongside every verdict considered along the
/// way — the same fixed-order, lazy, plan()-is-the-oracle walk
/// `auto_select` performs against real backends.
fn select<'a>(
    candidates: &[(&'a str, BackendCapabilities)],
    probe: &ExecutionSpec,
) -> (Option<&'a str>, Vec<ConsideredVerdict<'a>>) {
    let mut considered = Vec::new();
    for (id, caps) in candidates {
        match negotiate(probe, &identity(id), caps, &no_lowering()) {
            Ok(_) => {
                considered.push((*id, Ok(())));
                return (Some(id), considered);
            }
            Err(refusal) => {
                considered.push((*id, Err(refusal)));
            }
        }
    }
    (None, considered)
}

/// A policy whose lowered requirements only the native-shaped candidate can
/// satisfy selects it, after the sandlock-shaped candidate is tried first and
/// rejected for the domain it cannot cover.
#[test]
fn a_policy_only_the_native_domains_can_satisfy_selects_the_native_candidate() {
    let probe = spec(vec![
        ControlRequirement::prevent(CapabilityDomain::FilesystemWrite),
        ControlRequirement::prevent(CapabilityDomain::Syscall),
    ]);
    let candidates = [("sandlock", sandlock_shaped()), ("aasm-native", native_shaped())];

    let (selected, considered) = select(&candidates, &probe);

    assert_eq!(selected, Some("aasm-native"));
    assert_eq!(considered.len(), 2, "both candidates must have been walked");
    assert!(
        considered[0].1.is_err(),
        "sandlock cannot cover Syscall and must be rejected"
    );
    assert!(considered[1].1.is_ok(), "the native candidate must be the one selected");
}

/// A policy whose lowered requirements the first candidate already satisfies
/// stops there — the second candidate is never reached.
#[test]
fn a_policy_requiring_network_egress_stays_on_the_first_candidate() {
    let probe = spec(vec![
        ControlRequirement::prevent(CapabilityDomain::FilesystemWrite),
        ControlRequirement::prevent(CapabilityDomain::NetworkEgress),
    ]);
    let candidates = [("sandlock", sandlock_shaped()), ("aasm-native", native_shaped())];

    let (selected, considered) = select(&candidates, &probe);

    assert_eq!(selected, Some("sandlock"));
    assert_eq!(
        considered.len(),
        1,
        "the walk is lazy — a satisfied first candidate must never reach the second"
    );
}

/// A policy no candidate can satisfy selects none and names both, each with
/// its own distinct unmet domain.
#[test]
fn a_policy_no_candidate_satisfies_selects_none_and_names_both() {
    let probe = spec(vec![
        ControlRequirement::prevent(CapabilityDomain::NetworkEgress),
        ControlRequirement::prevent(CapabilityDomain::Syscall),
    ]);
    let candidates = [("sandlock", sandlock_shaped()), ("aasm-native", native_shaped())];

    let (selected, considered) = select(&candidates, &probe);

    assert_eq!(selected, None);
    assert_eq!(considered.len(), 2, "both candidates must be named in the refusal");

    let sandlock_domains: Vec<CapabilityDomain> = considered[0]
        .1
        .as_ref()
        .expect_err("sandlock cannot cover Syscall")
        .unmet()
        .iter()
        .filter_map(|(_, reason)| reason.domain())
        .collect();
    let native_domains: Vec<CapabilityDomain> = considered[1]
        .1
        .as_ref()
        .expect_err("the native candidate cannot cover NetworkEgress")
        .unmet()
        .iter()
        .filter_map(|(_, reason)| reason.domain())
        .collect();

    assert_eq!(sandlock_domains, vec![CapabilityDomain::Syscall]);
    assert_eq!(native_domains, vec![CapabilityDomain::NetworkEgress]);
    assert_ne!(
        sandlock_domains, native_domains,
        "the two rejections must name different gaps, not the same generic refusal twice"
    );
}

/// The control for the case above: drop `NetworkEgress` from the requirement
/// set and the same two candidates must resolve to the second one succeeding,
/// proving the "selects none" result above is about the requirement shape and
/// not about selection being broken outright.
#[test]
fn a_policy_the_second_candidate_satisfies_is_not_reported_as_unsatisfiable() {
    let probe = spec(vec![ControlRequirement::prevent(CapabilityDomain::Syscall)]);
    let candidates = [("sandlock", sandlock_shaped()), ("aasm-native", native_shaped())];

    let (selected, considered) = select(&candidates, &probe);

    assert_eq!(selected, Some("aasm-native"));
    assert_eq!(considered.len(), 2);
    assert!(considered[0].1.is_err());
    assert!(considered[1].1.is_ok());
}

/// The load-bearing premise of the whole design: a probe spec built from
/// nothing but the lowered requirements gets the identical `plan()` verdict a
/// real launch's spec would, because `narrow_for` and `negotiate` read only
/// [`ExecutionSpec::requirements`]. Two specs with identical requirements but
/// different program, args, identity, working directory and credentials must
/// agree on `Ok`/`Err` and, when they refuse, on exactly which domains are
/// unmet.
#[test]
fn probe_spec_and_real_spec_produce_the_same_verdict() {
    let requirements = vec![
        ControlRequirement::prevent(CapabilityDomain::FilesystemWrite),
        ControlRequirement::prevent(CapabilityDomain::Syscall),
    ];

    let mut probe_like = ExecutionSpec::new("probe", IdentityRef::root("probe"));
    for requirement in requirements.clone() {
        probe_like = probe_like.with_requirement(requirement);
    }

    let mut real_like = ExecutionSpec::new("/usr/bin/python3", IdentityRef::root("agent-42").with_team("pioneer"))
        .with_args(["ai_agent_main.py", "--flag"])
        .with_working_dir("/home/operator/project");
    for requirement in requirements {
        real_like = real_like.with_requirement(requirement);
    }

    let backend = identity("sandlock");
    let caps = sandlock_shaped();

    let probe_result = negotiate(&probe_like, &backend, &caps, &no_lowering());
    let real_result = negotiate(&real_like, &backend, &caps, &no_lowering());

    match (&probe_result, &real_result) {
        (Err(probe_refusal), Err(real_refusal)) => {
            let probe_domains: Vec<_> = probe_refusal.unmet().iter().filter_map(|(_, r)| r.domain()).collect();
            let real_domains: Vec<_> = real_refusal.unmet().iter().filter_map(|(_, r)| r.domain()).collect();
            assert_eq!(
                probe_domains, real_domains,
                "the probe and the real spec must refuse for exactly the same domains"
            );
        }
        (Ok(_), Ok(_)) => {}
        other => panic!("the probe and the real spec disagreed on Ok/Err: {other:?}"),
    }
}
