//! Independent falsification of the backend planner's property-satisfaction
//! and incompatible-backend-refusal contract (AAASM-6296, QA ST-9, journey
//! J88; feature AAASM-6167).
//!
//! **FIXTURES:** every candidate here is a synthetic, labelled capability
//! fixture, not a measurement of a real backend.
//!
//! # Why these exist next to `planner::tests`
//!
//! The developer-authored unit tests in `src/planner.rs` pin the two headline
//! mutations. These tests are the independent QA read of the same contract and
//! deliberately differ in method:
//!
//! * The posture ordering is checked against a **rank expressed separately**
//!   (an index into an explicit strongest-to-weakest array) rather than a
//!   second hand-written `match`, so the implementation's `match` and the
//!   oracle cannot be the same constant written twice.
//! * Every refusal is paired with a **control** that differs in exactly one
//!   input and is selected, so a refusal is attributable to the stated
//!   property and not to an incidental unavailable/inert candidate.
//! * Candidate **order is permuted**, so "the right backend was chosen" cannot
//!   be explained by declared order alone.
//! * The selection walk is projected into the same machine-readable report a
//!   run's receipt carries, so "visible in the evidence" is asserted over the
//!   artifact an operator or verifier actually reads.
//!
//! The mutation that must redden this file is "make `evaluate_candidate`
//! ignore `FailurePosture`" (see the PR description for the recorded run).

use aa_isolation::planner::{evaluate_candidate, select, select_pinned, Candidate, Selection};
use aa_isolation::{
    BackendAvailability, BackendCapabilities, BackendIdentity, CandidateVerdict, CapabilityDomain, CapabilityReport,
    ControlRequirement, CredentialPosture, DecisionTiming, DescendantCoverage, EvidenceMinimum, FailurePosture,
    IdentityRef, IsolationReport, Mediation, PlatformBoundary, Provenance, RefusalReason, RuntimeRequirements,
    SelectionMode, SessionRef, SupportLevel, Synchrony, TargetRef,
};

const FS: CapabilityDomain = CapabilityDomain::FilesystemWrite;
const NET: CapabilityDomain = CapabilityDomain::NetworkEgress;
const SYS: CapabilityDomain = CapabilityDomain::Syscall;

fn identity(id: &str) -> BackendIdentity {
    BackendIdentity {
        id: id.to_string(),
        version: "1.0".to_string(),
        provenance: Provenance {
            source: "qa".to_string(),
            license: "Apache-2.0".to_string(),
            modified: false,
        },
    }
}

/// One domain a candidate fully prevents (enforce / pre / sync / process tree),
/// with the two evidence axes `negotiate` never reads left as the knobs.
fn prevents(domain: CapabilityDomain, posture: FailurePosture, support: SupportLevel) -> CapabilityReport {
    CapabilityReport::new(domain, Mediation::Enforce, DecisionTiming::Pre, Synchrony::Sync)
        .with_descendants(DescendantCoverage::ProcessTree)
        .with_failure_posture(posture)
        .with_support(support)
}

fn candidate_with(id: &str, availability: BackendAvailability, reports: Vec<CapabilityReport>) -> Candidate {
    Candidate::new(
        identity(id),
        BackendCapabilities::new(availability, PlatformBoundary::SharedHostKernel, reports).expect("unique domains"),
    )
}

fn candidate(id: &str, reports: Vec<CapabilityReport>) -> Candidate {
    candidate_with(id, BackendAvailability::Available, reports)
}

fn min_posture(posture: FailurePosture) -> EvidenceMinimum {
    EvidenceMinimum::none().with_min_failure_posture(posture)
}

fn selected_id(selection: &Selection) -> Option<&str> {
    match selection {
        Selection::Selected { identity, .. } => Some(identity.id.as_str()),
        Selection::Refused => None,
    }
}

// ---------------------------------------------------------------------------
// The posture ordering, against an independently expressed rank.
// ---------------------------------------------------------------------------

/// Strongest to weakest. `FailOpenSilent` is documented as "the worst
/// posture"; `NotApplicable` is deliberately not on the ladder (it is the
/// "backend never stated an opinion" value and satisfies only itself).
const LADDER: [FailurePosture; 4] = [
    FailurePosture::FailClosed,
    FailurePosture::FailOpen,
    FailurePosture::SilentTruncation,
    FailurePosture::FailOpenSilent,
];

fn rank(posture: FailurePosture) -> usize {
    LADDER.iter().position(|p| *p == posture).expect("on the ladder")
}

/// For every (actual, minimum) pair on the ladder the planner's verdict must
/// equal "actual is at least as strong as the minimum". Every pair is run
/// through the public `evaluate_candidate`, with `negotiate` accepting every
/// candidate (enforce/pre/sync), so the only thing that can flip a verdict is
/// the evidence axis under test.
#[test]
fn every_failure_posture_pair_is_decided_by_the_ladder_and_nothing_else() {
    for actual in LADDER {
        for minimum in LADDER {
            let c = candidate("c", vec![prevents(FS, actual, SupportLevel::Full)]);
            let requirements = RuntimeRequirements::new()
                .with_confinement(ControlRequirement::prevent(FS))
                .with_evidence_minimum(FS, min_posture(minimum));
            let verdict = evaluate_candidate(&requirements, &c);
            let should_pass = rank(actual) <= rank(minimum);
            assert_eq!(
                verdict.is_ok(),
                should_pass,
                "actual={actual:?} minimum={minimum:?}: expected eligible={should_pass}"
            );
            if let Err(refusal) = verdict {
                let named = refusal.unmet().iter().any(|(_, reason)| {
                    matches!(
                        reason,
                        RefusalReason::EvidenceQualityBelowMinimum {
                            domain: FS,
                            required_failure_posture: Some(m),
                            actual_failure_posture: a,
                            ..
                        } if *m == minimum && *a == actual
                    )
                });
                assert!(
                    named,
                    "the refusal must name the stated minimum and the actual posture: {refusal}"
                );
            }
        }
    }
}

/// "A backend that never stated an opinion on this axis must not be read as
/// meeting a minimum it never addressed." `NotApplicable` (the default a
/// report keeps when `with_failure_posture` is never called) meets no ladder
/// minimum, while a stated-but-weaker `FailOpenSilent` still meets the weakest.
#[test]
fn a_posture_nobody_stated_meets_no_minimum_on_the_ladder() {
    for minimum in LADDER {
        let silent = candidate(
            "silent",
            vec![prevents(FS, FailurePosture::NotApplicable, SupportLevel::Full)],
        );
        let requirements = RuntimeRequirements::new()
            .with_confinement(ControlRequirement::prevent(FS))
            .with_evidence_minimum(FS, min_posture(minimum));
        assert!(
            evaluate_candidate(&requirements, &silent).is_err(),
            "NotApplicable must not satisfy a stated {minimum:?} minimum"
        );
    }
}

// ---------------------------------------------------------------------------
// Property satisfaction: the backend whose evidence matches is the one chosen.
// ---------------------------------------------------------------------------

/// Two backends with complementary evidence: `fs_strong` is fail-closed on
/// filesystem writes and fail-open-silent on network; `net_strong` is the
/// mirror. Each passes `negotiate` for both domains, so only the stated
/// evidence minimum can tell them apart.
fn complementary_pair() -> (Candidate, Candidate) {
    let fs_strong = candidate(
        "fs-strong",
        vec![
            prevents(FS, FailurePosture::FailClosed, SupportLevel::Full),
            prevents(NET, FailurePosture::FailOpenSilent, SupportLevel::Full),
        ],
    );
    let net_strong = candidate(
        "net-strong",
        vec![
            prevents(FS, FailurePosture::FailOpenSilent, SupportLevel::Full),
            prevents(NET, FailurePosture::FailClosed, SupportLevel::Full),
        ],
    );
    (fs_strong, net_strong)
}

fn both_domains_prevented() -> RuntimeRequirements {
    RuntimeRequirements::new()
        .with_confinement(ControlRequirement::prevent(FS))
        .with_confinement(ControlRequirement::prevent(NET))
}

/// The chosen backend follows the property that is demanded and not the
/// declared order: demanding fail-closed filesystem writes picks `fs-strong`
/// and demanding fail-closed network picks `net-strong`, in **both** candidate
/// orders. A planner that merely returned the first available candidate would
/// pick the same one in both rows of one order.
#[test]
fn the_selected_backend_follows_the_demanded_property_in_either_candidate_order() {
    let (fs_strong, net_strong) = complementary_pair();

    for (demanded, expected) in [(FS, "fs-strong"), (NET, "net-strong")] {
        let requirements =
            both_domains_prevented().with_evidence_minimum(demanded, min_posture(FailurePosture::FailClosed));

        for order in [
            vec![fs_strong.clone(), net_strong.clone()],
            vec![net_strong.clone(), fs_strong.clone()],
        ] {
            let (selection, report) = select(&requirements, &order);
            assert_eq!(
                selected_id(&selection),
                Some(expected),
                "demanding fail-closed {demanded:?} must select {expected} regardless of order; considered: {:?}",
                report.considered
            );
            // The selected plan's backend is the backend named in the verdict.
            if let Selection::Selected { plan, .. } = &selection {
                assert_eq!(plan.backend().id, expected);
            }
            // The rejected one is rejected for exactly the demanded domain.
            let rejected: Vec<_> = report
                .considered
                .iter()
                .filter(|c| c.verdict == CandidateVerdict::RejectedRequirementsUnmet)
                .collect();
            for r in rejected {
                assert_ne!(r.id, expected);
                assert_eq!(r.unmet_domains, vec![demanded], "{r:?}");
            }
        }
    }
}

/// The attribution control: with no evidence minimum stated, the same two
/// candidates are both eligible and declared order decides. That makes the
/// previous test's outcome attributable to the minimum, not to the fixtures.
#[test]
fn without_an_evidence_minimum_both_backends_are_eligible_and_declared_order_decides() {
    let (fs_strong, net_strong) = complementary_pair();
    let requirements = both_domains_prevented();

    let (a, _) = select(&requirements, &[fs_strong.clone(), net_strong.clone()]);
    let (b, _) = select(&requirements, &[net_strong, fs_strong]);
    assert_eq!(selected_id(&a), Some("fs-strong"));
    assert_eq!(selected_id(&b), Some("net-strong"));
}

/// Demanding fail-closed on **both** domains is satisfied by neither backend:
/// nothing is selected, and each rejection names the one domain it is weak on.
/// No "closest" backend is granted.
#[test]
fn a_property_combination_no_backend_satisfies_selects_nothing() {
    let (fs_strong, net_strong) = complementary_pair();
    let requirements = both_domains_prevented()
        .with_evidence_minimum(FS, min_posture(FailurePosture::FailClosed))
        .with_evidence_minimum(NET, min_posture(FailurePosture::FailClosed));

    let (selection, report) = select(&requirements, &[fs_strong, net_strong]);

    assert_eq!(selection, Selection::Refused);
    assert_eq!(report.considered.len(), 2, "every candidate is named");
    assert_eq!(report.considered[0].id, "fs-strong");
    assert_eq!(report.considered[0].unmet_domains, vec![NET]);
    assert_eq!(report.considered[1].id, "net-strong");
    assert_eq!(report.considered[1].unmet_domains, vec![FS]);
    for c in &report.considered {
        assert_eq!(c.verdict, CandidateVerdict::RejectedRequirementsUnmet);
        assert!(!c.detail.trim().is_empty(), "a rejection must carry its reason: {c:?}");
    }
}

/// An evidence minimum on one domain must not be satisfied by strength on a
/// different domain: a candidate that is fail-closed on network only does not
/// meet a fail-closed *syscall* minimum.
#[test]
fn strength_on_one_domain_does_not_satisfy_a_minimum_on_another() {
    let only_net = candidate(
        "only-net",
        vec![
            prevents(NET, FailurePosture::FailClosed, SupportLevel::Full),
            prevents(SYS, FailurePosture::FailOpenSilent, SupportLevel::Full),
        ],
    );
    let requirements = RuntimeRequirements::new()
        .with_confinement(ControlRequirement::prevent(SYS))
        .with_evidence_minimum(SYS, min_posture(FailurePosture::FailClosed));

    assert!(evaluate_candidate(&requirements, &only_net).is_err());

    let control = RuntimeRequirements::new()
        .with_confinement(ControlRequirement::prevent(NET))
        .with_evidence_minimum(NET, min_posture(FailurePosture::FailClosed));
    assert!(
        evaluate_candidate(&control, &only_net).is_ok(),
        "control: the same candidate meets the same minimum on the domain it is strong on"
    );
}

/// Full-support bar, paired with its control, on the second evidence axis.
#[test]
fn a_partial_support_report_is_refused_by_a_full_support_minimum_and_accepted_without_one() {
    let partial = candidate(
        "partial",
        vec![prevents(
            FS,
            FailurePosture::FailClosed,
            SupportLevel::Partial {
                limitations: vec!["does not cover device nodes".to_string()],
            },
        )],
    );
    let base = RuntimeRequirements::new().with_confinement(ControlRequirement::prevent(FS));

    assert!(
        evaluate_candidate(&base, &partial).is_ok(),
        "control: negotiate accepts it"
    );
    let strict = base.with_evidence_minimum(FS, EvidenceMinimum::none().with_full_support_required());
    let refusal = evaluate_candidate(&strict, &partial).expect_err("partial support must not meet a full-support bar");
    assert!(refusal.unmet().iter().any(|(_, reason)| matches!(
        reason,
        RefusalReason::EvidenceQualityBelowMinimum {
            required_full_support: true,
            ..
        }
    )));
}

/// "Unknown is not supported": a minimum stated on a domain the backend has no
/// report for is refused, not waved through.
#[test]
fn an_evidence_minimum_on_a_domain_the_backend_never_reported_is_refused() {
    let fs_only = candidate(
        "fs-only",
        vec![prevents(FS, FailurePosture::FailClosed, SupportLevel::Full)],
    );
    let requirements = RuntimeRequirements::new()
        .with_confinement(ControlRequirement::prevent(FS))
        .with_evidence_minimum(NET, min_posture(FailurePosture::FailOpenSilent));

    let refusal = evaluate_candidate(&requirements, &fs_only).expect_err("no report for NET");
    assert!(refusal
        .unmet()
        .iter()
        .any(|(_, reason)| matches!(reason, RefusalReason::NoCapabilityReported { domain: NET })));
}

// ---------------------------------------------------------------------------
// Incompatible-backend refusal: never a silent downgrade.
// ---------------------------------------------------------------------------

/// A backend that is otherwise a perfect match but reports itself unavailable
/// on this host is never selected, and the control is the identical backend
/// reported available.
#[test]
fn an_unavailable_backend_is_never_selected_however_well_its_evidence_matches() {
    let reports = || vec![prevents(FS, FailurePosture::FailClosed, SupportLevel::Full)];
    let requirements = RuntimeRequirements::new()
        .with_confinement(ControlRequirement::prevent(FS))
        .with_evidence_minimum(FS, min_posture(FailurePosture::FailClosed));

    let unavailable = candidate_with(
        "perfect-but-absent",
        BackendAvailability::Unavailable {
            reason: "not installed on this host".to_string(),
        },
        reports(),
    );
    let (selection, report) = select(&requirements, &[unavailable]);
    assert_eq!(selection, Selection::Refused);
    assert_eq!(report.considered.len(), 1);
    assert_eq!(report.considered[0].verdict, CandidateVerdict::RejectedUnavailable);
    assert!(
        report.considered[0].detail.contains("not installed on this host"),
        "the host reason must reach the record: {:?}",
        report.considered[0]
    );

    let available = candidate("perfect-but-absent", reports());
    let (selection, _) = select(&requirements, &[available]);
    assert_eq!(selected_id(&selection), Some("perfect-but-absent"));
}

/// A refused walk selects nothing, records every candidate in order, and
/// relaxing only the stated minimum flips the first candidate to selected,
/// which attributes the refusal to the minimum alone.
#[test]
fn a_refusal_is_attributable_to_the_stated_minimum_and_names_every_candidate_in_order() {
    let weak_a = candidate(
        "weak-a",
        vec![prevents(FS, FailurePosture::FailOpenSilent, SupportLevel::Full)],
    );
    let weak_b = candidate(
        "weak-b",
        vec![prevents(FS, FailurePosture::SilentTruncation, SupportLevel::Full)],
    );
    let strict = RuntimeRequirements::new()
        .with_confinement(ControlRequirement::prevent(FS))
        .with_evidence_minimum(FS, min_posture(FailurePosture::FailClosed));

    let (selection, report) = select(&strict, &[weak_a.clone(), weak_b.clone()]);
    assert_eq!(selection, Selection::Refused);
    assert_eq!(
        report.considered.iter().map(|c| c.id.as_str()).collect::<Vec<_>>(),
        vec!["weak-a", "weak-b"]
    );
    assert!(report
        .considered
        .iter()
        .all(|c| c.verdict == CandidateVerdict::RejectedRequirementsUnmet && c.unmet_domains == vec![FS]));
    assert_eq!(report.mode, SelectionMode::Automatic);

    let relaxed = RuntimeRequirements::new().with_confinement(ControlRequirement::prevent(FS));
    let (selection, _) = select(&relaxed, &[weak_a, weak_b]);
    assert_eq!(
        selected_id(&selection),
        Some("weak-a"),
        "control: with no minimum the same candidates are eligible"
    );
}

/// The automatic walk is lazy: nothing after the first eligible candidate is
/// considered, so a later, weaker candidate can never be recorded as chosen.
#[test]
fn the_walk_stops_at_the_first_eligible_candidate() {
    let first = candidate(
        "first",
        vec![prevents(FS, FailurePosture::FailClosed, SupportLevel::Full)],
    );
    let second = candidate(
        "second",
        vec![prevents(FS, FailurePosture::FailClosed, SupportLevel::Full)],
    );
    let requirements = RuntimeRequirements::new().with_confinement(ControlRequirement::prevent(FS));

    let (selection, report) = select(&requirements, &[first, second]);
    assert_eq!(selected_id(&selection), Some("first"));
    assert_eq!(report.considered.len(), 1);
    assert_eq!(report.considered[0].verdict, CandidateVerdict::Selected);
}

/// An explicit pin never falls back to a stronger neighbour, and agrees with
/// the automatic walk's verdict for the same candidate and requirements.
#[test]
fn a_pin_that_misses_the_property_refuses_and_agrees_with_the_walk() {
    let weak = candidate(
        "weak",
        vec![prevents(FS, FailurePosture::FailOpenSilent, SupportLevel::Full)],
    );
    let strong = candidate(
        "strong",
        vec![prevents(FS, FailurePosture::FailClosed, SupportLevel::Full)],
    );
    let requirements = RuntimeRequirements::new()
        .with_confinement(ControlRequirement::prevent(FS))
        .with_evidence_minimum(FS, min_posture(FailurePosture::FailClosed));

    let refusal = select_pinned(&requirements, &weak).expect_err("the pinned weak backend must refuse");
    assert_eq!(refusal.backend().id, "weak", "the refusal is the pinned backend's own");

    assert!(
        select_pinned(&requirements, &strong).is_ok(),
        "control: the strong pin is fine"
    );

    // Pin and walk agree for each candidate taken alone.
    for c in [&weak, &strong] {
        let pinned_ok = select_pinned(&requirements, c).is_ok();
        let (walk, _) = select(&requirements, std::slice::from_ref(c));
        assert_eq!(pinned_ok, walk != Selection::Refused, "{}", c.identity.id);
    }
}

/// A prevention requirement is still gated by `negotiate`: a candidate with
/// pristine evidence labels but an observe-only mediation is refused. The
/// planner adds a bar; it must not replace the existing one.
#[test]
fn excellent_evidence_labels_do_not_rescue_a_backend_that_cannot_prevent() {
    let observe_only = candidate(
        "observe-only",
        vec![
            CapabilityReport::new(FS, Mediation::Observe, DecisionTiming::Pre, Synchrony::Sync)
                .with_descendants(DescendantCoverage::ProcessTree)
                .with_failure_posture(FailurePosture::FailClosed)
                .with_support(SupportLevel::Full),
        ],
    );
    let requirements = RuntimeRequirements::new()
        .with_confinement(ControlRequirement::prevent(FS))
        .with_evidence_minimum(FS, min_posture(FailurePosture::FailClosed));

    let (selection, report) = select(&requirements, &[observe_only]);
    assert_eq!(selection, Selection::Refused);
    assert_eq!(
        report.considered[0].verdict,
        CandidateVerdict::RejectedRequirementsUnmet
    );
}

// ---------------------------------------------------------------------------
// Determinism.
// ---------------------------------------------------------------------------

/// Re-running the same request against freshly rebuilt, identical candidates
/// returns the same verdict and the same considered record every time, for a
/// selecting walk and for a refusing walk.
#[test]
fn repeated_selection_on_unchanged_capabilities_is_identical() {
    let requirements = both_domains_prevented().with_evidence_minimum(NET, min_posture(FailurePosture::FailClosed));
    let refusing = both_domains_prevented()
        .with_evidence_minimum(FS, min_posture(FailurePosture::FailClosed))
        .with_evidence_minimum(NET, min_posture(FailurePosture::FailClosed));

    let run = |req: &RuntimeRequirements| {
        let (a, b) = complementary_pair();
        select(req, &[a, b])
    };

    let (first_sel, first_rec) = run(&requirements);
    let (first_ref_sel, first_ref_rec) = run(&refusing);
    assert_eq!(selected_id(&first_sel), Some("net-strong"));
    assert_eq!(first_ref_sel, Selection::Refused);

    for _ in 0..100 {
        let (sel, rec) = run(&requirements);
        assert_eq!(sel, first_sel);
        assert_eq!(rec.considered, first_rec.considered);
        let (sel, rec) = run(&refusing);
        assert_eq!(sel, first_ref_sel);
        assert_eq!(rec.considered, first_ref_rec.considered);
    }
}

/// The control for determinism: a real capability change (the formerly weak
/// domain is upgraded) does change the answer, so the stability above is not
/// a planner that ignores its inputs.
#[test]
fn a_change_in_host_capability_changes_the_selection() {
    let requirements = both_domains_prevented().with_evidence_minimum(NET, min_posture(FailurePosture::FailClosed));
    let (fs_strong, net_strong) = complementary_pair();
    let (before, _) = select(&requirements, &[fs_strong.clone(), net_strong.clone()]);
    assert_eq!(selected_id(&before), Some("net-strong"));

    let upgraded = candidate(
        "fs-strong",
        vec![
            prevents(FS, FailurePosture::FailClosed, SupportLevel::Full),
            prevents(NET, FailurePosture::FailClosed, SupportLevel::Full),
        ],
    );
    let (after, _) = select(&requirements, &[upgraded, net_strong]);
    assert_eq!(selected_id(&after), Some("fs-strong"));
}

// ---------------------------------------------------------------------------
// The decision and its reasoning reach the report an operator reads.
// ---------------------------------------------------------------------------

fn machine(report: &IsolationReport) -> std::collections::BTreeMap<String, String> {
    report
        .machine_lines()
        .into_iter()
        .map(|line| {
            let (k, v) = line.split_once('=').expect("key=value");
            (k.to_string(), v.to_string())
        })
        .collect()
}

#[test]
fn the_selection_walk_and_its_reasons_reach_the_machine_readable_report() {
    let (fs_strong, net_strong) = complementary_pair();
    let requirements = both_domains_prevented().with_evidence_minimum(NET, min_posture(FailurePosture::FailClosed));
    let (_, selection) = select(&requirements, &[fs_strong, net_strong]);

    let report = IsolationReport::no_boundary(
        SessionRef::new("session-qa", "trace-qa"),
        IdentityRef::root("agent-qa"),
        TargetRef::new("qa-tool", 0),
        CredentialPosture::default(),
        "fixture without a launched boundary",
    )
    .with_selection(selection);
    let m = machine(&report);

    assert_eq!(m["backend_selection_mode"], "automatic");
    assert_eq!(m["backend_selection.considered_count"], "2");
    assert_eq!(m["backend_selection.considered.0.id"], "fs-strong");
    assert_eq!(
        m["backend_selection.considered.0.verdict"],
        "rejected_requirements_unmet"
    );
    assert_eq!(m["backend_selection.considered.0.unmet_domain_count"], "1");
    assert_eq!(m["backend_selection.considered.0.unmet_domain.0"], "network_egress");
    assert!(
        !m["backend_selection.considered.0.detail"].trim().is_empty(),
        "the reason for the rejection must be in the record"
    );
    assert_eq!(m["backend_selection.considered.1.id"], "net-strong");
    assert_eq!(m["backend_selection.considered.1.verdict"], "selected");
}

/// A refusal is also visible: the record of a walk that selected nothing still
/// names every rejected candidate with a rejecting verdict and no `selected`.
#[test]
fn a_refused_walk_is_recorded_with_no_selected_candidate() {
    let (fs_strong, net_strong) = complementary_pair();
    let requirements = both_domains_prevented()
        .with_evidence_minimum(FS, min_posture(FailurePosture::FailClosed))
        .with_evidence_minimum(NET, min_posture(FailurePosture::FailClosed));
    let (selection, record) = select(&requirements, &[fs_strong, net_strong]);
    assert_eq!(selection, Selection::Refused);

    let report = IsolationReport::no_boundary(
        SessionRef::new("session-qa", "trace-qa"),
        IdentityRef::root("agent-qa"),
        TargetRef::new("qa-tool", 0),
        CredentialPosture::default(),
        "fixture without a launched boundary",
    )
    .with_selection(record);
    let m = machine(&report);

    assert_eq!(m["backend_selection.considered_count"], "2");
    assert!(
        !m.iter()
            .any(|(k, v)| k.starts_with("backend_selection.considered.") && k.ends_with(".verdict") && v == "selected"),
        "a refused walk must not record any candidate as selected: {m:?}"
    );
}
