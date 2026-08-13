//! What the evidence grades permit and forbid.
//!
//! The tests that matter here are the negative ones. Several deliberately
//! construct *hostile* evidence — a setup-time record carrying a prevention
//! claim term — because a grading rule that only ever sees well-formed input
//! has not been tested at all.

use aa_core::attestation::ClaimTerm;
use aa_isolation::{
    negotiate, BackendAvailability, BackendCapabilities, BackendIdentity, CapabilityDomain, CapabilityReport,
    ControlRequirement, DecisionTiming, DescendantCoverage, EnforcementEvidence, EvidenceKind, EvidenceRecord,
    ExecutionSpec, IdentityRef, LaunchPosture, Lowering, Mediation, PlatformBoundary, Provenance, RequirementPosture,
    Synchrony,
};

fn identity() -> BackendIdentity {
    BackendIdentity {
        id: "test".to_string(),
        version: "1.0".to_string(),
        provenance: Provenance {
            source: "test".to_string(),
            license: "Apache-2.0".to_string(),
            modified: false,
        },
    }
}

fn preventing_capabilities(domain: CapabilityDomain) -> BackendCapabilities {
    BackendCapabilities::new(
        BackendAvailability::Available,
        PlatformBoundary::SharedHostKernel,
        vec![
            CapabilityReport::new(domain, Mediation::Enforce, DecisionTiming::Pre, Synchrony::Sync)
                .with_descendants(DescendantCoverage::ProcessTree),
        ],
    )
    .expect("unique")
}

// ---------------------------------------------------------------------------
// Setup-time evidence never becomes a prevention claim.
// ---------------------------------------------------------------------------

/// Hostile input: `Configured` and `Installed` records that carry
/// `DeniedBeforeExecution`. Neither may support a prevention claim, and neither
/// may raise `claim_for` above `Unmeasured`.
///
/// This is ADR 0035's validation bar — "E6 output never promotes
/// `available`/`configured`/`observed` into `enforced` without evidence" — with
/// the promotion actually attempted rather than merely avoided.
#[test]
fn setup_records_never_support_a_prevention_claim() {
    let domain = CapabilityDomain::NetworkEgress;
    for kind in [EvidenceKind::Configured, EvidenceKind::Installed] {
        let evidence = EnforcementEvidence::new(identity(), LaunchPosture::Ready).with_record(EvidenceRecord::new(
            kind,
            domain,
            ClaimTerm::DeniedBeforeExecution,
            "a record claiming more than its grade allows",
        ));
        assert!(
            !evidence.supports_prevention_claim(domain),
            "{kind:?} must not support a prevention claim"
        );
        assert_eq!(
            evidence.claim_for(domain),
            ClaimTerm::Unmeasured,
            "{kind:?} must not raise the supported claim"
        );
    }
}

/// A `Decision` record carrying a prevention term is the one thing that does.
#[test]
fn a_decision_record_supports_a_prevention_claim() {
    let domain = CapabilityDomain::NetworkEgress;
    let evidence = EnforcementEvidence::new(identity(), LaunchPosture::Ready).with_record(EvidenceRecord::new(
        EvidenceKind::Decision,
        domain,
        ClaimTerm::DeniedBeforeExecution,
        "connection to 10.0.0.1:443 refused before the socket was created",
    ));
    assert!(evidence.supports_prevention_claim(domain));
    assert_eq!(evidence.claim_for(domain), ClaimTerm::DeniedBeforeExecution);
}

/// A `Decision` record that did not prevent does not become prevention either.
#[test]
fn a_decision_that_observed_is_not_a_prevention_claim() {
    let domain = CapabilityDomain::NetworkEgress;
    let evidence = EnforcementEvidence::new(identity(), LaunchPosture::Ready).with_record(EvidenceRecord::new(
        EvidenceKind::Decision,
        domain,
        ClaimTerm::Observed,
        "connection observed",
    ));
    assert!(!evidence.supports_prevention_claim(domain));
    assert_eq!(evidence.claim_for(domain), ClaimTerm::Observed);
}

/// Independent verification corroborates; it does not substitute. Without a
/// decision from the enforcing component, an out-of-band probe showing the
/// action failed does not establish that this control is why.
#[test]
fn independent_verification_alone_is_not_a_prevention_claim() {
    let domain = CapabilityDomain::FilesystemWrite;
    let evidence = EnforcementEvidence::new(identity(), LaunchPosture::Ready).with_record(EvidenceRecord::new(
        EvidenceKind::IndependentVerification,
        domain,
        ClaimTerm::DeniedBeforeExecution,
        "adversarial probe could not write outside the allowed prefix",
    ));
    assert!(!evidence.supports_prevention_claim(domain));
    assert!(evidence.is_independently_verified(domain));
}

/// A prevention claim for one domain says nothing about another.
#[test]
fn a_prevention_claim_does_not_generalise_across_domains() {
    let evidence = EnforcementEvidence::new(identity(), LaunchPosture::Ready).with_record(EvidenceRecord::new(
        EvidenceKind::Decision,
        CapabilityDomain::NetworkEgress,
        ClaimTerm::DeniedBeforeExecution,
        "denied",
    ));
    assert!(evidence.supports_prevention_claim(CapabilityDomain::NetworkEgress));
    assert!(!evidence.supports_prevention_claim(CapabilityDomain::FilesystemWrite));
    assert_eq!(
        evidence.claim_for(CapabilityDomain::FilesystemWrite),
        ClaimTerm::Unmeasured
    );
}

/// Nothing recorded means nothing measured — not "clean". ADR 0035's threat
/// model item 5.
#[test]
fn absence_of_records_is_unmeasured_not_clean() {
    let evidence = EnforcementEvidence::new(identity(), LaunchPosture::Ready);
    for domain in CapabilityDomain::ALL {
        assert_eq!(evidence.claim_for(*domain), ClaimTerm::Unmeasured);
        assert!(!evidence.supports_prevention_claim(*domain));
    }
}

#[test]
fn claim_for_picks_the_strongest_runtime_claim() {
    let domain = CapabilityDomain::Syscall;
    let evidence = EnforcementEvidence::new(identity(), LaunchPosture::Ready)
        .with_record(EvidenceRecord::new(
            EvidenceKind::Exercised,
            domain,
            ClaimTerm::Observed,
            "call observed",
        ))
        .with_record(EvidenceRecord::new(
            EvidenceKind::Decision,
            domain,
            ClaimTerm::DeniedBeforeExecution,
            "call refused",
        ))
        .with_record(EvidenceRecord::new(
            EvidenceKind::Exercised,
            domain,
            ClaimTerm::Detected,
            "pattern matched",
        ));
    assert_eq!(evidence.claim_for(domain), ClaimTerm::DeniedBeforeExecution);
}

/// Degradation ranks below every form of observation, so it can never win
/// against a record showing something was actually seen.
#[test]
fn degraded_never_outranks_an_observation() {
    let domain = CapabilityDomain::Ipc;
    let evidence = EnforcementEvidence::new(identity(), LaunchPosture::Degraded)
        .with_record(EvidenceRecord::new(
            EvidenceKind::Exercised,
            domain,
            ClaimTerm::Degraded,
            "degraded",
        ))
        .with_record(EvidenceRecord::new(
            EvidenceKind::Exercised,
            domain,
            ClaimTerm::Observed,
            "observed",
        ));
    assert_eq!(evidence.claim_for(domain), ClaimTerm::Observed);
}

// ---------------------------------------------------------------------------
// Evidence derived from a plan or a refusal.
// ---------------------------------------------------------------------------

/// A plan is an intention. Even a requirement the plan will enforce is
/// `Planned` at this point, because the run has not happened.
///
/// This is also the behavioural form of "backend availability is not enforcement
/// evidence": the backend below is available *and* reports that it can prevent,
/// and the resulting evidence still supports no prevention claim.
#[test]
fn plan_evidence_is_planned_not_enforced() {
    let domain = CapabilityDomain::FilesystemWrite;
    let spec = ExecutionSpec::new("python", IdentityRef::root("agent-1"))
        .with_requirement(ControlRequirement::prevent(domain));
    let plan = negotiate(&spec, &identity(), &preventing_capabilities(domain), &|_, _| {
        Lowering::none()
    })
    .expect("plans");

    assert!(plan.planned()[0].outcome.is_prevention());

    let evidence = EnforcementEvidence::from_plan(&plan);
    assert_eq!(evidence.posture(), LaunchPosture::Ready);
    assert_eq!(evidence.records().len(), 1);
    assert_eq!(evidence.records()[0].kind, EvidenceKind::Configured);
    assert_eq!(evidence.records()[0].claim, ClaimTerm::Planned);
    assert!(
        !evidence.supports_prevention_claim(domain),
        "a plan to prevent is not evidence of prevention"
    );
    assert_eq!(evidence.claim_for(domain), ClaimTerm::Unmeasured);
}

/// A degraded requirement reads as degraded in plan evidence rather than as
/// planned-and-fine.
#[test]
fn plan_evidence_keeps_a_shortfall_visible() {
    let domain = CapabilityDomain::NetworkEgress;
    let spec = ExecutionSpec::new("python", IdentityRef::root("agent-1"))
        .with_requirement(ControlRequirement::prevent(domain).with_posture(RequirementPosture::DegradeIfUnavailable));
    let capabilities = BackendCapabilities::new(
        BackendAvailability::Available,
        PlatformBoundary::SharedHostKernel,
        vec![CapabilityReport::unsupported(domain, "none")],
    )
    .expect("unique");
    let plan = negotiate(&spec, &identity(), &capabilities, &|_, _| Lowering::none()).expect("degradation permitted");

    let evidence = EnforcementEvidence::from_plan(&plan);
    assert_eq!(evidence.posture(), LaunchPosture::Degraded);
    assert_eq!(evidence.records()[0].claim, ClaimTerm::Degraded);
}

/// A refused launch is an outcome E6 must see, not an absence of one.
#[test]
fn refusal_evidence_records_the_refusal() {
    let domain = CapabilityDomain::NetworkEgress;
    let spec = ExecutionSpec::new("python", IdentityRef::root("agent-1"))
        .with_requirement(ControlRequirement::prevent(domain));
    let capabilities = BackendCapabilities::new(
        BackendAvailability::Available,
        PlatformBoundary::SharedHostKernel,
        vec![CapabilityReport::unsupported(domain, "no mechanism")],
    )
    .expect("unique");
    let refusal = negotiate(&spec, &identity(), &capabilities, &|_, _| Lowering::none()).expect_err("refuses");

    let evidence = EnforcementEvidence::from_refusal(&refusal);
    assert_eq!(evidence.posture(), LaunchPosture::Refused);
    assert_eq!(evidence.records().len(), 1);
    assert_eq!(evidence.records()[0].claim, ClaimTerm::Unsupported);
    assert!(!evidence.supports_prevention_claim(domain));
    assert_eq!(evidence.claim_for(domain), ClaimTerm::Unmeasured);
}

/// An unavailable backend produces a run-level record rather than blaming a
/// domain that was never evaluated.
#[test]
fn refusal_evidence_for_an_unavailable_backend_names_no_domain() {
    let spec = ExecutionSpec::new("python", IdentityRef::root("agent-1"));
    let capabilities = BackendCapabilities::new(
        BackendAvailability::Unavailable {
            reason: "kernel too old".into(),
        },
        PlatformBoundary::SharedHostKernel,
        vec![],
    )
    .expect("unique");
    let refusal = negotiate(&spec, &identity(), &capabilities, &|_, _| Lowering::none()).expect_err("refuses");

    let evidence = EnforcementEvidence::from_refusal(&refusal);
    assert_eq!(evidence.records().len(), 1);
    assert_eq!(evidence.records()[0].domain, None);
}

/// Evidence carries backend provenance so E6 can attribute a claim to what
/// produced it.
#[test]
fn evidence_carries_backend_provenance() {
    let evidence = EnforcementEvidence::new(identity(), LaunchPosture::Ready);
    assert_eq!(evidence.backend().id, "test");
    assert_eq!(evidence.backend().provenance.license, "Apache-2.0");
}
