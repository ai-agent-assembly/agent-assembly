//! The reference backend, exercised through the trait.
//!
//! These tests are about the *contract*, not about the mock: they check that a
//! backend can be driven through discover → plan → prepare → spawn → evidence
//! as a trait object, and that the contract's refusal rules apply to it whether
//! it wants them to or not.

use aa_isolation::mock::MockBackend;
use aa_isolation::{
    CapabilityDomain, ControlRequirement, ExecutionSpec, IdentityRef, IsolationBackend, LaunchPosture, RefusalReason,
    RequirementPosture,
};

fn spec_requiring(domain: CapabilityDomain) -> ExecutionSpec {
    ExecutionSpec::new("python", IdentityRef::root("agent-1"))
        .with_args(["ai_agent_main.py"])
        .with_requirement(ControlRequirement::prevent(domain))
}

/// Backend selection happens at run time, so the trait has to survive being a
/// trait object. A compile-time check, asserted here so a signature change that
/// breaks object safety fails a test rather than a distant consumer.
#[test]
fn the_trait_is_object_safe() {
    let backend = MockBackend::inert();
    let as_object: &dyn IsolationBackend = &backend;
    assert_eq!(as_object.identity().id, "mock");

    let boxed: Box<dyn IsolationBackend> = Box::new(MockBackend::inert());
    assert_eq!(boxed.identity().id, "mock");
}

#[test]
fn a_backend_that_can_prevent_plans_prepares_and_spawns() {
    let domain = CapabilityDomain::FilesystemWrite;
    let backend = MockBackend::preventing(&[domain]);

    let plan = backend.plan(&spec_requiring(domain)).expect("plans");
    assert_eq!(plan.posture(), LaunchPosture::Ready);
    assert_eq!(plan.prevented_domains(), vec![domain]);

    let prepared = backend.prepare(plan).expect("prepares");
    let handle = backend.spawn(prepared).expect("spawns");
    assert_eq!(handle.posture(), LaunchPosture::Ready);
    assert_eq!(handle.backend().id, "mock");
}

/// The central claim of the mock's own documentation, tested rather than
/// asserted: it reports that it *can* prevent, and its evidence still supports
/// no prevention claim, because it never produced a decision.
///
/// This is the availability/capability versus evidence separation in one
/// assertion — the backend was available, the capability was reported, the plan
/// enforced, and none of that added up to a prevention claim.
#[test]
fn reported_capability_never_becomes_enforcement_evidence() {
    let domain = CapabilityDomain::FilesystemWrite;
    let backend = MockBackend::preventing(&[domain]);

    assert!(
        backend
            .capabilities()
            .report_for(domain)
            .expect("reported")
            .can_prevent(),
        "the mock reports that it can prevent this domain"
    );

    let plan = backend.plan(&spec_requiring(domain)).expect("plans");
    assert!(plan.planned()[0].outcome.is_prevention());

    let prepared = backend.prepare(plan).expect("prepares");
    let handle = backend.spawn(prepared).expect("spawns");
    let evidence = backend.evidence(&handle);

    assert!(
        !evidence.supports_prevention_claim(domain),
        "a backend that applied no mechanism must not support a prevention claim"
    );
    assert!(evidence
        .records()
        .iter()
        .all(|r| r.kind != aa_isolation::EvidenceKind::Decision));
}

/// The mock does not get to skip negotiation. Its `plan` delegates to the shared
/// `negotiate`, so an observe-only capability is refused for it exactly as for
/// any other backend.
#[test]
fn an_observing_backend_is_refused_a_prevention_requirement() {
    let domain = CapabilityDomain::NetworkEgress;
    let refusal = MockBackend::observing(&[domain])
        .plan(&spec_requiring(domain))
        .expect_err("observe-only cannot satisfy a prevention requirement");
    assert!(matches!(
        refusal.unmet()[0].1,
        RefusalReason::ObserveOnlyForPreventionRequirement { .. }
    ));
    assert_eq!(refusal.backend().id, "mock");
}

#[test]
fn an_inert_backend_refuses_every_required_prevention() {
    let backend = MockBackend::inert();
    for domain in CapabilityDomain::ALL {
        let refusal = backend
            .plan(&spec_requiring(*domain))
            .expect_err("an inert backend prevents nothing");
        assert!(matches!(refusal.unmet()[0].1, RefusalReason::DomainUnsupported { .. }));
    }
}

#[test]
fn an_unavailable_backend_refuses_to_plan() {
    let refusal = MockBackend::unavailable("not supported on this host")
        .plan(&spec_requiring(CapabilityDomain::Ipc))
        .expect_err("an unavailable backend cannot plan");
    assert_eq!(refusal.backend_unavailable(), Some("not supported on this host"));
}

/// An inert backend still runs, degraded, when the requirement permits it — and
/// the resulting evidence is not enforcement.
#[test]
fn an_inert_backend_runs_degraded_when_permitted() {
    let domain = CapabilityDomain::NetworkEgress;
    let spec = ExecutionSpec::new("python", IdentityRef::root("agent-1"))
        .with_requirement(ControlRequirement::prevent(domain).with_posture(RequirementPosture::DegradeIfUnavailable));
    let backend = MockBackend::inert();

    let plan = backend.plan(&spec).expect("degradation permitted");
    assert_eq!(plan.posture(), LaunchPosture::Degraded);

    let handle = backend.spawn(backend.prepare(plan).expect("prepares")).expect("spawns");
    assert_eq!(handle.posture(), LaunchPosture::Degraded);

    let evidence = backend.evidence(&handle);
    assert_eq!(evidence.posture(), LaunchPosture::Degraded);
    assert!(!evidence.supports_prevention_claim(domain));
}

/// A plan cannot be smuggled from one backend into another's `prepare`.
#[test]
fn prepare_rejects_a_plan_from_another_backend() {
    let domain = CapabilityDomain::FilesystemWrite;
    let plan = MockBackend::preventing(&[domain])
        .plan(&spec_requiring(domain))
        .expect("plans");

    let other = MockBackend::new(
        aa_isolation::BackendIdentity {
            id: "other".to_string(),
            version: "1".to_string(),
            provenance: aa_isolation::Provenance {
                source: "test".to_string(),
                license: "Apache-2.0".to_string(),
                modified: false,
            },
        },
        MockBackend::preventing(&[domain]).capabilities(),
    );

    let err = other
        .prepare(plan)
        .expect_err("a plan from another backend must be rejected");
    assert!(matches!(err, aa_isolation::SpawnError::BackendMismatch { .. }));
}

/// The handle grants no access into the confined tree — it holds an identifier
/// and a posture, and nothing that could be used to reach the process. ADR 0035
/// §5's trusted-supervisor boundary, held structurally.
#[test]
fn a_handle_is_a_reference_not_a_channel() {
    let domain = CapabilityDomain::FilesystemWrite;
    let backend = MockBackend::preventing(&[domain]);
    let handle = backend
        .spawn(
            backend
                .prepare(backend.plan(&spec_requiring(domain)).expect("plans"))
                .expect("prepares"),
        )
        .expect("spawns");
    assert!(!handle.token().is_empty());
    assert_eq!(handle.posture(), LaunchPosture::Ready);
}
