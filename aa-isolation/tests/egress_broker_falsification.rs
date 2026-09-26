//! Integration falsification tests for the egress contract composed with
//! `authority_gate` (AAASM-6163) — lives outside `src/` because it needs the
//! crate's public API (`egress_gate` composed with `authority_gate`), the same
//! reason `aa-isolation/tests/` already holds other cross-module falsification
//! suites for this Epic.

use std::time::{Duration, SystemTime};

use aa_isolation::{
    authority_gate, egress_gate, permit_only_selector, Ancestry, AuthorityRefusal, CapabilityDomain, CapabilityLease,
    ControlRequirement, EgressAuthority, EgressBrokerReport, EgressContract, EgressRefusal, ExecutionSpec,
    FailurePosture, IdentityRef, LeaseBasis, LeaseId, MediationDepth, MediationDepthScope, RequirementScope,
};

fn t(secs: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(secs)
}

fn identity() -> IdentityRef {
    IdentityRef::root("agent-under-test")
}

fn base_spec() -> ExecutionSpec {
    ExecutionSpec::new("echo", identity())
}

fn lease_for(domain: CapabilityDomain, scope: RequirementScope, expires_at: u64) -> CapabilityLease {
    CapabilityLease::new(
        LeaseId::new("lease-under-test"),
        identity(),
        domain,
        scope,
        t(1_000),
        t(expires_at),
        LeaseBasis::new(IdentityRef::root("issuer"), "test fixture"),
    )
}

fn scope(host: &str) -> RequirementScope {
    RequirementScope::Selectors(vec![permit_only_selector(host)])
}

fn available_broker() -> EgressBrokerReport {
    EgressBrokerReport::new(
        MediationDepth::DestinationOnly,
        MediationDepthScope::EveryDestination,
        FailurePosture::FailClosed,
    )
    .with_range_handling(true, "test fixture refuses restricted ranges")
}

/// An `EgressWitness` can only be produced from an `AuthorityWitness` obtained
/// from the same spec — `EgressAuthority::from_gated_spec` takes the witness
/// as a parameter, and there is no way to construct one any other way.
#[test]
fn egress_witness_requires_an_authority_witness_from_the_same_spec() {
    let host_scope = scope("api.example.com");
    let spec = base_spec()
        .with_requirement(ControlRequirement::prevent(CapabilityDomain::NetworkEgress).with_scope(host_scope.clone()))
        .with_lease(lease_for(CapabilityDomain::NetworkEgress, host_scope.clone(), 2_000))
        .with_lease(lease_for(
            CapabilityDomain::NameResolution,
            RequirementScope::Whole,
            2_000,
        ));

    let witness = authority_gate(&spec, &Ancestry::Root, t(1_500)).expect("valid lease admits at t(1_500)");
    let authority = EgressAuthority::from_gated_spec(&spec, &witness);
    let contract = EgressContract::broker_required();
    let broker = available_broker();
    assert!(egress_gate(&contract, &broker, &authority, &host_scope).is_ok());
}

/// An expired lease refuses at `authority_gate` before `egress_gate` is even
/// reached — the two gates fail at different points, for different reasons.
#[test]
fn an_expired_lease_refuses_at_authority_gate_before_egress_gate_is_reached() {
    let host_scope = scope("api.example.com");
    let spec = base_spec()
        .with_requirement(ControlRequirement::prevent(CapabilityDomain::NetworkEgress).with_scope(host_scope.clone()))
        .with_lease(lease_for(CapabilityDomain::NetworkEgress, host_scope, 2_000));

    // t(2_500) is past the lease's expires_at (2_000).
    let result = authority_gate(&spec, &Ancestry::Root, t(2_500));
    assert!(
        matches!(result, Err(AuthorityRefusal::LeaseInvalid { domain, .. }) if domain == CapabilityDomain::NetworkEgress),
        "expected authority_gate itself to refuse on the expired lease, got {result:?}"
    );
    // `egress_gate` was never reached — there is no witness to build an
    // `EgressAuthority` from, which is exactly the property under test.
}

/// A broker-required launch with a valid lease and an unavailable broker
/// refuses at `egress_gate` specifically — `authority_gate` succeeds first.
#[test]
fn a_broker_required_launch_with_a_valid_lease_and_unavailable_broker_refuses_at_egress_gate() {
    let host_scope = scope("api.example.com");
    let spec = base_spec()
        .with_requirement(ControlRequirement::prevent(CapabilityDomain::NetworkEgress).with_scope(host_scope.clone()))
        .with_lease(lease_for(CapabilityDomain::NetworkEgress, host_scope.clone(), 2_000));

    let witness = authority_gate(&spec, &Ancestry::Root, t(1_500)).expect("authority_gate must succeed here");
    let authority = EgressAuthority::from_gated_spec(&spec, &witness);
    let contract = EgressContract::broker_required();
    let broker = EgressBrokerReport::unavailable("no dedicated proxy is bound for this launch");
    assert_eq!(
        egress_gate(&contract, &broker, &authority, &host_scope),
        Err(EgressRefusal::BrokerRequiredButUnavailable {
            reason: "no dedicated proxy is bound for this launch".to_string(),
        })
    );
}
