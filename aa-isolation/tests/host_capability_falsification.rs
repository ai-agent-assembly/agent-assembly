//! Independent falsification of the typed host-capability broker's gate
//! contract (AAASM-6298, QA ST-11b, journey J89; feature AAASM-6171).
//!
//! **FIXTURES:** no host process is spawned here. These tests drive the
//! pure gate (`host_capability_gate`) with synthetic broker reports and
//! leases; the live `aasm host` behaviour lives in
//! `aa-cli/tests/host_capability_live.rs`.
//!
//! # Why these exist next to `host_capability::tests`
//!
//! The developer unit tests pin each `check_*` function in isolation. These
//! tests go through the composed `host_capability_gate` and pair every
//! refusal with a control that differs in exactly one input and is admitted,
//! so a refusal is attributable to the stated property and not to an
//! incidental unavailable broker or unreadable path.

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use aa_isolation::capability::FailurePosture;
use aa_isolation::{
    authority_gate, host_capability_gate, to_argv, Ancestry, BrokeredOperation, BuildAction, CapabilityDomain,
    CapabilityLease, CodesignRequest, ConfigurationName, ControlRequirement, Destination, ExecutionSpec,
    HostCapabilityAuthority, HostCapabilityBrokerReport, HostCapabilityContract, HostCapabilityRefusal, HostOperation,
    IdentityRef, LeaseBasis, LeaseId, LeaseInvalid, OperationKind, RequirementScope, RevocationState, SchemeName,
    SigningIdentityRef, SimulatorListRequest, XcodeBuildRequest, XcodeContainer, XcodeListRequest,
};

fn t(secs: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(secs)
}

fn agent(name: &str) -> IdentityRef {
    IdentityRef::root(name)
}

fn lease_for(who: &IdentityRef, id: &str) -> CapabilityLease {
    CapabilityLease::new(
        LeaseId::new(id),
        who.clone(),
        CapabilityDomain::ProcessCreation,
        RequirementScope::Whole,
        t(1_000),
        t(2_000),
        LeaseBasis::new(agent("issuer"), "qa fixture"),
    )
}

fn granted_spec(who: &IdentityRef, lease: CapabilityLease) -> ExecutionSpec {
    ExecutionSpec::new("qa", who.clone())
        .with_requirement(
            ControlRequirement::prevent(CapabilityDomain::ProcessCreation).with_scope(RequirementScope::Whole),
        )
        .with_lease(lease)
}

fn authority(spec: &ExecutionSpec, now: SystemTime) -> HostCapabilityAuthority {
    let w = authority_gate(spec, &Ancestry::Root, now).expect("fixture spec must pass authority_gate");
    HostCapabilityAuthority::from_gated_spec(spec, &w)
}

fn broker() -> HostCapabilityBrokerReport {
    let mut b = HostCapabilityBrokerReport::new(FailurePosture::FailClosed);
    for kind in [
        OperationKind::XcodeList,
        OperationKind::XcodeBuild,
        OperationKind::SimulatorList,
    ] {
        b = b.with_operation(BrokeredOperation {
            kind,
            mechanism_detail: "qa fixture".to_string(),
        });
    }
    b
}

fn list_op(root: &Path) -> HostOperation {
    HostOperation::XcodeList(XcodeListRequest::new(root.to_path_buf()))
}

fn build_op(root: &Path, scheme: &str) -> HostOperation {
    HostOperation::XcodeBuild(XcodeBuildRequest::new(
        root.to_path_buf(),
        XcodeContainer::SwiftPackage,
        SchemeName::new(scheme).unwrap(),
        ConfigurationName::new("Debug").unwrap(),
        Destination::GenericMacOs,
        root.join(".dd"),
        BuildAction::Build,
    ))
}

fn gate(
    contract: &HostCapabilityContract,
    auth: &HostCapabilityAuthority,
    op: &HostOperation,
    root: &Path,
    now: SystemTime,
) -> Result<(), HostCapabilityRefusal> {
    let roots: Vec<PathBuf> = vec![root.to_path_buf()];
    host_capability_gate(
        contract,
        &broker(),
        auth,
        op,
        &roots,
        &roots,
        &RequirementScope::Whole,
        &["App".to_string()],
        &[],
        now,
    )
    .map(|_| ())
}

fn all_permitted() -> HostCapabilityContract {
    HostCapabilityContract::broker_required().with_permitted_operations(vec![
        OperationKind::XcodeList,
        OperationKind::XcodeBuild,
        OperationKind::SimulatorList,
        OperationKind::Codesign,
    ])
}

fn root() -> PathBuf {
    std::fs::canonicalize(std::env::temp_dir()).unwrap()
}

// ---- AC1: no grant => refused, per operation class; grant => admitted --------

#[test]
fn no_grant_is_refused_for_every_operation_class_and_the_same_inputs_with_a_grant_are_admitted() {
    let root = root();
    let who = agent("agent-a");
    let ungranted = authority(&ExecutionSpec::new("qa", who.clone()), t(1_500));
    let granted = authority(&granted_spec(&who, lease_for(&who, "l1")), t(1_500));

    let ops = [
        list_op(&root),
        build_op(&root, "App"),
        HostOperation::SimulatorList(SimulatorListRequest::default()),
    ];
    for op in &ops {
        assert_eq!(
            gate(&all_permitted(), &ungranted, op, &root, t(1_500)),
            Err(HostCapabilityRefusal::NoProcessCreationGrant),
            "ungranted {:?} must be refused for lack of a grant specifically",
            op.kind()
        );
        // control: identical contract/broker/op/paths, only the authority differs
        assert_eq!(
            gate(&all_permitted(), &granted, op, &root, t(1_500)),
            Ok(()),
            "granted {:?} must be admitted",
            op.kind()
        );
    }
}

#[test]
fn signing_is_refused_even_with_a_grant_and_an_explicit_permit_because_no_invoker_exists() {
    let root = root();
    let who = agent("agent-a");
    let granted = authority(&granted_spec(&who, lease_for(&who, "l1")), t(1_500));
    // The artifact must exist, otherwise path scoping refuses first and this
    // test would be measuring the wrong refusal.
    let artifact = root.join(format!("aasm-qa-6298-{}.app", std::process::id()));
    std::fs::write(&artifact, b"").unwrap();
    let op = HostOperation::Codesign(CodesignRequest::new(
        artifact.clone(),
        SigningIdentityRef::new(&"A".repeat(40)).unwrap(),
    ));
    assert_eq!(
        gate(&all_permitted(), &granted, &op, &root, t(1_500)),
        Err(HostCapabilityRefusal::NoInvokerForOperation {
            kind: OperationKind::Codesign
        })
    );
    // and without the explicit permit it is refused earlier, as not permitted
    let no_sign = HostCapabilityContract::broker_required().with_permitted_operations(vec![OperationKind::XcodeList]);
    assert_eq!(
        gate(&no_sign, &granted, &op, &root, t(1_500)),
        Err(HostCapabilityRefusal::OperationNotPermitted {
            kind: OperationKind::Codesign
        })
    );
    let _ = std::fs::remove_file(&artifact);
}

#[test]
fn a_grant_for_one_class_does_not_admit_another_class_the_contract_does_not_permit() {
    let root = root();
    let who = agent("agent-a");
    let granted = authority(&granted_spec(&who, lease_for(&who, "l1")), t(1_500));
    let list_only = HostCapabilityContract::broker_required().with_permitted_operations(vec![OperationKind::XcodeList]);
    assert_eq!(gate(&list_only, &granted, &list_op(&root), &root, t(1_500)), Ok(()));
    assert_eq!(
        gate(&list_only, &granted, &build_op(&root, "App"), &root, t(1_500)),
        Err(HostCapabilityRefusal::OperationNotPermitted {
            kind: OperationKind::XcodeBuild
        })
    );
    assert_eq!(
        gate(
            &list_only,
            &granted,
            &HostOperation::SimulatorList(SimulatorListRequest::default()),
            &root,
            t(1_500)
        ),
        Err(HostCapabilityRefusal::OperationNotPermitted {
            kind: OperationKind::SimulatorList
        })
    );
}

#[test]
fn an_empty_permitted_set_permits_nothing_not_everything() {
    let root = root();
    let who = agent("agent-a");
    let granted = authority(&granted_spec(&who, lease_for(&who, "l1")), t(1_500));
    let empty = HostCapabilityContract::broker_required();
    assert!(matches!(
        gate(&empty, &granted, &list_op(&root), &root, t(1_500)),
        Err(HostCapabilityRefusal::OperationNotPermitted { .. })
    ));
}

// ---- AC2: attribution --------------------------------------------------------

#[test]
fn the_authority_carries_the_requesting_identity_and_two_agents_are_distinguishable() {
    let a = agent("agent-a");
    let b = agent("agent-b");
    let auth_a = authority(&granted_spec(&a, lease_for(&a, "la")), t(1_500));
    let auth_b = authority(&granted_spec(&b, lease_for(&b, "lb")), t(1_500));
    assert_eq!(auth_a.identity(), &a);
    assert_eq!(auth_b.identity(), &b);
    assert_ne!(auth_a.identity(), auth_b.identity());
    assert_eq!(auth_a.process_creation_lease().unwrap().id(), &LeaseId::new("la"));
}

#[test]
fn another_agents_lease_does_not_grant_this_agent() {
    // Adversarial: spec identity b, lease subject a. If this were admitted,
    // one agent's grant would be attributable to (and usable by) another.
    let a = agent("agent-a");
    let b = agent("agent-b");
    let spec = granted_spec(&b, lease_for(&a, "la"));
    let outcome = authority_gate(&spec, &Ancestry::Root, t(1_500));
    match outcome {
        Err(_) => {} // refused up front
        Ok(w) => {
            let auth = HostCapabilityAuthority::from_gated_spec(&spec, &w);
            assert!(
                auth.process_creation_lease().is_none(),
                "agent-b must not hold agent-a's lease"
            );
        }
    }
}

// ---- AC4: revocation / expiry blocks the next use ------------------------------

#[test]
fn a_revoked_lease_is_refused_and_the_same_lease_unrevoked_is_admitted() {
    let root = root();
    let who = agent("agent-a");
    let live = lease_for(&who, "l1");
    let revoked = lease_for(&who, "l1").with_revocation(RevocationState::Revoked {
        generation: 2,
        reason: "operator revoked".to_string(),
    });

    let live_auth = authority(&granted_spec(&who, live), t(1_500));
    assert_eq!(
        gate(&all_permitted(), &live_auth, &list_op(&root), &root, t(1_500)),
        Ok(())
    );

    // Revoked at spec-gate time: either authority_gate refuses outright, or the
    // authority collapses to no grant. Either way nothing is admitted.
    let spec = granted_spec(&who, revoked);
    match authority_gate(&spec, &Ancestry::Root, t(1_500)) {
        Err(_) => {}
        Ok(w) => {
            let auth = HostCapabilityAuthority::from_gated_spec(&spec, &w);
            let r = gate(&all_permitted(), &auth, &list_op(&root), &root, t(1_500));
            assert!(r.is_err(), "revoked lease must not admit, got {r:?}");
        }
    }
}

#[test]
fn a_lease_valid_at_one_gate_call_is_refused_at_the_next_once_it_has_expired() {
    let root = root();
    let who = agent("agent-a");
    let auth = authority(&granted_spec(&who, lease_for(&who, "l1")), t(1_500));
    assert_eq!(gate(&all_permitted(), &auth, &list_op(&root), &root, t(1_500)), Ok(()));
    let r = gate(&all_permitted(), &auth, &list_op(&root), &root, t(2_500));
    assert!(
        matches!(
            r,
            Err(HostCapabilityRefusal::LeaseInvalid(LeaseInvalid::Expired { .. }))
        ),
        "got {r:?}"
    );
    // not-yet-valid is refused too
    let r = gate(&all_permitted(), &auth, &list_op(&root), &root, t(500));
    assert!(matches!(r, Err(HostCapabilityRefusal::LeaseInvalid(_))), "got {r:?}");
}

/// Characterisation of a real limit, stated narrowly: there is NO revocation
/// channel into a built `HostCapabilityAuthority`. The authority copies the
/// lease value at construction and holds no ledger or shared handle, so nothing
/// a revoker could do to the issuer's lease can reach it. "Revoke mid-run blocks
/// the next use" therefore holds only where the caller rebuilds the authority
/// from a fresh lease per operation (as `aasm host` does, one process per call).
///
/// This test cannot show a revocation being missed (a value copy with no shared
/// state cannot observe anything by construction); it pins that the admitting
/// path consults only the snapshot, so a future ledger-aware gate has to change
/// this expectation deliberately.
#[test]
fn characterisation_there_is_no_revocation_channel_into_a_built_authority() {
    let root = root();
    let who = agent("agent-a");
    let auth = authority(&granted_spec(&who, lease_for(&who, "l1")), t(1_500));
    assert_eq!(
        gate(&all_permitted(), &auth, &list_op(&root), &root, t(1_600)),
        Ok(()),
        "the built authority admits from its snapshot alone"
    );
    // The only revocation the gate can see is one carried on the lease value
    // the authority was built from (covered by
    // `a_revoked_lease_is_refused_and_the_same_lease_unrevoked_is_admitted`).
    assert!(auth.process_creation_lease().unwrap().validate_at(t(1_600)).is_ok());
}

/// Characterisation (untested-path closure): a spec that states a
/// `ProcessCreation` requirement but carries no leases at all is not
/// lease-aware, so authority is `CompatibilityResidual` and
/// `check_process_creation_grant` admits it with no lease behind it. Not
/// reachable from `aasm host --lease-file` (a lease file always yields a lease),
/// but reachable to any in-process caller that builds a spec this way.
#[test]
fn characterisation_a_requirement_with_no_leases_is_a_compatibility_residual_that_the_gate_admits() {
    let root = root();
    let who = agent("agent-a");
    let spec = ExecutionSpec::new("qa", who.clone()).with_requirement(
        ControlRequirement::prevent(CapabilityDomain::ProcessCreation).with_scope(RequirementScope::Whole),
    );
    let auth = authority(&spec, t(1_500));
    assert!(matches!(
        auth.process_creation_state(),
        aa_isolation::AuthorityState::CompatibilityResidual
    ));
    assert!(auth.process_creation_lease().is_none());
    assert_eq!(gate(&all_permitted(), &auth, &list_op(&root), &root, t(1_500)), Ok(()));
    // control: the same spec with no requirement is Denied, so the Ok above is
    // attributable to the residual state and not to a permissive gate.
    let bare = authority(&ExecutionSpec::new("qa", who), t(1_500));
    assert_eq!(
        gate(&all_permitted(), &bare, &list_op(&root), &root, t(1_500)),
        Err(HostCapabilityRefusal::NoProcessCreationGrant)
    );
}

// ---- AC3: no bypass shape in the typed surface ---------------------------------

#[test]
fn argument_injection_is_rejected_before_the_gate_and_the_gate_rejects_unknown_schemes() {
    for bad in ["-derivedDataPath", "X=Y", "a b\nc", ""] {
        assert!(SchemeName::new(bad).is_err(), "{bad:?} must be rejected by the newtype");
    }
    let root = root();
    let who = agent("agent-a");
    let granted = authority(&granted_spec(&who, lease_for(&who, "l1")), t(1_500));
    // well-formed but not a scheme the container declares
    let r = gate(
        &all_permitted(),
        &granted,
        &build_op(&root, "NotDeclared"),
        &root,
        t(1_500),
    );
    assert!(
        matches!(r, Err(HostCapabilityRefusal::UnknownScheme { .. })),
        "got {r:?}"
    );
    assert_eq!(
        gate(&all_permitted(), &granted, &build_op(&root, "App"), &root, t(1_500)),
        Ok(())
    );
}

#[test]
fn a_path_outside_the_permitted_root_is_refused_and_inside_is_admitted() {
    let root = root();
    let who = agent("agent-a");
    let granted = authority(&granted_spec(&who, lease_for(&who, "l1")), t(1_500));
    let outside = std::fs::canonicalize("/usr").unwrap();
    let r = gate(&all_permitted(), &granted, &list_op(&outside), &root, t(1_500));
    assert!(
        matches!(r, Err(HostCapabilityRefusal::PathOutsidePermittedScope(_))),
        "got {r:?}"
    );
    assert_eq!(
        gate(&all_permitted(), &granted, &list_op(&root), &root, t(1_500)),
        Ok(())
    );
}

#[test]
fn argv_is_a_fixed_shape_with_no_shell_and_the_program_is_the_one_supplied() {
    let root = root();
    let argv = to_argv(&build_op(&root, "App"), Path::new("/x/xcodebuild")).unwrap();
    assert_eq!(argv.program, PathBuf::from("/x/xcodebuild"));
    assert!(!argv.args.iter().any(|a| a == "-c" || a == "sh" || a == "/bin/sh"));
    let list = to_argv(&list_op(&root), Path::new("/x/xcodebuild")).unwrap();
    assert_eq!(list.args, vec!["-list".to_string(), "-json".to_string()]);
}

// ---- Unavailable broker is distinguishable from grant refusal -----------------

#[test]
fn an_unavailable_broker_refuses_even_a_granted_agent_and_is_reported_as_unavailable_not_as_no_grant() {
    let root = root();
    let who = agent("agent-a");
    let granted = authority(&granted_spec(&who, lease_for(&who, "l1")), t(1_500));
    let roots = vec![root.clone()];
    let r = host_capability_gate(
        &all_permitted(),
        &HostCapabilityBrokerReport::unavailable("no Xcode"),
        &granted,
        &list_op(&root),
        &roots,
        &roots,
        &RequirementScope::Whole,
        &[],
        &[],
        t(1_500),
    );
    assert!(matches!(
        r,
        Err(HostCapabilityRefusal::BrokerRequiredButUnavailable { .. })
    ));
}

/// Characterisation (low severity): an *empty* scheme allowlist admits any
/// scheme name, because `check_arguments` only compares when the list is
/// non-empty. A container that declares no schemes therefore gets no scheme
/// confinement from this gate (the host `xcodebuild` then rejects it itself).
#[test]
fn characterisation_an_empty_scheme_allowlist_admits_any_well_formed_scheme() {
    let root = root();
    let who = agent("agent-a");
    let granted = authority(&granted_spec(&who, lease_for(&who, "l1")), t(1_500));
    let roots = vec![root.clone()];
    let r = host_capability_gate(
        &all_permitted(),
        &broker(),
        &granted,
        &build_op(&root, "AnythingAtAll"),
        &roots,
        &roots,
        &RequirementScope::Whole,
        &[],
        &[],
        t(1_500),
    );
    assert!(r.is_ok(), "got {r:?}");
}

#[test]
fn a_grant_scoped_to_one_selector_refuses_a_request_for_another_and_admits_the_covered_one() {
    let root = root();
    let who = agent("agent-a");
    let sel = |n: &str| RequirementScope::Selectors(vec![aa_isolation::permit_only_selector(n)]);
    let lease = CapabilityLease::new(
        LeaseId::new("scoped"),
        who.clone(),
        CapabilityDomain::ProcessCreation,
        sel("xcodebuild"),
        t(1_000),
        t(2_000),
        LeaseBasis::new(agent("issuer"), "qa fixture"),
    );
    let spec = ExecutionSpec::new("qa", who.clone())
        .with_requirement(ControlRequirement::prevent(CapabilityDomain::ProcessCreation).with_scope(sel("xcodebuild")))
        .with_lease(lease);
    let auth = authority(&spec, t(1_500));
    let roots = vec![root.clone()];
    let run = |scope: &RequirementScope| {
        host_capability_gate(
            &all_permitted(),
            &broker(),
            &auth,
            &list_op(&root),
            &roots,
            &roots,
            scope,
            &[],
            &[],
            t(1_500),
        )
        .map(|_| ())
    };
    assert_eq!(run(&sel("xcodebuild")), Ok(()));
    assert_eq!(
        run(&sel("codesign")),
        Err(HostCapabilityRefusal::ProcessCreationScopeNotCoveredByGrant)
    );
}
