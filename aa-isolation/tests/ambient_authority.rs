//! Ambient authority and descendant inheritance, across the public surface
//! (AAASM-5709).
//!
//! The unit tests inside `ambient`, `descriptor` and `descendant` pin each
//! module's own behaviour. What is checked here is that the pieces still say the
//! same thing after they have been composed — a plan built from an environment,
//! put on a spec, negotiated with a backend and rendered into evidence passes
//! through five types, and any one of them could drop the distinction the whole
//! Epic rests on.
//!
//! Every scenario that asserts a protection carries the variant with the
//! protection absent, so a green assertion cannot be explained by the thing
//! under test having done nothing.

use aa_isolation::{
    authority_widening, is_same_or_narrower, mock::MockBackend, AmbientAuthorityKind, AuthorityWidening,
    CapabilityDomain, CompatibilityException, ControlRequirement, CredentialPosture, DescriptorDisposition,
    DescriptorInventory, EnvironmentPlanner, ExecutionSpec, IdentityRef, InheritedDescriptor, IsolationBackend,
    RequirementPosture, STANDARD_DESCRIPTORS,
};

/// A launching environment with one credential that must go, one that is kept
/// for compatibility, one supervisor credential, and ordinary noise.
fn launching_environment() -> Vec<&'static str> {
    vec![
        "PATH",
        "HOME",
        "AWS_SECRET_ACCESS_KEY",
        "SSH_AUTH_SOCK",
        "AA_GATEWAY_AUTH",
        "AA_AGENT_ID",
    ]
}

/// **The property this ticket exists to hold, end to end.**
///
/// A variable kept by a documented compatibility exception must arrive at the
/// spec — and therefore at the plan, and therefore at evidence — as authority
/// that *could not be removed*, and must never appear in the removed list on the
/// way.
#[test]
fn a_kept_exception_survives_to_the_spec_as_unremoved_and_never_as_removed() {
    let plan = EnvironmentPlanner::new()
        .except(
            CompatibilityException::new(
                "SSH_AUTH_SOCK",
                "the agent authenticates its git remote through the operator's SSH agent",
            )
            .tracked_by("AAASM-5709"),
        )
        .plan(launching_environment());

    let spec = ExecutionSpec::new("/bin/agent", IdentityRef::root("agent")).with_credentials(plan.posture().clone());

    assert_eq!(spec.credentials().ambient_unremoved, ["SSH_AUTH_SOCK"]);
    assert!(
        !spec.credentials().removed.contains(&"SSH_AUTH_SOCK".to_string()),
        "authority that could not be removed was reported as removed: {:?}",
        spec.credentials()
    );
    assert!(spec.credentials().has_unremoved_ambient_authority());
    assert!(
        spec.credentials().contradictions().is_empty(),
        "{:?}",
        spec.credentials().contradictions()
    );
    assert!(!plan.is_least_authority());

    // Negative control: the identical environment through a planner with no
    // exception. The name moves to `removed`, the run becomes least-authority,
    // and nothing else about the plan changes — so the assertions above are
    // about the exception and not about the planner emitting fixed lists.
    let without = EnvironmentPlanner::new().plan(launching_environment());
    assert!(without.posture().ambient_unremoved.is_empty());
    assert!(without.posture().removed.contains(&"SSH_AUTH_SOCK".to_string()));
    assert!(without.is_least_authority());
}

/// The predicate that catches a posture nobody built with the planner.
///
/// A caller may assemble a [`CredentialPosture`] by hand — the fields are
/// public — and the failure this Epic is about is a name in `removed` that is
/// also in `ambient_unremoved`. The control is the same posture with the
/// contradiction removed.
#[test]
fn a_hand_built_posture_that_reports_a_kept_name_as_removed_is_caught() {
    let contradictory = CredentialPosture {
        removed: vec!["GITHUB_TOKEN".to_string(), "AWS_SECRET_ACCESS_KEY".to_string()],
        delegated: Vec::new(),
        ambient_unremoved: vec!["GITHUB_TOKEN".to_string()],
    };
    assert_eq!(contradictory.contradictions(), ["GITHUB_TOKEN"]);

    let coherent = CredentialPosture {
        removed: vec!["AWS_SECRET_ACCESS_KEY".to_string()],
        delegated: Vec::new(),
        ambient_unremoved: vec!["GITHUB_TOKEN".to_string()],
    };
    assert!(coherent.contradictions().is_empty());
    // Both postures still report the name as reaching the child, so the
    // difference between them is exactly the contradiction and not the outcome.
    assert!(contradictory.has_unremoved_ambient_authority());
    assert!(coherent.has_unremoved_ambient_authority());
}

/// AASM's own gateway credential must not reach the child, and a request that it
/// should must leave a trace an operator can read.
#[test]
fn supervisor_authority_does_not_reach_the_child_and_the_refusal_is_visible() {
    let plan = EnvironmentPlanner::new()
        .delegate("AA_GATEWAY_AUTH")
        .delegate("AA_AGENT_ID")
        .plan(launching_environment());

    assert_eq!(plan.withheld_supervisor_credentials(), ["AA_GATEWAY_AUTH"]);
    assert!(!plan.posture().delegated.contains(&"AA_GATEWAY_AUTH".to_string()));
    assert!(plan.posture().removed.contains(&"AA_GATEWAY_AUTH".to_string()));
    // The control: an ordinary AASM variable delegated through the identical
    // call does reach the child. Without it, the assertion above would also
    // pass against a planner that delegated nothing at all.
    assert!(plan.posture().delegated.contains(&"AA_AGENT_ID".to_string()));

    assert!(plan
        .classified()
        .iter()
        .any(|c| c.name == "AA_GATEWAY_AUTH" && c.kind == AmbientAuthorityKind::SupervisorCredential));
}

/// Ambient authority that arrives over a channel must name the domain that
/// carries the channel, or a launch that only replaced the environment reads as
/// having handled it.
#[test]
fn channel_backed_authority_names_more_than_the_credential_domain() {
    let plan = EnvironmentPlanner::new().plan(launching_environment());
    let agent = plan
        .classified()
        .iter()
        .find(|c| c.name == "SSH_AUTH_SOCK")
        .expect("the auth-agent socket is classified");
    assert_eq!(agent.kind, AmbientAuthorityKind::DelegatedAuthAgent);
    assert!(agent.kind.domains().contains(&CapabilityDomain::Ipc));
    assert!(agent.kind.domains().contains(&CapabilityDomain::Credential));
}

/// A credential posture travels through negotiation unchanged, so a backend and
/// an evidence consumer read the same three lists the planner produced.
#[test]
fn the_posture_reaches_the_plan_intact() {
    let posture = EnvironmentPlanner::new()
        .except(CompatibilityException::new("SSH_AUTH_SOCK", "compatibility"))
        .delegate("PATH")
        .plan(launching_environment())
        .into_posture();
    let spec = ExecutionSpec::new("/bin/agent", IdentityRef::root("agent"))
        .with_credentials(posture.clone())
        .with_requirement(ControlRequirement::prevent(CapabilityDomain::FilesystemWrite));

    let backend = MockBackend::preventing(&[CapabilityDomain::FilesystemWrite]);
    let plan = backend.plan(&spec).expect("the mock backend can meet this");
    assert_eq!(plan.spec().credentials(), &posture);
    assert_eq!(plan.spec().credentials().ambient_unremoved, ["SSH_AUTH_SOCK"]);
}

// ---------------------------------------------------------------------------
// Descendant inheritance.
// ---------------------------------------------------------------------------

fn confined_parent() -> ExecutionSpec {
    ExecutionSpec::new("/bin/agent", IdentityRef::root("parent"))
        .with_requirement(ControlRequirement::prevent(CapabilityDomain::FilesystemWrite))
        .with_requirement(ControlRequirement::prevent(CapabilityDomain::NetworkEgress))
        .with_credentials(CredentialPosture {
            removed: vec!["GITHUB_TOKEN".to_string()],
            ..CredentialPosture::default()
        })
}

/// A sub-agent launch may narrow its identity and must not widen its authority.
///
/// The pair is the control: the same nested spec, differing only by whether it
/// keeps its ancestor's requirements, is accepted in one direction and reported
/// in the other.
#[test]
fn a_sub_agent_may_narrow_and_may_not_widen() {
    let narrower = ExecutionSpec::new("/bin/sub-agent", IdentityRef::root("sub-agent").with_ancestor("parent"))
        .with_requirement(ControlRequirement::prevent(CapabilityDomain::FilesystemWrite))
        .with_requirement(ControlRequirement::prevent(CapabilityDomain::NetworkEgress))
        .with_requirement(ControlRequirement::prevent(CapabilityDomain::ProcessCreation));
    assert!(is_same_or_narrower(&confined_parent(), &narrower));

    let wider = ExecutionSpec::new("/bin/sub-agent", IdentityRef::root("sub-agent").with_ancestor("parent"))
        .with_requirement(ControlRequirement::prevent(CapabilityDomain::FilesystemWrite))
        .with_requirement(
            ControlRequirement::prevent(CapabilityDomain::NetworkEgress).with_posture(RequirementPosture::Optional),
        );
    assert_eq!(
        authority_widening(&confined_parent(), &wider),
        [AuthorityWidening::PostureWeakened {
            domain: CapabilityDomain::NetworkEgress,
            ancestor: RequirementPosture::Required,
            descendant: RequirementPosture::Optional,
        }]
    );
}

/// The credential half of the same rule: a sub-agent cannot hand its child a
/// name its parent's child never held, whichever list it arrives in.
#[test]
fn a_sub_agent_cannot_reintroduce_a_credential_its_ancestor_removed() {
    let base = ExecutionSpec::new("/bin/sub-agent", IdentityRef::root("sub-agent").with_ancestor("parent"))
        .with_requirement(ControlRequirement::prevent(CapabilityDomain::FilesystemWrite))
        .with_requirement(ControlRequirement::prevent(CapabilityDomain::NetworkEgress));

    for posture in [
        CredentialPosture {
            delegated: vec!["GITHUB_TOKEN".to_string()],
            ..CredentialPosture::default()
        },
        CredentialPosture {
            ambient_unremoved: vec!["GITHUB_TOKEN".to_string()],
            ..CredentialPosture::default()
        },
    ] {
        assert_eq!(
            authority_widening(&confined_parent(), &base.clone().with_credentials(posture.clone())),
            [AuthorityWidening::CredentialWidened {
                name: "GITHUB_TOKEN".to_string()
            }],
            "{posture:?}"
        );
    }

    // The control: the same sub-agent with the parent's own posture widens
    // nothing, so the reports above are about the credential and not about the
    // comparison rejecting every nested launch.
    assert!(is_same_or_narrower(
        &confined_parent(),
        &base.with_credentials(CredentialPosture {
            removed: vec!["GITHUB_TOKEN".to_string()],
            ..CredentialPosture::default()
        })
    ));
}

// ---------------------------------------------------------------------------
// Inherited descriptors.
// ---------------------------------------------------------------------------

fn delegated_standard_streams() -> Vec<InheritedDescriptor> {
    STANDARD_DESCRIPTORS
        .iter()
        .map(|(number, description)| InheritedDescriptor {
            number: *number,
            description: (*description).to_string(),
            disposition: DescriptorDisposition::Delegated {
                reason: "inherited by design".to_string(),
            },
        })
        .collect()
}

/// Two inventories with byte-identical descriptor lists, differing only in
/// whether the enumeration succeeded, must not make the same claim.
///
/// This is the descriptor form of the property the environment plan holds: an
/// unmeasured boundary is not a clean one, and the emptiness of a list nobody
/// could fill says nothing about what exists.
#[test]
fn an_unmeasurable_descriptor_inventory_never_claims_a_clean_boundary() {
    let measured = DescriptorInventory::enumerated(delegated_standard_streams());
    let unmeasurable =
        DescriptorInventory::not_enumerable("this host exposes no descriptor list", delegated_standard_streams());

    assert_eq!(measured.descriptors(), unmeasurable.descriptors());
    assert!(measured.asserts_clean_boundary());
    assert!(!unmeasurable.asserts_clean_boundary());
    assert!(unmeasurable
        .describe()
        .iter()
        .any(|line| line.contains("unmeasured, not absent")));
}

// ---------------------------------------------------------------------------
// Serialization.
// ---------------------------------------------------------------------------

/// The new types are part of the contract, so a consumer that turned the
/// optional `serde` feature on must be able to carry them.
#[test]
fn the_new_types_round_trip_through_serde() {
    let posture = EnvironmentPlanner::new()
        .except(CompatibilityException::new("SSH_AUTH_SOCK", "compatibility").tracked_by("AAASM-5709"))
        .plan(launching_environment())
        .into_posture();
    let json = serde_json::to_string(&posture).expect("serialize");
    let back: CredentialPosture = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(back, posture);
    assert!(json.contains("SSH_AUTH_SOCK"));

    let inventory = DescriptorInventory::not_enumerable("no listing", delegated_standard_streams());
    let json = serde_json::to_string(&inventory).expect("serialize");
    let back: DescriptorInventory = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(back, inventory);
    assert!(
        !back.asserts_clean_boundary(),
        "the completeness of the enumeration did not survive serialization"
    );
}
