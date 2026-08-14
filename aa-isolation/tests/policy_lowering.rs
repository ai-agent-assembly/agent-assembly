//! What a lowered policy is allowed to become once a backend answers.
//!
//! The unit tests inside `src/lowering.rs` pin what the lowering *says*; these
//! pin what happens when that output meets [`negotiate`]. Every test here is a
//! statement from ADR 0035 §4 or the AAASM-5707 scope refinement turned into an
//! assertion, and every one that could pass for a trivial reason carries the
//! control that makes it move.

use aa_core::attestation::ClaimTerm;
use aa_isolation::mock::MockBackend;
use aa_isolation::{
    lower_policy, negotiate, permitted_selector, BackendAvailability, BackendCapabilities, BackendIdentity,
    CapabilityDomain, CapabilityReport, DecisionTiming, DescendantCoverage, EnforcementEvidence, EnforcementPlan,
    ExecutionHandle, ExecutionSpec, ExitDisposition, IdentityRef, IsolationBackend, LaunchPosture, Lowering,
    LoweringOptions, Mediation, PlanRefusal, PlatformBoundary, PolicyLowering, PreparedExecution, Provenance,
    RefusalReason, RequirementOutcome, RequirementPosture, RequirementScope, SpawnError, Synchrony, TerminationRequest,
};
use aa_security::policy::{Capability, CapabilitySet, NetworkPolicy, PolicyDocument, SyscallAllowlist};

// ---------------------------------------------------------------------------
// Policy fixtures.
// ---------------------------------------------------------------------------

fn denying(capabilities: &[Capability]) -> PolicyDocument {
    let mut set = CapabilitySet::default();
    for capability in capabilities {
        set.deny.insert(capability.clone());
    }
    PolicyDocument {
        capabilities: Some(set),
        ..PolicyDocument::default()
    }
}

/// A document that restricts every dimension the schema can reach.
fn everything_the_schema_can_say() -> PolicyDocument {
    let mut policy = denying(&[Capability::FileRead, Capability::FileWrite, Capability::AgentSpawn]);
    policy.network = Some(NetworkPolicy {
        allowlist: vec!["api.openai.com".to_string()],
    });
    policy.syscall_allowlist = Some(SyscallAllowlist::from_names(["read", "write", "close"]).unwrap());
    policy
}

fn spec_from(lowering: &PolicyLowering) -> ExecutionSpec {
    lowering
        .apply_to(ExecutionSpec::new("python", IdentityRef::root("agent-1")).with_args(["ai_agent_main.py"]))
        .expect("these fixtures all express at least one restriction")
}

fn lowered_domains(lowering: &PolicyLowering) -> Vec<CapabilityDomain> {
    lowering.requirements().iter().map(|r| r.domain()).collect()
}

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

// ---------------------------------------------------------------------------
// Positive: a lowered policy plans.
// ---------------------------------------------------------------------------

#[test]
fn a_lowered_policy_negotiates_to_a_ready_plan_against_a_capable_backend() {
    let lowering = lower_policy(&everything_the_schema_can_say(), &LoweringOptions::strict());
    let domains = lowered_domains(&lowering);
    assert_eq!(
        domains,
        vec![
            CapabilityDomain::FilesystemRead,
            CapabilityDomain::FilesystemWrite,
            CapabilityDomain::NetworkEgress,
            CapabilityDomain::Syscall,
            CapabilityDomain::ProcessCreation,
        ],
    );

    let backend = MockBackend::preventing(&domains);
    let plan = backend
        .plan(&spec_from(&lowering))
        .expect("a backend that prevents every lowered domain satisfies the plan");
    assert_eq!(plan.posture(), LaunchPosture::Ready);
    assert_eq!(plan.prevented_domains(), domains);
    assert_eq!(plan.shortfalls().count(), 0);
}

// ---------------------------------------------------------------------------
// Unsupported: a required prevention control the backend lacks.
// ---------------------------------------------------------------------------

/// The controlled pair. The same lowering is refused by a backend with no
/// mechanism and accepted by one with the mechanism, so the refusal is
/// attributable to the backend's capability report rather than to the lowering
/// producing something unsatisfiable.
#[test]
fn a_backend_without_a_required_prevention_control_refuses_before_spawn() {
    let lowering = lower_policy(&denying(&[Capability::FileWrite]), &LoweringOptions::strict());
    let spec = spec_from(&lowering);

    let refusal = MockBackend::inert()
        .plan(&spec)
        .expect_err("a backend with no mechanism cannot meet a required prevention requirement");
    assert_eq!(refusal.unmet().len(), 1);
    assert!(matches!(
        refusal.unmet()[0].1,
        RefusalReason::DomainUnsupported {
            domain: CapabilityDomain::FilesystemWrite,
            ..
        }
    ));

    MockBackend::preventing(&[CapabilityDomain::FilesystemWrite])
        .plan(&spec)
        .expect("the same lowering is satisfiable by a backend that has the mechanism");
}

/// Silence about a domain is not a claim that the domain is unsupported, and
/// neither may satisfy a required prevention requirement.
#[test]
fn a_backend_that_says_nothing_about_a_lowered_domain_also_refuses() {
    let lowering = lower_policy(&denying(&[Capability::FileWrite]), &LoweringOptions::strict());
    let refusal = MockBackend::preventing(&[CapabilityDomain::NetworkEgress])
        .plan(&spec_from(&lowering))
        .expect_err("an unreported domain cannot satisfy a required prevention requirement");
    assert!(matches!(
        refusal.unmet()[0].1,
        RefusalReason::NoCapabilityReported {
            domain: CapabilityDomain::FilesystemWrite
        }
    ));
}

// ---------------------------------------------------------------------------
// Observe-only cannot satisfy a synchronous deny.
// ---------------------------------------------------------------------------

/// `MockBackend::preventing` and `MockBackend::observing` differ in exactly one
/// field — mediation — so the refusal is attributable to mediation alone. The
/// lowering emits `PreventBeforeEffect` for every policy node it reads, which
/// is what makes the observing backend refuse rather than quietly downgrade.
#[test]
fn an_observe_only_backend_cannot_satisfy_a_lowered_prevention_requirement() {
    let lowering = lower_policy(&denying(&[Capability::NetworkOutbound]), &LoweringOptions::strict());
    let spec = spec_from(&lowering);

    MockBackend::preventing(&[CapabilityDomain::NetworkEgress])
        .plan(&spec)
        .expect("an enforcing capability satisfies the lowered requirement");

    let refusal = MockBackend::observing(&[CapabilityDomain::NetworkEgress])
        .plan(&spec)
        .expect_err("an observing capability must not be promoted to prevention");
    assert!(matches!(
        refusal.unmet()[0].1,
        RefusalReason::ObserveOnlyForPreventionRequirement {
            domain: CapabilityDomain::NetworkEgress,
            mediation: Mediation::Observe,
        }
    ));
}

// ---------------------------------------------------------------------------
// Explicit degradation.
// ---------------------------------------------------------------------------

/// Degradation is reachable only because the caller selected it for that one
/// domain, and the resulting plan says so in three places at once: the launch
/// posture, the outcome variant and the claim ceiling. None of them reads as
/// enforcement.
#[test]
fn an_explicitly_degraded_requirement_is_recorded_and_is_never_enforcement() {
    let policy = denying(&[Capability::NetworkOutbound]);
    let strict = lower_policy(&policy, &LoweringOptions::strict());
    let backend = MockBackend::observing(&[CapabilityDomain::NetworkEgress]);

    // Without the selection, the same observing backend refuses.
    backend
        .plan(&spec_from(&strict))
        .expect_err("a required requirement is not degradable by default");

    let degradable = lower_policy(
        &policy,
        &LoweringOptions::strict().with_posture(
            CapabilityDomain::NetworkEgress,
            RequirementPosture::DegradeIfUnavailable,
        ),
    );
    let plan = backend
        .plan(&spec_from(&degradable))
        .expect("an explicitly degradable requirement proceeds");

    assert_eq!(plan.posture(), LaunchPosture::Degraded);
    assert_eq!(plan.prevented_domains(), Vec::<CapabilityDomain>::new());
    assert_eq!(plan.shortfalls().count(), 1);

    let planned = &plan.planned()[0];
    assert!(!planned.outcome.is_prevention());
    assert!(matches!(planned.outcome, RequirementOutcome::Degraded { .. }));
    assert_eq!(planned.outcome.claim_ceiling(), ClaimTerm::Degraded);
    assert!(!planned.outcome.claim_ceiling().is_prevention());

    // And the evidence derived from it cannot claim prevention either.
    let evidence = EnforcementEvidence::from_plan(&plan);
    assert!(!evidence.supports_prevention_claim(CapabilityDomain::NetworkEgress));
}

// ---------------------------------------------------------------------------
// The property the scope refinement exists for.
// ---------------------------------------------------------------------------

/// A `Ready` plan states that every requirement *asked for* was met. It does
/// not state that every domain is covered, and for the four domains the policy
/// schema cannot express it never can.
///
/// The control is that the domain the schema *can* express moves into the
/// prevented set when the document says so, while `Credential` — which no
/// policy node reaches — stays out of it under both documents and stays named
/// as a policy gap.
#[test]
fn a_domain_policy_cannot_express_never_becomes_a_prevented_domain() {
    let backend = MockBackend::preventing(CapabilityDomain::ALL);

    let syscalls_only = lower_policy(
        &PolicyDocument {
            syscall_allowlist: Some(SyscallAllowlist::from_names(["read"]).unwrap()),
            ..PolicyDocument::default()
        },
        &LoweringOptions::strict(),
    );
    let plan = backend
        .plan(&spec_from(&syscalls_only))
        .expect("a capable backend plans");
    assert_eq!(plan.posture(), LaunchPosture::Ready);
    assert_eq!(plan.prevented_domains(), vec![CapabilityDomain::Syscall]);
    assert!(!plan.prevented_domains().contains(&CapabilityDomain::FilesystemWrite));
    assert!(!plan.prevented_domains().contains(&CapabilityDomain::Credential));

    // The moving half: the schema can express filesystem writes, so saying so
    // puts that domain in the prevented set.
    let plus_filesystem = {
        let mut policy = denying(&[Capability::FileWrite]);
        policy.syscall_allowlist = Some(SyscallAllowlist::from_names(["read"]).unwrap());
        lower_policy(&policy, &LoweringOptions::strict())
    };
    let plan = backend
        .plan(&spec_from(&plus_filesystem))
        .expect("a capable backend plans");
    assert!(plan.prevented_domains().contains(&CapabilityDomain::FilesystemWrite));

    // The fixed half: `Credential` did not move, because no policy node reaches
    // it — and both lowerings say so rather than leaving it silently absent.
    assert!(!plan.prevented_domains().contains(&CapabilityDomain::Credential));
    for lowering in [&syscalls_only, &plus_filesystem] {
        let names: Vec<CapabilityDomain> = lowering.unrepresentable().map(|d| d.domain).collect();
        assert_eq!(
            names,
            vec![
                CapabilityDomain::NameResolution,
                CapabilityDomain::Ipc,
                CapabilityDomain::Credential,
                CapabilityDomain::Resource,
            ],
        );
    }

    // Nothing downstream may read the gap as coverage: with no requirement and
    // no record, the run-level claim for the domain is `Unmeasured`.
    let evidence = EnforcementEvidence::from_plan(&plan);
    assert_eq!(evidence.claim_for(CapabilityDomain::Credential), ClaimTerm::Unmeasured);
    assert!(!evidence.supports_prevention_claim(CapabilityDomain::Credential));
}

/// The other half of the same property: a document expressing nothing this
/// boundary can carry produces no spec at all, so it cannot reach a `Ready`
/// plan by having asked for nothing.
#[test]
fn a_policy_expressing_nothing_cannot_reach_a_ready_plan() {
    let lowering = lower_policy(&PolicyDocument::default(), &LoweringOptions::strict());
    assert!(lowering.requirements().is_empty());
    let refusal = lowering
        .apply_to(ExecutionSpec::new("python", IdentityRef::root("agent-1")))
        .expect_err("an empty lowering must not produce a spec");
    assert_eq!(refusal.unrepresentable().count(), 4);
}

// ---------------------------------------------------------------------------
// One lowering, two unrelated backends.
// ---------------------------------------------------------------------------

/// A second backend, written independently of `MockBackend` and reporting a
/// different platform boundary, consumes the identical lowering: it reads the
/// permitted set through `permitted_selector` and never asks which policy node
/// or which backend produced it.
///
/// The lowering itself contains no branch on backend identity — `BackendIdentity`
/// is not reachable from `lower_policy`'s signature at all — so this test's job
/// is to show the *output* is consumable without one.
struct RecordingBackend {
    identity: BackendIdentity,
    capabilities: BackendCapabilities,
}

impl RecordingBackend {
    fn new() -> Self {
        let reports = CapabilityDomain::ALL
            .iter()
            .map(|domain| {
                CapabilityReport::new(*domain, Mediation::Enforce, DecisionTiming::Pre, Synchrony::Sync)
                    .with_descendants(DescendantCoverage::ProcessTree)
            })
            .collect();
        Self {
            identity: identity("recording"),
            capabilities: BackendCapabilities::new(
                BackendAvailability::Available,
                // Deliberately different from `MockBackend`'s, to make the
                // point that the lowering did not depend on it.
                PlatformBoundary::GuestKernel,
                reports,
            )
            .expect("CapabilityDomain::ALL is unique"),
        }
    }
}

impl IsolationBackend for RecordingBackend {
    fn identity(&self) -> BackendIdentity {
        self.identity.clone()
    }

    fn capabilities(&self) -> BackendCapabilities {
        self.capabilities.clone()
    }

    fn plan(&self, spec: &ExecutionSpec) -> Result<EnforcementPlan, PlanRefusal> {
        negotiate(spec, &self.identity, &self.capabilities, &|requirement, _outcome| {
            // The only thing this backend needs to understand about a lowered
            // requirement: which names are permitted. No domain switch, no
            // policy-node knowledge.
            match requirement.scope() {
                RequirementScope::Selectors(selectors) => Lowering::new(
                    selectors
                        .iter()
                        .filter_map(|selector| permitted_selector(selector))
                        .map(|name| format!("permit {name}")),
                ),
                RequirementScope::Whole => Lowering::new([format!("deny all {}", requirement.domain())]),
                RequirementScope::Limits(_) => Lowering::none(),
            }
        })
    }

    fn prepare(&self, plan: EnforcementPlan) -> Result<PreparedExecution, SpawnError> {
        Ok(PreparedExecution::new(plan, "recording-0"))
    }

    fn spawn(&self, prepared: PreparedExecution) -> Result<ExecutionHandle, SpawnError> {
        Ok(ExecutionHandle::new(
            self.identity.clone(),
            prepared.token(),
            prepared.plan().posture(),
        ))
    }

    /// This backend runs nothing, so it reports no exit code rather than a
    /// successful one — the same reason [`MockBackend`] does.
    fn wait_for_exit(&self, _handle: &ExecutionHandle) -> Result<ExitDisposition, SpawnError> {
        Ok(ExitDisposition::NoCode {
            detail: "this test backend records a plan and starts no process".to_string(),
        })
    }

    fn terminate(&self, _handle: &ExecutionHandle, _request: TerminationRequest) -> Result<(), SpawnError> {
        Err(SpawnError::Supervision {
            detail: "this test backend started no process to terminate".to_string(),
        })
    }

    fn evidence(&self, handle: &ExecutionHandle) -> EnforcementEvidence {
        EnforcementEvidence::new(self.identity.clone(), handle.posture())
    }
}

#[test]
fn two_unrelated_backends_consume_the_same_lowering() {
    let lowering = lower_policy(&everything_the_schema_can_say(), &LoweringOptions::strict());
    let spec = spec_from(&lowering);

    let mock = MockBackend::preventing(&lowered_domains(&lowering));
    let mock_plan = mock.plan(&spec).expect("the mock backend plans");

    let recording = RecordingBackend::new();
    let recording_plan = recording.plan(&spec).expect("an unrelated backend plans the same spec");

    // Same requirements, same outcomes; only the backend-authored realization
    // differs, which is the one place a mechanism is allowed to show.
    assert_eq!(mock_plan.posture(), recording_plan.posture());
    assert_eq!(mock_plan.prevented_domains(), recording_plan.prevented_domains());
    assert_eq!(mock_plan.spec().requirements(), recording_plan.spec().requirements());
    assert_ne!(
        mock_plan.planned()[0].lowering.steps(),
        recording_plan.planned()[0].lowering.steps(),
    );

    // The permitted set survived the round trip through the opaque selector
    // list without either backend knowing which policy node wrote it.
    let syscall_steps = recording_plan
        .planned()
        .iter()
        .find(|planned| planned.requirement.domain() == CapabilityDomain::Syscall)
        .expect("the syscall requirement was planned")
        .lowering
        .steps()
        .to_vec();
    assert_eq!(syscall_steps, vec!["permit read", "permit write", "permit close"]);
}
