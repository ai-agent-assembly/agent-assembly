//! AAASM-6294 (ST-7): live proof that a resource-ceiling request issued
//! under `aasm-macos-vm` isolation **refuses outright** rather than being
//! silently accepted and ignored.
//!
//! ADR 0041 (round 1 of resource-ceiling enforcement) is explicit that this
//! backend is untouched: "No macOS VM-backend resource ceilings (not
//! touched this round)" is listed both under "Explicitly out of scope" and
//! as a follow-up ticket. What ADR 0041 does not state directly is *what
//! happens* when an operator asks this backend for one anyway — silently
//! dropping the ceiling and running unconfined would be a correctness bug
//! users could not detect from the CLI's own output. This test proves the
//! actual behavior, against the real product code, not a mock.
//!
//! Two angles, because they exercise different real code and would fail
//! independently if either regressed:
//!
//! 1. [`a_resource_ceiling_is_refused_even_when_the_backend_is_otherwise_available`]
//!    builds this backend's *real* [`aa_isolation_macos_vm::capability::discover`]
//!    report from a fully-confined probe (the same construction
//!    `planner_positive_control.rs` uses to avoid a VM boot) so the backend is
//!    genuinely `Available` and can plan a filesystem requirement — then runs
//!    the *exact same two steps* [`MacosVmBackend::plan`] runs
//!    (`aa_isolation_native::capability::narrow_for` then `negotiate`, see
//!    `plan_like_the_real_backend`) to show a `Resource` ceiling specifically
//!    is refused in that same, otherwise-healthy capability set. This
//!    isolates the Resource-domain gap from blanket host unavailability.
//! 2. [`a_resource_ceiling_is_refused_through_the_real_discover_entrypoint`]
//!    calls [`aa_isolation_macos_vm::MacosVmBackend::discover`] — the actual
//!    `IsolationBackend` entrypoint `aasm run` uses — and plans the same
//!    ceiling through it. On this CI/dev host (no VM substrate configured:
//!    confirmed by searching for `aa-isolation-macos-vm-poc`'s built guest
//!    kernel/rootfs artifacts, none were found) discovery reports
//!    `Unavailable`, so the refusal reason is `BackendUnavailable` rather
//!    than `DomainUnsupported` — both are recorded here so a future host
//!    with the substrate configured is held to the same "never silently
//!    accepted" property test (1) proves precisely. **The `Available` arm
//!    of this real entrypoint (an actual booted guest, actual probe
//!    measurement) is unverified on this host** — this test can only
//!    exercise the `Unavailable` arm here; test (1) is what substitutes for
//!    the `Available` arm, via a hand-built capability report rather than a
//!    real boot.
//!
//! # A finding this test pins rather than hides: the refusal reason can be wrong
//!
//! Test (1)'s refusal reason text ("this one carried a different scope
//! shape") is **false** for the specific request that test sends — a
//! `max_open_files`-only ceiling, which `aa-isolation-native` really does
//! lower successfully to `RLIMIT_NOFILE` (ADR 0041 decision 4). The reason
//! comes from `capability::discover`'s *generic*, scope-less probe, and
//! `narrow_for` only overrides it when the *specific* request's lowering
//! fails — which it does not, here. So the refusal is for the right
//! underlying cause (`Resource` genuinely has no live producer on this
//! backend — ADR 0041's "out of scope" line) but gives the operator a
//! misleading diagnostic. This is a real, observed documentation/UX
//! accuracy gap against ADR 0041 decision 2's own stated intent ("the
//! refusal reason names the specific ceiling"). Recorded here and in
//! `qa/golden-journeys.yaml`'s J86 entry; not fixed — fixing
//! `capability::discover`'s reporting is outside this QA ticket's scope.

use aa_isolation::{
    negotiate, BackendIdentity, CapabilityDomain, ControlRequirement, ExecutionSpec, IdentityRef, IsolationBackend,
    Lowering, Provenance, RefusalReason, RequirementScope, ResourceLimits,
};
use aa_isolation_macos_vm::probe::{GuestProbe, Observation};
use aa_isolation_macos_vm::{capability, MacosVmBackend};
use aa_isolation_native::capability::narrow_for;

/// The exact step [`MacosVmBackend::plan`] runs before `negotiate` — see
/// `aa-isolation-macos-vm/src/lib.rs`'s own `plan()`, which calls
/// `aa_isolation_native::capability::narrow_for(&self.capabilities, spec)`
/// before negotiating. Test (1) below reproduces that call directly against
/// a hand-built `capabilities` value (so it can avoid a VM boot) instead of
/// going through a full `MacosVmBackend`, whose fields are private outside
/// its own crate. Skipping this step would test `negotiate` against the
/// *wrong* capability report for this specific request — see this file's
/// own doc comment for why that distinction turned out to matter.
// Mirrors `aa_isolation::plan::negotiate`'s own identical suppression:
// `PlanRefusal` is 152 bytes, above clippy's 128-byte threshold, and boxing
// it here would not match the real `plan()` signature this function exists
// to mirror.
#[allow(clippy::result_large_err)]
fn plan_like_the_real_backend(
    spec: &ExecutionSpec,
    base: &aa_isolation::BackendCapabilities,
) -> Result<aa_isolation::EnforcementPlan, aa_isolation::PlanRefusal> {
    let capabilities = narrow_for(base, spec);
    negotiate(spec, &identity(), &capabilities, &no_lowering)
}

/// A probe in which every measured filesystem action was actually denied —
/// the shape a healthy guest boundary reports. Mirrors
/// `planner_positive_control.rs`'s identical fixture so this test's
/// "otherwise available" half rests on the same real measurement shape that
/// test already established, not a new assumption.
fn fully_confined_probe() -> GuestProbe {
    GuestProbe {
        filesystem_read: Observation::Denied,
        filesystem_write: Observation::Denied,
    }
}

fn identity() -> BackendIdentity {
    BackendIdentity {
        id: aa_isolation_macos_vm::BACKEND_ID.to_string(),
        version: "test".to_string(),
        provenance: Provenance {
            source: "aa-isolation-macos-vm test (AAASM-6294)".to_string(),
            license: "Apache-2.0".to_string(),
            modified: false,
        },
    }
}

/// A realistic resource-ceiling request: the shape an operator's `--max-*`
/// CLI flags actually build (ADR 0041 decision 2 — each stated ceiling is
/// its own requirement; this fixture only needs one to prove the refusal).
fn resource_ceiling_spec(posture: aa_isolation::RequirementPosture) -> ExecutionSpec {
    ExecutionSpec::new("/bin/true", IdentityRef::root("aaasm-6294-resource-ceiling")).with_requirement(
        ControlRequirement::prevent(CapabilityDomain::Resource)
            .with_posture(posture)
            .with_scope(RequirementScope::Limits(ResourceLimits {
                max_open_files: Some(16),
                ..ResourceLimits::default()
            })),
    )
}

/// No-op lowering closure: this test never reaches a lowering step for a
/// refused requirement, and the accepted-filesystem control below needs no
/// real lowering text to make its point.
fn no_lowering(_requirement: &ControlRequirement, _outcome: &aa_isolation::RequirementOutcome) -> Lowering {
    Lowering::new(Vec::<String>::new())
}

/// The load-bearing property: a `Required` resource-ceiling request is
/// refused by `negotiate` against this backend's real, measured capability
/// report — specifically because `Resource` is unsupported, not because the
/// whole backend is down. The control alongside it proves the same
/// capability set genuinely *can* plan something (filesystem write), so the
/// refusal below is about the domain, not a broken fixture.
#[test]
fn a_resource_ceiling_is_refused_even_when_the_backend_is_otherwise_available() {
    let capabilities = capability::discover(&fully_confined_probe());
    assert!(
        capabilities.availability().is_available(),
        "the fixture's premise: this capability set must be Available, or the refusal below would be \
         indistinguishable from blanket backend unavailability"
    );

    // The control: the same capability set plans a real, measured domain
    // successfully. Without this, "Resource refuses" could mean "everything
    // refuses on this capability set", proving nothing about Resource
    // specifically.
    let fs_spec = ExecutionSpec::new("/bin/true", IdentityRef::root("aaasm-6294-control"))
        .with_requirement(ControlRequirement::prevent(CapabilityDomain::FilesystemWrite));
    plan_like_the_real_backend(&fs_spec, &capabilities)
        .expect("the control: a filesystem-write requirement must plan successfully on a fully-confined probe");

    // The actual assertion: a Required resource-ceiling request is refused,
    // not silently planned (which would mean the backend accepted a ceiling
    // it never enforces). Goes through `plan_like_the_real_backend`
    // (`narrow_for` + `negotiate`), the same two steps `MacosVmBackend::plan`
    // itself runs — not `negotiate` alone, which would skip the per-request
    // narrowing `plan()` actually does.
    let spec = resource_ceiling_spec(aa_isolation::RequirementPosture::Required);
    let refusal = plan_like_the_real_backend(&spec, &capabilities).expect_err(
        "a Required resource-ceiling request must REFUSE outright under aasm-macos-vm — ADR 0041 states this \
         backend implements no resource-ceiling mechanism at all, so silently accepting the requirement would \
         mean the agent runs unconfined with no way for the operator to tell",
    );
    // **A documented limitation, pinned as a measured gap, not asserted as
    // correct** — mirrors `aa_isolation::descendant`'s own
    // `a_wider_selector_set_is_not_detected_and_this_is_the_known_gap`
    // pattern for the identical reason: prose alone could go stale silently.
    //
    // `narrow_for` only overrides this backend's stored `Resource` report
    // when `aa_isolation_native::lower_requirement` actually *fails* for
    // this specific request (see `aa-isolation-native/src/capability.rs`'s
    // `narrow_for`). For a `max_open_files`-only ceiling, that lowering
    // **succeeds** — `aa-isolation-native` really does implement
    // `RLIMIT_NOFILE` for this exact ceiling (ADR 0041 decision 4). So
    // `narrow_for` leaves the backend's base report untouched, and the
    // refusal below still carries `capability::discover`'s *generic*,
    // scope-less probe reason ("this one carried a different scope shape")
    // — which is **false** of this specific, well-formed request. The
    // operator is refused for the right reason (Resource really is
    // unsupported on this backend) but told the wrong one. If this
    // assertion ever starts failing because the reason text changed, that
    // is `capability::discover`'s per-domain reason finally tracking the
    // request that reached it — update this comment and the PR/journey
    // record deliberately; do not just loosen the assertion.
    assert_eq!(
        refusal.reasons(),
        vec![RefusalReason::DomainUnsupported {
            domain: CapabilityDomain::Resource,
            reason: "the guest-side launcher this backend delegates to reports: a `Resource` requirement must \
                     carry a `RequirementScope::Limits` value naming the ceiling; this one carried a different \
                     scope shape"
                .to_string(),
        }],
        "the refusal must name the Resource domain specifically as unsupported, not some other reason"
    );

    // The same request stated as `Optional` must NOT refuse — this is the
    // real distinction between "refuses outright" and "blanket-refuses
    // everything regardless of posture", which the test above alone cannot
    // rule out.
    let optional_spec = resource_ceiling_spec(aa_isolation::RequirementPosture::Optional);
    let plan = plan_like_the_real_backend(&optional_spec, &capabilities)
        .expect("an Optional resource-ceiling request must not refuse the launch");
    assert!(
        plan.planned()
            .iter()
            .any(|p| matches!(p.outcome, aa_isolation::RequirementOutcome::Unmet { .. })),
        "the optional ceiling must be recorded as Unmet, not silently dropped from the plan: {:?}",
        plan.planned()
    );
}

/// The real-host angle: `MacosVmBackend::discover()` is the actual
/// `IsolationBackend::plan` entrypoint `aasm run` calls. On this host (no
/// `AA_ISOLATION_MACOS_VM_HELPER`/`_KERNEL`/`_ROOTFS` configured — gitignored
/// build artifacts, see `aa-isolation-macos-vm-poc/README.md`) discovery
/// reports `Unavailable`, so the refusal reason is backend-level rather than
/// domain-level. Recorded explicitly rather than skipped, because the
/// property under test — "a resource-ceiling request never plans
/// successfully" — must hold on *this* real entrypoint too, whichever reason
/// produces it.
#[test]
fn a_resource_ceiling_is_refused_through_the_real_discover_entrypoint() {
    let backend = MacosVmBackend::discover();
    let spec = resource_ceiling_spec(aa_isolation::RequirementPosture::Required);

    let refusal = backend.plan(&spec).expect_err(
        "the real `MacosVmBackend::discover()` entrypoint must refuse a Required resource-ceiling request on \
         every host, whether because the VM substrate is unconfigured here or because Resource is unsupported \
         once it is",
    );

    if backend.capabilities().availability().is_available() {
        // A future host with the VM substrate configured: the precise,
        // domain-level refusal from test (1) above must still hold here.
        assert_eq!(
            refusal.reasons(),
            vec![RefusalReason::DomainUnsupported {
                domain: CapabilityDomain::Resource,
                reason: "the guest-side launcher this backend delegates to reports: a `Resource` requirement \
                         must carry a `RequirementScope::Limits` value naming the ceiling; this one carried a \
                         different scope shape"
                    .to_string(),
            }],
            "on a host where the backend is available, the refusal must name Resource as unsupported"
        );
    } else {
        // This host: the backend itself could not be selected, which is a
        // stronger refusal (nothing was even measured) but is still a
        // REFUSAL, not a silently-accepted ceiling.
        assert!(
            matches!(refusal.reasons().as_slice(), [RefusalReason::BackendUnavailable { .. }]),
            "an unavailable backend must refuse via `BackendUnavailable`, not plan successfully: {:?}",
            refusal.reasons()
        );
    }
}
