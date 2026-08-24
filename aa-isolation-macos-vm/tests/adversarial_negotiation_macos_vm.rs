//! Negotiation-level adversarial scenarios that need no guest boot, run
//! against the macOS VM backend (AAASM-5814).
//!
//! Same four backend-neutral scenarios `adversarial_negotiation_native.rs`
//! runs — see that file's module docs for why only these four generalize:
//! this backend's capability model has the same shape as native's (every
//! domain it does not measure is flatly `Unsupported`, no `Partial` state,
//! nothing to waive — see `aa-isolation-macos-vm/src/capability.rs`'s module
//! docs), so the same four Sandlock-lane scenarios that don't apply to
//! native don't apply here either, for the same reason.

mod adversarial;

use aa_isolation::mock::MockBackend;
use aa_isolation::CapabilityDomain;
use aa_isolation_macos_vm::MacosVmBackend;
use adversarial::{
    assert_blocked_unsupported_and_unmeasured_stay_distinct, assert_claim_is_promoted_only_by_a_decision_record,
    assert_observation_is_never_promoted_to_prevention, assert_required_prevention_refused_by_every_uncapable_backend,
    AdversarialTarget, MacosVmTarget, MockTarget,
};

/// AC: a required prevention requirement is refused by every backend that
/// cannot enforce it, and the refusal is a property of the contract rather
/// than of one mechanism — including this backend when it is unavailable.
#[test]
fn a_required_prevention_is_refused_by_every_backend_that_cannot_enforce_it() {
    const SCENARIO: &str = "macos-vm adversarial: required prevention refused by every backend that cannot enforce it";

    let inert = MockTarget {
        backend: MockBackend::inert(),
        label: "mock/inert",
    };
    let observing = MockTarget {
        backend: MockBackend::observing(CapabilityDomain::ALL),
        label: "mock/observe-only",
    };
    let absent = MacosVmTarget(MacosVmBackend::unavailable("no substrate configured (test double)"));
    let preventing = MockTarget {
        backend: MockBackend::preventing(CapabilityDomain::ALL),
        label: "mock/preventing",
    };

    assert_required_prevention_refused_by_every_uncapable_backend(
        SCENARIO,
        &[&inert as &dyn AdversarialTarget, &observing, &absent],
        &preventing,
    );
}

/// AC: observation is never promoted to enforcement, on any backend. Same
/// body as the native/Sandlock lanes' — both sides of the comparison are
/// `MockBackend` configurations, so nothing here is macOS-VM-specific; this
/// scenario exists on this lane so its CI job summary accounts for the same
/// property the other two lanes do.
#[test]
fn observation_is_never_promoted_to_prevention_on_any_backend() {
    assert_observation_is_never_promoted_to_prevention(
        "macos-vm adversarial: observation is never promoted to prevention on any backend",
    );
}

/// AC: audit/evidence assertions confirm blocked, unsupported and unmeasured
/// are not conflated. Same body as the other lanes'.
#[test]
fn blocked_unsupported_and_unmeasured_stay_three_distinct_report_states() {
    assert_blocked_unsupported_and_unmeasured_stay_distinct(
        "macos-vm adversarial: blocked, unsupported and unmeasured are distinct report states",
    );
}

/// AC: a claim is promoted only by a decision record, and corroboration is
/// not a decision. Same body as the other lanes'.
#[test]
fn a_claim_is_promoted_only_by_a_decision_record() {
    assert_claim_is_promoted_only_by_a_decision_record("macos-vm adversarial: only a decision record promotes a claim");
}
