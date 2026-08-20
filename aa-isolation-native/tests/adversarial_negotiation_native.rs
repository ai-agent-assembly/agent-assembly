//! Negotiation-level adversarial scenarios that need no kernel and no
//! mechanism, run against the AASM-native backend (AAASM-5805).
//!
//! # Why only four of the Sandlock lane's eight scenarios are here
//!
//! `aa-isolation-sandlock/tests/adversarial_negotiation.rs` has eight
//! negotiation scenarios. Four of them generalize over any
//! [`adversarial::AdversarialTarget`] and are shared verbatim, via
//! `adversarial::assert_required_prevention_refused_by_every_uncapable_backend`
//! and three self-contained `assert_*` functions that need no backend under
//! test at all. The other four —
//! `every_resource_ceiling_the_mechanism_cannot_decide_before_the_effect_is_refused`,
//! `unsupported_and_unmeasured_domains_refuse_for_different_reasons`,
//! `a_waived_protection_removes_the_domain_it_covers_rather_than_weakening_it`
//! and `missing_disabled_and_partially_configured_backends_are_three_distinct_states`
//! — drive `aa_isolation_sandlock::capability::discover`/`narrow_for` directly,
//! probing Sandlock's prerequisite-gated `Partial` support and its protection
//! waivers. Native's capability model has neither: every domain it does not
//! measure ([`aa_isolation::CapabilityDomain::FilesystemRead`],
//! [`aa_isolation::CapabilityDomain::FilesystemWrite`] and
//! [`aa_isolation::CapabilityDomain::Syscall`] are the only three) is flatly
//! `Unsupported`, with no intermediate `Partial` state and nothing to waive —
//! see `aa-isolation-native/src/capability.rs`'s module documentation, "Six
//! domains are unsupported on purpose". A scenario asserting a `Partial`/
//! `Unsupported` split, or a waiver removing a domain from `Partial` to
//! `Unsupported`, would be asserting something that is not true of this
//! backend, so no native counterpart is written for those four. What native
//! actually reports for the domains it does not measure is exercised instead
//! by the gap-measurement scenarios AAASM-5805 adds to
//! `adversarial_boundary_native_linux.rs`.

mod adversarial;

use aa_isolation::mock::MockBackend;
use aa_isolation::CapabilityDomain;
use aa_isolation_native::{HostUnusable, NativeBackend};
use adversarial::{
    assert_blocked_unsupported_and_unmeasured_stay_distinct, assert_claim_is_promoted_only_by_a_decision_record,
    assert_observation_is_never_promoted_to_prevention, assert_required_prevention_refused_by_every_uncapable_backend,
    AdversarialTarget, MockTarget, NativeTarget,
};

/// AC: a required prevention requirement is refused by every backend that
/// cannot enforce it, and the refusal is a property of the contract rather
/// than of one mechanism — including the native backend when it is absent.
#[test]
fn a_required_prevention_is_refused_by_every_backend_that_cannot_enforce_it() {
    const SCENARIO: &str = "native adversarial: required prevention refused by every backend that cannot enforce it";

    let inert = MockTarget {
        backend: MockBackend::inert(),
        label: "mock/inert",
    };
    let observing = MockTarget {
        backend: MockBackend::observing(CapabilityDomain::ALL),
        label: "mock/observe-only",
    };
    let absent = NativeTarget(NativeBackend::unavailable(&HostUnusable::LauncherNotFound {
        searched: Vec::new(),
    }));
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

/// AC: observation is never promoted to enforcement, on any backend. Same body
/// as the Sandlock lane's — both sides of the comparison are `MockBackend`
/// configurations, so nothing here is native-specific, and this scenario
/// exists on this lane so the CI job summary for the native lane accounts for
/// the same property the Sandlock lane does.
///
/// Named "... on any backend" rather than the shorter form
/// `adversarial_boundary_native_linux.rs` uses for its own, differently-scoped
/// scenario of nearly the same name (a real confined run, not a `MockBackend`
/// negotiation) — the ledger writes one record per scenario name, so the two
/// would collapse into one if they matched.
#[test]
fn observation_is_never_promoted_to_prevention_on_any_backend() {
    assert_observation_is_never_promoted_to_prevention(
        "native adversarial: observation is never promoted to prevention on any backend",
    );
}

/// AC: audit/evidence assertions confirm blocked, unsupported and unmeasured
/// are not conflated. Same body as the Sandlock lane's.
#[test]
fn blocked_unsupported_and_unmeasured_stay_three_distinct_report_states() {
    assert_blocked_unsupported_and_unmeasured_stay_distinct(
        "native adversarial: blocked, unsupported and unmeasured are distinct report states",
    );
}

/// AC: a claim is promoted only by a decision record, and corroboration is not
/// a decision. Same body as the Sandlock lane's.
#[test]
fn a_claim_is_promoted_only_by_a_decision_record() {
    assert_claim_is_promoted_only_by_a_decision_record("native adversarial: only a decision record promotes a claim");
}
