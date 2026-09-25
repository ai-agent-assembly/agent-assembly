//! AAASM-6167 positive control: `aa_isolation::planner` evaluated against a
//! real backend's actual, non-synthetic capability reporting logic — not a
//! `MockBackend`.
//!
//! `MacosVmBackend::discover()` reports `Unavailable` on a host without the
//! VM substrate configured (`aa-isolation-macos-vm-poc`'s helper binary,
//! guest kernel and rootfs — gitignored, and this session's host doesn't have
//! them), so it cannot itself supply a `BackendCapabilities` with populated
//! per-domain reports here. `aa_isolation_macos_vm::capability::discover`,
//! however, is the same pure function a live host's `discover()` would call
//! once a guest probe actually ran (`crate::probe::measure` → `capability::discover`
//! in this crate's own `lib.rs`) — feeding it a `GuestProbe` this test builds
//! directly exercises that backend's real `filesystem_read`/`filesystem_write`
//! reporting logic (`FailurePosture`, `SupportLevel`, descendant coverage) with
//! no VM boot required, which is exactly the "real backend capabilities" input
//! the ticket's positive control asks for.

use aa_isolation::{CapabilityDomain, ControlRequirement, PlatformBoundary, RuntimeRequirements};
use aa_isolation_macos_vm::probe::{GuestProbe, Observation};

fn identity() -> aa_isolation::BackendIdentity {
    aa_isolation::BackendIdentity {
        id: aa_isolation_macos_vm::BACKEND_ID.to_string(),
        version: "test".to_string(),
        provenance: aa_isolation::Provenance {
            source: "aa-isolation-macos-vm test".to_string(),
            license: "Apache-2.0".to_string(),
            modified: false,
        },
    }
}

/// A probe in which every measured filesystem action was actually denied to
/// the descendant that attempted it — the shape a healthy guest boundary
/// reports.
fn fully_confined_probe() -> GuestProbe {
    GuestProbe {
        filesystem_read: Observation::Denied,
        filesystem_write: Observation::Denied,
    }
}

/// This backend's real `capability::discover` reports `SupportLevel::Partial`
/// on `FilesystemWrite` unconditionally — `shared_limitations()` always
/// carries stated limitations, even for a fully-denied probe — while still
/// reporting `Mediation::Enforce`/`DecisionTiming::Pre`/`Synchrony::Sync` and
/// `FailurePosture::FailClosed`. That is precisely the "can_prevent() is true,
/// SupportLevel is not Full" shape the planner's evidence-minimum axis exists
/// to catch independently of `negotiate`'s own prevention check — proven here
/// against the real reporting function rather than a synthetic capability.
#[test]
fn real_backend_can_prevent_filesystem_write_but_is_never_full_support() {
    let capabilities = aa_isolation_macos_vm::capability::discover(&fully_confined_probe());
    let report = capabilities
        .report_for(CapabilityDomain::FilesystemWrite)
        .expect("discover always reports filesystem_write");

    assert!(
        report.can_prevent(),
        "a fully-denied probe must satisfy negotiate's prevention check"
    );
    assert!(
        matches!(report.support(), aa_isolation::SupportLevel::Partial { .. }),
        "this backend's own capability.rs always states filesystem limitations; support() should be Partial, was {:?}",
        report.support()
    );
}

/// The real backend passes a `RuntimeRequirements` asking for prevention plus
/// a `FailClosed` evidence minimum on `FilesystemWrite` — the axis a real,
/// fully-confined guest genuinely satisfies.
#[test]
fn positive_control_selects_the_real_backend_under_a_fail_closed_minimum() {
    let candidate = aa_isolation::Candidate::new(
        identity(),
        aa_isolation_macos_vm::capability::discover(&fully_confined_probe()),
    );
    let requirements = RuntimeRequirements::new()
        .with_confinement(ControlRequirement::prevent(CapabilityDomain::FilesystemWrite))
        .with_evidence_minimum(
            CapabilityDomain::FilesystemWrite,
            aa_isolation::EvidenceMinimum::none().with_min_failure_posture(aa_isolation::FailurePosture::FailClosed),
        )
        .with_allowed_platform_boundaries(vec![PlatformBoundary::GuestKernel]);

    let plan = aa_isolation::select_pinned(&requirements, &candidate)
        .expect("a fully-denied real guest probe must satisfy prevention plus a fail-closed minimum");
    assert_eq!(plan.backend().id, aa_isolation_macos_vm::BACKEND_ID);
}

/// The same real backend, under a `require_full_support` minimum, is
/// disqualified — proving the independent evidence-minimum bar actually
/// excludes a real (not synthetic) backend that `negotiate` alone would
/// still accept.
#[test]
fn a_full_support_minimum_disqualifies_the_real_backend_negotiate_would_accept() {
    let candidate = aa_isolation::Candidate::new(
        identity(),
        aa_isolation_macos_vm::capability::discover(&fully_confined_probe()),
    );
    let probe_only_requirements =
        RuntimeRequirements::new().with_confinement(ControlRequirement::prevent(CapabilityDomain::FilesystemWrite));
    assert!(
        aa_isolation::select_pinned(&probe_only_requirements, &candidate).is_ok(),
        "negotiate alone must accept this real backend for the mutation to prove anything"
    );

    let requirements = probe_only_requirements.with_evidence_minimum(
        CapabilityDomain::FilesystemWrite,
        aa_isolation::EvidenceMinimum::none().with_full_support_required(),
    );
    let refusal = aa_isolation::select_pinned(&requirements, &candidate)
        .expect_err("this backend's own capability.rs never reports Full support for FilesystemWrite");
    assert_eq!(refusal.unmet()[0].0.domain(), CapabilityDomain::FilesystemWrite);
}
