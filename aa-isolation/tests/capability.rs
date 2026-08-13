//! What a backend may say about itself, and what the manifest vocabulary
//! requires it to be able to say.

use aa_core::attestation::ClaimTerm;
use aa_isolation::{
    BackendAvailability, BackendCapabilities, CapabilityDomain, CapabilityReport, DecisionTiming, DescendantCoverage,
    FailurePosture, Mediation, PlatformBoundary, Prerequisite, PrerequisiteStatus, SupportLevel, Synchrony,
};

/// The four vocabularies this crate must be able to speak, read from the schema
/// that defines them rather than copied into this file.
///
/// Copying the tokens here would make the test agree with itself: it would pass
/// just as happily if the schema changed underneath it. Reading the real file
/// means a schema edit that this crate has not accounted for fails the test.
fn schema_enum(field: &str) -> Vec<String> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../schemas/capability-manifest/v1/capability-manifest.schema.json");
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read capability manifest schema at {path:?}: {e}"));
    let schema: serde_json::Value = serde_json::from_str(&raw).expect("capability manifest schema is not valid JSON");
    let values = schema["definitions"]["capability"]["properties"][field]["enum"]
        .as_array()
        .unwrap_or_else(|| panic!("schema has no definitions.capability.properties.{field}.enum"));
    values
        .iter()
        .map(|v| v.as_str().expect("schema enum member is not a string").to_string())
        .collect()
}

fn assert_speaks(field: &str, tokens: &[&str]) {
    let schema = schema_enum(field);
    for token in tokens {
        assert!(
            schema.iter().any(|s| s == token),
            "`{token}` is not a member of the schema's `{field}` enum {schema:?}"
        );
    }
    // The reverse direction: a token the schema accepts and this crate cannot
    // produce is a gap, and it must fail here rather than at the point some
    // later ticket tries to write a manifest row.
    assert_eq!(
        schema.len(),
        tokens.len(),
        "schema `{field}` enum is {schema:?} but this crate produces {tokens:?}"
    );
}

#[test]
fn decision_timing_speaks_the_manifest_vocabulary() {
    assert_speaks(
        "decision_timing",
        &[
            DecisionTiming::Pre.as_manifest_str(),
            DecisionTiming::InLine.as_manifest_str(),
            DecisionTiming::Post.as_manifest_str(),
            DecisionTiming::None.as_manifest_str(),
        ],
    );
}

#[test]
fn mediation_speaks_the_manifest_vocabulary() {
    assert_speaks(
        "observe_or_enforce",
        &[
            Mediation::Enforce.as_manifest_str(),
            Mediation::Observe.as_manifest_str(),
            Mediation::None.as_manifest_str(),
        ],
    );
}

#[test]
fn synchrony_speaks_the_manifest_vocabulary() {
    assert_speaks(
        "sync_or_best_effort",
        &[
            Synchrony::Sync.as_manifest_str(),
            Synchrony::BestEffort.as_manifest_str(),
            Synchrony::None.as_manifest_str(),
        ],
    );
}

#[test]
fn failure_posture_speaks_the_manifest_vocabulary() {
    // `failure_posture` is not under `definitions.capability.properties`, so it
    // is checked against the ADR-recorded set directly. The five tokens below
    // are the ones the ticket pins.
    let produced = [
        FailurePosture::FailClosed.as_manifest_str(),
        FailurePosture::FailOpen.as_manifest_str(),
        FailurePosture::FailOpenSilent.as_manifest_str(),
        FailurePosture::SilentTruncation.as_manifest_str(),
        FailurePosture::NotApplicable.as_manifest_str(),
    ];
    assert_eq!(
        produced,
        [
            "fail_closed",
            "fail_open",
            "fail_open_silent",
            "silent_truncation",
            "not_applicable"
        ]
    );
}

/// `can_prevent` requires five conditions. This walks each one down from a
/// passing baseline, one at a time, so a failure names the single axis that
/// broke it rather than "something about this report".
#[test]
fn prevention_requires_every_axis_independently() {
    let baseline = || {
        CapabilityReport::new(
            CapabilityDomain::FilesystemWrite,
            Mediation::Enforce,
            DecisionTiming::Pre,
            Synchrony::Sync,
        )
    };
    assert!(baseline().can_prevent(), "baseline must prevent");

    // 1. mediation
    for mediation in [Mediation::Observe, Mediation::None] {
        let report = CapabilityReport::new(
            CapabilityDomain::FilesystemWrite,
            mediation,
            DecisionTiming::Pre,
            Synchrony::Sync,
        );
        assert!(!report.can_prevent(), "mediation {mediation:?} must not prevent");
    }

    // 2. timing
    for timing in [DecisionTiming::InLine, DecisionTiming::Post, DecisionTiming::None] {
        let report = CapabilityReport::new(
            CapabilityDomain::FilesystemWrite,
            Mediation::Enforce,
            timing,
            Synchrony::Sync,
        );
        assert!(!report.can_prevent(), "timing {timing:?} must not prevent");
    }

    // 3. synchrony
    for synchrony in [Synchrony::BestEffort, Synchrony::None] {
        let report = CapabilityReport::new(
            CapabilityDomain::FilesystemWrite,
            Mediation::Enforce,
            DecisionTiming::Pre,
            synchrony,
        );
        assert!(!report.can_prevent(), "synchrony {synchrony:?} must not prevent");
    }

    // 4. support level
    assert!(!baseline()
        .with_support(SupportLevel::Unsupported {
            reason: "no mechanism".into()
        })
        .can_prevent());

    // 5. prerequisites, including the unchecked case
    assert!(!baseline()
        .with_prerequisite(Prerequisite::unsatisfied("kernel feature", "absent"))
        .can_prevent());
    assert!(
        !baseline()
            .with_prerequisite(Prerequisite {
                requirement: "kernel feature".into(),
                status: PrerequisiteStatus::Unchecked,
            })
            .can_prevent(),
        "an unchecked prerequisite must not support a prevention claim"
    );
    assert!(baseline()
        .with_prerequisite(Prerequisite::satisfied("kernel feature"))
        .can_prevent());
}

/// Partial support still prevents within its stated scope — the deliberate
/// exception documented on `can_prevent`.
#[test]
fn partial_support_still_prevents() {
    let report = CapabilityReport::new(
        CapabilityDomain::FilesystemWrite,
        Mediation::Enforce,
        DecisionTiming::Pre,
        Synchrony::Sync,
    )
    .with_support(SupportLevel::Partial {
        limitations: vec!["device nodes are not covered".into()],
    });
    assert!(report.can_prevent());
    assert_eq!(report.claim_ceiling(), ClaimTerm::DeniedBeforeExecution);
}

#[test]
fn claim_ceiling_never_exceeds_what_the_capability_does() {
    let observing = CapabilityReport::new(
        CapabilityDomain::NetworkEgress,
        Mediation::Observe,
        DecisionTiming::Pre,
        Synchrony::Sync,
    );
    assert_eq!(observing.claim_ceiling(), ClaimTerm::Observed);
    assert!(!observing.claim_ceiling().is_prevention());

    let unsupported = CapabilityReport::unsupported(CapabilityDomain::NetworkEgress, "no mechanism");
    assert_eq!(unsupported.claim_ceiling(), ClaimTerm::Unsupported);
    assert!(!unsupported.claim_ceiling().asserts_coverage());
}

/// An unsupported report cannot simultaneously advertise a decision it does not
/// make — the constructor pins mediation, timing and synchrony to `None`.
#[test]
fn unsupported_report_advertises_no_decision() {
    let report = CapabilityReport::unsupported(CapabilityDomain::Syscall, "not available here");
    assert_eq!(report.mediation(), Mediation::None);
    assert_eq!(report.timing(), DecisionTiming::None);
    assert_eq!(report.synchrony(), Synchrony::None);
    assert!(!report.can_prevent());
    assert!(!report.can_observe());
}

/// Descendant coverage defaults to `Unmeasured`, so a backend author who forgets
/// to state it under-claims rather than over-claims.
#[test]
fn descendant_coverage_defaults_to_unmeasured() {
    let report = CapabilityReport::new(
        CapabilityDomain::ProcessCreation,
        Mediation::Enforce,
        DecisionTiming::Pre,
        Synchrony::Sync,
    );
    assert_eq!(report.descendants(), DescendantCoverage::Unmeasured);
}

#[test]
fn duplicate_domain_reports_are_rejected() {
    let err = BackendCapabilities::new(
        BackendAvailability::Available,
        PlatformBoundary::SharedHostKernel,
        vec![
            CapabilityReport::unsupported(CapabilityDomain::Ipc, "a"),
            CapabilityReport::unsupported(CapabilityDomain::Ipc, "b"),
        ],
    )
    .expect_err("two reports for one domain must be rejected");
    assert_eq!(err.0, CapabilityDomain::Ipc);
}

/// A domain nobody reported is unknown, not unsupported. The distinction is
/// what stops an incomplete capability report from reading as a deliberate one.
#[test]
fn silence_about_a_domain_is_not_a_report() {
    let capabilities = BackendCapabilities::new(
        BackendAvailability::Available,
        PlatformBoundary::SharedHostKernel,
        vec![CapabilityReport::unsupported(CapabilityDomain::Ipc, "no mechanism")],
    )
    .expect("unique");
    assert!(capabilities.report_for(CapabilityDomain::Ipc).is_some());
    assert!(capabilities.report_for(CapabilityDomain::NetworkEgress).is_none());
    assert_eq!(capabilities.unreported_domains().len(), CapabilityDomain::ALL.len() - 1);
}
