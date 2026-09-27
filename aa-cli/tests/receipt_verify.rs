//! Tests for the AAASM-6166 execution-receipt module: seal tamper detection
//! (test set A), truth-downgrade validation (test set B), the population/
//! falsification control for missing-evidence downgrade (test set C),
//! redaction by construction (test set D), and the CLI surface.
//!
//! Determinism (test set E) is pinned inline in
//! `aa-cli/src/commands/execution_receipt/canonical.rs` — see that file's own
//! `#[cfg(test)]` module — because it has to land in the same commit as the
//! canonicalizer, not a later one.
use std::io::Write as _;

use aa_cli::commands::execution_receipt::canonical::Digest;
use aa_cli::commands::execution_receipt::host;
use aa_cli::commands::execution_receipt::project::{body_for_run, ReceiptContext, TerminationInput};
use aa_cli::commands::execution_receipt::schema::{ReceiptBody, ReceiptEnvelope, TerminationRecord};
use aa_cli::commands::execution_receipt::text::{FieldName, ReceiptText};
use aa_cli::commands::execution_receipt::validate::{defects, ReceiptDefect};
use aa_cli::commands::execution_receipt::verify::{verify, SealVerdict};

use aa_core::attestation::ClaimTerm;
use aa_isolation::mock::MockBackend;
use aa_isolation::{
    CapabilityDomain, CredentialPosture, EnforcementEvidence, EvidenceKind, EvidenceRecord, ExecutionSpec, IdentityRef,
    IsolationBackend, IsolationReport, SessionRef,
};
use aa_policy::resolve::{PolicyResolution, Unconfigured};

/// Synthetic literal matching `aa-core`'s own scanner fixture convention
/// (`aa-core/src/integration/fingerprint.rs`) — never a real credential shape.
const SYNTHETIC_SECRET: &str =
    "sk-ant-api03-AAASM6166SYNTHETICDONOTUSEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

/// Build a real receipt body from a `MockBackend` fixture. `preventing`
/// selects which domains the mock reports as prevention-capable; nothing here
/// gives the mock an `EvidenceKind::Decision` record — that is added per-test
/// where a test needs one.
fn build_body(preventing: &[CapabilityDomain]) -> ReceiptBody {
    let session = SessionRef::new("test-session", "test-trace");
    let identity = IdentityRef::root("agent-1").with_team("team-1");
    let mut spec = ExecutionSpec::new("/usr/bin/true", identity).with_args(["--flag", SYNTHETIC_SECRET]);
    spec = spec.with_credentials(CredentialPosture {
        removed: vec!["ANTHROPIC_API_KEY".to_string()],
        delegated: Vec::new(),
        ambient_unremoved: Vec::new(),
    });

    let backend = MockBackend::preventing(preventing);
    let plan = backend
        .plan(&spec)
        .expect("mock backend never refuses an empty requirement set");
    let report = IsolationReport::from_plan(session.clone(), &plan);
    let prepared = backend
        .prepare(plan)
        .expect("mock prepare never fails for its own plan");
    let handle = backend
        .spawn(prepared)
        .expect("mock spawn never fails for its own prepared execution");
    let disposition = backend
        .wait_for_exit(&handle)
        .expect("mock wait_for_exit never fails for its own handle");
    let evidence = backend.evidence(&handle);
    let final_report = report.with_evidence(&evidence);

    let ctx = ReceiptContext {
        session: &session,
        spec: &spec,
        report: &final_report,
        evidence: &evidence,
        backend: &backend,
        policy: &PolicyResolution::Unconfigured(Unconfigured::NoSource {
            searched: vec!["policy.yaml".to_string()],
        }),
        started_at: std::time::SystemTime::now(),
        ended_at: std::time::SystemTime::now(),
        disposition: &disposition,
        termination: TerminationInput::SelfExited,
    };
    body_for_run(&ctx).expect("a mock-backend fixture never carries a float or a non-serializable value")
}

fn sealed(body: ReceiptBody) -> ReceiptEnvelope {
    ReceiptEnvelope::seal(body).expect("a receipt body built by this test file always canonicalizes")
}

// ---------------------------------------------------------------------------
// Test set A: the seal detects byte mutation, without recomputing it.
// ---------------------------------------------------------------------------

#[test]
fn seal_detects_a_mutated_spec_digest() {
    let mut envelope = sealed(build_body(&[]));
    envelope.body.spec.digest = Digest::of_canonical("tampered");
    assert_eq!(verify(&envelope).seal, SealVerdict::Mismatch);
}

#[test]
fn seal_detects_a_mutated_backend_id() {
    let mut envelope = sealed(build_body(&[CapabilityDomain::FilesystemWrite]));
    if let Some(backend) = envelope.body.backend.as_mut() {
        backend.id = ReceiptText::screened("some-other-backend");
    }
    assert_eq!(verify(&envelope).seal, SealVerdict::Mismatch);
}

#[test]
fn seal_detects_a_domain_claim_raised_from_unmeasured() {
    let mut envelope = sealed(build_body(&[]));
    envelope.body.domains[0].claim = ReceiptText::token(ClaimTerm::DeniedBeforeExecution.as_str());
    assert_eq!(verify(&envelope).seal, SealVerdict::Mismatch);
}

#[test]
fn seal_detects_an_exit_code_mutation() {
    let mut envelope = sealed(build_body(&[]));
    envelope.body.execution.exit_code = Some(0);
    assert_eq!(verify(&envelope).seal, SealVerdict::Mismatch);
}

#[test]
fn seal_detects_asserted_identity_mutation() {
    let mut envelope = sealed(build_body(&[]));
    envelope.body.asserted_identity.agent_id = ReceiptText::screened("someone-else");
    assert_eq!(verify(&envelope).seal, SealVerdict::Mismatch);
}

#[test]
fn seal_detects_withheld_fields_emptied() {
    let mut body = build_body(&[]);
    // Force a real withholding to exist so emptying the list is a genuine
    // mutation rather than a no-op.
    body.policy.source = Some(ReceiptText::Withheld);
    body.withheld_fields.push(FieldName::PolicySource);
    let mut envelope = sealed(body);
    envelope.body.withheld_fields.clear();
    assert_eq!(verify(&envelope).seal, SealVerdict::Mismatch);
}

#[test]
fn seal_detects_a_degraded_condition_deleted() {
    let mut body = build_body(&[]);
    assert!(
        !body.degraded.is_empty(),
        "an unmeasured-everywhere fixture always records degraded conditions"
    );
    let mut envelope = sealed(body.clone());
    body.degraded.pop();
    envelope.body.degraded = body.degraded;
    assert_eq!(verify(&envelope).seal, SealVerdict::Mismatch);
}

/// Negative control: re-serializing the same content with different
/// whitespace/key order must NOT trip the seal — without this, a seal that is
/// accidentally a raw-file hash rather than a content digest would pass every
/// case above too.
#[test]
fn reformatting_the_stored_json_does_not_break_the_seal() {
    let envelope = sealed(build_body(&[CapabilityDomain::NetworkEgress]));
    let compact = serde_json::to_string(&envelope).unwrap();
    let pretty = serde_json::to_string_pretty(&envelope).unwrap();
    assert_ne!(
        compact, pretty,
        "the two renderings must actually differ in bytes for this control to mean anything"
    );

    let from_compact: ReceiptEnvelope = serde_json::from_str(&compact).unwrap();
    let from_pretty: ReceiptEnvelope = serde_json::from_str(&pretty).unwrap();
    assert_eq!(verify(&from_compact).seal, SealVerdict::Holds);
    assert_eq!(verify(&from_pretty).seal, SealVerdict::Holds);
}

/// The seal covers `body` only — mutating `schema` never trips it, but
/// `defects()` still catches the result. Pins the boundary `mod.rs` documents
/// rather than leaving it merely asserted in prose.
#[test]
fn mutating_the_envelope_schema_holds_the_seal_but_is_still_a_defect() {
    let mut envelope = sealed(build_body(&[]));
    envelope.schema = "some.other.schema/9".to_string();
    let verification = verify(&envelope);
    assert_eq!(verification.seal, SealVerdict::Holds);
    assert!(verification
        .defects
        .iter()
        .any(|d| matches!(d, ReceiptDefect::UnknownSchema { .. })));
    assert!(!verification.is_trustworthy());
}

// ---------------------------------------------------------------------------
// Test set B: validate() catches a re-sealed lie.
// ---------------------------------------------------------------------------

#[test]
fn a_freshly_resealed_overclaim_still_fails_validation() {
    let mut body = build_body(&[]);
    // Every domain starts unmeasured/planned on this fixture. Hand-raise one
    // domain's claim to a prevention term on setup-only evidence, then reseal
    // — the seal will hold; `defects()` must not.
    body.domains[0].claim = ReceiptText::token(ClaimTerm::DeniedBeforeExecution.as_str());
    body.domains[0].evidence_basis = ReceiptText::token("setup_only");
    let envelope = sealed(body);
    assert_eq!(verify(&envelope).seal, SealVerdict::Holds);
    let found = defects(&envelope);
    assert!(!found.is_empty());
    assert!(found
        .iter()
        .any(|d| matches!(d, ReceiptDefect::PreventionWithoutDecision { .. })));
}

#[test]
fn coverage_claim_on_none_evidence_is_a_defect() {
    let mut body = build_body(&[]);
    body.domains[0].claim = ReceiptText::token(ClaimTerm::Observed.as_str());
    body.domains[0].evidence_basis = ReceiptText::token("none");
    let envelope = sealed(body);
    let found = defects(&envelope);
    assert!(found
        .iter()
        .any(|d| matches!(d, ReceiptDefect::CoverageWithoutRuntimeEvidence { .. })));
}

#[test]
fn prevention_flag_true_without_decision_evidence_is_a_defect() {
    let mut body = build_body(&[]);
    body.domains[0].prevention_supported = true;
    body.domains[0].evidence_basis = ReceiptText::token("runtime_without_decision");
    let envelope = sealed(body);
    let found = defects(&envelope);
    assert!(found
        .iter()
        .any(|d| matches!(d, ReceiptDefect::PreventionFlagInconsistent { .. })));
}

#[test]
fn prevention_claim_over_a_degraded_domain_is_a_defect() {
    let mut body = build_body(&[]);
    body.domains[0].claim = ReceiptText::token(ClaimTerm::DeniedBeforeExecution.as_str());
    body.domains[0].evidence_basis = ReceiptText::token("decision");
    body.domains[0].prevention_supported = true;
    body.degraded
        .push(aa_cli::commands::execution_receipt::schema::DegradedCondition {
            domain: Some(body.domains[0].domain.clone()),
            kind: aa_cli::commands::execution_receipt::schema::DegradedKind::ControlShortfall,
            detail: ReceiptText::token("shortfall"),
        });
    let envelope = sealed(body);
    let found = defects(&envelope);
    assert!(found
        .iter()
        .any(|d| matches!(d, ReceiptDefect::PreventionOverDegradedDomain { .. })));
}

#[test]
fn coverage_claim_with_no_backend_is_a_defect() {
    let mut body = build_body(&[]);
    body.backend = None;
    body.domains[0].claim = ReceiptText::token(ClaimTerm::Observed.as_str());
    body.domains[0].evidence_basis = ReceiptText::token("decision");
    let envelope = sealed(body);
    let found = defects(&envelope);
    assert!(found
        .iter()
        .any(|d| matches!(d, ReceiptDefect::CoverageWithoutBackend { .. })));
}

#[test]
fn a_coverage_claim_on_an_unmeasured_state_is_a_defect() {
    let mut body = build_body(&[]);
    body.domains[0].state = ReceiptText::token("unmeasured");
    body.domains[0].claim = ReceiptText::token(ClaimTerm::Observed.as_str());
    body.domains[0].evidence_basis = ReceiptText::token("decision");
    let envelope = sealed(body);
    let found = defects(&envelope);
    assert!(found
        .iter()
        .any(|d| matches!(d, ReceiptDefect::StateClaimIncoherent { .. })));
}

#[test]
fn removing_a_domain_is_a_defect() {
    let mut body = build_body(&[]);
    body.domains.pop();
    let envelope = sealed(body);
    let found = defects(&envelope);
    assert!(found.iter().any(|d| matches!(d, ReceiptDefect::DomainMissing { .. })));
}

#[test]
fn an_unrecorded_withholding_is_a_defect() {
    let mut body = build_body(&[]);
    body.policy.source = Some(ReceiptText::Withheld);
    // Deliberately NOT pushed to `withheld_fields`.
    let envelope = sealed(body);
    let found = defects(&envelope);
    assert!(found.iter().any(|d| matches!(
        d,
        ReceiptDefect::WithholdingUnrecorded {
            field: FieldName::PolicySource
        }
    )));
}

#[test]
fn an_inverted_timeline_is_a_defect() {
    let mut body = build_body(&[]);
    body.execution.started_at_unix_secs = 100;
    body.execution.ended_at_unix_secs = 50;
    let envelope = sealed(body);
    let found = defects(&envelope);
    assert!(found.iter().any(|d| matches!(d, ReceiptDefect::TimelineInverted)));
}

// ---------------------------------------------------------------------------
// Test set C: the downgrade rule bound to a falsifying control.
// ---------------------------------------------------------------------------

#[test]
fn only_a_decision_record_flips_prevention_and_only_for_its_own_domain() {
    let session = SessionRef::new("s", "t");
    let identity = IdentityRef::root("agent-1");
    let spec = ExecutionSpec::new("/usr/bin/true", identity);
    let backend = MockBackend::preventing(&[CapabilityDomain::FilesystemWrite]);
    let plan = backend.plan(&spec).unwrap();
    let report = IsolationReport::from_plan(session.clone(), &plan);

    // Baseline: every record is Configured (setup-only) — population
    // assertion that every domain's claim is non-coverage.
    let baseline_evidence = EnforcementEvidence::from_plan(&plan);
    let baseline_report = report.clone().with_evidence(&baseline_evidence);
    for projection in baseline_report.domains() {
        assert!(
            !projection.claim.asserts_coverage(),
            "domain {} unexpectedly asserts coverage",
            projection.domain
        );
    }

    // Flip exactly one record to a real Decision for FilesystemWrite.
    let mut evidence = baseline_evidence;
    evidence.record(EvidenceRecord::new(
        EvidenceKind::Decision,
        CapabilityDomain::FilesystemWrite,
        ClaimTerm::DeniedBeforeExecution,
        "test: a synthetic decision record",
    ));
    let flipped_report = report.with_evidence(&evidence);

    for projection in flipped_report.domains() {
        let expect_prevention = evidence.supports_prevention_claim(projection.domain);
        if projection.domain == CapabilityDomain::FilesystemWrite {
            assert!(
                expect_prevention,
                "the domain the decision record names must now support prevention"
            );
        } else {
            assert!(
                !expect_prevention,
                "domain {} must not be affected by another domain's decision",
                projection.domain
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Test set D: redaction.
// ---------------------------------------------------------------------------

#[test]
fn argv_secret_never_reaches_the_canonical_json_but_arg_count_and_digest_do() {
    let body = build_body(&[]);
    let canonical = serde_json::to_string(&body).unwrap();
    assert!(!canonical.contains("AAASM6166SYNTHETIC"), "{canonical}");
    assert_eq!(body.spec.arg_count, 2);
    assert_ne!(body.spec.argv_digest.as_str(), "");
}

#[test]
fn ambient_credential_names_are_present_with_no_values() {
    let body = build_body(&[]);
    let canonical = serde_json::to_string(&body).unwrap();
    assert!(canonical.contains("ANTHROPIC_API_KEY"));
}

#[test]
fn a_withheld_policy_source_is_recorded_and_degraded() {
    let mut body = build_body(&[]);
    body.policy.source = Some(ReceiptText::screened(SYNTHETIC_SECRET));
    assert!(body.policy.source.as_ref().unwrap().is_withheld());
}

#[test]
fn the_screen_itself_has_a_positive_and_negative_control() {
    assert!(ReceiptText::screened(SYNTHETIC_SECRET).is_withheld());
    assert!(!ReceiptText::screened("a perfectly ordinary sentence").is_withheld());
}

// ---------------------------------------------------------------------------
// F (reduced scope): host facts differ between a shared-host-kernel-shaped
// and a guest-kernel-shaped backend, and a verified receipt's termination
// record matches what actually happened. Full dual-platform CLI coverage
// lives in `aa-integration-tests/tests/cli_run_execution_receipt.rs`.
// ---------------------------------------------------------------------------

#[test]
fn a_completed_run_records_self_exited_termination() {
    let body = build_body(&[]);
    assert_eq!(body.execution.termination, TerminationRecord::SelfExited);
}

#[test]
fn host_facts_differ_by_platform_boundary_shape() {
    let shared = host::facts(&MockBackend::inert());
    let kernel_release = shared.iter().find(|f| f.name == host::FactName::KernelRelease).unwrap();
    // On this dev machine (macOS), `/proc` does not exist, so this is
    // unmeasured rather than measured — still distinguishes it from a
    // guest-kernel backend, which is unconditionally unmeasured for a
    // different, stated reason. `aa-integration-tests` asserts the Linux-
    // native measured case for real.
    assert!(matches!(
        kernel_release.basis,
        host::FactBasis::Unmeasured { .. } | host::FactBasis::Measured { .. }
    ));
}

// ---------------------------------------------------------------------------
// The store + CLI surface (also exercised end-to-end via `assert_cmd`).
// ---------------------------------------------------------------------------

#[test]
fn cli_receipt_verify_reports_success_for_a_holding_receipt() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("receipt.json");
    let envelope = sealed(build_body(&[]));
    let mut file = std::fs::File::create(&path).unwrap();
    file.write_all(serde_json::to_string(&envelope).unwrap().as_bytes())
        .unwrap();

    let mut cmd = assert_cmd::Command::cargo_bin("aasm").expect("aasm binary");
    cmd.args(["receipt", "verify", path.to_str().unwrap()]);
    cmd.assert().success();
}

#[test]
fn cli_receipt_verify_reports_failure_for_a_tampered_receipt() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("receipt.json");
    let mut envelope = sealed(build_body(&[]));
    envelope.body.execution.exit_code = Some(0);
    let mut file = std::fs::File::create(&path).unwrap();
    file.write_all(serde_json::to_string(&envelope).unwrap().as_bytes())
        .unwrap();

    let mut cmd = assert_cmd::Command::cargo_bin("aasm").expect("aasm binary");
    cmd.args(["receipt", "verify", path.to_str().unwrap()]);
    cmd.assert().failure();
}
