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
        workspace: None,
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
fn a_workspace_binding_missing_one_scope_disclaimer_token_is_a_defect() {
    use aa_cli::commands::execution_receipt::schema::{WorkspaceBinding, NOT_TRANSACTIONAL};

    let mut body = build_body(&[]);
    body.workspace = Some(WorkspaceBinding {
        committed: Some(true),
        // Every token except the first — the falsifying mutation, not a
        // hand-picked expectation string.
        not_transactional: NOT_TRANSACTIONAL[1..].iter().copied().map(ReceiptText::token).collect(),
        ..Default::default()
    });
    let envelope = sealed(body);
    let found = defects(&envelope);
    assert!(
        found
            .iter()
            .any(|d| matches!(d, ReceiptDefect::WorkspaceScopeDisclaimerMissing { missing } if missing == &[NOT_TRANSACTIONAL[0].to_string()])),
        "expected a WorkspaceScopeDisclaimerMissing defect naming {:?}, got {found:?}",
        NOT_TRANSACTIONAL[0]
    );
}

#[test]
fn a_workspace_binding_carrying_the_full_disclaimer_is_not_a_defect() {
    use aa_cli::commands::execution_receipt::schema::{WorkspaceBinding, NOT_TRANSACTIONAL};

    let mut body = build_body(&[]);
    body.workspace = Some(WorkspaceBinding {
        committed: Some(true),
        not_transactional: NOT_TRANSACTIONAL.iter().copied().map(ReceiptText::token).collect(),
        ..Default::default()
    });
    let envelope = sealed(body);
    let found = defects(&envelope);
    assert!(!found
        .iter()
        .any(|d| matches!(d, ReceiptDefect::WorkspaceScopeDisclaimerMissing { .. })));
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

// ---------------------------------------------------------------------------
// Test set F (AAASM-6295, ST-8): the CLI exit-code surface for every tamper
// category the ticket names, plus the positive control and the
// recompute-the-digest-too control. All of these drive the real `aasm
// receipt verify` binary end-to-end (`assert_cmd`), not the internal
// `verify()` function test set A already covers at the library level.
//
// AAASM-6287 (macOS hardware re-qualification) merged, but
// `aa-isolation-macos-vm` remains an unwired PoC on this host — no VM
// helper/kernel/rootfs assets are configured
// (`aa-isolation-macos-vm-poc/README.md`), and the only other two compiled-in
// backends (`aasm-native`, `aasm-sandlock`) are Linux-only. So no isolation
// backend in this build can establish a confined boundary on this host at
// all (empirically confirmed: `cli_run_execution_receipt.rs`'s existing
// macOS test still hits its own `MACOS_VM_UNAVAILABLE_MARKER` branch, and
// `aa-integration-tests/tests/cli_run_execution_receipt.rs`'s new
// AAASM-6295 test shows `aasm-native` refuses on macOS too). The receipt
// these tests tamper with is therefore built through the real
// `body_for_run`/`ReceiptEnvelope::seal`/`ReceiptStore` production pipeline
// — the exact functions `aasm run` itself calls — driven by
// `aa_isolation::mock::MockBackend` rather than a genuinely confined child
// process, because nothing else can produce a sealed receipt on this host.
// This is recorded here as a known limitation for AAASM-6295's AC, not
// silently substituted.
// ---------------------------------------------------------------------------

fn write_envelope_json(dir: &std::path::Path, name: &str, value: &serde_json::Value) -> std::path::PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, serde_json::to_string(value).unwrap()).unwrap();
    path
}

fn verify_json(path: &std::path::Path) -> (bool, serde_json::Value) {
    let mut cmd = assert_cmd::Command::cargo_bin("aasm").expect("aasm binary");
    let output = cmd
        .args(["receipt", "verify", "--json", path.to_str().unwrap()])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let value: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("aasm receipt verify --json did not print valid JSON: {e}\nstdout:\n{stdout}"));
    (output.status.success(), value)
}

/// A genuine receipt, as JSON, from the real production pipeline.
fn genuine_envelope_json(preventing: &[CapabilityDomain]) -> serde_json::Value {
    let envelope = sealed(build_body(preventing));
    serde_json::to_value(&envelope).unwrap()
}

/// Positive control: an untouched receipt must verify with exit code 0, seal
/// holding, and no defects.
#[test]
fn f_an_untouched_receipt_verifies_with_exit_code_0() {
    let dir = tempfile::tempdir().unwrap();
    let json = genuine_envelope_json(&[]);
    let path = write_envelope_json(dir.path(), "receipt.json", &json);

    let (success, report) = verify_json(&path);
    assert!(success, "an untouched receipt must exit 0: {report}");
    assert_eq!(report["seal"], "holds");
    assert_eq!(report["trustworthy"], true);
}

/// Tamper category 1: flip a byte inside the `spec` sealed section (one hex
/// character of its digest) — stays JSON- and type-valid, so this tests the
/// seal, not the parser.
#[test]
fn f_flip_a_byte_in_the_spec_section_trips_the_seal() {
    let dir = tempfile::tempdir().unwrap();
    let mut json = genuine_envelope_json(&[]);
    let digest = json["body"]["spec"]["digest"].as_str().unwrap().to_string();
    let mut chars: Vec<char> = digest.chars().collect();
    let last = chars.len() - 1;
    chars[last] = if chars[last] == 'a' { 'b' } else { 'a' };
    json["body"]["spec"]["digest"] = serde_json::Value::String(chars.into_iter().collect());
    let path = write_envelope_json(dir.path(), "receipt.json", &json);

    let (success, report) = verify_json(&path);
    assert!(!success, "a flipped byte in the spec section must fail: {report}");
    assert_eq!(report["seal"], "mismatch");
}

/// Tamper category 1 (continued): flip a byte inside the `backend` sealed
/// section.
#[test]
fn f_flip_a_byte_in_the_backend_section_trips_the_seal() {
    let dir = tempfile::tempdir().unwrap();
    let mut json = genuine_envelope_json(&[CapabilityDomain::FilesystemWrite]);
    assert!(
        !json["body"]["backend"].is_null(),
        "fixture must carry a backend binding"
    );
    let id = json["body"]["backend"]["id"]["value"].as_str().unwrap().to_string();
    json["body"]["backend"]["id"]["value"] = serde_json::Value::String(format!("{id}-tampered"));
    let path = write_envelope_json(dir.path(), "receipt.json", &json);

    let (success, report) = verify_json(&path);
    assert!(!success, "a flipped byte in the backend section must fail: {report}");
    assert_eq!(report["seal"], "mismatch");
}

/// Tamper category 1 (continued): flip a byte inside the `domains` sealed
/// section.
#[test]
fn f_flip_a_byte_in_the_domains_section_trips_the_seal() {
    let dir = tempfile::tempdir().unwrap();
    let mut json = genuine_envelope_json(&[]);
    let claim = json["body"]["domains"][0]["claim"]["value"]
        .as_str()
        .unwrap()
        .to_string();
    json["body"]["domains"][0]["claim"]["value"] = serde_json::Value::String(format!("{claim}x"));
    let path = write_envelope_json(dir.path(), "receipt.json", &json);

    let (success, report) = verify_json(&path);
    assert!(!success, "a flipped byte in the domains section must fail: {report}");
    assert_eq!(report["seal"], "mismatch");
}

/// Tamper category 1 (continued): flip a byte inside the `execution` sealed
/// section (the exit code).
#[test]
fn f_flip_a_byte_in_the_execution_section_trips_the_seal() {
    let dir = tempfile::tempdir().unwrap();
    let mut json = genuine_envelope_json(&[]);
    let exit_code = json["body"]["execution"]["exit_code"].as_i64().unwrap_or(0);
    json["body"]["execution"]["exit_code"] = serde_json::Value::from(exit_code + 1);
    let path = write_envelope_json(dir.path(), "receipt.json", &json);

    let (success, report) = verify_json(&path);
    assert!(!success, "a flipped byte in the execution section must fail: {report}");
    assert_eq!(report["seal"], "mismatch");
}

/// Negative control for the four flips above: mutating `seal.sealed_by` (a
/// field the digest does NOT cover, per `mod.rs`'s "What the seal covers")
/// must leave the seal holding — otherwise the four flip tests above would
/// mean nothing (they'd pass even if `verify` tripped on every byte change
/// anywhere in the file, sealed or not).
#[test]
fn f_mutating_an_unsealed_seal_metadata_field_does_not_trip_the_seal() {
    let dir = tempfile::tempdir().unwrap();
    let mut json = genuine_envelope_json(&[]);
    json["seal"]["sealed_by"]["value"] = serde_json::Value::String("someone-else".to_string());
    let path = write_envelope_json(dir.path(), "receipt.json", &json);

    let (success, report) = verify_json(&path);
    assert!(
        success,
        "sealed_by sits outside the digest and must not trip the seal: {report}"
    );
    assert_eq!(report["seal"], "holds");
}

/// Tamper category 2a: removing a required (non-`Option`) field — `run_id`
/// — must fail to parse at all. A loud, non-silent failure, never a bypass.
#[test]
fn f_removing_a_required_field_fails_to_parse() {
    let dir = tempfile::tempdir().unwrap();
    let mut json = genuine_envelope_json(&[]);
    json["body"].as_object_mut().unwrap().remove("run_id");
    let path = write_envelope_json(dir.path(), "receipt.json", &json);

    let (success, report) = verify_json(&path);
    assert!(!success, "a missing required field must fail to parse: {report}");
    assert_eq!(report["trustworthy"], false);
    assert!(
        report.get("error").is_some(),
        "a parse failure must surface as `error`, not a seal verdict: {report}"
    );
}

/// Tamper category 2b (AAASM-6295 finding, not a bug): removing an
/// `Option` field whose stored value is already `null` is UNDETECTABLE —
/// `runtime_image` is documented as `None` on every backend today
/// (`schema.rs`), so dropping the key entirely reparses to the same `None`
/// serde implicitly assigns a missing `Option` field, which re-serializes
/// to the exact same canonical bytes the digest already covers. This is not
/// a defect in the design: nothing of substance was removed, because the
/// field carried no information to begin with. It is recorded here because
/// the ticket's blanket expectation ("removing a field" always trips a
/// non-zero exit) does not hold universally — only for a field that
/// actually carried content.
#[test]
fn f_removing_an_already_null_optional_field_is_undetectable_by_design() {
    let dir = tempfile::tempdir().unwrap();
    let mut json = genuine_envelope_json(&[]);
    assert!(
        json["body"]["runtime_image"].is_null(),
        "fixture precondition: runtime_image must already be null"
    );
    json["body"].as_object_mut().unwrap().remove("runtime_image");
    let path = write_envelope_json(dir.path(), "receipt.json", &json);

    let (success, report) = verify_json(&path);
    assert!(
        success,
        "removing an already-null field changes nothing the digest covers, so this is expected to verify: {report}"
    );
    assert_eq!(report["seal"], "holds");
}

/// Tamper category 3 (AAASM-6295 finding): adding an unknown field is
/// UNDETECTABLE, because the seal is recomputed over the *parsed struct*
/// (`serde_json::to_value(&body)`), and nothing in this module's types
/// carries `#[serde(deny_unknown_fields)]` — confirmed by reading every
/// file under `aa-cli/src/commands/execution_receipt/` (no occurrence). An
/// unrecognized key is silently dropped by `serde_json::from_str` and never
/// reaches the digest computation at all. This is a real finding to record,
/// not a test to relax: a receipt with an added field the writer never put
/// there still verifies clean.
#[test]
fn f_adding_an_unknown_field_is_undetectable_by_design() {
    let dir = tempfile::tempdir().unwrap();
    let mut json = genuine_envelope_json(&[]);
    json["body"]["an_unknown_field_nobody_wrote"] = serde_json::Value::String("injected".to_string());
    let path = write_envelope_json(dir.path(), "receipt.json", &json);

    let (success, report) = verify_json(&path);
    assert!(
        success,
        "an added unknown field is silently dropped before the digest is recomputed, so this verifies clean \
         (a real, documented-here finding, not a bypass of anything the design claims to catch): {report}"
    );
    assert_eq!(report["seal"], "holds");
}

/// Tamper category 4: truncating the file mid-write must fail to parse.
#[test]
fn f_truncating_the_file_fails_to_parse() {
    let dir = tempfile::tempdir().unwrap();
    let json = genuine_envelope_json(&[]);
    let full = serde_json::to_string(&json).unwrap();
    let truncated = &full[..full.len() / 2];
    let path = dir.path().join("receipt.json");
    std::fs::write(&path, truncated).unwrap();

    let (success, report) = verify_json(&path);
    assert!(!success, "a truncated file must fail to parse: {report}");
    assert_eq!(report["trustworthy"], false);
    assert!(
        report.get("error").is_some(),
        "a truncation must surface as `error`: {report}"
    );
}

/// Tamper category 5: transplant another receipt's digest onto this one.
/// Two independently-built, independently-sealed receipts never share a
/// digest (different `run_id`/`trace_id`/`recorded_at_unix_secs` alone
/// guarantee different canonical bytes), so swapping one's `seal.digest`
/// onto the other's envelope must mismatch.
#[test]
fn f_transplanting_another_receipts_digest_trips_the_seal() {
    let dir = tempfile::tempdir().unwrap();
    let mut json_a = genuine_envelope_json(&[]);
    let json_b = genuine_envelope_json(&[CapabilityDomain::NetworkEgress]);
    assert_ne!(
        json_a["seal"]["digest"], json_b["seal"]["digest"],
        "the two fixtures must genuinely differ for this transplant to mean anything"
    );
    json_a["seal"]["digest"] = json_b["seal"]["digest"].clone();
    let path = write_envelope_json(dir.path(), "receipt.json", &json_a);

    let (success, report) = verify_json(&path);
    assert!(
        !success,
        "a transplanted digest from another receipt must mismatch: {report}"
    );
    assert_eq!(report["seal"], "mismatch");
}

/// The documented non-tamper-proof design point: tamper a sealed section
/// AND recompute the digest to match the tampered content. The seal is a
/// content digest, not a signature (see `mod.rs`'s module documentation and
/// `docs/src/cli/receipt.md`'s "What receipt integrity proves — and does
/// not prove", which already states this accurately — "tamper-evident, not
/// tamper-proof" — so no documentation fix is needed here). This is
/// EXPECTED to verify successfully: the attacker who can rewrite the body
/// can recompute a holding seal over the rewritten content just as easily
/// as `aasm` did, because no key exists anywhere in this design.
#[test]
fn f_tampering_and_recomputing_the_digest_still_verifies_successfully() {
    let dir = tempfile::tempdir().unwrap();
    let mut envelope = sealed(build_body(&[]));
    // A benign content change — not one that trips any `validate::defects`
    // truth-downgrade rule — so the only thing under test is the seal
    // recomputation, not an unrelated validation failure.
    envelope.body.execution.exit_code = Some(envelope.body.execution.exit_code.unwrap_or(0) + 1);
    let recomputed = aa_cli::commands::execution_receipt::canonical::digest_of(&envelope.body)
        .expect("a tampered body built from a real fixture still canonicalizes");
    envelope.seal.digest = recomputed;
    assert!(
        envelope.seal_holds().unwrap(),
        "the reseal must actually match the tampered content for this control to mean anything"
    );
    assert!(
        defects(&envelope).is_empty(),
        "this mutation must not trip an unrelated validation rule, or the test would not isolate the seal"
    );

    let json = serde_json::to_value(&envelope).unwrap();
    let path = write_envelope_json(dir.path(), "receipt.json", &json);

    let (success, report) = verify_json(&path);
    assert!(
        success,
        "a tampered-then-resealed receipt is EXPECTED to verify successfully — the seal is a content \
         digest, not a signature, and recomputing it after tampering is exactly as available to an \
         attacker as it is to `aasm` itself: {report}"
    );
    assert_eq!(report["seal"], "holds");
}
