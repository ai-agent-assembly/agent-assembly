//! Tests for `aasm receipt inspect`/`list` (AAASM-6172): the Gate A/Gate B
//! refusal split (test set A/B), redaction (test set C), determinism (test
//! set D), and the `workspace.diff_digest` correctness fix (test set E).
//!
//! Fixture helpers (`build_body`, `sealed`, `SYNTHETIC_SECRET`) mirror
//! `receipt_verify.rs` exactly, rather than re-deriving them.
use std::io::Write as _;

use aa_cli::commands::execution_receipt::canonical::Digest;
use aa_cli::commands::execution_receipt::inspect::{inspect_report, list_report, InspectArgs, ListArgs};
use aa_cli::commands::execution_receipt::project::{body_for_run, ReceiptContext, TerminationInput};
use aa_cli::commands::execution_receipt::schema::{
    DegradedCondition, DegradedKind, ReceiptBody, ReceiptEnvelope, WorkspaceBinding, NOT_TRANSACTIONAL,
};
use aa_cli::commands::execution_receipt::store::ReceiptStore;
use aa_cli::commands::execution_receipt::text::{FieldName, ReceiptText};

use aa_core::attestation::ClaimTerm;
use aa_isolation::mock::MockBackend;
use aa_isolation::{
    CapabilityDomain, CredentialPosture, ExecutionSpec, IdentityRef, IsolationBackend, IsolationReport, SessionRef,
};
use aa_policy::resolve::{PolicyResolution, Unconfigured};

/// Synthetic literal matching `aa-core`'s own scanner fixture convention
/// (`aa-core/src/integration/fingerprint.rs`) — never a real credential shape.
const SYNTHETIC_SECRET: &str =
    "sk-ant-api03-AAASM6166SYNTHETICDONOTUSEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

/// Mirrors `receipt_verify.rs::build_body`.
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

fn write_envelope(dir: &std::path::Path, name: &str, envelope: &ReceiptEnvelope) -> std::path::PathBuf {
    let path = dir.join(name);
    let mut file = std::fs::File::create(&path).unwrap();
    file.write_all(serde_json::to_string(envelope).unwrap().as_bytes())
        .unwrap();
    path
}

/// Serializes every test that mutates the process-global `AASM_STATE_DIR`
/// env var (needed because `InspectArgs::run_id` resolves through
/// `ReceiptStore::default_location()`, which reads it) — this test binary
/// runs its `#[test]` functions in parallel threads by default, and an
/// unguarded env var is shared mutable state across all of them.
static ENV_GUARD: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn inspect_args_for_path(path: std::path::PathBuf, json: bool) -> InspectArgs {
    InspectArgs {
        run_id: None,
        path: Some(path),
        json,
        re_evaluate: false,
    }
}

// ---------------------------------------------------------------------------
// A: refuse-to-render.
// ---------------------------------------------------------------------------

#[test]
fn a_missing_run_id_refuses_with_zero_body_fields() {
    let _guard = ENV_GUARD.lock().unwrap();
    let dir = tempfile::tempdir().unwrap();
    // SAFETY: serialized by `ENV_GUARD` against every other env-mutating
    // test in this binary; no other thread reads/writes this var concurrently.
    unsafe { std::env::set_var("AASM_STATE_DIR", dir.path()) };

    let args = InspectArgs {
        run_id: Some("does-not-exist".to_string()),
        path: None,
        json: false,
        re_evaluate: false,
    };
    let (code, output) = inspect_report(&args);
    assert_eq!(code, std::process::ExitCode::FAILURE);
    assert!(output.contains("no stored receipt matches run id"));
    assert!(!output.contains("[identity]"));

    unsafe { std::env::remove_var("AASM_STATE_DIR") };
}

#[test]
fn a_tampered_receipt_refuses_and_omits_the_backend_id() {
    let dir = tempfile::tempdir().unwrap();
    let mut envelope = sealed(build_body(&[CapabilityDomain::FilesystemWrite]));
    // Flip exit_code without recomputing the seal — a byte mutation, same
    // shape as receipt_verify.rs's own seal-mismatch tests.
    envelope.body.execution.exit_code = Some(0);
    let backend_id = envelope
        .body
        .backend
        .as_ref()
        .and_then(|b| b.id.as_str())
        .unwrap()
        .to_string();

    let path = write_envelope(dir.path(), "tampered.json", &envelope);
    let (code, output) = inspect_report(&inspect_args_for_path(path, false));

    assert_eq!(code, std::process::ExitCode::FAILURE);
    assert!(output.contains("seal does not match"));
    assert!(
        !output.contains(&backend_id),
        "a renderer that ignores the seal gate would leak the backend id: {output}"
    );
}

#[test]
fn truncated_json_refuses_as_corrupt_with_no_body() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("truncated.json");
    std::fs::write(&path, b"{\"schema\": \"aasm.ex").unwrap();

    let (code, output) = inspect_report(&inspect_args_for_path(path, false));
    assert_eq!(code, std::process::ExitCode::FAILURE);
    assert!(output.contains("corrupt"));
    assert!(!output.contains("[identity]"));
}

#[test]
fn an_unknown_schema_refuses_with_no_body_even_though_the_seal_holds() {
    let dir = tempfile::tempdir().unwrap();
    let mut envelope = sealed(build_body(&[]));
    // `schema` sits outside the seal digest — mutating it alone must not
    // break the seal, but it must still gate rendering.
    envelope.schema = "some.other.schema/9".to_string();
    let path = write_envelope(dir.path(), "unknown-schema.json", &envelope);

    let (code, output) = inspect_report(&inspect_args_for_path(path, false));
    assert_eq!(code, std::process::ExitCode::FAILURE);
    assert!(output.contains("does not read"));
    assert!(!output.contains("[identity]"));
}

#[test]
fn two_receipts_colliding_on_the_sanitized_run_id_suffix_refuse_naming_both_paths() {
    let _guard = ENV_GUARD.lock().unwrap();
    let dir = tempfile::tempdir().unwrap();
    // SAFETY: see `ENV_GUARD`'s doc comment.
    unsafe { std::env::set_var("AASM_STATE_DIR", dir.path()) };
    let store = ReceiptStore::default_location().unwrap();

    let mut body_a = build_body(&[]);
    body_a.run_id = "run:a".to_string();
    body_a.recorded_at_unix_secs = 1_700_000_000;
    let mut body_b = build_body(&[]);
    // Sanitizes to the identical suffix as "run:a" (':' -> '_').
    body_b.run_id = "run_a".to_string();
    body_b.recorded_at_unix_secs = 1_700_000_001;

    let path_a = store.write(&sealed(body_a)).unwrap();
    let path_b = store.write(&sealed(body_b)).unwrap();

    let args = InspectArgs {
        run_id: Some("run:a".to_string()),
        path: None,
        json: false,
        re_evaluate: false,
    };
    let (code, output) = inspect_report(&args);
    assert_eq!(code, std::process::ExitCode::FAILURE);
    assert!(output.contains(path_a.to_str().unwrap()));
    assert!(output.contains(path_b.to_str().unwrap()));
    assert!(!output.contains("[identity]"));

    unsafe { std::env::remove_var("AASM_STATE_DIR") };
}

// ---------------------------------------------------------------------------
// B: render-with-findings — proves Gate A and Gate B are two different gates.
// ---------------------------------------------------------------------------

#[test]
fn a_resealed_overclaim_renders_the_full_body_and_lists_the_finding() {
    let mut body = build_body(&[CapabilityDomain::FilesystemWrite]);
    let backend_id = body.backend.as_ref().and_then(|b| b.id.as_str()).unwrap().to_string();
    // Hand-raise one domain's claim to a prevention term on setup-only
    // evidence, then reseal — the seal will hold; the body should still
    // render in full, with the defect surfaced.
    body.domains[0].claim = ReceiptText::token(ClaimTerm::DeniedBeforeExecution.as_str());
    body.domains[0].evidence_basis = ReceiptText::token("setup_only");
    let envelope = sealed(body);

    let dir = tempfile::tempdir().unwrap();
    let path = write_envelope(dir.path(), "overclaim.json", &envelope);
    let (code, output) = inspect_report(&inspect_args_for_path(path, false));

    assert_eq!(code, std::process::ExitCode::FAILURE);
    assert!(
        output.contains(&backend_id),
        "Gate B must still render the full body: {output}"
    );
    assert!(
        output.contains("no decision record"),
        "Gate B must surface the PreventionWithoutDecision finding: {output}"
    );
}

// ---------------------------------------------------------------------------
// C: redaction.
// ---------------------------------------------------------------------------

#[test]
fn a_withheld_credential_shaped_field_never_appears_in_text_or_json_output() {
    let mut body = build_body(&[]);
    body.policy.source = Some(ReceiptText::screened(SYNTHETIC_SECRET));
    body.withheld_fields.push(FieldName::PolicySource);
    let envelope = sealed(body);

    let dir = tempfile::tempdir().unwrap();
    let path = write_envelope(dir.path(), "withheld.json", &envelope);

    let (code, text_output) = inspect_report(&inspect_args_for_path(path.clone(), false));
    assert_eq!(code, std::process::ExitCode::SUCCESS);
    assert!(!text_output.contains("AAASM6166SYNTHETIC"));
    assert!(text_output.contains("PolicySource"));

    let (code_json, json_output) = inspect_report(&inspect_args_for_path(path, true));
    assert_eq!(code_json, std::process::ExitCode::SUCCESS);
    assert!(!json_output.contains("AAASM6166SYNTHETIC"));
    // `FieldName` serializes `#[serde(rename_all = "snake_case")]` in JSON
    // (unlike the text renderer's `{:?}` Debug formatting), so the JSON
    // body's `withheld_fields` entry reads `policy_source`, not `PolicySource`.
    assert!(json_output.contains("policy_source"));
}

#[test]
fn falsification_control_a_benign_policy_source_does_appear_in_output() {
    let mut body = build_body(&[]);
    body.policy.source = Some(ReceiptText::screened("/etc/aasm/policy.yaml"));
    let envelope = sealed(body);

    let dir = tempfile::tempdir().unwrap();
    let path = write_envelope(dir.path(), "benign.json", &envelope);
    let (code, output) = inspect_report(&inspect_args_for_path(path, false));

    assert_eq!(code, std::process::ExitCode::SUCCESS);
    assert!(
        output.contains("/etc/aasm/policy.yaml"),
        "without this control, the withheld-field test could pass vacuously: {output}"
    );
}

// ---------------------------------------------------------------------------
// D: determinism.
// ---------------------------------------------------------------------------

#[test]
fn json_inspect_output_is_byte_identical_across_repeated_runs() {
    let envelope = sealed(build_body(&[CapabilityDomain::NetworkEgress]));
    let dir = tempfile::tempdir().unwrap();
    let path = write_envelope(dir.path(), "repeat.json", &envelope);

    let (_, first) = inspect_report(&inspect_args_for_path(path.clone(), true));
    let (_, second) = inspect_report(&inspect_args_for_path(path, true));
    assert_eq!(first, second);
}

#[test]
fn the_underlying_verification_is_identical_across_repeated_runs() {
    use aa_cli::commands::execution_receipt::verify::verify;
    let envelope = sealed(build_body(&[CapabilityDomain::NetworkEgress]));
    assert_eq!(verify(&envelope), verify(&envelope));
}

// ---------------------------------------------------------------------------
// E: workspace.diff_digest correctness.
// ---------------------------------------------------------------------------

#[test]
fn a_discarded_transaction_does_not_present_diff_digest_as_meaningful() {
    let mut body = build_body(&[]);
    // The exact constant: the digest of an empty change set, which is what
    // every non-committed transaction's `diff_digest` carries today.
    let empty_list_digest = Digest::of_canonical("[]");
    body.workspace = Some(WorkspaceBinding {
        committed: Some(false),
        diff_digest: Some(empty_list_digest.clone()),
        not_transactional: NOT_TRANSACTIONAL.iter().copied().map(ReceiptText::token).collect(),
        ..Default::default()
    });
    let envelope = sealed(body);

    let dir = tempfile::tempdir().unwrap();
    let path = write_envelope(dir.path(), "discarded.json", &envelope);
    let (_, text_output) = inspect_report(&inspect_args_for_path(path.clone(), false));
    assert!(
        !text_output.contains(&format!("diff_digest={empty_list_digest}")),
        "the constant digest must never render as an unqualified diff_digest value: {text_output}"
    );
    assert!(text_output.contains("not meaningful"));

    let (_, json_output) = inspect_report(&inspect_args_for_path(path, true));
    assert!(
        !json_output.contains(empty_list_digest.as_str()),
        "the constant digest must not leak into the JSON body either: {json_output}"
    );
    assert!(json_output.contains("not_meaningful"));
}

#[test]
fn a_committed_transaction_renders_all_digests_and_every_not_transactional_token() {
    let mut body = build_body(&[]);
    body.workspace = Some(WorkspaceBinding {
        base_digest: Some(Digest::of_canonical("\"base\"")),
        result_digest: Some(Digest::of_canonical("\"result\"")),
        diff_digest: Some(Digest::of_canonical("[[\"added\",\"src/new.txt\"]]")),
        committed: Some(true),
        added_count: 1,
        not_transactional: NOT_TRANSACTIONAL.iter().copied().map(ReceiptText::token).collect(),
        ..Default::default()
    });
    let envelope = sealed(body);

    let dir = tempfile::tempdir().unwrap();
    let path = write_envelope(dir.path(), "committed.json", &envelope);
    let (code, output) = inspect_report(&inspect_args_for_path(path, false));

    assert_eq!(code, std::process::ExitCode::SUCCESS);
    assert!(output.contains("base_digest=sha256:"));
    assert!(output.contains("result_digest=sha256:"));
    assert!(output.contains("diff_digest=sha256:"));
    for token in NOT_TRANSACTIONAL {
        assert!(
            output.contains(token),
            "inspect output is missing the non-transactional token `{token}`: {output}"
        );
    }
}

// ---------------------------------------------------------------------------
// F: a degraded-condition fixture renders without panicking, plus `list`.
// ---------------------------------------------------------------------------

#[test]
fn degraded_conditions_render_without_panicking() {
    let mut body = build_body(&[]);
    body.degraded.push(DegradedCondition {
        domain: None,
        kind: DegradedKind::FactUnavailable,
        detail: ReceiptText::token("example"),
    });
    let envelope = sealed(body);
    let dir = tempfile::tempdir().unwrap();
    let path = write_envelope(dir.path(), "degraded.json", &envelope);
    let (_, output) = inspect_report(&inspect_args_for_path(path, false));
    assert!(output.contains("[degraded]"));
}

#[test]
fn list_enumerates_without_verifying_and_respects_limit() {
    let _guard = ENV_GUARD.lock().unwrap();
    let dir = tempfile::tempdir().unwrap();
    // SAFETY: see `ENV_GUARD`'s doc comment.
    unsafe { std::env::set_var("AASM_STATE_DIR", dir.path()) };
    let store = ReceiptStore::default_location().unwrap();

    let mut body_a = build_body(&[]);
    body_a.run_id = "run-a".to_string();
    body_a.recorded_at_unix_secs = 1_700_000_000;
    let mut body_b = build_body(&[]);
    body_b.run_id = "run-b".to_string();
    body_b.recorded_at_unix_secs = 1_700_000_050;

    store.write(&sealed(body_a)).unwrap();
    store.write(&sealed(body_b)).unwrap();

    let (code, output) = list_report(&ListArgs {
        json: false,
        limit: None,
    });
    assert_eq!(code, std::process::ExitCode::SUCCESS);
    assert!(output.contains("run-a"));
    assert!(output.contains("run-b"));

    let (_, limited) = list_report(&ListArgs {
        json: false,
        limit: Some(1),
    });
    assert!(limited.contains("run-b"));
    assert!(!limited.contains("run-a"));

    unsafe { std::env::remove_var("AASM_STATE_DIR") };
}

// ---------------------------------------------------------------------------
// CLI surface (also exercised via assert_cmd, mirroring receipt_verify.rs).
// ---------------------------------------------------------------------------

#[test]
fn cli_receipt_inspect_reports_success_for_a_holding_clean_receipt() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("receipt.json");
    let envelope = sealed(build_body(&[]));
    let mut file = std::fs::File::create(&path).unwrap();
    file.write_all(serde_json::to_string(&envelope).unwrap().as_bytes())
        .unwrap();

    let mut cmd = assert_cmd::Command::cargo_bin("aasm").expect("aasm binary");
    cmd.args(["receipt", "inspect", "--path", path.to_str().unwrap()]);
    cmd.assert().success();
}

#[test]
fn cli_receipt_list_reports_success_on_an_empty_store() {
    let dir = tempfile::tempdir().unwrap();
    let mut cmd = assert_cmd::Command::cargo_bin("aasm").expect("aasm binary");
    cmd.env("AASM_STATE_DIR", dir.path());
    cmd.args(["receipt", "list"]);
    cmd.assert().success();
}
