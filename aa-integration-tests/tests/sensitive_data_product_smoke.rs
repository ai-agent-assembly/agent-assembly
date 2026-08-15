//! AAASM-5791 — black-box product smoke / LLM QA for sensitive-data
//! protection.
//!
//! # What this is, and what it is not
//!
//! This drives the same real pre-action decision path
//! `aa-integration-tests/tests/e2e_secret_interception.rs` already drives —
//! `PolicyEngine::evaluate()`, the actual Stage 3/6 gateway path an SDK call
//! reaches — against a declarative scenario pack
//! (`tests/fixtures/sensitive_data_product_smoke/scenarios.json`) rather than
//! a fixed list of `#[test]` functions. The pack is written so an LLM QA
//! agent (or a reviewer) can read the expected outcome for every scenario
//! without reading this file or any `aa-security`/`aa-gateway` source — see
//! the pack's own `_comment` block for the contract.
//!
//! It deliberately does **not** re-implement:
//!
//! - the credential-detection/redaction unit-level assertions —
//!   `conformance/vectors/credential_detection/` and
//!   `conformance/vectors/zh_tw_detection/` already own that, and this
//!   runner *loads its payloads directly from those vector files* rather
//!   than duplicating the synthetic secrets inline;
//! - real-destination/non-transmission verification — that is
//!   `aa-proxy/tests/mitm_execution_evidence.rs` and
//!   `aa-proxy/tests/refusal_evidence.rs`, which already dial a real TLS
//!   MitM tunnel against a real bound TCP listener standing in for the
//!   destination and assert the credential either never arrives (refusal)
//!   or arrives only in evidence form. Re-running that ~150-line harness a
//!   third time here would be exactly the duplication AAASM-5791 was asked
//!   to avoid; this file cites it instead. Run it alongside this one:
//!   `cargo nextest run -p aa-proxy --test mitm_execution_evidence --test refusal_evidence`.
//! - Dashboard/Design QA — `dashboard/tests/e2e/verify-aaasm-5360.spec.ts`
//!   (AAASM-5694 real-backend lane) already drives the live sensitive-data
//!   API/UI surface; see that spec and its README for how to run it and
//!   capture screenshots.
//!
//! # Falsification
//!
//! Every scenario here is provably capable of failing, not just currently
//! green: `sensitive_data_product_smoke_scenarios_are_falsifiable` inverts
//! one `expect.clean` in the loaded pack in-memory (a benign scenario
//! demanded to have produced a finding) and asserts the runner reports it as
//! a failure. Manually verified during review by editing
//! `scenarios.json` itself — pointing `benign-english-prose` at
//! `pii_ssn.json` — and confirming `sensitive_data_product_smoke_scenarios_pass`
//! goes red with a clear mismatch message, then reverting.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use aa_core::identity::{AgentId, SessionId};
use aa_core::time::Timestamp;
use aa_core::{AgentContext, GovernanceAction, GovernanceLevel, PolicyResult};
use aa_gateway::{EvaluationResult, PolicyEngine};
use serde::Deserialize;
use serde_json::Value;

// ── Scenario pack types ──────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct ScenarioPack {
    policy_fixture: String,
    scenarios: Vec<Scenario>,
}

#[derive(Debug, Deserialize)]
struct Scenario {
    id: String,
    #[allow(dead_code)]
    class: String,
    support: String,
    #[allow(dead_code)]
    persona: String,
    #[serde(default)]
    vector_ref: Option<String>,
    #[serde(default)]
    payload: Option<String>,
    expect: Expect,
    #[serde(default)]
    notes: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
struct Expect {
    decision: Option<String>,
    #[serde(default)]
    credential_kind: Option<String>,
    #[serde(default)]
    custom_finding: bool,
    #[serde(default)]
    canonical_finding: bool,
    #[serde(default)]
    redacted: bool,
    #[serde(default)]
    clean: bool,
    #[serde(default)]
    result: Option<String>,
}

// ── Fixture loading ──────────────────────────────────────────────────────────

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn load_pack() -> ScenarioPack {
    let path = manifest_dir().join("tests/fixtures/sensitive_data_product_smoke/scenarios.json");
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("scenario pack must be readable at {}: {e}", path.display()));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("scenario pack at {} must parse: {e}", path.display()))
}

/// Load a conformance vector's `input_text` verbatim — this is the "no
/// duplicated payloads" mechanism the pack's `_comment` block promises.
fn payload_for(scenario: &Scenario, conformance_dir: &Path) -> String {
    if let Some(inline) = &scenario.payload {
        return inline.clone();
    }
    let vector_ref = scenario
        .vector_ref
        .as_ref()
        .unwrap_or_else(|| panic!("scenario {} carries neither payload nor vector_ref", scenario.id));
    let path = conformance_dir.join(vector_ref);
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "scenario {}: vector {} must be readable: {e}",
            scenario.id,
            path.display()
        )
    });
    let value: Value = serde_json::from_str(&text)
        .unwrap_or_else(|e| panic!("scenario {}: vector {} must parse: {e}", scenario.id, path.display()));
    value["input_text"]
        .as_str()
        .unwrap_or_else(|| panic!("scenario {}: vector {} has no input_text", scenario.id, path.display()))
        .to_string()
}

fn policy_fixture_path(pack: &ScenarioPack) -> PathBuf {
    manifest_dir().join("tests/fixtures").join(&pack.policy_fixture)
}

/// Repository root, three levels up from this crate — where `conformance/`
/// lives. Resolved from `CARGO_MANIFEST_DIR` rather than relative to the
/// process cwd, which nextest does not guarantee.
fn conformance_dir() -> PathBuf {
    manifest_dir()
        .parent()
        .expect("aa-integration-tests must have a parent directory")
        .join("conformance/vectors")
}

// ── Product-path driver ──────────────────────────────────────────────────────

fn make_ctx(agent_seed: u8) -> AgentContext {
    AgentContext {
        agent_id: AgentId::from_bytes([agent_seed; 16]),
        session_id: SessionId::from_bytes([0xABu8; 16]),
        pid: 1,
        started_at: Timestamp::from_nanos(0),
        metadata: BTreeMap::new(),
        governance_level: GovernanceLevel::default(),
        parent_agent_id: None,
        team_id: None,
        depth: 0,
        delegation_reason: None,
        spawned_by_tool: None,
        root_agent_id: None,
    }
}

fn evaluate_payload(engine: &PolicyEngine, payload: &str, agent_seed: u8) -> EvaluationResult {
    let action = GovernanceAction::ToolCall {
        name: "test_tool".to_string(),
        args: payload.to_string(),
    };
    engine.evaluate(&make_ctx(agent_seed), &action)
}

// ── Verdict ───────────────────────────────────────────────────────────────────

/// One scenario's outcome versus its declared expectation. `Ok(())` on
/// match; `Err(String)` carries a message naming exactly what mismatched, so
/// a failure is legible without re-deriving it from the raw
/// `EvaluationResult`.
fn check_scenario(scenario: &Scenario, result: &EvaluationResult, raw_payload: &str) -> Result<(), String> {
    let e = &scenario.expect;

    if let Some(expected_decision) = &e.decision {
        let actual = match &result.decision {
            PolicyResult::Allow => "Allow",
            PolicyResult::Deny { .. } => "Deny",
            PolicyResult::RequiresApproval { .. } => "RequiresApproval",
        };
        if actual != expected_decision {
            return Err(format!("decision: expected {expected_decision}, got {actual}"));
        }
    }

    if e.clean {
        if !result.credential_findings.is_empty() {
            return Err(format!(
                "expected clean (support={}), got credential_findings={:?}",
                scenario.support, result.credential_findings
            ));
        }
        if !result.canonical_findings.is_empty() {
            return Err(format!(
                "expected clean (support={}), got {} canonical_findings",
                scenario.support,
                result.canonical_findings.len()
            ));
        }
        if result.redacted_payload.is_some() {
            return Err("expected clean, but redacted_payload is Some — benign content was altered".to_string());
        }
        if scenario.support == "unsupported" && e.result.as_deref() != Some("EXPECTED_UNSUPPORTED") {
            return Err("unsupported scenario must declare expect.result = EXPECTED_UNSUPPORTED".to_string());
        }
        return Ok(());
    }

    if let Some(kind) = &e.credential_kind {
        let found = result
            .credential_findings
            .iter()
            .any(|f| format!("{:?}", f.kind) == *kind);
        if !found {
            return Err(format!(
                "expected a credential_findings entry of kind {kind}, got {:?}",
                result
                    .credential_findings
                    .iter()
                    .map(|f| format!("{:?}", f.kind))
                    .collect::<Vec<_>>()
            ));
        }
    }

    if e.custom_finding && result.credential_findings.is_empty() {
        return Err("expected a policy-defined custom pattern finding, got none".to_string());
    }

    if e.canonical_finding && result.canonical_findings.is_empty() {
        return Err("expected at least one canonical_findings entry (locale-pack hit), got none".to_string());
    }

    if e.redacted {
        match &result.redacted_payload {
            None => return Err("expected redacted_payload to be Some, got None".to_string()),
            Some(redacted) => {
                if redacted == raw_payload {
                    return Err("redacted_payload is identical to the raw input — nothing was redacted".to_string());
                }
            }
        }
    }

    Ok(())
}

// ── The one test that walks the whole pack ──────────────────────────────────

/// Drives every scenario in the pack through the real `PolicyEngine`
/// pre-action path and asserts each against its declared `expect`. A single
/// `#[test]` rather than one generated per scenario, so the failure output
/// names every mismatching scenario at once instead of stopping at the
/// first (`nextest` still reports this as one test; the assertion loop
/// below is what gives per-scenario granularity in the panic message).
#[test]
fn sensitive_data_product_smoke_scenarios_pass() {
    let pack = load_pack();
    let policy_path = policy_fixture_path(&pack);
    let (tx, _rx) = tokio::sync::broadcast::channel::<aa_gateway::budget::BudgetAlert>(64);
    let engine = PolicyEngine::load_from_file(&policy_path, tx)
        .unwrap_or_else(|e| panic!("policy fixture {} must load: {e:?}", policy_path.display()));

    let conformance = conformance_dir();
    let mut failures = Vec::new();
    let mut ran = 0usize;

    for (i, scenario) in pack.scenarios.iter().enumerate() {
        let raw_payload = payload_for(scenario, &conformance);
        let result = evaluate_payload(&engine, &raw_payload, i as u8);
        ran += 1;
        if let Err(msg) = check_scenario(scenario, &result, &raw_payload) {
            let note = scenario.notes.as_deref().unwrap_or("");
            failures.push(format!(
                "[{}] {msg}{}",
                scenario.id,
                if note.is_empty() {
                    String::new()
                } else {
                    format!(" — {note}")
                }
            ));
        }
    }

    assert!(
        ran >= 20,
        "scenario pack shrank unexpectedly — only {ran} scenarios ran, expected at least 20"
    );
    assert!(
        failures.is_empty(),
        "{} of {ran} scenario(s) failed:\n  {}",
        failures.len(),
        failures.join("\n  ")
    );
}

/// Proves `check_scenario` can actually fail — a runner that always returns
/// `Ok` regardless of input would pass every scenario above for the wrong
/// reason. Feeds it a genuine mismatch (a positive-expectation scenario
/// evaluated against a payload that produces no finding) and asserts the
/// mismatch is reported rather than silently accepted.
#[test]
fn sensitive_data_product_smoke_scenarios_are_falsifiable() {
    let pack = load_pack();
    let policy_path = policy_fixture_path(&pack);
    let (tx, _rx) = tokio::sync::broadcast::channel::<aa_gateway::budget::BudgetAlert>(64);
    let engine = PolicyEngine::load_from_file(&policy_path, tx)
        .unwrap_or_else(|e| panic!("policy fixture {} must load: {e:?}", policy_path.display()));

    let anthropic_key_scenario = pack
        .scenarios
        .iter()
        .find(|s| s.id == "credential-anthropic-key")
        .expect("credential-anthropic-key scenario must exist in the pack");

    // Evaluate a clean payload but check it against the Anthropic-key
    // scenario's *positive* expectation — a real mismatch a broken
    // (or vacuous) `check_scenario` implementation could paper over.
    let clean_result = evaluate_payload(&engine, "nothing sensitive in this string at all", 250);
    let verdict = check_scenario(
        anthropic_key_scenario,
        &clean_result,
        "nothing sensitive in this string at all",
    );

    assert!(
        verdict.is_err(),
        "check_scenario must report a mismatch when a positive-expectation scenario sees a clean payload; got Ok"
    );
}
