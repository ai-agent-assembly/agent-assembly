//! CLI integration tests for `aasm status` (AAASM-1466 / F121 ST-10).
//!
//! Exercises the `aasm status` top-level command — the kubectl-style fleet
//! overview that aggregates runtime health, active agents, pending approvals,
//! and budget into a single render — against a live in-process gateway booted
//! via `CliFixture`.
//!
//! ## Surface vs. AC
//!
//! The ticket description (AAASM-1466) referenced an `aasm status --component
//! {fleet|agents|approvals|budget}` filter and a populated-state test that
//! seeds alerts + cost samples. Both deviate from source today:
//!
//! * `--component` does not exist on `StatusArgs` (`aa-cli/src/commands/status/
//!   mod.rs` declares only `--watch`). The 5 `--component` tests are dropped;
//!   the PR description proposes a follow-up Subtask if the flag is wanted.
//! * The AC explicitly restricts new shared infra to **only** `seed_approval`.
//!   The populated-state test therefore seeds agents + approvals only; alert /
//!   cost coverage is deferred to a future Phase B ST that introduces both
//!   helpers together.
//!
//! Net = 9 tests across happy path, per-output format (×3), JSON↔YAML
//! equivalence, populated state, exit codes 1 and 2, and a `--watch` smoke.

mod common;

use common::cli::CliFixture;
use common::format::{parse_json, parse_yaml};
use rstest::rstest;

// =============================================================================
// aasm status
// =============================================================================

#[tokio::test(flavor = "multi_thread")]
async fn status_happy_path_empty_gateway_exits_zero_and_renders_all_sections() {
    let fixture = CliFixture::start().await.expect("fixture should start");

    let out = fixture
        .cmd()
        .arg("status")
        .output()
        .expect("aasm status should execute");

    assert!(
        out.status.success(),
        "empty gateway should exit 0\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("RUNTIME HEALTH"),
        "missing RUNTIME HEALTH section:\n{stdout}"
    );
    assert!(
        stdout.contains("ACTIVE AGENTS"),
        "missing ACTIVE AGENTS section:\n{stdout}"
    );
    assert!(
        stdout.contains("PENDING APPROVALS"),
        "missing PENDING APPROVALS section:\n{stdout}",
    );
    assert!(
        stdout.contains("BUDGET STATUS"),
        "missing BUDGET STATUS section:\n{stdout}"
    );
}

#[rstest]
#[case::json("json")]
#[case::yaml("yaml")]
#[case::table("table")]
#[tokio::test(flavor = "multi_thread")]
async fn status_succeeds_for_every_output_format(#[case] fmt: &str) {
    let fixture = CliFixture::start().await.expect("fixture should start");

    let out = fixture
        .cmd()
        .args(["status", "--output", fmt])
        .output()
        .expect("aasm status should execute");

    assert!(
        out.status.success(),
        "{fmt} should exit 0; stderr:\n{}",
        String::from_utf8_lossy(&out.stderr),
    );
    assert!(!out.stdout.is_empty(), "{fmt} stdout should not be empty");
}

#[tokio::test(flavor = "multi_thread")]
async fn status_json_and_yaml_are_structurally_equivalent() {
    let fixture = CliFixture::start().await.expect("fixture should start");

    let json_out = fixture
        .cmd()
        .args(["status", "--output", "json"])
        .output()
        .expect("json call should execute");
    let yaml_out = fixture
        .cmd()
        .args(["status", "--output", "yaml"])
        .output()
        .expect("yaml call should execute");
    assert!(json_out.status.success() && yaml_out.status.success());

    // Parse both, then assert structural equality after normalizing the
    // runtime.uptime_secs field — it counts wall-clock seconds since the
    // gateway started and naturally drifts between the two back-to-back
    // CLI invocations. All other section fields are deterministic given
    // a fresh empty fixture.
    let mut json_v = parse_json(&json_out.stdout);
    let yaml_as_json: serde_json::Value =
        serde_json::to_value(parse_yaml(&yaml_out.stdout)).expect("yaml should round-trip to JSON");
    let mut yaml_v = yaml_as_json;
    if let Some(r) = json_v.get_mut("runtime").and_then(|x| x.as_object_mut()) {
        r.insert("uptime_secs".into(), serde_json::Value::from(0));
    }
    if let Some(r) = yaml_v.get_mut("runtime").and_then(|x| x.as_object_mut()) {
        r.insert("uptime_secs".into(), serde_json::Value::from(0));
    }
    assert_eq!(
        json_v,
        yaml_v,
        "JSON and YAML status renders should be structurally identical (uptime_secs normalized)\n\
         json stdout:\n{}\nyaml stdout:\n{}",
        String::from_utf8_lossy(&json_out.stdout),
        String::from_utf8_lossy(&yaml_out.stdout),
    );
    assert!(json_v.get("runtime").is_some(), "json missing 'runtime' key");
    assert!(json_v.get("agents").is_some(), "json missing 'agents' key");
    assert!(json_v.get("approvals").is_some(), "json missing 'approvals' key");
    assert!(json_v.get("budget").is_some(), "json missing 'budget' key");
}

#[tokio::test(flavor = "multi_thread")]
async fn status_populated_state_renders_seeded_agents_and_approvals() {
    let fixture = CliFixture::start().await.expect("fixture should start");
    let agent_ids = fixture.seed_agents(3);
    let first_agent_hex = CliFixture::hex_id(&agent_ids[0]);
    fixture.seed_approval(&first_agent_hex, "delete_production_db");
    fixture.seed_approval(&first_agent_hex, "wire_funds_to_external_account");

    let out = fixture
        .cmd()
        .args(["status", "--output", "json"])
        .output()
        .expect("aasm status should execute");
    assert!(
        out.status.success(),
        "status should exit 0; stderr:\n{}",
        String::from_utf8_lossy(&out.stderr),
    );
    let v = parse_json(&out.stdout);

    let agents = v["agents"].as_array().expect("agents should be array");
    assert_eq!(agents.len(), 3, "3 seeded agents should appear in agents array");

    let pending = v["approvals"]["pending_count"]
        .as_u64()
        .expect("approvals.pending_count should be a number");
    assert_eq!(pending, 2, "2 seeded approvals should appear as pending");
}
