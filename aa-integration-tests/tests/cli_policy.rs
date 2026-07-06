//! CLI integration tests for `aasm policy` (AAASM-1261 / F121 Phase A ST-3).
//!
//! Exercises every `aasm policy <leaf>` subcommand against a live in-process
//! gateway booted via `CliFixture`. `list`, `show`, and no-arg `get` hit the
//! gateway via HTTP; `get --version`, `history`, and `simulate` are
//! filesystem-only and read from `AA_DATA_DIR` (defaulting via
//! `HistoryConfig::default_config()`). `CliFixture::cmd()` automatically
//! sets `AA_DATA_DIR` to a per-fixture TempDir so these tests don't
//! pollute `~/.aa/`.
//!
//! ## Leaf surface (from `aa-cli/src/commands/policy/`)
//!
//! | Leaf | Args | Backend | Notes |
//! | --- | --- | --- | --- |
//! | list     | —                                    | GET `/api/v1/policies`                                          | PaginatedResponse |
//! | get      | (none)                                | GET `/api/v1/policies/active`                                   | raw active YAML to stdout |
//! | get      | `--version`                           | filesystem (`AA_DATA_DIR/policy-history`)                       | raw YAML to stdout |
//! | show     | `<agent_id> --show-permissions --show-budget` | GET `/api/v1/policies/agents/{id}/permissions` + `/budget` | `{permissions, budget}` |
//! | history  | `-n / --limit`                        | filesystem (`AA_DATA_DIR/policy-history`)                       | table |
//! | simulate | `--policy --against --live --duration` | filesystem                                                     | `--live` returns "not yet supported" (AAASM-73); `--against` required when `--live=false` |
//!
//! Static YAML fixtures live at `tests/common/fixtures/policies/`.

mod common;

use common::cli::CliFixture;
use rstest::rstest;
use serde_json::Value;

// =============================================================================
// aasm policy list
// =============================================================================

#[tokio::test(flavor = "multi_thread")]
async fn policy_list_empty_registry_prints_helpful_message() {
    let fixture = CliFixture::start().await.expect("fixture should start");

    let out = fixture
        .cmd()
        .args(["policy", "list"])
        .output()
        .expect("aasm policy list should execute");
    assert!(
        out.status.success(),
        "should exit 0\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("No policies found"),
        "empty list should print helpful message; got:\n{stdout}",
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn policy_list_with_seeded_policy_returns_array() {
    let fixture = CliFixture::start().await.expect("fixture should start");
    let yaml =
        std::fs::read_to_string(CliFixture::fixture_path("policies/allow_all.yaml")).expect("read allow_all fixture");
    let _name = fixture.seed_policy(&yaml).await.expect("seed_policy should succeed");

    let out = fixture
        .cmd()
        .args(["policy", "list", "--output", "json"])
        .output()
        .expect("aasm policy list should execute");
    assert!(
        out.status.success(),
        "should exit 0\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    let v: Value = serde_json::from_slice(&out.stdout).expect("stdout is JSON");
    let items = v.as_array().expect("stdout is array");
    assert!(
        !items.is_empty(),
        "list should include seeded policy; got:\n{}",
        String::from_utf8_lossy(&out.stdout),
    );
}

#[rstest]
#[case::json("json")]
#[case::yaml("yaml")]
#[case::table("table")]
#[tokio::test(flavor = "multi_thread")]
async fn policy_list_succeeds_for_every_output_format(#[case] fmt: &str) {
    let fixture = CliFixture::start().await.expect("fixture should start");
    let yaml =
        std::fs::read_to_string(CliFixture::fixture_path("policies/allow_all.yaml")).expect("read allow_all fixture");
    fixture.seed_policy(&yaml).await.expect("seed_policy");

    let out = fixture
        .cmd()
        .args(["policy", "list", "--output", fmt])
        .output()
        .expect("aasm policy list should execute");
    assert!(
        out.status.success(),
        "{fmt} should exit 0; stderr:\n{}",
        String::from_utf8_lossy(&out.stderr),
    );
    assert!(!out.stdout.is_empty(), "{fmt} stdout should not be empty");
}

// =============================================================================
// aasm policy get
// =============================================================================

#[tokio::test(flavor = "multi_thread")]
async fn policy_get_no_version_resolves_active_policy() {
    let fixture = CliFixture::start().await.expect("fixture should start");
    // No-arg `policy get` resolves the currently active policy from the
    // gateway (`GET /api/v1/policies/active`), not the local history store
    // — so a just-applied policy is found instead of "no versions". Seed
    // an active policy first to make the assertion deterministic.
    let yaml =
        std::fs::read_to_string(CliFixture::fixture_path("policies/allow_all.yaml")).expect("read allow_all fixture");
    fixture.seed_policy(&yaml).await.expect("seed_policy");

    let out = fixture
        .cmd()
        .args(["policy", "get"])
        .output()
        .expect("aasm policy get should execute");
    assert!(
        out.status.success(),
        "no-arg get should resolve the active policy and exit 0; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    assert!(
        !out.stdout.is_empty(),
        "no-arg get should print the active policy YAML; stderr:\n{}",
        String::from_utf8_lossy(&out.stderr),
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn policy_get_unknown_version_exits_failure() {
    let fixture = CliFixture::start().await.expect("fixture should start");

    let out = fixture
        .cmd()
        .args(["policy", "get", "--version", "deadbeefcafe"])
        .output()
        .expect("aasm policy get --version should execute");
    assert!(
        !out.status.success(),
        "unknown version should fail; stderr:\n{}",
        String::from_utf8_lossy(&out.stderr),
    );
}

// =============================================================================
// aasm policy show
// =============================================================================

#[tokio::test(flavor = "multi_thread")]
async fn policy_show_with_show_permissions_succeeds() {
    let fixture = CliFixture::start().await.expect("fixture should start");
    let ids = fixture.seed_agents(1);
    let hex = CliFixture::hex_id(&ids[0]);

    let out = fixture
        .cmd()
        .args(["policy", "show", &hex, "--show-permissions", "--output", "json"])
        .output()
        .expect("aasm policy show should execute");
    assert!(
        out.status.success(),
        "should exit 0\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    assert!(!out.stdout.is_empty(), "stdout should not be empty");
}

#[tokio::test(flavor = "multi_thread")]
async fn policy_show_with_show_budget_succeeds() {
    let fixture = CliFixture::start().await.expect("fixture should start");
    let ids = fixture.seed_agents(1);
    let hex = CliFixture::hex_id(&ids[0]);

    let out = fixture
        .cmd()
        .args(["policy", "show", &hex, "--show-budget", "--output", "json"])
        .output()
        .expect("aasm policy show should execute");
    assert!(
        out.status.success(),
        "should exit 0\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn policy_show_with_both_flags_succeeds() {
    let fixture = CliFixture::start().await.expect("fixture should start");
    let ids = fixture.seed_agents(1);
    let hex = CliFixture::hex_id(&ids[0]);

    let out = fixture
        .cmd()
        .args([
            "policy",
            "show",
            &hex,
            "--show-permissions",
            "--show-budget",
            "--output",
            "json",
        ])
        .output()
        .expect("aasm policy show should execute");
    assert!(
        out.status.success(),
        "should exit 0; stderr:\n{}",
        String::from_utf8_lossy(&out.stderr),
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn policy_show_missing_agent_returns_error() {
    let fixture = CliFixture::start().await.expect("fixture should start");
    let bogus = "ffffffffffffffffffffffffffffffff";

    let out = fixture
        .cmd()
        .args(["policy", "show", bogus, "--show-permissions"])
        .output()
        .expect("aasm policy show should execute");
    assert!(
        !out.status.success(),
        "unknown agent should fail; stdout:\n{}",
        String::from_utf8_lossy(&out.stdout),
    );
}

// =============================================================================
// aasm policy history
// =============================================================================

#[tokio::test(flavor = "multi_thread")]
async fn policy_history_with_empty_data_dir_prints_empty_message() {
    let fixture = CliFixture::start().await.expect("fixture should start");
    // AA_DATA_DIR is empty; history should report no versions and exit 0.

    let out = fixture
        .cmd()
        .args(["policy", "history"])
        .output()
        .expect("aasm policy history should execute");
    assert!(
        out.status.success(),
        "empty history should still exit 0; stderr:\n{}",
        String::from_utf8_lossy(&out.stderr),
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("No policy versions"),
        "should print empty-history message; got:\n{stdout}",
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn policy_history_with_explicit_limit_still_runs_cleanly() {
    let fixture = CliFixture::start().await.expect("fixture should start");

    let out = fixture
        .cmd()
        .args(["policy", "history", "--limit", "5"])
        .output()
        .expect("aasm policy history --limit should execute");
    assert!(
        out.status.success(),
        "--limit should be accepted; stderr:\n{}",
        String::from_utf8_lossy(&out.stderr),
    );
}

// =============================================================================
// aasm policy simulate
// =============================================================================

#[tokio::test(flavor = "multi_thread")]
async fn policy_simulate_without_required_policy_flag_returns_error() {
    let fixture = CliFixture::start().await.expect("fixture should start");

    let out = fixture
        .cmd()
        .args(["policy", "simulate"])
        .output()
        .expect("aasm policy simulate should execute");
    assert!(
        !out.status.success(),
        "missing --policy should fail (clap-enforced); stdout:\n{}",
        String::from_utf8_lossy(&out.stdout),
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn policy_simulate_live_mode_returns_not_yet_supported() {
    let fixture = CliFixture::start().await.expect("fixture should start");
    let policy = CliFixture::fixture_path("policies/allow_all.yaml");

    let out = fixture
        .cmd()
        .args(["policy", "simulate", "--policy", policy.to_str().unwrap(), "--live"])
        .output()
        .expect("aasm policy simulate --live should execute");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !out.status.success(),
        "--live should fail; stdout:\n{}\nstderr:\n{stderr}",
        String::from_utf8_lossy(&out.stdout),
    );
    assert!(
        stderr.contains("live simulation is not yet supported"),
        "stderr should explain --live is unimplemented; got:\n{stderr}",
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn policy_simulate_without_against_or_live_returns_error() {
    let fixture = CliFixture::start().await.expect("fixture should start");
    let policy = CliFixture::fixture_path("policies/allow_all.yaml");

    let out = fixture
        .cmd()
        .args(["policy", "simulate", "--policy", policy.to_str().unwrap()])
        .output()
        .expect("aasm policy simulate (no --against) should execute");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !out.status.success(),
        "missing --against (and not --live) should fail; stdout:\n{}\nstderr:\n{stderr}",
        String::from_utf8_lossy(&out.stdout),
    );
    assert!(
        stderr.contains("--against <log-file> is required"),
        "stderr should explain --against is required; got:\n{stderr}",
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn policy_simulate_with_output_file_writes_report() {
    let fixture = CliFixture::start().await.expect("fixture should start");
    let policy = CliFixture::fixture_path("policies/allow_all.yaml");

    // HistoricalReplay::from_file expects JSONL with {event_type, agent_id, payload},
    // where `payload` is a serialized `GovernanceAction`. Use a real ToolCall so
    // the events actually evaluate (allow-all) instead of erroring on an
    // unparseable payload — otherwise the run now fails the errored>0 exit gate.
    let scratch = tempfile::tempdir().expect("scratch tempdir");
    let log_path = scratch.path().join("events.jsonl");
    let payload = serde_json::to_string(&aa_core::GovernanceAction::ToolCall {
        name: "search".to_string(),
        args: "{}".to_string(),
    })
    .expect("serialize governance action");
    let line = |agent: &str| {
        serde_json::to_string(&serde_json::json!({
            "event_type": "ToolCallIntercepted",
            "agent_id": agent,
            "payload": payload,
        }))
        .expect("serialize audit line")
    };
    std::fs::write(&log_path, format!("{}\n{}\n", line("a1"), line("a2"))).expect("write replay log");
    let report_path = scratch.path().join("report.json");

    let out = fixture
        .cmd()
        .args([
            "policy",
            "simulate",
            "--policy",
            policy.to_str().unwrap(),
            "--against",
            log_path.to_str().unwrap(),
            "--output-file",
            report_path.to_str().unwrap(),
        ])
        .output()
        .expect("aasm policy simulate --output-file should execute");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "simulate should succeed for allow-all replay; stdout:\n{}\nstderr:\n{stderr}",
        String::from_utf8_lossy(&out.stdout),
    );
    assert!(
        report_path.exists(),
        "simulate should write report to --output-file at {}",
        report_path.display(),
    );
    let body = std::fs::read_to_string(&report_path).expect("read written report");
    let parsed: Value = serde_json::from_str(&body).expect("report.json should be valid JSON");
    assert_eq!(
        parsed["total_events"], 2,
        "report should account for both replayed events; got:\n{body}",
    );
}
