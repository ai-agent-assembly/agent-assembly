//! CLI integration tests for `aasm topology` (AAASM-1260 / F121 Phase A ST-1).
//!
//! Exercises every `aasm topology <leaf>` subcommand against a live
//! in-process gateway booted via `CliFixture`. For each leaf: happy path,
//! every `--output` format (json / yaml / table), and per-flag toggles.
//!
//! ## Leaf surface (from `aa-cli/src/commands/topology/`)
//!
//! | Leaf | Args | Flags | Output shape |
//! | --- | --- | --- | --- |
//! | overview | — | `--status`, `--show-budget` | nested object (`TopologyOverview`) |
//! | tree | `<agent_id>` | `--max-depth`, `--status`, `--show-budget` | recursive node (`AgentTree`) |
//! | team | `<team_id>` | `--status`, `--show-budget` | nested with inner `members` array (`TeamTopology`) |
//! | lineage | `<agent_id>` | `--show-permissions` | nested with inner `ancestors` array (`AgentLineage`) |
//! | stats | — | — | nested object (`TopologyStats`) |
//!
//! Per-test gateway boot is the established pattern (see AAASM-1066's
//! divergence note: cross-runtime `OnceCell` sharing is unsound because
//! each `#[tokio::test]` drops its runtime — and the spawned server task
//! with it — between tests).

mod common;

use common::cli::CliFixture;
use common::format::{assert_equivalent_objects, parse_json};
use rstest::rstest;

// =============================================================================
// aasm topology overview
// =============================================================================

#[tokio::test(flavor = "multi_thread")]
async fn topology_overview_happy_path_returns_object_with_counts() {
    let fixture = CliFixture::start().await.expect("fixture should start");
    fixture.seed_team_members("alpha", 2);
    fixture.seed_team_members("beta", 1);

    let out = fixture
        .cmd()
        .args(["topology", "overview", "--output", "json"])
        .output()
        .expect("aasm topology overview should execute");
    assert!(
        out.status.success(),
        "should exit 0\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    let v = parse_json(&out.stdout);
    assert_eq!(v["team_count"].as_u64(), Some(2), "team_count should be 2");
    assert_eq!(
        v["total_agent_count"].as_u64(),
        Some(3),
        "total_agent_count should be 3",
    );
}

#[rstest]
#[case::json("json")]
#[case::yaml("yaml")]
#[case::table("table")]
#[tokio::test(flavor = "multi_thread")]
async fn topology_overview_succeeds_for_every_output_format(#[case] fmt: &str) {
    let fixture = CliFixture::start().await.expect("fixture should start");
    fixture.seed_team_members("alpha", 1);

    let out = fixture
        .cmd()
        .args(["topology", "overview", "--output", fmt])
        .output()
        .expect("aasm topology overview should execute");
    assert!(
        out.status.success(),
        "{fmt} should exit 0; stderr:\n{}",
        String::from_utf8_lossy(&out.stderr),
    );
    assert!(!out.stdout.is_empty(), "{fmt} stdout should not be empty");
}

#[tokio::test(flavor = "multi_thread")]
async fn topology_overview_json_and_yaml_are_structurally_equivalent() {
    let fixture = CliFixture::start().await.expect("fixture should start");
    fixture.seed_team_members("alpha", 2);

    let json_out = fixture
        .cmd()
        .args(["topology", "overview", "--output", "json"])
        .output()
        .expect("json call should execute");
    let yaml_out = fixture
        .cmd()
        .args(["topology", "overview", "--output", "yaml"])
        .output()
        .expect("yaml call should execute");
    assert!(json_out.status.success() && yaml_out.status.success());

    assert_equivalent_objects(&json_out.stdout, &yaml_out.stdout);
}

// =============================================================================
// aasm topology tree
// =============================================================================

#[tokio::test(flavor = "multi_thread")]
async fn topology_tree_happy_path_renders_root_and_child() {
    let fixture = CliFixture::start().await.expect("fixture should start");
    let (parent_id, child_id) = fixture.seed_parent_child("alpha");
    let parent_hex = CliFixture::hex_id(&parent_id);
    let child_hex = CliFixture::hex_id(&child_id);

    let out = fixture
        .cmd()
        .args(["topology", "tree", &parent_hex, "--output", "json"])
        .output()
        .expect("aasm topology tree should execute");
    assert!(
        out.status.success(),
        "should exit 0\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    let v = parse_json(&out.stdout);
    assert_eq!(v["id"].as_str(), Some(parent_hex.as_str()));
    let children = v["children"].as_array().expect("children should be array");
    assert_eq!(children.len(), 1, "parent should have one child");
    assert_eq!(children[0]["id"].as_str(), Some(child_hex.as_str()));
}

#[rstest]
#[case::json("json")]
#[case::yaml("yaml")]
#[case::table("table")]
#[tokio::test(flavor = "multi_thread")]
async fn topology_tree_succeeds_for_every_output_format(#[case] fmt: &str) {
    let fixture = CliFixture::start().await.expect("fixture should start");
    let (parent_id, _child_id) = fixture.seed_parent_child("alpha");
    let parent_hex = CliFixture::hex_id(&parent_id);

    let out = fixture
        .cmd()
        .args(["topology", "tree", &parent_hex, "--output", fmt])
        .output()
        .expect("aasm topology tree should execute");
    assert!(
        out.status.success(),
        "{fmt} should exit 0; stderr:\n{}",
        String::from_utf8_lossy(&out.stderr),
    );
    assert!(!out.stdout.is_empty(), "{fmt} stdout should not be empty");
}

#[tokio::test(flavor = "multi_thread")]
async fn topology_tree_max_depth_zero_returns_error() {
    let fixture = CliFixture::start().await.expect("fixture should start");
    let (parent_id, _) = fixture.seed_parent_child("alpha");
    let parent_hex = CliFixture::hex_id(&parent_id);

    let out = fixture
        .cmd()
        .args(["topology", "tree", &parent_hex, "--max-depth", "0"])
        .output()
        .expect("aasm topology tree --max-depth 0 should execute");
    assert!(
        !out.status.success(),
        "--max-depth 0 should fail; stdout:\n{}",
        String::from_utf8_lossy(&out.stdout),
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn topology_tree_missing_agent_id_returns_error() {
    let fixture = CliFixture::start().await.expect("fixture should start");
    let bogus = "ffffffffffffffffffffffffffffffff";

    let out = fixture
        .cmd()
        .args(["topology", "tree", bogus])
        .output()
        .expect("aasm topology tree <bogus> should execute");
    assert!(
        !out.status.success(),
        "unknown agent_id should fail; stdout:\n{}",
        String::from_utf8_lossy(&out.stdout),
    );
}

// =============================================================================
// aasm topology team
// =============================================================================

#[tokio::test(flavor = "multi_thread")]
async fn topology_team_happy_path_returns_members() {
    let fixture = CliFixture::start().await.expect("fixture should start");
    fixture.seed_team_members("alpha", 3);

    let out = fixture
        .cmd()
        .args(["topology", "team", "alpha", "--output", "json"])
        .output()
        .expect("aasm topology team should execute");
    assert!(
        out.status.success(),
        "should exit 0\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    let v = parse_json(&out.stdout);
    assert_eq!(v["team_id"].as_str(), Some("alpha"));
    let members = v["members"].as_array().expect("members should be array");
    assert_eq!(members.len(), 3, "3 seeded members expected");
}

#[rstest]
#[case::json("json")]
#[case::yaml("yaml")]
#[case::table("table")]
#[tokio::test(flavor = "multi_thread")]
async fn topology_team_succeeds_for_every_output_format(#[case] fmt: &str) {
    let fixture = CliFixture::start().await.expect("fixture should start");
    fixture.seed_team_members("alpha", 2);

    let out = fixture
        .cmd()
        .args(["topology", "team", "alpha", "--output", fmt])
        .output()
        .expect("aasm topology team should execute");
    assert!(
        out.status.success(),
        "{fmt} should exit 0; stderr:\n{}",
        String::from_utf8_lossy(&out.stderr),
    );
    assert!(!out.stdout.is_empty(), "{fmt} stdout should not be empty");
}

#[tokio::test(flavor = "multi_thread")]
async fn topology_team_unknown_team_returns_error() {
    let fixture = CliFixture::start().await.expect("fixture should start");

    let out = fixture
        .cmd()
        .args(["topology", "team", "no-such-team"])
        .output()
        .expect("aasm topology team should execute");
    assert!(
        !out.status.success(),
        "unknown team should fail; stdout:\n{}",
        String::from_utf8_lossy(&out.stdout),
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn topology_team_show_budget_flag_does_not_break_output() {
    let fixture = CliFixture::start().await.expect("fixture should start");
    fixture.seed_team_members("alpha", 1);

    let out = fixture
        .cmd()
        .args(["topology", "team", "alpha", "--show-budget", "--output", "json"])
        .output()
        .expect("aasm topology team --show-budget should execute");
    assert!(
        out.status.success(),
        "--show-budget should exit 0; stderr:\n{}",
        String::from_utf8_lossy(&out.stderr),
    );
    let v = parse_json(&out.stdout);
    assert_eq!(v["team_id"].as_str(), Some("alpha"));
}
