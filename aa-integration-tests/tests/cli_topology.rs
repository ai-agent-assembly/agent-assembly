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
