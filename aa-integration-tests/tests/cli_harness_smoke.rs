//! Smoke tests for the CLI integration test harness (AAASM-1449 / F121 ST-0).
//!
//! Proves the shared `CliFixture` infrastructure works end-to-end before
//! Phase A's per-command test files (cli_topology.rs / cli_agent.rs /
//! cli_policy.rs) start consuming it:
//!
//! 1. `CliFixture::start()` boots the in-process gateway.
//! 2. `cmd()` builds a `Command` that successfully invokes `aasm`.
//! 3. `seed_agents()` registers agents that the gateway returns over its
//!    REST + CLI surface.
//! 4. `fixture_path()` resolves to an on-disk fixture under the crate's
//!    `tests/common/fixtures/` tree.

mod common;

use common::cli::CliFixture;

#[tokio::test(flavor = "multi_thread")]
async fn fixture_starts_and_aasm_version_succeeds() {
    let fixture = CliFixture::start().await.expect("CliFixture should start");

    let out = fixture
        .cmd()
        .arg("--version")
        .output()
        .expect("cargo run aasm --version should execute");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);

    assert!(
        out.status.success(),
        "aasm --version should exit 0\nstdout:\n{stdout}\nstderr:\n{stderr}",
    );
    assert!(stdout.contains("aasm"), "stdout should mention aasm\nstdout:\n{stdout}",);
}

#[tokio::test(flavor = "multi_thread")]
async fn seed_agents_registers_agents_visible_to_topology_overview() {
    let fixture = CliFixture::start().await.expect("CliFixture should start");
    let seeded = fixture.seed_agents(3);
    assert_eq!(seeded.len(), 3, "seed_agents(3) should return 3 ids");

    // Each seeded agent should be readable back through the registry.
    for id in &seeded {
        let record = fixture
            .env
            .agent_registry
            .get(id)
            .expect("seeded agent should be in registry");
        assert_eq!(
            record.team_id.as_deref(),
            Some("cli-it"),
            "default team should be cli-it",
        );
    }

    // And reachable through the live HTTP surface via `aasm topology overview`.
    let out = fixture
        .cmd()
        .args(["topology", "overview", "--output", "json"])
        .output()
        .expect("cargo run aasm topology overview should execute");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "aasm topology overview should exit 0\nstdout:\n{stdout}\nstderr:\n{stderr}",
    );

    // Just confirm the output parses as JSON — schema assertions are ST-1's job.
    let _: serde_json::Value =
        serde_json::from_str(&stdout).unwrap_or_else(|e| panic!("stdout should be valid JSON: {e}\nstdout:\n{stdout}"));
}

#[test]
fn fixture_path_resolves_to_existing_fixture_files() {
    for rel in [
        "policies/allow_all.yaml",
        "policies/deny_websearch.yaml",
        "policies/invalid.yaml",
        "audit/chain_valid.jsonl",
        "audit/chain_tampered.jsonl",
        "README.md",
    ] {
        let path = CliFixture::fixture_path(rel);
        assert!(path.exists(), "fixture {rel} should exist at {}", path.display(),);
    }
}

#[test]
fn hex_id_renders_16_byte_array_as_32_char_lowercase_hex() {
    let id = [
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
    ];
    assert_eq!(CliFixture::hex_id(&id), "0123456789abcdeffedcba9876543210");
}
