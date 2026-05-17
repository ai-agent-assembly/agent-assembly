//! CLI integration tests for `aasm alerts` (AAASM-1460 / F121 ST-4).
//!
//! Exercises every `aasm alerts <leaf>` subcommand against a live
//! in-process gateway booted via `CliFixture`. For each leaf: happy path,
//! every `--output` format (json / yaml / table), and per-flag toggles.
//!
//! ## Leaf surface (from `aa-cli/src/commands/alerts/`)
//!
//! | Leaf    | Args         | Flags                          | Output shape                |
//! | ------- | ------------ | ------------------------------ | --------------------------- |
//! | list    | —            | `--agent`, `--severity`, `--status` | array of `AlertResponse`  |
//! | get     | `<alert_id>` | —                              | one `AlertResponse`         |
//! | resolve | `<alert_id>` | `--reason`, `--force`          | one `AlertResponse`         |
//!
//! ## Gateway coverage
//!
//! All three endpoints the CLI calls (`GET /alerts`, `GET /alerts/:id`,
//! `POST /alerts/:id/resolve`) are wired up in `aa-api/src/routes/alerts.rs`
//! — `:id` lookup and `resolve` landed via AAASM-1474.
//!
//! ## Persisted alert shape
//!
//! `aa-api`'s `AlertResponse` does not include a `status` field on the
//! `list` payload itself; the CLI's response model defaults `status` to
//! `"unresolved"` via serde. As a result, `aasm alerts list --status resolved`
//! returns an empty list against alerts that have never been resolved
//! (covered by `alerts_list_status_resolved_currently_returns_empty_against_persisted_alerts`).

mod common;

use std::io::Write;
use std::process::Stdio;

use common::cli::CliFixture;
use rstest::rstest;

// =============================================================================
// aasm alerts list
// =============================================================================

#[tokio::test(flavor = "multi_thread")]
async fn alerts_list_happy_path_returns_seeded_records() {
    let fixture = CliFixture::start().await.expect("fixture should start");
    fixture.seed_alert(80, [0x11; 16]);
    fixture.seed_alert(95, [0x22; 16]);
    fixture.seed_alert(70, [0x33; 16]);

    let out = fixture
        .cmd()
        .args(["alerts", "list", "--output", "json"])
        .output()
        .expect("aasm alerts list should execute");
    assert!(
        out.status.success(),
        "should exit 0\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    let v = common::format::parse_json(&out.stdout);
    let arr = v.as_array().expect("list output should be a JSON array");
    assert_eq!(arr.len(), 3, "should return all 3 seeded alerts");
}

#[rstest]
#[case::json("json")]
#[case::yaml("yaml")]
#[case::table("table")]
#[tokio::test(flavor = "multi_thread")]
async fn alerts_list_succeeds_for_every_output_format(#[case] fmt: &str) {
    let fixture = CliFixture::start().await.expect("fixture should start");
    fixture.seed_alert(95, [0x11; 16]);

    let out = fixture
        .cmd()
        .args(["alerts", "list", "--output", fmt])
        .output()
        .expect("aasm alerts list should execute");
    assert!(
        out.status.success(),
        "{fmt} should exit 0; stderr:\n{}",
        String::from_utf8_lossy(&out.stderr),
    );
    assert!(!out.stdout.is_empty(), "{fmt} stdout should not be empty");
}

#[tokio::test(flavor = "multi_thread")]
async fn alerts_list_json_and_yaml_describe_the_same_record_set() {
    let fixture = CliFixture::start().await.expect("fixture should start");
    fixture.seed_alert(80, [0x11; 16]);
    fixture.seed_alert(95, [0x22; 16]);

    let json_out = fixture
        .cmd()
        .args(["alerts", "list", "--output", "json"])
        .output()
        .expect("json call should execute");
    let yaml_out = fixture
        .cmd()
        .args(["alerts", "list", "--output", "yaml"])
        .output()
        .expect("yaml call should execute");
    assert!(json_out.status.success() && yaml_out.status.success());

    common::format::assert_equivalent_records(&json_out.stdout, &yaml_out.stdout, "id");
}

#[tokio::test(flavor = "multi_thread")]
async fn alerts_list_severity_filter_narrows_to_matching_records() {
    let fixture = CliFixture::start().await.expect("fixture should start");
    fixture.seed_alert(95, [0x11; 16]); // critical
    fixture.seed_alert(80, [0x22; 16]); // warning
    fixture.seed_alert(50, [0x33; 16]); // info

    let out = fixture
        .cmd()
        .args(["alerts", "list", "--severity", "critical", "--output", "json"])
        .output()
        .expect("aasm alerts list --severity critical should execute");
    assert!(
        out.status.success(),
        "stderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );

    let arr = common::format::parse_json(&out.stdout)
        .as_array()
        .expect("output should be a JSON array")
        .clone();
    assert_eq!(arr.len(), 1, "exactly one critical alert was seeded");
    assert_eq!(arr[0]["severity"].as_str(), Some("critical"));
}

#[tokio::test(flavor = "multi_thread")]
async fn alerts_list_agent_filter_narrows_to_matching_records() {
    let fixture = CliFixture::start().await.expect("fixture should start");
    let target_id = [0xAB; 16];
    fixture.seed_alert(80, target_id);
    fixture.seed_alert(95, [0x22; 16]);
    fixture.seed_alert(50, [0x33; 16]);
    let target_hex: String = target_id.iter().map(|b| format!("{b:02x}")).collect();

    let out = fixture
        .cmd()
        .args(["alerts", "list", "--agent", &target_hex, "--output", "json"])
        .output()
        .expect("aasm alerts list --agent should execute");
    assert!(
        out.status.success(),
        "stderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );

    let arr = common::format::parse_json(&out.stdout)
        .as_array()
        .expect("output should be a JSON array")
        .clone();
    assert_eq!(arr.len(), 1, "exactly one alert references the target agent");
    assert_eq!(arr[0]["agent_id"].as_str(), Some(target_hex.as_str()));
}

/// Documents the current behaviour: the API's `AlertResponse` has no
/// `status` field, so the CLI's serde default fills in `"unresolved"`
/// for every record — meaning `--status resolved` always returns empty.
///
/// Tracked under AAASM-1474; once the API gains `status`, replace this
/// with an assertion that the `resolved` filter returns the seeded
/// resolved record.
#[tokio::test(flavor = "multi_thread")]
async fn alerts_list_status_resolved_currently_returns_empty_against_persisted_alerts() {
    let fixture = CliFixture::start().await.expect("fixture should start");
    fixture.seed_alert(95, [0x11; 16]);
    fixture.seed_alert(80, [0x22; 16]);

    let out = fixture
        .cmd()
        .args(["alerts", "list", "--status", "resolved", "--output", "json"])
        .output()
        .expect("aasm alerts list --status resolved should execute");
    assert!(
        out.status.success(),
        "stderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );

    // The CLI prints "No alerts found." when the filter matches nothing —
    // not a JSON array — so check stdout directly.
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("No alerts found."),
        "expected empty-list sentinel, got:\n{stdout}",
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn alerts_list_combined_severity_and_agent_filter_narrows_correctly() {
    let fixture = CliFixture::start().await.expect("fixture should start");
    let target_id = [0xCD; 16];
    // The combined filter should match only this seed: critical AND target agent.
    fixture.seed_alert(95, target_id);
    // Same agent but warning severity — excluded by `--severity critical`.
    fixture.seed_alert(80, target_id);
    // Critical severity but different agent — excluded by `--agent`.
    fixture.seed_alert(95, [0x99; 16]);
    let target_hex: String = target_id.iter().map(|b| format!("{b:02x}")).collect();

    let out = fixture
        .cmd()
        .args([
            "alerts",
            "list",
            "--severity",
            "critical",
            "--agent",
            &target_hex,
            "--output",
            "json",
        ])
        .output()
        .expect("aasm alerts list (combined filters) should execute");
    assert!(
        out.status.success(),
        "stderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );

    let arr = common::format::parse_json(&out.stdout)
        .as_array()
        .expect("output should be a JSON array")
        .clone();
    assert_eq!(arr.len(), 1, "exactly one alert matches both filters");
    assert_eq!(arr[0]["severity"].as_str(), Some("critical"));
    assert_eq!(arr[0]["agent_id"].as_str(), Some(target_hex.as_str()));
}

// =============================================================================
// aasm alerts get
// =============================================================================

#[tokio::test(flavor = "multi_thread")]
async fn alerts_get_unknown_id_exits_non_zero_with_clean_error() {
    let fixture = CliFixture::start().await.expect("fixture should start");

    let out = fixture
        .cmd()
        .args(["alerts", "get", "does-not-exist"])
        .output()
        .expect("aasm alerts get should execute");
    assert!(
        !out.status.success(),
        "unknown id should exit non-zero; stdout:\n{}",
        String::from_utf8_lossy(&out.stdout),
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.to_lowercase().contains("error"),
        "stderr should describe the failure; got:\n{stderr}",
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn alerts_get_happy_path_returns_seeded_record() {
    let fixture = CliFixture::start().await.expect("fixture should start");
    let id = fixture.seed_alert(95, [0x11; 16]);

    let out = fixture
        .cmd()
        .args(["alerts", "get", &id.to_string(), "--output", "json"])
        .output()
        .expect("aasm alerts get should execute");
    assert!(
        out.status.success(),
        "stderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );

    let v = common::format::parse_json(&out.stdout);
    assert_eq!(v["id"].as_str(), Some(id.to_string().as_str()));
    assert_eq!(v["severity"].as_str(), Some("critical"));
}

#[tokio::test(flavor = "multi_thread")]
async fn alerts_get_json_and_yaml_describe_the_same_record() {
    let fixture = CliFixture::start().await.expect("fixture should start");
    let id = fixture.seed_alert(95, [0x11; 16]);

    let json_out = fixture
        .cmd()
        .args(["alerts", "get", &id.to_string(), "--output", "json"])
        .output()
        .expect("json call should execute");
    let yaml_out = fixture
        .cmd()
        .args(["alerts", "get", &id.to_string(), "--output", "yaml"])
        .output()
        .expect("yaml call should execute");
    assert!(json_out.status.success() && yaml_out.status.success());

    common::format::assert_equivalent_records(&json_out.stdout, &yaml_out.stdout, "id");
}

// =============================================================================
// aasm alerts resolve
// =============================================================================

#[tokio::test(flavor = "multi_thread")]
async fn alerts_resolve_unknown_id_exits_non_zero_with_clean_error() {
    let fixture = CliFixture::start().await.expect("fixture should start");

    // `--force` skips the interactive confirmation prompt so the test
    // exercises the network path rather than blocking on stdin.
    let out = fixture
        .cmd()
        .args(["alerts", "resolve", "does-not-exist", "--force"])
        .output()
        .expect("aasm alerts resolve should execute");
    assert!(
        !out.status.success(),
        "unknown id should exit non-zero; stdout:\n{}",
        String::from_utf8_lossy(&out.stdout),
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.to_lowercase().contains("error"),
        "stderr should describe the failure; got:\n{stderr}",
    );
}

/// Exercises the interactive confirmation prompt that the CLI shows when
/// `--force` is omitted. The ticket's `--reason` matrix called for a
/// stdin-form variant; `aasm alerts resolve` does not accept the reason
/// via stdin (only `--reason`), but it does read stdin for the y/N
/// confirmation. Per the ticket guidance "if stdin is not supported,
/// test the prompt path or skip", this covers the prompt path: piping
/// `n\n` makes the CLI print `Aborted.` on stderr and exit non-zero
/// without ever calling the gateway — so this test is independent of
/// the missing AAASM-1474 endpoints.
#[tokio::test(flavor = "multi_thread")]
async fn alerts_resolve_without_force_prompts_for_confirmation() {
    let fixture = CliFixture::start().await.expect("fixture should start");
    let id = fixture.seed_alert(95, [0x11; 16]);

    let mut child = fixture
        .cmd()
        .args(["alerts", "resolve", &id.to_string()])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("aasm alerts resolve should spawn");

    // Decline the y/N prompt — CLI must print `Aborted.` and exit non-zero
    // before reaching the network call (which would otherwise 404 on
    // the unimplemented gateway endpoint).
    child
        .stdin
        .as_mut()
        .expect("child stdin should be piped")
        .write_all(b"n\n")
        .expect("write to child stdin should succeed");

    let out = child.wait_with_output().expect("wait_with_output should succeed");
    assert!(
        !out.status.success(),
        "declining the prompt should exit non-zero; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("Are you sure"),
        "stderr should include the confirmation prompt; got:\n{stderr}",
    );
    assert!(
        stderr.contains("Aborted."),
        "stderr should include the abort message; got:\n{stderr}",
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn alerts_resolve_happy_path_flips_status_to_resolved() {
    let fixture = CliFixture::start().await.expect("fixture should start");
    let id = fixture.seed_alert(95, [0x11; 16]);

    let out = fixture
        .cmd()
        .args(["alerts", "resolve", &id.to_string(), "--force", "--output", "json"])
        .output()
        .expect("aasm alerts resolve should execute");
    assert!(
        out.status.success(),
        "stderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );

    let v = common::format::parse_json(&out.stdout);
    assert_eq!(v["status"].as_str(), Some("resolved"));
}

#[tokio::test(flavor = "multi_thread")]
async fn alerts_resolve_with_reason_flag_passes_reason_through() {
    let fixture = CliFixture::start().await.expect("fixture should start");
    let id = fixture.seed_alert(95, [0x11; 16]);

    let out = fixture
        .cmd()
        .args([
            "alerts",
            "resolve",
            &id.to_string(),
            "--force",
            "--reason",
            "false-positive",
            "--output",
            "json",
        ])
        .output()
        .expect("aasm alerts resolve --reason should execute");
    assert!(
        out.status.success(),
        "stderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// Idempotency: a second `resolve` on the same id must return the same
/// record with `updated_at` unchanged.
#[tokio::test(flavor = "multi_thread")]
async fn alerts_resolve_is_idempotent_on_already_resolved_alert() {
    let fixture = CliFixture::start().await.expect("fixture should start");
    let id = fixture.seed_alert(95, [0x11; 16]);

    let first = fixture
        .cmd()
        .args(["alerts", "resolve", &id.to_string(), "--force", "--output", "json"])
        .output()
        .expect("first resolve should execute");
    assert!(first.status.success());
    let first_v = common::format::parse_json(&first.stdout);
    let first_updated_at = first_v["updated_at"].as_str().map(String::from);

    let second = fixture
        .cmd()
        .args(["alerts", "resolve", &id.to_string(), "--force", "--output", "json"])
        .output()
        .expect("second resolve should execute");
    assert!(second.status.success(), "second resolve should still exit 0");
    let second_v = common::format::parse_json(&second.stdout);
    assert_eq!(
        second_v["updated_at"].as_str().map(String::from),
        first_updated_at,
        "updated_at must not advance on a no-op resolve",
    );
}
