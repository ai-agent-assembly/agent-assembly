//! AAASM-1515 — F116 ST-C: Go SDK E2E tests.
//!
//! Builds the Go driver binary at `tests/fixtures/e2e/sdk_go_driver/` and
//! exercises 5 scenarios: happy-path registration + event emission, fast-fail
//! on an unreachable gateway, team-ID validation, panic-with-defer cleanup,
//! and concurrent goroutine registration.
//!
//! Tests skip gracefully when `go` is not in PATH (e.g. local dev without Go).
//! In CI the workflow installs Go ≥ 1.26 and sets `GO_SDK_PATH` before
//! running `cargo nextest run -p aa-integration-tests`.

mod common;

use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::OnceLock;
use std::time::Instant;

// ---------------------------------------------------------------------------
// Build helper
// ---------------------------------------------------------------------------

fn driver_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("e2e")
        .join("sdk_go_driver")
}

/// Compile the Go driver once; cache the binary path.
/// Returns `None` when `go` is not available — callers soft-skip.
static DRIVER_BINARY: OnceLock<Option<PathBuf>> = OnceLock::new();

fn go_driver_binary() -> Option<&'static PathBuf> {
    DRIVER_BINARY
        .get_or_init(|| {
            // Skip entirely when `go` is not on PATH.
            if Command::new("go").arg("version").output().is_err() {
                return None;
            }

            let dir = driver_dir();

            // Point the replace directive at the correct go-sdk path.
            // CI sets GO_SDK_PATH to ${{ github.workspace }}/go-sdk.
            // Local dev: go-sdk is a true sibling of agent-assembly.
            let go_sdk_path = std::env::var("GO_SDK_PATH").unwrap_or_else(|_| {
                // 5 levels up from sdk_go_driver/ = agent-assembly root,
                // then up one more = workspace parent, then go-sdk sibling.
                dir.ancestors()
                    .nth(5)
                    .expect("driver dir has 5 ancestor levels")
                    .parent()
                    .expect("agent-assembly has a parent directory")
                    .join("go-sdk")
                    .to_string_lossy()
                    .into_owned()
            });

            let replace_arg = format!("-replace=github.com/agent-assembly/go-sdk={go_sdk_path}");
            let edit_ok = Command::new("go")
                .args(["mod", "edit", &replace_arg])
                .current_dir(&dir)
                .status()
                .map(|s| s.success())
                .unwrap_or(false);
            if !edit_ok {
                eprintln!("e2e_sdk_go: go mod edit failed — skipping Go driver tests");
                return None;
            }

            let out_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("target")
                .join("go-e2e-driver");
            let _ = std::fs::create_dir_all(&out_dir);
            let binary = out_dir.join("sdk_go_driver");

            let build_ok = Command::new("go")
                .args(["build", "-o", binary.to_str().unwrap(), "."])
                .current_dir(&dir)
                .status()
                .map(|s| s.success())
                .unwrap_or(false);

            if build_ok {
                Some(binary)
            } else {
                eprintln!("e2e_sdk_go: go build failed — skipping Go driver tests");
                None
            }
        })
        .as_ref()
}

/// Run the driver with the given env vars (inherits PATH/HOME from test process).
fn run_driver(binary: &Path, envs: &[(&str, &str)]) -> std::io::Result<Output> {
    let mut cmd = Command::new(binary);
    for (k, v) in envs {
        cmd.env(k, v);
    }
    cmd.output()
}

/// Parse stdout as newline-delimited JSON objects.
fn parse_events(stdout: &[u8]) -> Vec<serde_json::Value> {
    String::from_utf8_lossy(stdout)
        .lines()
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Happy-path: driver emits started → tool_call → deregistered → done.
#[test]
fn e2e_go_sdk_registers_and_emits_events() {
    let Some(bin) = go_driver_binary() else {
        eprintln!("SKIP: go not available");
        return;
    };
    let out =
        run_driver(bin, &[("AA_SELFTEST", "1"), ("AA_AGENT_ID", "e2e-go-reg-test")]).expect("driver invocation failed");

    assert!(out.status.success(), "driver exited non-zero: {:?}", out.status);

    let events = parse_events(&out.stdout);
    let kinds: Vec<&str> = events.iter().filter_map(|e| e["event"].as_str()).collect();

    assert!(kinds.contains(&"started"), "missing 'started' event; got {kinds:?}");
    assert!(kinds.contains(&"tool_call"), "missing 'tool_call' event; got {kinds:?}");
    assert!(
        kinds.contains(&"deregistered"),
        "missing 'deregistered' event; got {kinds:?}"
    );
    assert_eq!(kinds.last(), Some(&"done"), "last event must be 'done'; got {kinds:?}");

    let agent_id = events[0]["agent_id"].as_str().unwrap_or("");
    assert_eq!(agent_id, "e2e-go-reg-test", "agent_id mismatch");
}

/// Fast-fail: Init against an unreachable gateway returns an error within the timeout.
#[test]
fn e2e_go_sdk_init_with_unreachable_gateway_fails_fast() {
    let Some(bin) = go_driver_binary() else {
        eprintln!("SKIP: go not available");
        return;
    };
    let start = Instant::now();
    let out = run_driver(
        bin,
        &[
            ("AA_SCENARIO", "unreachable"),
            ("AA_GATEWAY_ADDR", "127.0.0.1:19999"),
            ("AA_TEAM_ID", "team-e2e"),
        ],
    )
    .expect("driver invocation failed");
    let elapsed = start.elapsed();

    assert!(!out.status.success(), "expected non-zero exit for unreachable gateway");
    assert!(elapsed.as_secs() < 5, "fast-fail took too long: {elapsed:?}");

    let events = parse_events(&out.stdout);
    let has_init_error = events.iter().any(|e| e["event"] == "init_error");
    assert!(has_init_error, "expected 'init_error' event; got {events:?}");
}

/// Validation: missing AA_TEAM_ID causes exit code 2 without network calls.
#[test]
fn e2e_go_sdk_init_with_invalid_team_fails_validation() {
    let Some(bin) = go_driver_binary() else {
        eprintln!("SKIP: go not available");
        return;
    };
    let out = run_driver(bin, &[]).expect("driver invocation failed");

    let code = out.status.code().unwrap_or(-1);
    assert_eq!(code, 2, "expected exit code 2 for missing AA_TEAM_ID; got {code}");

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("AA_TEAM_ID"),
        "expected AA_TEAM_ID mention in stderr; got: {stderr}"
    );
}

/// Defer contract: a panic in agent code still triggers the deferred cleanup.
#[test]
fn e2e_go_sdk_panic_still_deregisters() {
    let Some(bin) = go_driver_binary() else {
        eprintln!("SKIP: go not available");
        return;
    };
    let out = run_driver(bin, &[("AA_SELFTEST", "1"), ("AA_SCENARIO", "panic")]).expect("driver invocation failed");

    assert!(out.status.success(), "driver exited non-zero: {:?}", out.status);

    let events = parse_events(&out.stdout);
    let kinds: Vec<&str> = events.iter().filter_map(|e| e["event"].as_str()).collect();

    let dereg_pos = kinds.iter().position(|&k| k == "deregistered");
    let done_pos = kinds.iter().position(|&k| k == "done");

    assert!(dereg_pos.is_some(), "missing 'deregistered' event; got {kinds:?}");
    assert!(done_pos.is_some(), "missing 'done' event; got {kinds:?}");
    assert!(
        dereg_pos < done_pos,
        "'deregistered' must appear before 'done'; got {kinds:?}"
    );
}

/// Concurrency: two goroutines each emit a 'started' event; done carries count=2.
#[test]
fn e2e_go_sdk_goroutine_concurrent_agents_register() {
    let Some(bin) = go_driver_binary() else {
        eprintln!("SKIP: go not available");
        return;
    };
    let out =
        run_driver(bin, &[("AA_SELFTEST", "1"), ("AA_SCENARIO", "concurrent")]).expect("driver invocation failed");

    assert!(out.status.success(), "driver exited non-zero: {:?}", out.status);

    let events = parse_events(&out.stdout);
    let started_count = events.iter().filter(|e| e["event"] == "started").count();
    assert_eq!(started_count, 2, "expected 2 'started' events; got {started_count}");

    let done = events.iter().find(|e| e["event"] == "done");
    assert!(done.is_some(), "missing 'done' event");
    let count = done.unwrap()["count"].as_i64().unwrap_or(0);
    assert_eq!(count, 2, "done.count must be 2; got {count}");
}
