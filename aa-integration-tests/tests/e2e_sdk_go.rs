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

/// Why the driver binary isn't available — distinguished so the causes get
/// different treatment (AAASM-5977). `go` missing from `PATH`, and the
/// go-sdk sibling checkout being absent, are genuine environment
/// preconditions: `ci.yml`'s ordinary `Test` job installs Go but never
/// checks out a go-sdk sibling (only `integration-tests.yml` does, via
/// `GO_SDK_PATH`), so "no go-sdk at the resolved path" is that lane's
/// permanent, honest state, not a defect. Once a go-sdk checkout genuinely
/// exists at the resolved path, `go mod edit`/`go build` failing against it
/// is not a precondition at all — the tool and the dependency are both
/// present and the driver itself is broken, which is a defect regardless of
/// lane, so that case is never a skip.
enum DriverUnavailable {
    ToolAbsent(String),
    BuildBroken(String),
}

/// Compile the Go driver once; cache the outcome.
static DRIVER_BINARY: OnceLock<Result<PathBuf, DriverUnavailable>> = OnceLock::new();

fn go_driver_binary_result() -> &'static Result<PathBuf, DriverUnavailable> {
    DRIVER_BINARY.get_or_init(|| {
        // `go` not on PATH is the one legitimate precondition here.
        if Command::new("go").arg("version").output().is_err() {
            return Err(DriverUnavailable::ToolAbsent("`go` not found on PATH".to_string()));
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

        // A missing sibling checkout is the ordinary state of `ci.yml`'s `Test`
        // job (it never checks out go-sdk) — treat it the same as `go` being
        // absent rather than as a broken driver.
        if !Path::new(&go_sdk_path).is_dir() {
            return Err(DriverUnavailable::ToolAbsent(format!(
                "go-sdk sibling not found at {go_sdk_path}"
            )));
        }

        // AAASM-6218: prepare and build in a private copy, never in the
        // committed fixture.
        //
        // nextest gives every test its own process, so all five of these run
        // `OnceLock::get_or_init` concurrently against the same directory.
        // `go mod edit` rewrites go.mod in place, and two processes doing that
        // at once is `go: go.mod changed during editing; not overwriting` —
        // a window only a few milliseconds wide today, which is why it has
        // never been observed, and which any further `go mod` step here would
        // widen into a reproducible flake. A lock would serialize the five
        // processes; copying removes the shared mutable state instead, so
        // there is nothing to serialize.
        //
        // Two further things fall out of it: the checked-out fixture is no
        // longer rewritten in place (AAASM-6111's fix had to hand-restore the
        // committed relative `replace` path afterwards), and `go.sum` stays
        // byte-stable for `setup-go`'s `cache-dependency-path`.
        let dir = match private_module_copy(&dir) {
            Ok(d) => d,
            Err(reason) => {
                return Err(DriverUnavailable::BuildBroken(format!(
                    "could not stage a private copy of the Go driver module: {reason}"
                )));
            }
        };

        let replace_arg = format!("-replace=github.com/ai-agent-assembly/go-sdk={go_sdk_path}");
        if let Err(stderr) = run_go(&dir, &["mod", "edit", &replace_arg]) {
            return Err(DriverUnavailable::BuildBroken(format!(
                "`go mod edit -replace=...={go_sdk_path}` failed — `go` is present but the driver module is broken\n{stderr}"
            )));
        }

        // Inside the private copy for the same reason (AAASM-6218): a shared
        // output path means one process can rewrite the binary while another
        // is exec'ing it, which surfaces as ETXTBSY rather than as anything
        // that names the cause.
        let binary = dir.join("sdk_go_driver");

        match run_go(&dir, &["build", "-o", binary.to_str().unwrap(), "."]) {
            Ok(()) => Ok(binary),
            Err(stderr) => Err(DriverUnavailable::BuildBroken(format!(
                "`go build` failed — `go` is present but the driver source does not compile.\n{stderr}"
            ))),
        }
    })
}

/// Stage a private, per-process copy of the driver module and return its path.
///
/// AAASM-6218. The copy is keyed on the process id so concurrent nextest test
/// processes cannot collide, and it is removed first so a reused pid cannot
/// inherit a previous run's state.
///
/// The fixture is a flat module (`go.mod`, `go.sum`, `main.go`). A
/// subdirectory appearing here would be a Go package the copy silently
/// dropped, and the build would then fail on a missing symbol with no hint
/// that the cause was the copy — so an unexpected entry is a hard error rather
/// than something to skip.
fn private_module_copy(src: &Path) -> Result<PathBuf, String> {
    let dest = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join("go-e2e-driver")
        .join(format!("module-{}", std::process::id()));

    if dest.exists() {
        std::fs::remove_dir_all(&dest).map_err(|e| format!("removing {}: {e}", dest.display()))?;
    }
    std::fs::create_dir_all(&dest).map_err(|e| format!("creating {}: {e}", dest.display()))?;

    for entry in std::fs::read_dir(src).map_err(|e| format!("reading {}: {e}", src.display()))? {
        let entry = entry.map_err(|e| format!("reading an entry of {}: {e}", src.display()))?;
        let path = entry.path();
        let file_type = entry.file_type().map_err(|e| format!("stat {}: {e}", path.display()))?;
        if !file_type.is_file() {
            return Err(format!(
                "{} is not a regular file. The driver fixture is expected to be a flat Go \
                 module; extend this copy before adding a package there, or the build will \
                 fail on a missing symbol with no sign that the copy dropped it.",
                path.display()
            ));
        }
        std::fs::copy(&path, dest.join(entry.file_name())).map_err(|e| format!("copying {}: {e}", path.display()))?;
    }

    Ok(dest)
}

/// Run one `go` subcommand in `dir`, returning its stderr on failure.
///
/// AAASM-6218: the stderr is the point. This used to discard it and assert a
/// fixed string, so a `go: updates to go.mod needed` module-graph failure was
/// reported as "the driver source does not compile" — which sent the first
/// look straight to `main.go`, twice, in AAASM-6111 and again here. Every
/// failure arm now carries what `go` actually said.
fn run_go(dir: &Path, args: &[&str]) -> Result<(), String> {
    match Command::new("go").args(args).current_dir(dir).output() {
        Ok(out) if out.status.success() => Ok(()),
        Ok(out) => Err(format!(
            "`go {}` exited {}:\n{}{}",
            args.join(" "),
            out.status
                .code()
                .map_or_else(|| "by signal".to_string(), |c| c.to_string()),
            String::from_utf8_lossy(&out.stderr),
            String::from_utf8_lossy(&out.stdout),
        )),
        Err(e) => Err(format!("`go {}` could not be spawned: {e}", args.join(" "))),
    }
}

/// Resolve the driver binary for one test scenario.
///
/// `go` or the go-sdk sibling genuinely absent routes through
/// `common::precondition::require` (graceful skip locally, red under
/// `AA_REQUIRE_PRECONDITIONS`). A broken `go mod edit`/`go build` against a
/// go-sdk that does exist is never a skip — both the tool and the dependency
/// are present and the driver itself is broken, which is a defect in every
/// lane — so that arm panics unconditionally rather than going through
/// `require`.
fn go_driver_binary(scenario: &str) -> Option<&'static Path> {
    match go_driver_binary_result() {
        Ok(bin) => Some(bin.as_path()),
        Err(DriverUnavailable::ToolAbsent(reason)) => {
            // `Err(..)` in, so `require` returns `false` here (or panics under
            // strict mode) — the bool is not otherwise interesting.
            common::precondition::require(scenario, Err(reason.clone()));
            None
        }
        Err(DriverUnavailable::BuildBroken(reason)) => {
            panic!("{scenario}: {reason}");
        }
    }
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
    let Some(bin) = go_driver_binary("e2e_go_sdk_registers_and_emits_events") else {
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
    let Some(bin) = go_driver_binary("e2e_go_sdk_init_with_unreachable_gateway_fails_fast") else {
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
    let Some(bin) = go_driver_binary("e2e_go_sdk_init_with_invalid_team_fails_validation") else {
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
    let Some(bin) = go_driver_binary("e2e_go_sdk_panic_still_deregisters") else {
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
    let Some(bin) = go_driver_binary("e2e_go_sdk_goroutine_concurrent_agents_register") else {
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
