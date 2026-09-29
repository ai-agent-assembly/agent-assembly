//! AAASM-1230 / F115 — cross-SDK runtime lifecycle smoke tests.
//!
//! Drives each language SDK's F115 helpers (find/is_running/start/init) via a
//! short subprocess and asserts the binary-in-PATH and binary-not-found
//! contract holds identically across Python, Node, and Go.
//!
//! Tests soft-skip when the sibling SDK repo is absent, the F115 runtime
//! module has not been merged there (AAASM-1227/1228/1229), or the language
//! toolchain is missing. This lets the file compile and pass cleanly even on a
//! stripped-down dev box.
//!
//! AAASM-6224: "pass cleanly" was doing too much work in that sentence. Each
//! guard was a bare `eprintln!` plus `return`, and an early `return` from a
//! `#[test]` fn is a **pass** — so on a machine (or a CI lane) where the
//! precondition was unmet, the test reported success having asserted nothing,
//! and nextest suppressed the `eprintln!` because it only prints captured
//! output for tests that *fail*. The two `node_*` tests below were in exactly
//! that state on every `Integration tests` run, because the lane checked the
//! sibling node-sdk out and never built it. The guards now go through
//! [`common::precondition::require`], which the integration lane arms
//! (`AA_REQUIRE_PRECONDITIONS`) to panic instead — a lane that provisions an
//! artifact has no honest reason to skip a test gated on it — while a
//! developer box keeps the graceful behaviour.
//!
//! Sibling-repo resolution mirrors the established pattern in
//! `e2e_sdk_python.rs` / `e2e_sdk_node.rs` / `e2e_sdk_go.rs`:
//!   * CI sets `PYTHON_SDK_PATH` / `NODE_SDK_PATH` / `GO_SDK_PATH` to the
//!     checkout location (see `project_sibling_repo_ci_pattern` memory).
//!   * Local dev: each SDK is a true sibling of `agent-assembly/`.

#![allow(dead_code)]

mod common;

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Shorthand for the guards below: `Ok(())` when `met`, else `Err(reason())`.
///
/// `reason` is a closure so the (sometimes filesystem-touching) message is
/// only built on the declining path.
fn met_or(met: bool, reason: impl FnOnce() -> String) -> Result<(), String> {
    if met {
        Ok(())
    } else {
        Err(reason())
    }
}

/// Resolve a binary name (e.g. `"go"`) to its absolute path by walking the
/// current process's `PATH`. Needed before any `Command::new(name)` call
/// that also sets `.env("PATH", …)` — on Linux glibc's `posix_spawnp`
/// uses the *child's* envp `PATH` for the binary lookup, so an
/// overridden empty PATH makes the spawn itself fail with `NotFound`
/// even when the parent process can see the binary. Returns `None` when
/// the binary is missing from the parent's `PATH`.
fn resolve_in_path(name: &str) -> Option<PathBuf> {
    let path_env = std::env::var_os("PATH")?;
    std::env::split_paths(&path_env)
        .map(|dir| dir.join(name))
        .find(|candidate| candidate.is_file())
}

/// `<workspace-parent>/agent-assembly/` — derived from `CARGO_MANIFEST_DIR`.
fn agent_assembly_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("aa-integration-tests has a parent")
        .to_path_buf()
}

/// Directory containing all sibling repos (`python-sdk`, `node-sdk`, `go-sdk`).
fn workspace_parent() -> PathBuf {
    agent_assembly_root()
        .parent()
        .expect("agent-assembly has a parent directory")
        .to_path_buf()
}

/// Resolve `<env_key>` → fall back to `<workspace-parent>/<default_name>`.
fn sibling_repo(env_key: &str, default_name: &str) -> PathBuf {
    std::env::var(env_key)
        .map(PathBuf::from)
        .unwrap_or_else(|_| workspace_parent().join(default_name))
}

/// Write a no-op executable named `aasm` inside `dir`. Used to populate a
/// fake-`$PATH` for the binary-in-PATH scenario.
fn make_fake_aasm(dir: &Path) -> PathBuf {
    let path = dir.join("aasm");
    fs::write(&path, "#!/bin/sh\nexit 0\n").expect("write fake aasm");
    let mut perms = fs::metadata(&path).expect("stat fake aasm").permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&path, perms).expect("chmod fake aasm");
    path
}

/// `$PATH` value that is guaranteed not to contain an `aasm` executable.
const EMPTY_PATH_DIR: &str = "/var/empty-AAASM-1230-no-aasm";

// ── Python ────────────────────────────────────────────────────────────────────

fn python_sdk_path() -> PathBuf {
    sibling_repo("PYTHON_SDK_PATH", "python-sdk")
}

/// True when the sibling python-sdk has the AAASM-1227 runtime module.
fn python_runtime_present() -> bool {
    python_sdk_path().join("agent_assembly/runtime.py").exists()
}

#[test]
fn python_binary_in_path_returns_resolved_path() {
    const NAME: &str = "python_binary_in_path_returns_resolved_path";
    if !common::precondition::require(
        NAME,
        met_or(python_runtime_present(), || {
            format!(
                "{} has no agent_assembly/runtime.py (AAASM-1227 likely not yet merged)",
                python_sdk_path().display()
            )
        }),
    ) {
        return;
    }
    let tmp = tempfile::tempdir().expect("create temp dir");
    let fake = make_fake_aasm(tmp.path());
    // No `if !` on the toolchain guards in this file: there is no
    // met-precondition branch to fall through to, because the value being
    // bound is the thing that is missing. Under `AA_REQUIRE_PRECONDITIONS`
    // `require` panics before the `return`; on a developer box it records the
    // decline and returns false, and either way there is nothing to run.
    let Some(py_bin) = resolve_in_path("python3") else {
        common::precondition::require(NAME, Err("`python3` not on $PATH".to_string()));
        return;
    };
    let fake_home = tempfile::tempdir().expect("create fake HOME");
    let out = Command::new(&py_bin)
        .arg("-c")
        .arg(
            "from agent_assembly.runtime import find_aasm_binary; \
             p = find_aasm_binary(); print(p if p else 'NONE')",
        )
        .env("PYTHONPATH", python_sdk_path())
        .env("PATH", tmp.path())
        .env("HOME", fake_home.path())
        .output()
        .expect("spawn python3");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "python probe failed; stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        stdout.trim().ends_with("/aasm"),
        "expected resolved path to end in /aasm, got: {stdout:?}"
    );
    let _ = fake;
}

#[test]
fn python_init_assembly_raises_runtime_error_when_missing() {
    const NAME: &str = "python_init_assembly_raises_runtime_error_when_missing";
    if !common::precondition::require(
        NAME,
        met_or(python_runtime_present(), || {
            format!("{} has no agent_assembly/runtime.py", python_sdk_path().display())
        }),
    ) {
        return;
    }
    let Some(py_bin) = resolve_in_path("python3") else {
        common::precondition::require(NAME, Err("`python3` not on $PATH".to_string()));
        return;
    };
    let fake_home = tempfile::tempdir().expect("create fake HOME");
    let out = Command::new(&py_bin)
        .arg("-c")
        .arg("from agent_assembly.runtime import init_assembly; init_assembly()")
        .env("PYTHONPATH", python_sdk_path())
        .env("PATH", EMPTY_PATH_DIR)
        .env("HOME", fake_home.path())
        .output()
        .expect("spawn python3");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !out.status.success(),
        "expected non-zero exit when binary missing; stderr:\n{stderr}"
    );
    assert!(
        stderr.contains("agent-assembly runtime not found"),
        "INSTALL_HINT missing from stderr:\n{stderr}"
    );
}

// ── Go ────────────────────────────────────────────────────────────────────────

fn go_sdk_path() -> PathBuf {
    sibling_repo("GO_SDK_PATH", "go-sdk")
}

/// True when the sibling go-sdk has the AAASM-1229 runtime file.
fn go_runtime_present() -> bool {
    go_sdk_path().join("assembly/aasm_runtime.go").exists()
}

fn probe_go_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/f115/probe_go")
}

/// Rewrite the fixture's go.mod replace directive to point at the
/// effective sibling go-sdk path. Idempotent — `go mod edit -replace=`
/// overwrites any existing directive for the same module.
fn refresh_go_replace_directive() -> bool {
    let arg = format!(
        "-replace=github.com/ai-agent-assembly/go-sdk={}",
        go_sdk_path().display()
    );
    Command::new("go")
        .args(["mod", "edit", &arg])
        .current_dir(probe_go_dir())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

#[test]
fn go_init_assembly_succeeds_when_binary_in_path() {
    const NAME: &str = "go_init_assembly_succeeds_when_binary_in_path";
    if !common::precondition::require(
        NAME,
        met_or(go_runtime_present(), || {
            format!(
                "{} has no assembly/aasm_runtime.go (AAASM-1229 likely not yet merged)",
                go_sdk_path().display()
            )
        }),
    ) {
        return;
    }
    if !common::precondition::require(
        NAME,
        met_or(Command::new("go").arg("version").output().is_ok(), || {
            "`go` not on $PATH".to_string()
        }),
    ) {
        return;
    }
    // `go mod edit` failing is not a toolchain absence — `go` answered
    // `version` immediately above, and the fixture's go.mod is committed. It is
    // a broken working tree, so a lane that forbids skips should go red on it
    // rather than report a pass.
    if !common::precondition::require(
        NAME,
        met_or(refresh_go_replace_directive(), || {
            format!("`go mod edit -replace` failed in {}", probe_go_dir().display())
        }),
    ) {
        return;
    }
    let tmp = tempfile::tempdir().expect("create temp dir");
    let _fake = make_fake_aasm(tmp.path());
    let Some(go_bin) = resolve_in_path("go") else {
        common::precondition::require(NAME, Err("`go` not on $PATH".to_string()));
        return;
    };
    // Empty-but-writable HOME so `go run .` can populate its build
    // cache (`$HOME/.cache/go-build`) without inheriting aasm-on-PATH
    // via HOME-relative lookups in the spawned probe.
    let fake_home = tempfile::tempdir().expect("create fake HOME");
    let out = Command::new(&go_bin)
        .args(["run", "."])
        .arg("find")
        .current_dir(probe_go_dir())
        .env("PATH", tmp.path())
        .env("HOME", fake_home.path())
        // probe_go is a fixture with a `replace` directive at a local
        // path and no committed go.sum — `-mod=mod` lets `go run`
        // populate the missing go.sum entries on the fly instead of
        // failing with "missing go.sum entry". `GOFLAGS` is inherited
        // by the spawned compile.
        .env("GOFLAGS", "-mod=mod")
        .output()
        .expect("spawn go run");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "go probe failed; stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(stdout.trim() == "FOUND", "expected FOUND, got: {stdout:?}");
}

#[test]
fn go_init_assembly_returns_err_when_missing() {
    const NAME: &str = "go_init_assembly_returns_err_when_missing";
    if !common::precondition::require(
        NAME,
        met_or(go_runtime_present(), || {
            format!("{} has no assembly/aasm_runtime.go", go_sdk_path().display())
        }),
    ) {
        return;
    }
    if !common::precondition::require(
        NAME,
        met_or(Command::new("go").arg("version").output().is_ok(), || {
            "`go` not on $PATH".to_string()
        }),
    ) {
        return;
    }
    if !common::precondition::require(
        NAME,
        met_or(refresh_go_replace_directive(), || {
            format!("`go mod edit -replace` failed in {}", probe_go_dir().display())
        }),
    ) {
        return;
    }
    let Some(go_bin) = resolve_in_path("go") else {
        common::precondition::require(NAME, Err("`go` not on $PATH".to_string()));
        return;
    };
    // Empty-but-writable HOME so `go run .` can populate its build
    // cache (`$HOME/.cache/go-build`) without inheriting aasm-on-PATH
    // via HOME-relative lookups in the spawned probe.
    let fake_home = tempfile::tempdir().expect("create fake HOME");
    let out = Command::new(&go_bin)
        .args(["run", "."])
        .arg("init")
        .current_dir(probe_go_dir())
        .env("PATH", EMPTY_PATH_DIR)
        .env("HOME", fake_home.path())
        // probe_go is a fixture with a `replace` directive at a local
        // path and no committed go.sum — `-mod=mod` lets `go run`
        // populate the missing go.sum entries on the fly instead of
        // failing with "missing go.sum entry". `GOFLAGS` is inherited
        // by the spawned compile.
        .env("GOFLAGS", "-mod=mod")
        .output()
        .expect("spawn go run");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !out.status.success(),
        "expected non-zero exit when binary missing; stderr:\n{stderr}"
    );
    assert!(
        stderr.contains("agent-assembly runtime not found"),
        "InstallHint missing from stderr:\n{stderr}"
    );
}

fn node_sdk_path() -> PathBuf {
    sibling_repo("NODE_SDK_PATH", "node-sdk")
}

/// True when the sibling node-sdk has been built (AAASM-1228 + `pnpm build`).
fn node_runtime_present() -> bool {
    node_sdk_path().join("dist/esm/runtime.js").exists()
}

fn probe_node_fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/f115/probe_node.mjs")
}

#[test]
fn node_binary_in_path_returns_resolved_path() {
    const NAME: &str = "node_binary_in_path_returns_resolved_path";
    // This is one of the two guards AAASM-6224 was filed for: the integration
    // lane checked the sibling node-sdk out and never built it, so
    // `dist/esm/runtime.js` was absent on every run and this test passed here
    // without ever spawning the probe.
    if !common::precondition::require(
        NAME,
        met_or(node_runtime_present(), || {
            format!(
                "{} has no dist/esm/runtime.js (AAASM-1228 not merged or pnpm build not run)",
                node_sdk_path().display()
            )
        }),
    ) {
        return;
    }
    let tmp = tempfile::tempdir().expect("create temp dir");
    let fake = make_fake_aasm(tmp.path());
    let Some(node_bin) = resolve_in_path("node") else {
        common::precondition::require(NAME, Err("`node` not on $PATH".to_string()));
        return;
    };
    let fake_home = tempfile::tempdir().expect("create fake HOME");
    let out = Command::new(&node_bin)
        .arg(probe_node_fixture())
        .arg("find")
        .env("NODE_SDK_PATH", node_sdk_path())
        .env("PATH", tmp.path())
        .env("HOME", fake_home.path())
        .output()
        .expect("spawn node");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "node probe failed; stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        stdout.trim().ends_with("/aasm"),
        "expected resolved path to end in /aasm, got: {stdout:?}"
    );
    let _ = fake;
}

#[test]
fn node_init_assembly_throws_when_missing() {
    const NAME: &str = "node_init_assembly_throws_when_missing";
    if !common::precondition::require(
        NAME,
        met_or(node_runtime_present(), || {
            format!("{} has no dist/esm/runtime.js", node_sdk_path().display())
        }),
    ) {
        return;
    }
    let Some(node_bin) = resolve_in_path("node") else {
        common::precondition::require(NAME, Err("`node` not on $PATH".to_string()));
        return;
    };
    let fake_home = tempfile::tempdir().expect("create fake HOME");
    let out = Command::new(&node_bin)
        .arg(probe_node_fixture())
        .arg("init")
        .env("NODE_SDK_PATH", node_sdk_path())
        .env("PATH", EMPTY_PATH_DIR)
        .env("HOME", fake_home.path())
        // AAASM-3124 (node #153) gated sidecar auto-start behind AA_AUTO_START.
        // Opt in so init exercises the resolve-and-throw path (binary lookup
        // followed by the INSTALL_HINT error) rather than the auto-start-disabled
        // early return, which is what this test asserts.
        .env("AA_AUTO_START", "1")
        .output()
        .expect("spawn node");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !out.status.success(),
        "expected non-zero exit when binary missing; stderr:\n{stderr}"
    );
    assert!(
        stderr.contains("agent-assembly runtime not found"),
        "INSTALL_HINT missing from stderr:\n{stderr}"
    );
}
