//! AAASM-1230 / F115 — cross-SDK runtime lifecycle smoke tests.
//!
//! Drives each language SDK's F115 helpers (find/is_running/start/init) via a
//! short subprocess and asserts the binary-in-PATH and binary-not-found
//! contract holds identically across Python, Node, and Go.
//!
//! Tests **soft-skip** with an `eprintln!` (and `return`) when the sibling
//! SDK repo is absent, the F115 runtime module has not been merged there
//! (AAASM-1227/1228/1229), or the language toolchain is missing. This lets
//! the file compile and pass cleanly even on a stripped-down dev box.
//!
//! Sibling-repo resolution mirrors the established pattern in
//! `e2e_sdk_python.rs` / `e2e_sdk_node.rs` / `e2e_sdk_go.rs`:
//!   * CI sets `PYTHON_SDK_PATH` / `NODE_SDK_PATH` / `GO_SDK_PATH` to the
//!     checkout location (see `project_sibling_repo_ci_pattern` memory).
//!   * Local dev: each SDK is a true sibling of `agent-assembly/`.

#![allow(dead_code)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

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
    if !python_runtime_present() {
        eprintln!(
            "skip python_binary_in_path: {} has no agent_assembly/runtime.py \
             (AAASM-1227 likely not yet merged)",
            python_sdk_path().display()
        );
        return;
    }
    let tmp = tempfile::tempdir().expect("create temp dir");
    let fake = make_fake_aasm(tmp.path());
    let out = Command::new("python3")
        .arg("-c")
        .arg(
            "from agent_assembly.runtime import find_aasm_binary; \
             p = find_aasm_binary(); print(p if p else 'NONE')",
        )
        .env("PYTHONPATH", python_sdk_path())
        .env("PATH", tmp.path())
        .env("HOME", "/var/empty-AAASM-1230-fake-home")
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
    if !python_runtime_present() {
        eprintln!(
            "skip python_init_assembly_raises_…: {} has no agent_assembly/runtime.py",
            python_sdk_path().display()
        );
        return;
    }
    let out = Command::new("python3")
        .arg("-c")
        .arg("from agent_assembly.runtime import init_assembly; init_assembly()")
        .env("PYTHONPATH", python_sdk_path())
        .env("PATH", EMPTY_PATH_DIR)
        .env("HOME", "/var/empty-AAASM-1230-fake-home")
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
