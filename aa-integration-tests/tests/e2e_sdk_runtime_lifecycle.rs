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
