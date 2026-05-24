//! Sibling-repo lookup helpers for the Node.js SDK
//! (`AI-agent-assembly/node-sdk`).
//!
//! The TypeScript fixtures under
//! `aa-integration-tests/tests/fixtures/agents/typescript/` resolve
//! `@agent-assembly/sdk` via a `file:` protocol pointing at a sibling
//! `node-sdk/` checkout — see the fixture's `package.json`. The
//! sibling path defaults to `<parent of agent-assembly>/node-sdk` and
//! can be overridden by `NODE_SDK_PATH` (mirrors the
//! `PYTHON_SDK_PATH` convention used by the Python SDK integration
//! suite).
//!
//! `e2e_sdk_node.rs`'s `real_*` tests need both:
//! 1. The sibling repo checked out (CI handles this with a second
//!    `actions/checkout@v6`).
//! 2. The napi-rs native binding built (`pnpm native:build`) so the
//!    `@agent-assembly/sdk` import resolves to a loadable `.node`
//!    artifact.
//!
//! [`native_binding_ready`] returns `Ok(())` only when both conditions
//! hold; tests skip with `eprintln!` otherwise so a missing sibling
//! checkout or unbuilt binding doesn't show up as a confusing
//! `pnpm exec tsx` runtime error.

use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};

/// Resolve the sibling `node-sdk/` checkout.
///
/// Order:
/// 1. `NODE_SDK_PATH` env var (absolute or relative).
/// 2. `<parent of CARGO_MANIFEST_DIR>/../node-sdk` — the layout used
///    by the workspace (`AI-agent-assembly/{agent-assembly,node-sdk}/`).
pub fn node_sdk_dir() -> Result<PathBuf> {
    if let Ok(p) = std::env::var("NODE_SDK_PATH") {
        let path = PathBuf::from(p);
        if path.exists() {
            return Ok(path);
        }
    }
    let manifest = std::env::var("CARGO_MANIFEST_DIR").context("CARGO_MANIFEST_DIR not set")?;
    // `<manifest>/aa-integration-tests` → up to workspace root → up to parent.
    let workspace_root = Path::new(&manifest).parent().context("manifest has no parent")?;
    let candidate = workspace_root
        .parent()
        .context("workspace has no parent")?
        .join("node-sdk");
    if candidate.exists() {
        return Ok(candidate);
    }
    Err(anyhow!(
        "node-sdk sibling repo not found at {} (set NODE_SDK_PATH to override)",
        candidate.display(),
    ))
}

/// Return `true` when at least one napi-rs `.node` artifact exists in
/// `<node_sdk>/native/aa-ffi-node/`. napi-rs names the file with a
/// platform suffix (e.g. `aa-ffi-node.darwin-arm64.node`,
/// `aa-ffi-node.linux-x64-gnu.node`) so we glob the directory rather
/// than checking a fixed filename.
pub fn native_binding_built(node_sdk: &Path) -> bool {
    let native_dir = node_sdk.join("native").join("aa-ffi-node");
    let Ok(entries) = std::fs::read_dir(&native_dir) else {
        return false;
    };
    entries
        .filter_map(|e| e.ok())
        .any(|e| e.path().extension().and_then(|s| s.to_str()) == Some("node"))
}

/// Combined readiness probe — returns `Ok(())` only when the sibling
/// `node-sdk/` checkout is present **and** the napi-rs `.node` artifact
/// has been built. Error string is suitable for `eprintln!` so tests
/// can skip cleanly.
pub fn native_binding_ready() -> Result<()> {
    let dir = node_sdk_dir()?;
    if !native_binding_built(&dir) {
        return Err(anyhow!(
            "Node.js native binding not built at {}/native/aa-ffi-node/*.node — \
             run `pnpm --dir {} install && pnpm --dir {} native:build`",
            dir.display(),
            dir.display(),
            dir.display(),
        ));
    }
    Ok(())
}
