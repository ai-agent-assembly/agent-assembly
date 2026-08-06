//! Compile-time build identity for `aa-runtime` (AAASM-5628).
//!
//! # Why a build script exists for this
//!
//! A version string cannot answer "which build answered?". Two checkouts at the
//! same `0.0.1-rc.6` are indistinguishable by version, and that is exactly the
//! failure AAASM-5628 records: a runtime from another checkout served a whole
//! QA campaign, and every measurement was silently against the wrong build.
//! The commit SHA is the smallest thing that tells them apart, and it has to be
//! *baked into the binary* — asking the running process to shell out to `git`
//! would report the SHA of whatever directory it happens to be started from,
//! which is not the same question.
//!
//! `aa-cli` depends on `aa-runtime`, so both halves of the client/server pair
//! read the same two constants from the same compiled crate. Equal constants
//! therefore mean "compiled together", which is precisely the claim the client
//! needs to make.
//!
//! # The three sources, in order
//!
//! 1. `AA_BUILD_SHA` / `AA_BUILD_SOURCE_PATH` from the environment. Release and
//!    reproducible builds set them explicitly; setting `AA_BUILD_SOURCE_PATH`
//!    to the empty string is also how a packager keeps a build-machine path out
//!    of a published binary.
//! 2. `git rev-parse HEAD` in the workspace root, for a normal checkout or
//!    linked worktree.
//! 3. `unknown` — a crates.io tarball has no `.git`, and inventing a SHA there
//!    would be worse than admitting there is none.
//!
//! # Staleness
//!
//! Cargo caches build-script output, so the `rerun-if-changed` lines below are
//! load-bearing: a SHA that lags `HEAD` is worse than no SHA at all, because it
//! *looks* verified. `HEAD`, the ref it points at and `packed-refs` are all
//! watched, which covers commit, checkout and branch switch.

use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-env-changed=AA_BUILD_SHA");
    println!("cargo:rerun-if-env-changed=AA_BUILD_SOURCE_PATH");

    let source_root = std::env::var_os("CARGO_MANIFEST_DIR")
        .map(PathBuf::from)
        .and_then(|dir| dir.parent().map(Path::to_path_buf));

    if let Some(root) = source_root.as_deref() {
        watch_git_head(root);
    }

    let sha = env_override("AA_BUILD_SHA")
        .or_else(|| source_root.as_deref().and_then(git_head_sha))
        .unwrap_or_else(|| "unknown".to_string());

    // Unset falls back to the checkout this was built from; explicitly empty
    // stays empty, so a packager can suppress it without inventing a value.
    let source_path = match std::env::var("AA_BUILD_SOURCE_PATH") {
        Ok(explicit) => explicit,
        Err(_) => source_root
            .as_deref()
            .map(|p| p.display().to_string())
            .unwrap_or_default(),
    };

    println!("cargo:rustc-env=AA_BUILD_SHA={sha}");
    println!("cargo:rustc-env=AA_BUILD_SOURCE_PATH={source_path}");
}

/// A non-blank environment override, or `None`.
fn env_override(key: &str) -> Option<String> {
    std::env::var(key)
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

/// Ask `git` for the current commit, or `None` outside a checkout.
fn git_head_sha(root: &Path) -> Option<String> {
    let output = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(root)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let sha = String::from_utf8(output.stdout).ok()?.trim().to_string();
    (!sha.is_empty()).then_some(sha)
}

/// Emit `rerun-if-changed` for everything that can move `HEAD`.
///
/// Resolved through `git rev-parse --git-path` rather than assembled from
/// `<root>/.git/…`: in a linked worktree `.git` is a *file* pointing elsewhere,
/// and the naive path would watch a file that never changes.
fn watch_git_head(root: &Path) {
    let Some(head) = git_path(root, "HEAD") else {
        return;
    };
    println!("cargo:rerun-if-changed={}", head.display());

    if let Some(packed) = git_path(root, "packed-refs") {
        println!("cargo:rerun-if-changed={}", packed.display());
    }

    // A commit on the checked-out branch moves the ref, not `HEAD` itself.
    if let Some(refname) = git_output(root, &["symbolic-ref", "-q", "HEAD"]) {
        if let Some(ref_path) = git_path(root, &refname) {
            println!("cargo:rerun-if-changed={}", ref_path.display());
        }
    }
}

/// Resolve a git-internal path (`HEAD`, `refs/heads/main`, …) to a real one.
fn git_path(root: &Path, name: &str) -> Option<PathBuf> {
    let raw = git_output(root, &["rev-parse", "--git-path", name])?;
    let path = PathBuf::from(&raw);
    Some(if path.is_absolute() { path } else { root.join(path) })
}

/// Run `git` in `root` and return trimmed stdout on success.
fn git_output(root: &Path, args: &[&str]) -> Option<String> {
    let output = Command::new("git").args(args).current_dir(root).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let value = String::from_utf8(output.stdout).ok()?.trim().to_string();
    (!value.is_empty()).then_some(value)
}
