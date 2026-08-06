//! Reading a build identity out of a git checkout (AAASM-5628).
//!
//! Lives beside `build.rs` rather than inside it so the same code the build
//! script runs can be exercised by a test: this is the half of the identity
//! pipeline that talks to another program and to the filesystem, and it is the
//! half that decides whether an identity is *authoritative*. A build script's
//! functions are otherwise unreachable from any test target.
//!
//! Pulled in with `#[path]` by both `aa-runtime/build.rs` and
//! `aa-runtime/tests/build_git_discovery.rs`.

use std::path::{Path, PathBuf};
use std::process::Command;

/// Ask `git` for the current commit, or `None` outside a checkout.
pub fn git_head_sha(root: &Path) -> Option<String> {
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
pub fn watch_git_head(root: &Path) {
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
