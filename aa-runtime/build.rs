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
//! # The identity must say where it came from, not just what it is
//!
//! The client's comparison is three-state (match / mismatch / **unverifiable**),
//! and the third state exists because two binaries that both say "I don't know"
//! have proved nothing about each other. So this script emits *two* facts: the
//! identity, and [`AA_BUILD_IDENTITY_SOURCE`] — the mechanism that produced it.
//! Only an identity from an authoritative mechanism can raise a comparison to
//! `Match`; `absent` can only ever produce `Unverifiable`. Emitting the source
//! explicitly means "is this authoritative?" is a recorded fact rather than
//! something inferred from the shape of a string.
//!
//! # The four sources, in order
//!
//! | `AA_BUILD_IDENTITY_SOURCE` | Where the SHA came from | Authoritative |
//! | --- | --- | --- |
//! | `injected` | `AA_BUILD_SHA` in the build environment | yes |
//! | `checkout` | `git rev-parse HEAD` in the workspace root | yes |
//! | `packaged` | `.cargo_vcs_info.json` in a `cargo package` tarball | yes |
//! | `absent` | nothing could be resolved — the SHA is `unknown` | **no** |
//!
//! `packaged` is what makes an installed-from-a-tarball pairing verifiable
//! rather than merely unrefuted. `cargo package` (and therefore `cargo publish`)
//! writes `.cargo_vcs_info.json` into the `.crate` tarball, recording the commit
//! the crate was published from. That is a *real* shared artifact identity — two
//! crates published from one commit carry the same `sha1` — as opposed to
//! version-string equality, which proves nothing about build content. A tarball
//! packaged from a dirty tree carries `"dirty": true`, and is rejected: the
//! source does not correspond to the commit it names, so the commit is not an
//! identity for it.
//!
//! # Staleness
//!
//! Cargo caches build-script output, so the `rerun-if-changed` lines below are
//! load-bearing: a SHA that lags `HEAD` is worse than no SHA at all, because it
//! *looks* verified. `HEAD`, the ref it points at and `packed-refs` are all
//! watched, which covers commit, checkout and branch switch.

use std::path::{Path, PathBuf};
use std::process::Command;

/// What `build.rs` writes when there was no checkout to read a commit from.
/// Must stay in step with `provenance::UNKNOWN_SHA`.
const UNKNOWN_SHA: &str = "unknown";

/// The file `cargo package` writes into a `.crate` tarball.
const VCS_INFO_FILE: &str = ".cargo_vcs_info.json";

fn main() {
    println!("cargo:rerun-if-env-changed=AA_BUILD_SHA");
    println!("cargo:rerun-if-env-changed=AA_BUILD_SOURCE_PATH");

    let manifest_dir = std::env::var_os("CARGO_MANIFEST_DIR").map(PathBuf::from);
    let source_root = manifest_dir
        .as_deref()
        .and_then(|dir| dir.parent().map(Path::to_path_buf));

    if let Some(root) = source_root.as_deref() {
        watch_git_head(root);
    }

    // A packaged tarball's vcs info sits beside the manifest, so it is watched
    // there rather than at the workspace root — in a published crate there is
    // no workspace root above it at all.
    if let Some(dir) = manifest_dir.as_deref() {
        println!("cargo:rerun-if-changed={}", dir.join(VCS_INFO_FILE).display());
    }

    let (sha, identity_source) = env_override("AA_BUILD_SHA")
        .map(|sha| (sha, "injected"))
        .or_else(|| {
            source_root
                .as_deref()
                .and_then(git_head_sha)
                .map(|sha| (sha, "checkout"))
        })
        .or_else(|| {
            manifest_dir
                .as_deref()
                .and_then(packaged_vcs_sha)
                .map(|sha| (sha, "packaged"))
        })
        .unwrap_or_else(|| (UNKNOWN_SHA.to_string(), "absent"));

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
    println!("cargo:rustc-env=AA_BUILD_IDENTITY_SOURCE={identity_source}");
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

/// The commit a `cargo package` tarball records it was published from.
///
/// Hand-parsed rather than pulled through `serde_json`: the file is written by
/// cargo to a fixed, tiny schema, and a build script on the critical path of
/// every compile is a bad place to add a dependency tree for two string reads.
/// Anything that does not parse yields `None`, which degrades to `absent` — the
/// safe direction, since `absent` can only ever produce `Unverifiable`.
///
/// A tarball packaged from a dirty tree carries `"dirty": true`; the commit it
/// names is then not an identity for its contents, so it is refused.
fn packaged_vcs_sha(manifest_dir: &Path) -> Option<String> {
    let raw = std::fs::read_to_string(manifest_dir.join(VCS_INFO_FILE)).ok()?;
    if json_flag_is_true(&raw, "dirty") {
        return None;
    }
    let sha = json_string_field(&raw, "sha1")?;
    // Cargo writes a full hex object id; anything else is not one, and guessing
    // would put a fabricated identity on the wire.
    (sha.len() >= 40 && sha.chars().all(|c| c.is_ascii_hexdigit())).then_some(sha)
}

/// The value of `"<key>": "<value>"`, for cargo's generated vcs-info file.
fn json_string_field(raw: &str, key: &str) -> Option<String> {
    let after_key = raw.split_once(&format!("\"{key}\""))?.1;
    let after_colon = after_key.split_once(':')?.1;
    let after_quote = after_colon.split_once('"')?.1;
    after_quote.split_once('"').map(|(value, _)| value.to_string())
}

/// Whether `"<key>": true` appears, for cargo's generated vcs-info file.
fn json_flag_is_true(raw: &str, key: &str) -> bool {
    raw.split_once(&format!("\"{key}\""))
        .and_then(|(_, rest)| rest.split_once(':'))
        .is_some_and(|(_, value)| value.trim_start().starts_with("true"))
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
