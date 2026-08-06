//! Reading a build identity out of a git checkout (AAASM-5628).
//!
//! Lives beside `build.rs` rather than inside it so the same code the build
//! script runs can be exercised by a test: this is the half of the identity
//! pipeline that talks to another program and to the filesystem, and it is the
//! half that decides whether an identity is *authoritative*. A build script's
//! functions are otherwise unreachable from any test target, which is how the
//! defect in [`git_head_sha`]'s original form survived review.
//!
//! Pulled in with `#[path]` by both `aa-runtime/build.rs` and
//! `aa-runtime/tests/build_git_discovery.rs`.

use std::path::{Path, PathBuf};
use std::process::Command;

/// The commit `root` is checked out at, or `None` when `root` is not itself a
/// git checkout.
///
/// # Why the toplevel is checked before the SHA is believed
///
/// Git discovery **ascends**: `git rev-parse HEAD` run anywhere inside a
/// directory tree walks upward until it finds a repository and answers from
/// *that* one. So a vendored copy of this source tree, an extracted tarball
/// unpacked inside someone's checkout, or a build performed in a scratch
/// directory that happens to sit under an unrelated repository would all get a
/// commit id back — one that describes a different repository entirely — and
/// `build.rs` would bake it in as an **authoritative** `checkout` identity.
///
/// That is the same mistake this whole mechanism exists to prevent, moved from
/// run time to build time: `provenance`'s module doc rejects shelling out to
/// `git` at run time precisely because it "would report the SHA of whatever
/// directory it was started from". An ascending build-time lookup reports the
/// SHA of whatever directory the *source* was placed in, which is no better,
/// and worse in one respect — the wrong answer is then frozen into the binary
/// and compares `Match` against any other binary carrying the same mistake.
///
/// So the repository must be `root` **exactly**, not merely an ancestor of it.
/// Ancestry is the failing condition, not the passing one: every enclosing
/// repository is an ancestor, which is what makes the vendored case look valid.
/// Equality is also the right answer for the two legitimate non-checkout
/// builds — a `cargo package` tarball unpacked under `target/package/`, and any
/// exported source tree — because both then fall through to `packaged` or
/// `injected`, which state their identity rather than inferring it, or to
/// `absent`, which can only ever produce `Unverifiable`.
///
/// Paths are canonicalised on both sides before comparison so a symlinked
/// checkout (`/tmp` → `/private/tmp` on macOS, a symlinked worktree) is not
/// mistaken for a different directory.
pub fn git_head_sha(root: &Path) -> Option<String> {
    if !is_checkout_root(root) {
        return None;
    }
    git_output(root, &["rev-parse", "HEAD"])
}

/// Whether `root` is the top level of a git working tree, rather than merely
/// sitting somewhere inside one. See [`git_head_sha`].
fn is_checkout_root(root: &Path) -> bool {
    let Some(toplevel) = git_output(root, &["rev-parse", "--show-toplevel"]) else {
        return false;
    };
    match (Path::new(&toplevel).canonicalize(), root.canonicalize()) {
        (Ok(toplevel), Ok(root)) => toplevel == root,
        // A path that cannot be resolved is not evidence that the two are the
        // same, and guessing here would reopen the case above.
        _ => false,
    }
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
///
/// `GIT_DIR` and `GIT_WORK_TREE` are cleared rather than inherited. They
/// override discovery outright, so a build launched from a shell (or a CI step,
/// or a hook) that had them set would answer about *that* repository no matter
/// which directory it was pointed at — the same substitution
/// [`git_head_sha`]'s toplevel check refuses, arriving through the environment
/// instead of through the directory tree. Clearing them makes `root` the only
/// input that decides which repository is consulted.
fn git_output(root: &Path, args: &[&str]) -> Option<String> {
    let output = Command::new("git")
        .args(args)
        .current_dir(root)
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let value = String::from_utf8(output.stdout).ok()?.trim().to_string();
    (!value.is_empty()).then_some(value)
}
