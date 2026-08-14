//! What `aa-runtime/build.rs` is allowed to call a `checkout` identity
//! (AAASM-5668).
//!
//! The build script bakes a commit id into the binary and labels it
//! **authoritative**, which is what lets two binaries compare `Match`. Getting
//! that id from the wrong repository is therefore not a cosmetic error: it
//! fabricates the exact agreement the provenance mechanism exists to establish.
//!
//! Build scripts are compiled as their own binary and nothing can `use` them,
//! so `build.rs` keeps this half in `build_support/git_identity.rs` and both
//! targets `#[path]`-include the same file. These tests run the same function
//! the build runs, against real repositories on disk.

use std::path::Path;
use std::process::Command;

#[allow(dead_code, unused_imports)]
#[path = "../build_support/git_identity.rs"]
mod git_identity;

use git_identity::git_head_sha;

/// Run `git` in `dir` with a hermetic identity and configuration.
///
/// The ambient user/system config is cut out so a developer's `commit.gpgsign`,
/// hook path or template directory cannot make these fixtures behave
/// differently from CI's. The *code under test* keeps the ambient environment,
/// which is the situation it actually runs in.
fn git(dir: &Path, args: &[&str]) {
    let output = Command::new("git")
        .args(args)
        .current_dir(dir)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .env("GIT_AUTHOR_NAME", "aa-test")
        .env("GIT_AUTHOR_EMAIL", "aa-test@example.invalid")
        .env("GIT_COMMITTER_NAME", "aa-test")
        .env("GIT_COMMITTER_EMAIL", "aa-test@example.invalid")
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .output()
        .expect("git must be on PATH for these tests");
    assert!(
        output.status.success(),
        "git {args:?} in {} failed: {}",
        dir.display(),
        String::from_utf8_lossy(&output.stderr)
    );
}

/// A repository at `dir` with exactly one commit, and that commit's id.
fn repo_with_one_commit(dir: &Path) -> String {
    std::fs::create_dir_all(dir).expect("create repository directory");
    git(dir, &["init", "-q", "."]);
    git(dir, &["commit", "-q", "--allow-empty", "-m", "fixture"]);
    let out = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(dir)
        .output()
        .expect("git rev-parse");
    String::from_utf8(out.stdout).expect("utf-8").trim().to_string()
}

/// **Positive control.** A directory that really is the top of a checkout must
/// yield that checkout's commit.
///
/// Without this, every other test here would still pass if `git_head_sha`
/// were changed to `None` unconditionally — which would silently disable the
/// `checkout` identity source altogether and downgrade every local build to
/// `absent`.
#[test]
fn a_checkout_root_yields_its_own_head() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let root = tmp.path().join("checkout");
    let head = repo_with_one_commit(&root);

    assert_eq!(
        git_head_sha(&root),
        Some(head),
        "the top of a real checkout must supply its own HEAD"
    );
}

/// A vendored copy of this source tree, unpacked inside an unrelated
/// repository, must **not** inherit that repository's commit.
///
/// Git discovery ascends, so `git rev-parse HEAD` answers from the enclosing
/// repository. Baking that in would put a commit id that describes a different
/// project into the binary and mark it authoritative — and two binaries
/// vendored into the same enclosing checkout would then compare `Match`.
#[test]
fn a_vendored_copy_does_not_inherit_the_enclosing_repository() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let enclosing = tmp.path().join("enclosing");
    let enclosing_head = repo_with_one_commit(&enclosing);

    // The vendored source tree: no `.git` of its own, several levels down.
    let vendored = enclosing.join("third_party").join("agent-assembly");
    std::fs::create_dir_all(vendored.join("aa-runtime")).expect("create vendored tree");

    let found = git_head_sha(&vendored);
    assert_ne!(
        found.as_deref(),
        Some(enclosing_head.as_str()),
        "a vendored copy must not claim the enclosing repository's commit"
    );
    assert_eq!(
        found, None,
        "an enclosing repository is not an identity for the tree inside it, so there is nothing to report"
    );
}

/// A directory one level below a checkout root is not itself a checkout.
///
/// This is the shape a `cargo package` tarball takes when it is unpacked and
/// verified under `target/package/`: the manifest's parent is not the
/// repository top level, and the identity must come from the tarball's own
/// `.cargo_vcs_info.json` (the `packaged` source) rather than from whatever
/// repository happens to enclose the build directory.
#[test]
fn a_subdirectory_of_a_checkout_is_not_a_checkout_root() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let root = tmp.path().join("checkout");
    repo_with_one_commit(&root);
    let nested = root.join("target").join("package").join("aa-runtime-0.0.0");
    std::fs::create_dir_all(&nested).expect("create nested directory");

    assert_eq!(
        git_head_sha(&nested),
        None,
        "only the top level of a working tree is a checkout identity"
    );
}

/// An inherited `GIT_DIR` must not decide which repository is consulted.
///
/// A build launched from a shell, CI step or git hook that had `GIT_DIR` set
/// would otherwise answer about *that* repository regardless of the directory
/// it was pointed at — the same substitution as the vendored case, arriving
/// through the environment instead of the directory tree.
#[test]
fn an_inherited_git_dir_does_not_supply_an_identity() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let elsewhere = tmp.path().join("elsewhere");
    let elsewhere_head = repo_with_one_commit(&elsewhere);
    let unrelated = tmp.path().join("unrelated");
    std::fs::create_dir_all(&unrelated).expect("create unrelated directory");

    // `set_var` is process-global, and it is removed before any assertion can
    // unwind past it. `cargo nextest` runs each test in its own process, so no
    // other test in this file observes it either way.
    std::env::set_var("GIT_DIR", elsewhere.join(".git"));
    let found = git_head_sha(&unrelated);
    std::env::remove_var("GIT_DIR");

    assert_ne!(
        found.as_deref(),
        Some(elsewhere_head.as_str()),
        "an inherited GIT_DIR must not become this build's identity"
    );
    assert_eq!(found, None, "there is no checkout at the directory being built");
}

/// No repository anywhere above the tree means no `checkout` identity, which is
/// the honest answer rather than a fabricated one.
#[test]
fn a_tree_outside_any_repository_has_no_identity() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let root = tmp.path().join("loose");
    std::fs::create_dir_all(&root).expect("create directory");

    // `tempdir()` can itself sit inside a repository on some machines; skip
    // rather than assert a precondition this test does not control.
    let enclosed = Command::new("git")
        .args(["rev-parse", "--show-toplevel"])
        .current_dir(&root)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if enclosed {
        return;
    }

    assert_eq!(git_head_sha(&root), None);
}
