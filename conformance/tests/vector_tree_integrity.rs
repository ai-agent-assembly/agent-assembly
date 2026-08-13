//! Structural integrity of the vector tree itself, as opposed to the content of
//! any individual vector.
//!
//! AAASM-5452: a self-referential symlink (`conformance/vectors/vectors ->
//! conformance/vectors`) was found in a working tree. It was untracked, in no
//! commit, and had no consumer, so nothing failed and nothing reported it — but
//! any naive recursive walk over the vector tree (a fixture generator, a
//! coverage sweep, a packaging or archive step, plain `find`) would have
//! descended it until it ran out of depth.
//!
//! `git status` stays clean for an untracked link and every content test keeps
//! passing, because none of them walks the tree. This module is the assertion
//! that would have caught it.

use std::path::{Path, PathBuf};

/// Depth at which the walk gives up and calls the tree recursive.
///
/// The real vector tree is two levels deep (`vectors/<category>/<name>.json`),
/// so this leaves a wide margin for legitimate nesting while still terminating
/// promptly on a loop. The bound is what makes a recursive link *fail* rather
/// than hang CI.
const MAX_DEPTH: usize = 16;

/// Walks `root` without following symlinks and reports the first link that
/// would make the tree recursively traversable.
///
/// A link is rejected when its target, once resolved, is the link's own parent
/// directory or an ancestor of it — descending such a link re-enters a
/// directory the walk has already visited. A link that cannot be resolved at
/// all (`ELOOP`, a direct self-reference) is rejected for the same reason.
///
/// Returns `Err` with the offending path, so a failure names the file to delete
/// rather than only asserting that something is wrong.
fn find_recursive_symlink(root: &Path) -> Result<(), String> {
    let mut stack: Vec<(PathBuf, usize)> = vec![(root.to_path_buf(), 0)];

    while let Some((dir, depth)) = stack.pop() {
        if depth > MAX_DEPTH {
            return Err(format!(
                "walk exceeded depth {MAX_DEPTH} at {} — the vector tree is recursive",
                dir.display()
            ));
        }

        let entries = match std::fs::read_dir(&dir) {
            Ok(e) => e,
            // A directory that cannot be read is not this test's concern.
            Err(_) => continue,
        };

        for entry in entries.flatten() {
            let path = entry.path();
            // `symlink_metadata` does not follow the link, so the walk itself
            // can never be led into a loop by the thing it is looking for.
            let Ok(meta) = std::fs::symlink_metadata(&path) else {
                continue;
            };

            if meta.file_type().is_symlink() {
                let Ok(parent) = dir.canonicalize() else {
                    continue;
                };
                match path.canonicalize() {
                    Ok(target) => {
                        if parent.starts_with(&target) {
                            return Err(format!(
                                "{} resolves to {}, which is its own parent or an ancestor of it",
                                path.display(),
                                target.display()
                            ));
                        }
                    }
                    Err(err) => {
                        return Err(format!(
                            "{} could not be resolved ({err}) — a direct self-reference resolves this way",
                            path.display()
                        ));
                    }
                }
            } else if meta.file_type().is_dir() {
                stack.push((path, depth + 1));
            }
        }
    }

    Ok(())
}

#[test]
fn the_vector_tree_contains_no_recursive_symlink() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("vectors");
    if let Err(offender) = find_recursive_symlink(&root) {
        panic!("vector tree is recursively traversable: {offender}");
    }
}

/// Removes a scratch directory on the way out, whether the test passed or
/// panicked, so a failing run does not leave a symlink loop in the temp dir.
struct Scratch(PathBuf);

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The positive control for [`the_vector_tree_contains_no_recursive_symlink`].
///
/// There are zero symlinks under `conformance/vectors/`, so the real-tree test
/// passes identically whether [`find_recursive_symlink`] works or is stubbed to
/// return `Ok(())`. On its own it therefore carries no evidence — it asserts
/// over a tree that happens to be clean rather than over the detector that
/// decides.
///
/// This test builds the exact shape that was found in the working tree and
/// proves the same detector rejects it. Stub the detector and this fails.
#[cfg(unix)]
#[test]
fn the_detector_rejects_a_synthetic_self_parent_symlink() {
    use std::os::unix::fs::symlink;

    let root = std::env::temp_dir().join(format!(
        "aaasm5452-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _scratch = Scratch(root.clone());

    let nested = root.join("vectors");
    std::fs::create_dir_all(&nested).expect("create scratch tree");

    // The shape that was found: a link inside the tree pointing at the tree.
    symlink(&nested, nested.join("vectors")).expect("create self-parent symlink");

    let result = find_recursive_symlink(&root);
    assert!(
        result.is_err(),
        "detector accepted a self-parent symlink — the real-tree test proves nothing"
    );
    let message = result.unwrap_err();
    assert!(
        message.contains("vectors"),
        "failure should name the offending path, got: {message}"
    );
}

/// A symlink that points *outside* its own subtree is not recursive and must
/// not be rejected.
///
/// Without this, the guard could be satisfied by banning symlinks outright,
/// which is a different and broader rule than the one AAASM-5452 asks for.
#[cfg(unix)]
#[test]
fn the_detector_accepts_a_non_recursive_symlink() {
    use std::os::unix::fs::symlink;

    let root = std::env::temp_dir().join(format!(
        "aaasm5452-ok-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _scratch = Scratch(root.clone());

    let tree = root.join("vectors");
    let outside = root.join("elsewhere");
    std::fs::create_dir_all(&tree).expect("create scratch tree");
    std::fs::create_dir_all(&outside).expect("create sibling dir");
    std::fs::write(outside.join("payload.json"), b"{}").expect("write payload");

    symlink(outside.join("payload.json"), tree.join("payload.json")).expect("create sibling link");

    assert!(
        find_recursive_symlink(&tree).is_ok(),
        "detector rejected a non-recursive symlink; the rule is about recursion, not symlinks"
    );
}
