//! Falsification tests for the ticket's own testing list (AAASM-6162):
//! discard leaves base unchanged, commit applies exactly the intended change
//! set, protected-path denial leaves base unchanged, and concurrent base
//! drift inside vs. outside the change set. Each test is paired with a
//! control that can make it fail — never a bare assertion that a mechanism
//! "did nothing wrong" with no proof it was exercised at all.

use std::fs;
use std::path::Path;

use aa_isolation::TransactionId;
use aa_workspace_tx::WorkspaceTransaction;

fn write(path: &Path, content: &str) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(path, content).unwrap();
}

fn base_digest(base_root: &Path) -> aa_isolation::WorkspaceDigest {
    let manifest = aa_workspace_tx::manifest::measure(base_root, &[]).unwrap();
    aa_workspace_tx::manifest::aggregate_digest(&manifest)
}

#[test]
fn discard_leaves_base_byte_for_byte_unchanged() {
    let fixture = tempfile::tempdir().unwrap();
    let base_root = fixture.path().join("base");
    let state_root = fixture.path().join("state");
    fs::create_dir_all(&base_root).unwrap();
    write(&base_root.join("a.txt"), "original");

    let before = base_digest(&base_root);

    let id = TransactionId::new("discard-test");
    let tx = WorkspaceTransaction::open(id, &state_root, &base_root, vec![]).unwrap();

    // Positive control: prove the staged layer actually diverged from base
    // before discarding it — otherwise "base unchanged" would be true for
    // the trivial, useless reason that nothing was ever staged.
    write(&tx.staged_dir().join("a.txt"), "mutated by the confined process");
    write(&tx.staged_dir().join("new_file.txt"), "brand new");
    let staged_manifest = aa_workspace_tx::manifest::measure(tx.staged_dir(), &[]).unwrap();
    let staged_digest = aa_workspace_tx::manifest::aggregate_digest(&staged_manifest);
    assert_ne!(
        before, staged_digest,
        "the staged layer must actually differ from base before discard is a meaningful test"
    );

    tx.discard().unwrap();

    let after = base_digest(&base_root);
    assert_eq!(
        before, after,
        "discard must leave the base tree byte-for-byte unchanged"
    );
    assert_eq!(
        fs::read_to_string(base_root.join("a.txt")).unwrap(),
        "original",
        "the original file content must survive discard verbatim"
    );
    assert!(
        !base_root.join("new_file.txt").exists(),
        "a file only ever written to the staged layer must never appear in base after discard"
    );
}

#[test]
fn commit_applies_exactly_the_intended_change_set() {
    let fixture = tempfile::tempdir().unwrap();
    let base_root = fixture.path().join("base");
    let state_root = fixture.path().join("state");
    fs::create_dir_all(&base_root).unwrap();
    write(&base_root.join("added.txt"), ""); // placeholder, removed below
    fs::remove_file(base_root.join("added.txt")).unwrap();
    write(&base_root.join("modified.txt"), "before");
    write(&base_root.join("untouched.txt"), "control: never touched");

    let id = TransactionId::new("commit-exact-test");
    let mut tx = WorkspaceTransaction::open(id, &state_root, &base_root, vec![]).unwrap();

    write(&tx.staged_dir().join("added.txt"), "new file added by the run");
    write(&tx.staged_dir().join("modified.txt"), "after");
    // untouched.txt is left exactly as materialized — the control.

    tx.close();
    let outcome = tx
        .commit(&[], false)
        .expect("commit should succeed with no protected hits");

    let applied_paths: Vec<&str> = outcome.applied().entries().iter().map(|e| e.path()).collect();
    assert!(
        applied_paths.contains(&"added.txt"),
        "the added file must be in the applied change set"
    );
    assert!(
        applied_paths.contains(&"modified.txt"),
        "the modified file must be in the applied change set"
    );
    assert!(
        !applied_paths.contains(&"untouched.txt"),
        "an untouched file must never appear in the applied change set"
    );
    assert_eq!(
        applied_paths.len(),
        2,
        "exactly the intended change set must be applied, nothing more: {applied_paths:?}"
    );

    assert_eq!(
        fs::read_to_string(base_root.join("added.txt")).unwrap(),
        "new file added by the run"
    );
    assert_eq!(fs::read_to_string(base_root.join("modified.txt")).unwrap(), "after");
    assert_eq!(
        fs::read_to_string(base_root.join("untouched.txt")).unwrap(),
        "control: never touched",
        "the untouched file's content must be byte-for-byte unaffected by commit"
    );
}

#[test]
fn protected_path_denial_leaves_base_unchanged_and_the_denial_is_the_actual_cause() {
    let fixture = tempfile::tempdir().unwrap();
    let base_root = fixture.path().join("base");
    let state_root = fixture.path().join("state");
    fs::create_dir_all(&base_root).unwrap();
    write(&base_root.join("secrets/config.toml"), "old");

    let id = TransactionId::new("protected-test");
    let mut tx = WorkspaceTransaction::open(id, &state_root, &base_root, vec![]).unwrap();
    write(&tx.staged_dir().join("secrets/config.toml"), "new");
    tx.close();

    let before = base_digest(&base_root);
    let refusal = tx
        .commit(&["secrets/config.toml".to_string()], false)
        .expect_err("an unapproved protected-path hit must refuse the commit");
    assert!(
        matches!(refusal, aa_isolation::CommitRefusal::ProtectedPathNotApproved { .. }),
        "the refusal reason must name the protected-path gate, not something else: {refusal:?}"
    );
    let after = base_digest(&base_root);
    assert_eq!(
        before, after,
        "a refused commit must leave the base tree completely untouched"
    );
    assert_eq!(
        fs::read_to_string(base_root.join("secrets/config.toml")).unwrap(),
        "old"
    );

    // Falsifier: the SAME staged change, with the selector removed from the
    // protected list, must now succeed — proving the refusal above was
    // actually caused by the protected-path gate, not by some other defect
    // that would have refused any commit regardless.
    let id2 = TransactionId::new("protected-test-falsifier");
    let mut tx2 = WorkspaceTransaction::open(id2, &state_root, &base_root, vec![]).unwrap();
    write(&tx2.staged_dir().join("secrets/config.toml"), "new");
    tx2.close();
    let outcome = tx2
        .commit(&[], false)
        .expect("the identical change must succeed once the path is no longer protected");
    assert_eq!(outcome.applied().entries().len(), 1);
    assert_eq!(
        fs::read_to_string(base_root.join("secrets/config.toml")).unwrap(),
        "new"
    );
}

#[test]
fn base_drift_inside_the_change_set_refuses_drift_outside_it_does_not() {
    let fixture = tempfile::tempdir().unwrap();
    let base_root = fixture.path().join("base");
    let state_root = fixture.path().join("state");
    fs::create_dir_all(&base_root).unwrap();
    write(&base_root.join("in_scope.txt"), "original");
    write(&base_root.join("out_of_scope.txt"), "original");

    let id = TransactionId::new("drift-in-scope-test");
    let mut tx = WorkspaceTransaction::open(id, &state_root, &base_root, vec![]).unwrap();
    write(&tx.staged_dir().join("in_scope.txt"), "staged change");
    tx.close();

    // Someone else writes to base concurrently, on the exact path this
    // transaction is about to change.
    write(&base_root.join("in_scope.txt"), "modified by a concurrent process");

    let refusal = tx
        .commit(&[], false)
        .expect_err("drift on an in-change-set path must refuse the commit");
    assert!(
        matches!(refusal, aa_isolation::CommitRefusal::BaseDrift { ref paths } if paths.iter().any(|p| p == "in_scope.txt")),
        "the refusal must name in_scope.txt as the drifted path: {refusal:?}"
    );
    assert_eq!(
        fs::read_to_string(base_root.join("in_scope.txt")).unwrap(),
        "modified by a concurrent process",
        "a refused commit must not overwrite the concurrent write — lost update, not silent overwrite"
    );

    // Control: drift on a path OUTSIDE the change set must not block a
    // commit that never touches it.
    let id2 = TransactionId::new("drift-out-of-scope-test");
    let mut tx2 = WorkspaceTransaction::open(id2, &state_root, &base_root, vec![]).unwrap();
    write(&tx2.staged_dir().join("in_scope.txt"), "second attempt");
    tx2.close();
    write(
        &base_root.join("out_of_scope.txt"),
        "concurrent write to an untouched path",
    );
    let outcome = tx2
        .commit(&[], false)
        .expect("drift on a path outside the change set must not block this commit");
    assert_eq!(outcome.applied().entries().len(), 1);
    assert_eq!(
        fs::read_to_string(base_root.join("in_scope.txt")).unwrap(),
        "second attempt"
    );
    assert_eq!(
        fs::read_to_string(base_root.join("out_of_scope.txt")).unwrap(),
        "concurrent write to an untouched path",
        "the out-of-scope concurrent write must survive untouched by this commit"
    );
}

#[test]
fn commit_before_close_is_refused() {
    let fixture = tempfile::tempdir().unwrap();
    let base_root = fixture.path().join("base");
    let state_root = fixture.path().join("state");
    fs::create_dir_all(&base_root).unwrap();
    write(&base_root.join("a.txt"), "original");

    let id = TransactionId::new("not-closed-test");
    let tx = WorkspaceTransaction::open(id, &state_root, &base_root, vec![]).unwrap();
    // Deliberately never call tx.close().
    let refusal = tx
        .commit(&[], false)
        .expect_err("an Open (not Closed) transaction must refuse commit");
    assert!(
        matches!(refusal, aa_isolation::CommitRefusal::NotClosed { .. }),
        "the refusal must name the lifecycle violation: {refusal:?}"
    );
}
