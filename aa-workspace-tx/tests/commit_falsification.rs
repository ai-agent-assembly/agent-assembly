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

/// AAASM-6305: a leftover apply journal means a crashed, failed or concurrent
/// apply over a possibly half-written base. Reopening the same transaction id
/// must refuse instead of re-measuring the base and re-materializing a fresh
/// staged copy over the in-flight one.
///
/// The "crash point" is constructed deterministically by hand-writing the
/// journal `commit::write_journal` leaves right before `apply` runs, rather
/// than racing a real `SIGKILL` against a real `fsync`.
#[test]
fn reopen_after_a_crash_mid_apply_refuses_and_touches_nothing() {
    let fixture = tempfile::tempdir().unwrap();
    let base_root = fixture.path().join("base");
    let state_root = fixture.path().join("state");
    fs::create_dir_all(&base_root).unwrap();
    write(&base_root.join("a.txt"), "original");

    let before = base_digest(&base_root);

    let id = TransactionId::new("crash-reopen-test");
    let tx = WorkspaceTransaction::open(id.clone(), &state_root, &base_root, vec![]).unwrap();

    // Positive control: a real staged change exists, so the transaction had
    // something to apply when it "crashed".
    write(&tx.staged_dir().join("a.txt"), "staged but never applied");
    let staged_manifest = aa_workspace_tx::manifest::measure(tx.staged_dir(), &[]).unwrap();
    assert_ne!(
        before,
        aa_workspace_tx::manifest::aggregate_digest(&staged_manifest),
        "the staged layer must differ from base for this crash scenario to mean anything"
    );

    let tx_state_dir = state_root.join(id.as_str());
    let journal_path = tx_state_dir.join("journal");
    fs::write(&journal_path, b"MOD a.txt\n").unwrap();
    drop(tx);

    let refused = WorkspaceTransaction::open(id, &state_root, &base_root, vec![]);
    match refused {
        Err(aa_workspace_tx::TransactionError::InterruptedApply { journal }) => {
            assert_eq!(journal, journal_path, "the error must name the leftover journal");
        }
        other => panic!(
            "reopen over a leftover journal must refuse, got {:?}",
            other.map(|_| ())
        ),
    }

    // Refusing must destroy nothing: the journal and the in-flight staged
    // edit survive, and the stale journal is never auto-applied to the base.
    assert!(journal_path.exists(), "the journal is evidence and must not be removed");
    assert_eq!(
        fs::read_to_string(tx_state_dir.join("staged").join("a.txt")).unwrap(),
        "staged but never applied",
        "refusing must not re-materialize over the in-flight staged edit"
    );
    assert_eq!(
        before,
        base_digest(&base_root),
        "a leftover journal must never be auto-applied"
    );
    assert_eq!(fs::read_to_string(base_root.join("a.txt")).unwrap(), "original");
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

/// AAASM-6305: the real CLI path opens each launch under a fresh session id,
/// so the leftover journal lives in a *different* transaction's directory.
/// It must still block a new transaction over the same base — and only that
/// base.
#[test]
fn a_leftover_journal_blocks_other_ids_over_the_same_base_but_not_other_bases() {
    let fixture = tempfile::tempdir().unwrap();
    let base_root = fixture.path().join("base");
    let other_base = fixture.path().join("other-base");
    let state_root = fixture.path().join("state");
    fs::create_dir_all(&base_root).unwrap();
    fs::create_dir_all(&other_base).unwrap();
    write(&base_root.join("a.txt"), "original");
    write(&other_base.join("b.txt"), "other");

    let crashed = TransactionId::new("crashed-session");
    drop(WorkspaceTransaction::open(crashed.clone(), &state_root, &base_root, vec![]).unwrap());
    let journal = format!("BASE {}\nMOD a.txt\n", base_root.canonicalize().unwrap().display());
    fs::write(state_root.join(crashed.as_str()).join("journal"), journal).unwrap();

    let same_base = WorkspaceTransaction::open(TransactionId::new("fresh-session"), &state_root, &base_root, vec![]);
    assert!(
        matches!(
            same_base,
            Err(aa_workspace_tx::TransactionError::InterruptedApply { .. })
        ),
        "a different id over the same base must refuse"
    );

    // Control: the same state root, a base the journal does not name.
    WorkspaceTransaction::open(TransactionId::new("fresh-session-2"), &state_root, &other_base, vec![])
        .expect("a journal scoped to another base must not block this one");
}

/// AAASM-6305: a failure *during* apply (not a crash) must not be reported as
/// "nothing changed". It returns ApplyInterrupted, sets the status, keeps the
/// BASE-scoped journal, and blocks the next transaction over that base.
#[test]
fn a_failed_apply_reports_apply_interrupted_and_blocks_the_next_open() {
    use std::os::unix::fs::PermissionsExt;

    let fixture = tempfile::tempdir().unwrap();
    let base_root = fixture.path().join("base");
    let state_root = fixture.path().join("state");
    fs::create_dir_all(base_root.join("d")).unwrap();
    write(&base_root.join("a.txt"), "original");

    let id = TransactionId::new("failed-apply-test");
    let mut tx = WorkspaceTransaction::open(id.clone(), &state_root, &base_root, vec![]).unwrap();
    write(&tx.staged_dir().join("d").join("new.txt"), "staged");
    tx.close();

    // Make the apply step fail: a read-only directory the change set writes into.
    let locked = base_root.join("d");
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o500)).unwrap();
    if fs::write(locked.join("probe"), b"x").is_ok() {
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o700)).unwrap();
        // Fail rather than skip: returning here would report PASS on a root
        // runner without ever exercising ApplyInterrupted.
        panic!("cannot induce an apply failure: this process writes into a 0500 directory (running as root?)");
    }

    let refusal = tx
        .commit(&[], false)
        .expect_err("apply into a read-only directory must fail");
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o700)).unwrap();

    let journal_path = state_root.join(id.as_str()).join("journal");
    match &refusal {
        aa_isolation::CommitRefusal::ApplyInterrupted { journal, .. } => {
            assert_eq!(journal, &journal_path.display().to_string());
        }
        other => panic!("a failed apply must be ApplyInterrupted, got {other:?}"),
    }
    let journal_body = fs::read_to_string(&journal_path).expect("the journal must be retained");
    assert!(
        journal_body.starts_with(&format!("BASE {}\n", base_root.canonicalize().unwrap().display())),
        "the journal must be scoped to the base: {journal_body:?}"
    );

    let next = WorkspaceTransaction::open(TransactionId::new("after-failure"), &state_root, &base_root, vec![]);
    assert!(
        matches!(next, Err(aa_workspace_tx::TransactionError::InterruptedApply { .. })),
        "the next transaction over the same base must refuse"
    );
}

/// AAASM-6412: a base directory symlink `d -> <outside>` must not let a
/// commit write, create or delete outside the base. The confined run
/// replaces the link with a real directory in the staged copy; without the
/// ancestor check `Modified d` + `Added d/f` pass every lexical check and
/// `d/f` lands under `<outside>`.
#[cfg(unix)]
#[test]
fn a_base_symlink_replaced_by_a_directory_cannot_redirect_the_commit_outside_the_base() {
    use std::os::unix::fs::symlink;

    let fixture = tempfile::tempdir().unwrap();
    let base_root = fixture.path().join("base");
    let outside = fixture.path().join("outside");
    let state_root = fixture.path().join("state");
    fs::create_dir_all(&base_root).unwrap();
    fs::create_dir_all(&outside).unwrap();
    write(&base_root.join("untouched.txt"), "control");
    symlink(&outside, base_root.join("d")).unwrap();

    let id = TransactionId::new("symlink-ancestor-test");
    let mut tx = WorkspaceTransaction::open(id, &state_root, &base_root, vec![]).unwrap();

    // Positive control: the staged copy really holds the link we replace, so
    // the scenario below is the one that was exploitable, not a lookalike.
    assert!(
        fs::symlink_metadata(tx.staged_dir().join("d"))
            .unwrap()
            .file_type()
            .is_symlink(),
        "the staged copy must start with the base's symlink"
    );
    fs::remove_file(tx.staged_dir().join("d")).unwrap();
    write(&tx.staged_dir().join("d").join("f"), "escaped");

    tx.close();
    let refusal = tx
        .commit(&[], false)
        .expect_err("a destination behind a symlinked base directory must refuse");
    assert!(
        matches!(&refusal, aa_isolation::CommitRefusal::BoundaryEscape { path } if path == "d/f"),
        "the refusal must be the boundary check on the nested path: {refusal:?}"
    );
    assert!(
        !outside.join("f").exists(),
        "nothing may be written through the base symlink"
    );
    assert!(
        fs::symlink_metadata(base_root.join("d"))
            .unwrap()
            .file_type()
            .is_symlink(),
        "the base symlink must be left exactly as it was"
    );
    assert_eq!(fs::read_to_string(base_root.join("untouched.txt")).unwrap(), "control");
}

/// Negative control for the test above: the same nested write with a real
/// directory in the base applies normally, so the refusal is caused by the
/// symlink and not by nesting.
#[test]
fn the_same_nested_change_without_a_base_symlink_applies() {
    let fixture = tempfile::tempdir().unwrap();
    let base_root = fixture.path().join("base");
    let state_root = fixture.path().join("state");
    fs::create_dir_all(base_root.join("d")).unwrap();
    write(&base_root.join("untouched.txt"), "control");

    let id = TransactionId::new("symlink-ancestor-control");
    let mut tx = WorkspaceTransaction::open(id, &state_root, &base_root, vec![]).unwrap();
    write(&tx.staged_dir().join("d").join("f"), "applied");

    tx.close();
    tx.commit(&[], false).expect("a plain nested add must apply");
    assert_eq!(fs::read_to_string(base_root.join("d").join("f")).unwrap(), "applied");
}

fn journal_exists_under(root: &Path) -> bool {
    fs::read_dir(root).unwrap().flatten().any(|e| {
        let p = e.path();
        (p.is_file() && e.file_name() == "journal") || (p.is_dir() && journal_exists_under(&p))
    })
}

/// AAASM-6418 (F13): a case-only rename (`a.txt` -> `A.txt`) diffs as
/// `Added A.txt` + `Deleted a.txt`. On a case-insensitive base the apply
/// writes `A.txt` over the very entry `a.txt` names and the deletion phase
/// then removes it, silently losing the file. The fold check refuses it
/// before the journal is written, on any filesystem, so this test is
/// hermetic: the change set is built by hand rather than by relying on the
/// host's case sensitivity.
#[test]
fn case_only_rename_is_refused_before_the_journal_and_nothing_is_applied() {
    let fixture = tempfile::tempdir().unwrap();
    let base_root = fixture.path().join("base");
    let state_root = fixture.path().join("state");
    fs::create_dir_all(&base_root).unwrap();
    write(&base_root.join("a.txt"), "precious");
    write(&base_root.join("untouched.txt"), "control");
    let before = base_digest(&base_root);

    let id = TransactionId::new("case-rename-test");
    let mut tx = WorkspaceTransaction::open(id, &state_root, &base_root, vec![]).unwrap();
    fs::remove_file(tx.staged_dir().join("a.txt")).unwrap();
    write(&tx.staged_dir().join("A.txt"), "precious");
    // Positive control: the staged tree really holds both spellings' effect.
    let names: Vec<String> = fs::read_dir(tx.staged_dir())
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    assert!(
        names.contains(&"A.txt".to_string()),
        "staged rename must exist: {names:?}"
    );

    tx.close();
    let refusal = tx
        .commit(&[], false)
        .expect_err("a change set that differs only by case between an add and a delete must refuse");
    assert!(
        matches!(&refusal, aa_isolation::CommitRefusal::BoundaryEscape { path } if path.eq_ignore_ascii_case("a.txt")),
        "the refusal must name the colliding path: {refusal:?}"
    );
    assert!(
        !journal_exists_under(&state_root),
        "no journal may be written for a refusal"
    );
    assert_eq!(fs::read_to_string(base_root.join("a.txt")).unwrap(), "precious");
    assert_eq!(base_digest(&base_root), before, "the base must be untouched");
}

/// Negative control: a rename to a different name (not a case fold) applies,
/// so the refusal above is caused by the fold and not by renames in general.
#[test]
fn a_rename_to_a_different_name_still_applies() {
    let fixture = tempfile::tempdir().unwrap();
    let base_root = fixture.path().join("base");
    let state_root = fixture.path().join("state");
    fs::create_dir_all(&base_root).unwrap();
    write(&base_root.join("a.txt"), "moved");

    let id = TransactionId::new("rename-control");
    let mut tx = WorkspaceTransaction::open(id, &state_root, &base_root, vec![]).unwrap();
    fs::remove_file(tx.staged_dir().join("a.txt")).unwrap();
    write(&tx.staged_dir().join("b.txt"), "moved");
    tx.close();
    tx.commit(&[], false).expect("a plain rename must apply");
    assert!(!base_root.join("a.txt").exists());
    assert_eq!(fs::read_to_string(base_root.join("b.txt")).unwrap(), "moved");
}

/// True when `dir`'s filesystem folds case (macOS APFS default).
fn fs_is_case_insensitive(dir: &Path) -> bool {
    let probe = dir.join("CaseProbe.tmp");
    fs::write(&probe, b"x").unwrap();
    let folded = dir.join("caseprobe.tmp").exists();
    fs::remove_file(&probe).unwrap();
    folded
}

/// AAASM-6418 (F13), host-gated: the real rename on a case-insensitive
/// filesystem, exactly as `git mv a.txt A.txt` would leave the staged copy.
#[test]
fn real_case_insensitive_fs_case_only_rename_does_not_lose_the_file() {
    let fixture = tempfile::tempdir().unwrap();
    if !fs_is_case_insensitive(fixture.path()) {
        eprintln!("SKIP: temp dir is on a case-sensitive filesystem; the hermetic fold test covers the logic");
        return;
    }
    let base_root = fixture.path().join("base");
    let state_root = fixture.path().join("state");
    fs::create_dir_all(&base_root).unwrap();
    write(&base_root.join("a.txt"), "precious");

    let id = TransactionId::new("real-case-rename");
    let mut tx = WorkspaceTransaction::open(id, &state_root, &base_root, vec![]).unwrap();
    fs::rename(tx.staged_dir().join("a.txt"), tx.staged_dir().join("A.txt")).unwrap();
    tx.close();
    let result = tx.commit(&[], false);
    assert!(result.is_err(), "case-only rename must be refused, got {result:?}");
    assert_eq!(
        fs::read_to_string(base_root.join("a.txt")).expect("the base file must still exist"),
        "precious"
    );
}

/// AAASM-6418 (F12): the protected gate folds case, so a case variant of a
/// selector is never an unprotected path (over-protect, never under-protect).
#[test]
fn protected_gate_fires_on_case_variant_of_selector() {
    let fixture = tempfile::tempdir().unwrap();
    let base_root = fixture.path().join("base");
    let state_root = fixture.path().join("state");
    fs::create_dir_all(&base_root).unwrap();
    write(&base_root.join("keep.txt"), "x");

    let id = TransactionId::new("protect-case");
    let mut tx = WorkspaceTransaction::open(id, &state_root, &base_root, vec![]).unwrap();
    write(&tx.staged_dir().join(".ENV"), "SECRET=1");
    write(&tx.staged_dir().join("Secrets").join("k"), "k");
    tx.close();
    let refusal = tx
        .commit(&[".env".to_string(), "secrets/k".to_string()], false)
        .expect_err("a case variant of a protected selector must hit the gate");
    assert!(
        matches!(&refusal, aa_isolation::CommitRefusal::ProtectedPathNotApproved { selectors }
            if selectors == &[".env".to_string(), "secrets/k".to_string()]),
        "{refusal:?}"
    );
    assert!(!base_root.join(".ENV").exists());
}

/// Negative control: a selector that is only a string-prefix of a name (not a
/// path-component prefix, not a case variant) does not fire.
#[test]
fn protected_gate_does_not_fire_on_an_unrelated_name() {
    let fixture = tempfile::tempdir().unwrap();
    let base_root = fixture.path().join("base");
    let state_root = fixture.path().join("state");
    fs::create_dir_all(&base_root).unwrap();
    write(&base_root.join("keep.txt"), "x");

    let id = TransactionId::new("protect-case-control");
    let mut tx = WorkspaceTransaction::open(id, &state_root, &base_root, vec![]).unwrap();
    write(&tx.staged_dir().join(".envx"), "not protected");
    tx.close();
    tx.commit(&[".env".to_string()], false)
        .expect(".envx is not .env nor under it");
    assert!(base_root.join(".envx").exists());
}

#[cfg(unix)]
fn mode_of(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    fs::metadata(path).unwrap().permissions().mode() & 0o7777
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}

/// AAASM-6418 (F6): committing a modified file must not change its mode.
/// Run through the whole open/modify/commit cycle so copy-in is covered too.
#[cfg(unix)]
fn commit_modified_with_mode(mode: u32, id: &str) -> u32 {
    let fixture = tempfile::tempdir().unwrap();
    let base_root = fixture.path().join("base");
    let state_root = fixture.path().join("state");
    fs::create_dir_all(&base_root).unwrap();
    write(&base_root.join("f"), "before");
    set_mode(&base_root.join("f"), mode);

    let mut tx = WorkspaceTransaction::open(TransactionId::new(id), &state_root, &base_root, vec![]).unwrap();
    // The confined process rewrites content in place (keeps whatever mode the staged copy has).
    fs::write(tx.staged_dir().join("f"), "after").unwrap();
    tx.close();
    tx.commit(&[], false).expect("commit");
    assert_eq!(fs::read_to_string(base_root.join("f")).unwrap(), "after");
    mode_of(&base_root.join("f"))
}

#[cfg(unix)]
#[test]
fn modified_0600_file_keeps_0600() {
    assert_eq!(commit_modified_with_mode(0o600, "mode-600"), 0o600);
}

#[cfg(unix)]
#[test]
fn modified_0755_script_keeps_exec_bit() {
    assert_eq!(commit_modified_with_mode(0o755, "mode-755"), 0o755);
}

/// Control: the common default also survives, so the two tests above fail on
/// the old umask-derived behaviour for the mode they change, not for all modes.
#[cfg(unix)]
#[test]
fn modified_0644_file_keeps_0644() {
    assert_eq!(commit_modified_with_mode(0o644, "mode-644"), 0o644);
}

/// An added file takes the staged file's permission bits (executable bit
/// kept) but never setuid/setgid/sticky.
#[cfg(unix)]
#[test]
fn added_file_keeps_exec_bit_and_never_gets_setuid_bits() {
    let fixture = tempfile::tempdir().unwrap();
    let base_root = fixture.path().join("base");
    let state_root = fixture.path().join("state");
    fs::create_dir_all(&base_root).unwrap();
    write(&base_root.join("keep"), "x");

    let mut tx = WorkspaceTransaction::open(TransactionId::new("mode-added"), &state_root, &base_root, vec![]).unwrap();
    write(&tx.staged_dir().join("run.sh"), "#!/bin/sh\n");
    set_mode(&tx.staged_dir().join("run.sh"), 0o4755);
    write(&tx.staged_dir().join("secret"), "s");
    set_mode(&tx.staged_dir().join("secret"), 0o600);
    tx.close();
    tx.commit(&[], false).expect("commit");
    assert_eq!(mode_of(&base_root.join("run.sh")), 0o755);
    assert_eq!(mode_of(&base_root.join("secret")), 0o600);
}

/// Copy-in preserves the base mode, so a workspace script stays runnable in
/// the staged tree.
#[cfg(unix)]
#[test]
fn copy_in_preserves_the_base_file_mode() {
    let fixture = tempfile::tempdir().unwrap();
    let base_root = fixture.path().join("base");
    let state_root = fixture.path().join("state");
    fs::create_dir_all(&base_root).unwrap();
    write(&base_root.join("tool.sh"), "#!/bin/sh\n");
    set_mode(&base_root.join("tool.sh"), 0o755);
    write(&base_root.join("key"), "k");
    set_mode(&base_root.join("key"), 0o600);

    let tx = WorkspaceTransaction::open(TransactionId::new("mode-copy-in"), &state_root, &base_root, vec![]).unwrap();
    assert_eq!(mode_of(&tx.staged_dir().join("tool.sh")), 0o755);
    assert_eq!(mode_of(&tx.staged_dir().join("key")), 0o600);
}
