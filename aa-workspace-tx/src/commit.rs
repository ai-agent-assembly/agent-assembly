//! The fail-closed commit decision sequence, and the two-phase apply that
//! runs only once every refusal check has passed.
//!
//! Order matters and is deliberate: drift is checked before protected paths,
//! and both are checked before anything in the change set is touched, so a
//! caller can never observe a partially-applied commit from a refusal —
//! every refusal above returns `Err` with the base untouched. The one
//! exception is a failure *during* apply, after the journal is written:
//! that returns [`CommitRefusal::ApplyInterrupted`], and the base may be
//! partially modified.

use std::fs;
use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use aa_isolation::{ChangeEntry, ChangeSet, CommitOutcome, CommitRefusal, EntryKind, TransactionId};

use crate::manifest::{self, absolute};
use crate::materialize;
use crate::state::{self, StateDir};

/// Run the full fail-closed commit sequence. See module docs for the order
/// and this file's section comments for what each stage refuses.
#[allow(clippy::too_many_arguments)]
pub fn commit(
    id: &TransactionId,
    state: &StateDir,
    base_root: &Path,
    exclusions: &[String],
    opened_base_manifest: &aa_isolation::BaseManifest,
    protected: &[String],
    approved: bool,
) -> Result<CommitOutcome, CommitRefusal> {
    // --- Measure both sides freshly, right before deciding anything. ---
    let current_base = manifest::measure(base_root, exclusions).map_err(io_refusal)?;
    let staged = manifest::measure(state.staged_dir(), &[]).map_err(io_refusal)?;
    let change_set = diff(opened_base_manifest, &staged);
    let change_paths = change_set.paths();

    // --- 1. Base drift, scoped to the change set only. ---
    let drift = manifest::drifted_paths(opened_base_manifest, &current_base);
    let drift_in_scope: Vec<String> = drift
        .into_iter()
        .filter(|p| change_paths.contains(p.as_str()))
        .collect();
    if !drift_in_scope.is_empty() {
        return Err(CommitRefusal::BaseDrift { paths: drift_in_scope });
    }

    // --- 2. Protected-path gate: all-or-nothing, no partial commit. ---
    let hit_selectors: Vec<String> = protected
        .iter()
        .filter(|selector| {
            // Folded comparison: on a case-insensitive base `.ENV` IS `.env`, and the
            // selector may name a path that does not exist yet. Over-matching on a
            // case-sensitive filesystem costs an extra approval, never a missed one.
            let selector = fold(selector);
            change_paths.iter().any(|p| {
                let p = fold(p);
                p == selector || p.starts_with(&format!("{selector}/"))
            })
        })
        .cloned()
        .collect();
    if !hit_selectors.is_empty() && !approved {
        return Err(CommitRefusal::ProtectedPathNotApproved {
            selectors: hit_selectors,
        });
    }

    // --- 3. Applier-side boundary check on every changed path. ---
    for path in &change_paths {
        if !is_normal_relative(path) {
            return Err(CommitRefusal::BoundaryEscape {
                path: (*path).to_string(),
            });
        }
    }

    // --- 3b. No destination may sit behind a symlinked base directory. ---
    // `is_normal_relative` is lexical only: a symlink such as `d -> /outside`
    // in the base would otherwise let `create_dir_all`/write/remove follow it
    // out of the base once the agent replaced `d` with a real directory in
    // the staged copy. Refused here, before the journal or any mutation.
    for path in &change_paths {
        if ancestor_is_symlink(base_root, path).map_err(io_refusal)? {
            return Err(CommitRefusal::BoundaryEscape {
                path: (*path).to_string(),
            });
        }
    }

    // --- 3c. No two touched paths, and no added path and existing base entry, may
    // collide under case/normalization folding. ---
    // A case-only rename (`a.txt` -> `A.txt`) diffs as `Added A.txt` + `Deleted a.txt`. On a
    // case-insensitive base the write replaces the entry `a.txt` names and the deletion phase
    // then removes the file just written. Refused on every filesystem so the decision does not
    // depend on probing the host. `BoundaryEscape` is reused to keep `CommitRefusal` unchanged;
    // the path text says what the refusal really is.
    if let Some(detail) = fold_collision(base_root, &change_set).map_err(io_refusal)? {
        return Err(CommitRefusal::BoundaryEscape { path: detail });
    }

    // --- 4. Copy-never-hardlink invariant, re-verified at commit time. ---
    for entry in change_set.entries() {
        if matches!(entry, ChangeEntry::Added { .. } | ChangeEntry::Modified { .. }) {
            let staged_path = absolute(state.staged_dir(), entry.path());
            let base_path = absolute(base_root, entry.path());
            if materialize::shares_inode(&staged_path, &base_path).map_err(io_refusal)? {
                return Err(CommitRefusal::HardlinkToBase {
                    path: entry.path().to_string(),
                });
            }
        }
    }

    // --- Every refusal check passed. Two-phase apply. ---
    let journal_path = state.root().join(state::JOURNAL_FILE);
    write_journal(&journal_path, base_root, &change_set).map_err(io_refusal)?;

    // From here the base may change. A failure leaves the journal in place on
    // purpose: it is what makes the next transaction over this base refuse.
    apply(base_root, state.staged_dir(), &staged, &change_set).map_err(|e| CommitRefusal::ApplyInterrupted {
        journal: journal_path.display().to_string(),
        detail: e.to_string(),
    })?;

    fsync_dir(base_root).map_err(io_refusal)?;
    let _ = fs::remove_file(&journal_path);

    let base_digest = manifest::aggregate_digest(&current_base);
    let after = manifest::measure(base_root, exclusions).map_err(io_refusal)?;
    let result_digest = manifest::aggregate_digest(&after);

    Ok(CommitOutcome::new(id.clone(), base_digest, result_digest, change_set))
}

/// Case + normalization folding used for protected-path matching and collision
/// detection: NFD, per-character lowercase with `ς` -> `σ` and `ß` -> `ss`, then NFC,
/// so NFC/NFD spellings of one name and final-sigma variants fold equal. Per-character
/// (not `str::to_lowercase`) because the latter is context-sensitive for sigma.
/// This is an approximation of full Unicode case folding; it over-matches, never
/// under-matches, the common fold pairs filesystems apply.
fn fold(s: &str) -> String {
    use unicode_normalization::UnicodeNormalization;
    let mut out = String::with_capacity(s.len());
    for c in s.nfd() {
        match c {
            'ς' => out.push('σ'),
            'ß' | 'ẞ' => out.push_str("ss"),
            _ => out.extend(c.to_lowercase()),
        }
    }
    out.nfc().collect()
}

/// Detect a path-fold collision the apply step could not survive on a folding
/// filesystem. Returns a description naming the offending path, or `None`.
///
/// 1. Any two touched paths (Added/Modified/Deleted) that share a component-wise
///    folded prefix but spell it differently: `Added A.txt` + `Deleted a.txt`,
///    `Added a`+`Added A`, `Deleted foo` + `Added FOO/x`.
/// 2. An Added path that, component by component, matches an existing base entry
///    only through folding (that entry is not in the change set, or it would have
///    been caught above).
fn fold_collision(base_root: &Path, change_set: &ChangeSet) -> io::Result<Option<String>> {
    use std::collections::HashMap;
    let mut seen: HashMap<String, String> = HashMap::new();
    for entry in change_set.entries() {
        let mut folded = String::new();
        let mut exact = String::new();
        for comp in entry.path().split('/') {
            if !folded.is_empty() {
                folded.push('/');
                exact.push('/');
            }
            folded.push_str(&fold(comp));
            exact.push_str(comp);
            match seen.get(&folded) {
                Some(prev) if *prev != exact => {
                    return Ok(Some(format!(
                        "{} (case/normalization collision with {prev}; not a boundary escape)",
                        entry.path()
                    )));
                }
                Some(_) => {}
                None => {
                    seen.insert(folded.clone(), exact.clone());
                }
            }
        }
    }
    for entry in change_set.entries() {
        if !matches!(entry, ChangeEntry::Added { .. }) {
            continue;
        }
        let mut current = base_root.to_path_buf();
        for comp in entry.path().split('/') {
            let names: Vec<String> = match fs::read_dir(&current) {
                Ok(rd) => rd
                    .flatten()
                    .map(|e| e.file_name().to_string_lossy().into_owned())
                    .collect(),
                Err(e) if e.kind() == io::ErrorKind::NotFound => break,
                Err(e) => return Err(e),
            };
            if names.iter().any(|n| n == comp) {
                current.push(comp);
                continue;
            }
            let folded = fold(comp);
            if let Some(other) = names.iter().find(|n| fold(n) == folded) {
                return Ok(Some(format!(
                    "{} (case/normalization collision with existing base entry {other}; not a boundary escape)",
                    entry.path()
                )));
            }
            break;
        }
    }
    Ok(None)
}

fn io_refusal(e: io::Error) -> CommitRefusal {
    CommitRefusal::LockUnavailable {
        detail: format!("I/O error during commit: {e}"),
    }
}

/// Diff an opening-time base manifest against a freshly-measured staged
/// workspace manifest into the exact set of changed paths.
pub fn diff(base: &aa_isolation::BaseManifest, staged: &aa_isolation::BaseManifest) -> ChangeSet {
    let mut entries = Vec::new();
    for entry in staged.entries() {
        match base.entry(entry.path()) {
            None => entries.push(ChangeEntry::Added {
                path: entry.path().to_string(),
            }),
            Some(before) if !entries_equal(before, entry) => entries.push(ChangeEntry::Modified {
                path: entry.path().to_string(),
            }),
            Some(_) => {}
        }
    }
    for entry in base.entries() {
        if staged.entry(entry.path()).is_none() {
            entries.push(ChangeEntry::Deleted {
                path: entry.path().to_string(),
            });
        }
    }
    ChangeSet::new(entries)
}

fn entries_equal(a: &aa_isolation::ManifestEntry, b: &aa_isolation::ManifestEntry) -> bool {
    a.kind() == b.kind() && a.digest() == b.digest() && a.symlink_target() == b.symlink_target()
}

/// A path is safe to apply only if it is relative, non-empty, and contains
/// no parent-directory or root component — i.e. it cannot name anything
/// outside the tree it was measured under.
fn is_normal_relative(path: &str) -> bool {
    if path.is_empty() {
        return false;
    }
    let p = Path::new(path);
    if p.is_absolute() {
        return false;
    }
    p.components().all(|c| matches!(c, std::path::Component::Normal(_)))
}

/// Whether any proper ancestor of `path` (below `base_root`) is currently a
/// symlink in the base. A component that does not exist ends the walk: nothing
/// deeper can be a link, and `create_dir_all` will create real directories.
/// The final component is deliberately not inspected — replacing or deleting a
/// symlink entry itself never follows it.
fn ancestor_is_symlink(base_root: &Path, path: &str) -> io::Result<bool> {
    let mut components: Vec<_> = Path::new(path).components().collect();
    components.pop();
    let mut current = base_root.to_path_buf();
    for component in components {
        current.push(component);
        match fs::symlink_metadata(&current) {
            Ok(meta) if meta.file_type().is_symlink() => return Ok(true),
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(false),
            Err(e) => return Err(e),
        }
    }
    Ok(false)
}

/// Write a durable, `fsync`'d record of exactly what this commit is about to
/// apply, before applying any of it — the crash-safety half of "two-phase".
///
/// The first line names the base directory so a later transaction over a
/// different base is not blocked by this journal.
fn write_journal(path: &Path, base_root: &Path, change_set: &ChangeSet) -> io::Result<()> {
    let mut body = format!("{}{}\n", state::JOURNAL_BASE_PREFIX, state::base_key(base_root));
    for entry in change_set.entries() {
        let verb = match entry {
            ChangeEntry::Added { .. } => "ADD",
            ChangeEntry::Modified { .. } => "MOD",
            ChangeEntry::Deleted { .. } => "DEL",
            // aa_isolation::ChangeEntry is #[non_exhaustive]; a future verb
            // still needs a journal line so a partial journal is never
            // silently produced.
            _ => "UNKNOWN",
        };
        body.push_str(verb);
        body.push(' ');
        body.push_str(entry.path());
        body.push('\n');
    }
    materialize::write_via_temp(path, body.as_bytes())?;
    let file = fs::File::open(path)?;
    file.sync_all()?;
    fsync_dir(path.parent().unwrap_or(Path::new(".")))?;
    Ok(())
}

fn fsync_dir(dir: &Path) -> io::Result<()> {
    // Best-effort on platforms/paths where a directory cannot be opened for
    // read (rare); the file-level `sync_all` above is the load-bearing call.
    if let Ok(f) = fs::File::open(dir) {
        let _ = f.sync_all();
    }
    Ok(())
}

/// Apply every entry in `change_set` to `base_root`, sourcing Added/Modified
/// content from `staged_root` (never following a symlink to get there) and
/// removing Deleted paths.
fn apply(
    base_root: &Path,
    staged_root: &Path,
    staged_manifest: &aa_isolation::BaseManifest,
    change_set: &ChangeSet,
) -> io::Result<()> {
    // Directories from the staged side that are newly added must exist
    // before files inside them are written.
    for entry in change_set.entries() {
        if let ChangeEntry::Added { path } | ChangeEntry::Modified { path } = entry {
            if let Some(staged_entry) = staged_manifest.entry(path) {
                if staged_entry.kind() == EntryKind::Directory {
                    fs::create_dir_all(absolute(base_root, path))?;
                }
            }
        }
    }
    for entry in change_set.entries() {
        match entry {
            ChangeEntry::Added { path } | ChangeEntry::Modified { path } => {
                let Some(staged_entry) = staged_manifest.entry(path) else {
                    continue;
                };
                let dest = absolute(base_root, path);
                match staged_entry.kind() {
                    EntryKind::Directory => { /* already created above */ }
                    EntryKind::File => {
                        if let Some(parent) = dest.parent() {
                            fs::create_dir_all(parent)?;
                        }
                        let src = absolute(staged_root, path);
                        let content = fs::read(&src)?;
                        // Modified keeps the base file's current mode (an agent chmod is not a
                        // change); Added takes the staged file's bits minus setuid/setgid/sticky.
                        let mode = match fs::symlink_metadata(&dest) {
                            Ok(m) if m.file_type().is_file() => m.mode() & 0o777,
                            _ => fs::symlink_metadata(&src)?.mode() & 0o777,
                        };
                        materialize::write_via_temp_with_mode(&dest, &content, mode)?;
                    }
                    EntryKind::Symlink => {
                        if let Some(parent) = dest.parent() {
                            fs::create_dir_all(parent)?;
                        }
                        if dest.exists() || fs::symlink_metadata(&dest).is_ok() {
                            let _ = fs::remove_file(&dest);
                        }
                        let target = staged_entry.symlink_target().unwrap_or_default();
                        materialize::create_symlink_via_temp(target, &dest)?;
                    }
                    // #[non_exhaustive]: fail closed on an entry kind this
                    // crate's apply step does not implement.
                    _ => {
                        return Err(io::Error::new(
                            io::ErrorKind::Unsupported,
                            format!("unsupported entry kind for {path}"),
                        ));
                    }
                }
            }
            ChangeEntry::Deleted { .. } => {}
            // #[non_exhaustive]: fail closed rather than guess at a verb
            // this crate does not implement apply semantics for.
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    format!("unsupported change verb for {}", entry.path()),
                ));
            }
        }
    }
    // Deletions last, deepest paths first, so a directory is empty by the
    // time its own removal is attempted.
    let mut deletions: Vec<&str> = change_set
        .entries()
        .iter()
        .filter_map(|e| match e {
            ChangeEntry::Deleted { path } => Some(path.as_str()),
            _ => None,
        })
        .collect();
    deletions.sort_by_key(|p| std::cmp::Reverse(p.matches('/').count()));
    for path in deletions {
        let target = absolute(base_root, path);
        let meta = fs::symlink_metadata(&target)?;
        if meta.is_dir() {
            fs::remove_dir(&target)?;
        } else {
            fs::remove_file(&target)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn added(p: &str) -> ChangeEntry {
        ChangeEntry::Added { path: p.into() }
    }
    fn modified(p: &str) -> ChangeEntry {
        ChangeEntry::Modified { path: p.into() }
    }
    fn deleted(p: &str) -> ChangeEntry {
        ChangeEntry::Deleted { path: p.into() }
    }

    /// Hermetic: the change set is built by hand, so no filesystem folding is involved.
    fn collides(base_files: &[&str], entries: Vec<ChangeEntry>) -> bool {
        let base = tempfile::tempdir().unwrap();
        for f in base_files {
            let p = base.path().join(f);
            fs::create_dir_all(p.parent().unwrap()).unwrap();
            fs::write(p, f).unwrap();
        }
        fold_collision(base.path(), &ChangeSet::new(entries)).unwrap().is_some()
    }

    #[test]
    fn added_plus_deleted_case_pair_collides() {
        assert!(collides(&["a.txt"], vec![added("A.txt"), deleted("a.txt")]));
    }

    #[test]
    fn added_plus_added_case_pair_collides() {
        assert!(collides(&[], vec![added("x"), added("X")]));
    }

    #[test]
    fn modified_plus_added_case_pair_collides() {
        assert!(collides(&["a.txt"], vec![modified("a.txt"), added("A.TXT")]));
    }

    #[test]
    fn modified_plus_deleted_case_pair_collides() {
        assert!(collides(
            &["a.txt", "B.txt"],
            vec![modified("a.txt"), deleted("B.txt"), added("b.txt")]
        ));
        assert!(collides(&["a.txt", "B.txt"], vec![modified("B.txt"), deleted("b.txt")]));
    }

    #[test]
    fn deleted_dir_plus_added_file_under_case_variant_dir_collides() {
        assert!(collides(
            &["foo/old.txt"],
            vec![deleted("foo/old.txt"), deleted("foo"), added("FOO"), added("FOO/x")]
        ));
        assert!(collides(&["foo/old.txt"], vec![deleted("foo"), added("FOO/x")]));
    }

    #[test]
    fn added_path_fold_colliding_with_an_unchanged_base_entry_collides() {
        assert!(collides(&["a.txt"], vec![added("A.txt")]));
        assert!(collides(&["Dir/k"], vec![added("dir/new")]));
    }

    #[test]
    fn nfc_nfd_spellings_collide() {
        let nfc = "caf\u{e9}.txt";
        let nfd = "cafe\u{301}.txt";
        assert_ne!(nfc, nfd);
        assert!(collides(&[], vec![added(nfd), deleted(nfc)]));
        assert!(collides(&[nfc], vec![added(nfd)]));
    }

    #[test]
    fn final_sigma_and_sharp_s_spellings_collide() {
        // `str::to_lowercase` maps a word-final capital sigma to `ς` but a lone one to `σ`.
        assert_eq!(
            fold("\u{39f}\u{394}\u{39f}\u{3a3}"),
            fold("\u{3bf}\u{3b4}\u{3bf}\u{3c3}")
        );
        assert_eq!(
            fold("\u{3bf}\u{3b4}\u{3bf}\u{3c2}"),
            fold("\u{3bf}\u{3b4}\u{3bf}\u{3c3}")
        );
        assert!(collides(&[], vec![added("\u{3bf}\u{3c2}"), deleted("\u{3bf}\u{3c3}")]));
        assert_eq!(fold("Stra\u{df}e"), fold("STRASSE"));
    }

    /// Controls: identical spellings, unrelated names and nested distinct names never collide.
    #[test]
    fn unrelated_and_identical_paths_do_not_collide() {
        assert!(!collides(&["a.txt"], vec![modified("a.txt")]));
        assert!(!collides(&["a.txt"], vec![deleted("a.txt"), added("b.txt")]));
        assert!(!collides(&["d/x"], vec![modified("d/x"), added("d/y")]));
        assert!(!collides(&["d/x"], vec![deleted("d/x"), added("d/x2")]));
    }

    /// Control on a case-sensitive base: unchanged coexisting `A` and `a` plus an unrelated add.
    #[test]
    fn unchanged_coexisting_case_variants_are_unaffected() {
        let probe = tempfile::tempdir().unwrap();
        fs::write(probe.path().join("P"), b"x").unwrap();
        if probe.path().join("p").exists() {
            eprintln!("SKIP: case-insensitive filesystem cannot hold both A and a");
            return;
        }
        assert!(!collides(&["A", "a"], vec![added("b")]));
        assert!(!collides(&["A", "a"], vec![modified("A")]));
        assert!(!collides(&["A/x", "a/y"], vec![added("A/z")]));
    }
}
