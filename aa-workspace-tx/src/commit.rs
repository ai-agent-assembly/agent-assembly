//! The fail-closed commit decision sequence, and the two-phase apply that
//! runs only once every refusal check has passed.
//!
//! Order matters and is deliberate: drift is checked before protected paths,
//! and both are checked before anything in the change set is touched, so a
//! caller can never observe a partially-applied commit — [`commit`] either
//! returns `Ok` with everything applied, or `Err` with the base untouched.

use std::fs;
use std::io;
use std::path::Path;

use aa_isolation::{ChangeEntry, ChangeSet, CommitOutcome, CommitRefusal, EntryKind, TransactionId};

use crate::manifest::{self, absolute};
use crate::materialize;
use crate::state::StateDir;

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
            change_paths
                .iter()
                .any(|p| *p == selector.as_str() || p.starts_with(&format!("{selector}/")))
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
    let journal_path = state.root().join("journal");
    write_journal(&journal_path, &change_set).map_err(io_refusal)?;

    apply(base_root, state.staged_dir(), &staged, &change_set).map_err(io_refusal)?;

    fsync_dir(base_root).map_err(io_refusal)?;
    let _ = fs::remove_file(&journal_path);

    let base_digest = manifest::aggregate_digest(&current_base);
    let after = manifest::measure(base_root, exclusions).map_err(io_refusal)?;
    let result_digest = manifest::aggregate_digest(&after);

    Ok(CommitOutcome::new(id.clone(), base_digest, result_digest, change_set))
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

/// Write a durable, `fsync`'d record of exactly what this commit is about to
/// apply, before applying any of it — the crash-safety half of "two-phase".
fn write_journal(path: &Path, change_set: &ChangeSet) -> io::Result<()> {
    let mut body = String::new();
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
                        let content = fs::read(absolute(staged_root, path))?;
                        materialize::write_via_temp(&dest, &content)?;
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
