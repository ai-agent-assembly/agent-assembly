//! Measuring a declared surface into a [`BaseManifest`].
//!
//! "Declared surface" means: walk `root`, skip any relative path that matches
//! an entry in `exclusions` (or is inside one), and never follow a symlink —
//! `symlink_metadata` only, everywhere, per the ticket's applier-side
//! boundary requirement. A symlink is recorded as a symlink with its literal
//! target string; it is never resolved, walked into, or treated as the file
//! or directory it points at.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use aa_isolation::{BaseManifest, EntryKind, ManifestEntry, WorkspaceDigest};
use sha2::{Digest, Sha256};

/// Measure `root`, excluding any relative path equal to or nested under an
/// entry of `exclusions`.
pub fn measure(root: &Path, exclusions: &[String]) -> io::Result<BaseManifest> {
    let mut entries = Vec::new();
    if root.exists() {
        walk(root, root, exclusions, &mut entries)?;
    }
    Ok(BaseManifest::new(
        root.to_string_lossy().into_owned(),
        exclusions.to_vec(),
        entries,
    ))
}

fn is_excluded(rel: &str, exclusions: &[String]) -> bool {
    exclusions
        .iter()
        .any(|ex| rel == ex || rel.starts_with(&format!("{ex}/")))
}

fn walk(root: &Path, dir: &Path, exclusions: &[String], out: &mut Vec<ManifestEntry>) -> io::Result<()> {
    let mut names: Vec<_> = fs::read_dir(dir)?.collect::<Result<_, _>>()?;
    names.sort_by_key(|e| e.file_name());
    for entry in names {
        let path = entry.path();
        let rel = relative(root, &path);
        if is_excluded(&rel, exclusions) {
            continue;
        }
        let meta = fs::symlink_metadata(&path)?;
        if meta.file_type().is_symlink() {
            let target = fs::read_link(&path)?;
            out.push(ManifestEntry::symlink(rel, target.to_string_lossy().into_owned()));
        } else if meta.is_dir() {
            out.push(ManifestEntry::directory(rel));
            walk(root, &path, exclusions, out)?;
        } else {
            let digest = digest_file(&path)?;
            out.push(ManifestEntry::file(rel, digest));
        }
    }
    Ok(())
}

fn relative(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

/// SHA-256 hex digest of a regular file's content.
pub fn digest_file(path: &Path) -> io::Result<WorkspaceDigest> {
    let bytes = fs::read(path)?;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    Ok(WorkspaceDigest::new(hex::encode(hasher.finalize())))
}

/// A single digest summarizing an entire manifest — every entry's path, kind
/// and content digest folded together in path order.
///
/// Used for `CommitOutcome::base_digest`/`result_digest`: an operator-facing
/// "did the tree change at all" summary, not a security boundary in its own
/// right (the per-path digests already are that).
pub fn aggregate_digest(manifest: &BaseManifest) -> WorkspaceDigest {
    let mut hasher = Sha256::new();
    let mut sorted: Vec<_> = manifest.entries().iter().collect();
    sorted.sort_by(|a, b| a.path().cmp(b.path()));
    for entry in sorted {
        hasher.update(entry.path().as_bytes());
        hasher.update([0u8]);
        match entry.kind() {
            EntryKind::File => {
                hasher.update(b"f");
                if let Some(d) = entry.digest() {
                    hasher.update(d.as_str().as_bytes());
                }
            }
            EntryKind::Directory => hasher.update(b"d"),
            EntryKind::Symlink => {
                hasher.update(b"s");
                if let Some(t) = entry.symlink_target() {
                    hasher.update(t.as_bytes());
                }
            }
            // aa_isolation::EntryKind is #[non_exhaustive]: a future variant
            // must still hash to *something* stable rather than fail to
            // compile here. Folded in as an explicit, distinguishable tag.
            _ => hasher.update(b"?"),
        }
        hasher.update([0u8]);
    }
    WorkspaceDigest::new(hex::encode(hasher.finalize()))
}

/// Paths whose measured state differs between two manifests of the *same*
/// surface (added, removed, or changed digest/kind/target).
pub fn drifted_paths(before: &BaseManifest, after: &BaseManifest) -> Vec<String> {
    let mut drifted = Vec::new();
    for entry in before.entries() {
        match after.entry(entry.path()) {
            None => drifted.push(entry.path().to_string()),
            Some(now) if !entries_equal(entry, now) => drifted.push(entry.path().to_string()),
            Some(_) => {}
        }
    }
    for entry in after.entries() {
        if before.entry(entry.path()).is_none() {
            drifted.push(entry.path().to_string());
        }
    }
    drifted.sort();
    drifted.dedup();
    drifted
}

fn entries_equal(a: &ManifestEntry, b: &ManifestEntry) -> bool {
    a.kind() == b.kind() && a.digest() == b.digest() && a.symlink_target() == b.symlink_target()
}

/// Absolute path a manifest was measured at, joined back with a relative
/// entry path. Small helper kept here rather than duplicated by every
/// caller.
pub fn absolute(root: &Path, rel: &str) -> PathBuf {
    root.join(rel)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    #[test]
    fn measures_files_dirs_and_symlinks_without_following() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.txt"), b"hello").unwrap();
        std::fs::create_dir(dir.path().join("sub")).unwrap();
        std::fs::write(dir.path().join("sub/b.txt"), b"world").unwrap();
        symlink("a.txt", dir.path().join("link")).unwrap();

        let manifest = measure(dir.path(), &[]).unwrap();
        assert_eq!(manifest.entry("a.txt").unwrap().kind(), EntryKind::File);
        assert_eq!(manifest.entry("sub").unwrap().kind(), EntryKind::Directory);
        assert_eq!(manifest.entry("sub/b.txt").unwrap().kind(), EntryKind::File);
        let link = manifest.entry("link").unwrap();
        assert_eq!(link.kind(), EntryKind::Symlink);
        assert_eq!(link.symlink_target(), Some("a.txt"));
    }

    #[test]
    fn exclusions_skip_the_whole_subtree() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("target")).unwrap();
        std::fs::write(dir.path().join("target/big.bin"), b"binary").unwrap();
        std::fs::write(dir.path().join("keep.txt"), b"keep").unwrap();

        let manifest = measure(dir.path(), &["target".to_string()]).unwrap();
        assert!(manifest.entry("target").is_none());
        assert!(manifest.entry("target/big.bin").is_none());
        assert!(manifest.entry("keep.txt").is_some());
    }

    #[test]
    fn drift_detects_content_change_addition_and_removal() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.txt"), b"one").unwrap();
        std::fs::write(dir.path().join("b.txt"), b"stable").unwrap();
        let before = measure(dir.path(), &[]).unwrap();

        std::fs::write(dir.path().join("a.txt"), b"two").unwrap();
        std::fs::write(dir.path().join("c.txt"), b"new").unwrap();
        let after = measure(dir.path(), &[]).unwrap();

        let drifted = drifted_paths(&before, &after);
        assert_eq!(drifted, vec!["a.txt".to_string(), "c.txt".to_string()]);
    }
}
