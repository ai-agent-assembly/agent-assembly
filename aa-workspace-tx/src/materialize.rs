//! Copying a measured surface into a staged workspace, and back out again at
//! apply time — both directions go through `copy`, never `hard_link`.
//!
//! # Why copy, never hardlink
//!
//! A hardlinked staged file shares an inode with the base file. A write
//! through the staged path (`open(O_WRONLY) + write`, without first
//! unlinking) would then mutate the base file's content in place, before any
//! commit decision — silently defeating the entire point of staging. This
//! module never calls `std::fs::hard_link`, and [`crate::commit`] additionally
//! refuses to apply any staged entry whose inode matches a base entry's
//! (`st_ino` comparison), as a second, independent line of defense.

use std::fs;
use std::io;
use std::os::unix::fs::{symlink, MetadataExt};
use std::path::Path;

use aa_isolation::{BaseManifest, EntryKind};

/// Copy every entry in `manifest` from `base_root` into `staged_root`,
/// preserving directory structure and recording symlinks as symlinks
/// (never followed, never resolved).
pub fn copy_surface(base_root: &Path, staged_root: &Path, manifest: &BaseManifest) -> io::Result<()> {
    // Directories first (sorted path order already guarantees a parent is
    // measured before its children, since `measure` walks top-down).
    for entry in manifest.entries() {
        let dest = staged_root.join(entry.path());
        match entry.kind() {
            EntryKind::Directory => {
                fs::create_dir_all(&dest)?;
            }
            EntryKind::File => {
                if let Some(parent) = dest.parent() {
                    fs::create_dir_all(parent)?;
                }
                let src = base_root.join(entry.path());
                copy_file_never_hardlink(&src, &dest)?;
            }
            EntryKind::Symlink => {
                if let Some(parent) = dest.parent() {
                    fs::create_dir_all(parent)?;
                }
                let target = entry.symlink_target().unwrap_or_default();
                create_symlink_via_temp(target, &dest)?;
            }
            // aa_isolation::EntryKind is #[non_exhaustive]. Fail closed
            // (refuse the materialization) rather than silently skip an
            // entry kind this crate does not yet know how to stage safely.
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    format!("unsupported entry kind for {}", entry.path()),
                ));
            }
        }
    }
    Ok(())
}

/// Copy `src`'s content into a brand-new file at `dest`, via a temp file in
/// the same directory plus `rename`, so a reader never observes a
/// partially-written `dest`.
pub fn copy_file_never_hardlink(src: &Path, dest: &Path) -> io::Result<()> {
    let bytes = fs::read(src)?;
    write_via_temp(dest, &bytes)
}

/// Write `bytes` to `dest` via temp-file-plus-rename.
pub fn write_via_temp(dest: &Path, bytes: &[u8]) -> io::Result<()> {
    let parent = dest
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "destination has no parent directory"))?;
    let tmp = parent.join(format!(".awtx-tmp-{}-{}", std::process::id(), tmp_suffix()));
    fs::write(&tmp, bytes)?;
    fs::rename(&tmp, dest)?;
    Ok(())
}

/// Create a symlink at `dest` pointing at `target`, via a temp symlink path
/// plus `rename` (symlinks cannot be written-then-renamed like regular file
/// content, but the temp-name-then-rename pattern still avoids ever exposing
/// a half-created entry at `dest`).
pub fn create_symlink_via_temp(target: &str, dest: &Path) -> io::Result<()> {
    let parent = dest
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "destination has no parent directory"))?;
    let tmp = parent.join(format!(".awtx-tmp-{}-{}", std::process::id(), tmp_suffix()));
    symlink(target, &tmp)?;
    fs::rename(&tmp, dest)?;
    Ok(())
}

fn tmp_suffix() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

/// Whether `staged` and `base` name the same inode on the same device — the
/// signature of a hardlink, which must never survive to an apply.
pub fn shares_inode(staged: &Path, base: &Path) -> io::Result<bool> {
    if !base.exists() {
        return Ok(false);
    }
    let a = fs::symlink_metadata(staged)?;
    let b = fs::symlink_metadata(base)?;
    Ok(a.dev() == b.dev() && a.ino() == b.ino())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::measure;

    #[test]
    fn copied_files_are_distinct_inodes_from_base() {
        let base = tempfile::tempdir().unwrap();
        std::fs::write(base.path().join("a.txt"), b"hello").unwrap();
        let manifest = measure(base.path(), &[]).unwrap();

        let staged = tempfile::tempdir().unwrap();
        copy_surface(base.path(), staged.path(), &manifest).unwrap();

        assert!(!shares_inode(&staged.path().join("a.txt"), &base.path().join("a.txt")).unwrap());
        assert_eq!(
            std::fs::read(staged.path().join("a.txt")).unwrap(),
            std::fs::read(base.path().join("a.txt")).unwrap()
        );
    }

    /// Falsifying control: a HARD-LINKED staging strategy (what this crate
    /// deliberately does not do) would fail the very invariant the crate
    /// exists to hold — a write through the staged path mutates the base
    /// before any commit. This test builds that rejected alternative by hand
    /// to prove the distinction is real, not asserted by naming alone.
    #[test]
    fn a_hardlinked_staging_strategy_would_have_let_a_staged_write_mutate_base() {
        let base = tempfile::tempdir().unwrap();
        let base_file = base.path().join("a.txt");
        std::fs::write(&base_file, b"original").unwrap();

        let staged = tempfile::tempdir().unwrap();
        let staged_file = staged.path().join("a.txt");
        std::fs::hard_link(&base_file, &staged_file).unwrap();

        // A write through the staged path, as a confined process might do.
        std::fs::write(&staged_file, b"mutated-through-staged-path").unwrap();

        // The base was mutated before any commit decision ran — this is
        // exactly the failure `copy_file_never_hardlink` exists to prevent.
        assert_eq!(std::fs::read(&base_file).unwrap(), b"mutated-through-staged-path");
        assert!(shares_inode(&staged_file, &base_file).unwrap());
    }
}
