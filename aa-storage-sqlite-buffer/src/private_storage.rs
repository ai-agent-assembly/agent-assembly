//! Ownership and permission checks for the buffer's on-disk files (AAASM-6460).
//!
//! The audit buffer holds interception records. If another local uid could
//! pre-create the database, its `-wal`/`-shm` sidecars, or the directory they
//! live in (the old default was a file in the shared temp dir), it could read
//! the records, feed forged ones into the replay, or redirect writes through a
//! symlink. [`prepare`] therefore creates what is missing owner-only and
//! *refuses* anything that is not ours, before SQLite opens the file.
//!
//! # What the check relies on, and what it does not cover
//!
//! The parent directory must be a real directory owned by the effective uid
//! with no group/other write bit, and **every ancestor** of its canonical path
//! must be owned by the effective uid or root and either not group/other
//! writable or sticky. Under those conditions only our uid or root can create,
//! rename or unlink the buffer's files or replace any directory on the path, so
//! another uid cannot swap a validated file (or the validated directory) for a
//! symlink or hardlink between the check and SQLite's `open`.
//!
//! The checks are one-shot, at open. Later `-wal`/`-shm`/`-journal` files are
//! created by SQLite and rely on it giving them the 0600 mode of the database
//! (observed on macOS; asserted for Linux by `tests/private_storage.rs`, which
//! CI runs). Only directories controlled by our uid or root may contain symlink
//! components on the path; the open uses the resolved, validated directory.
//!
//! Limits, stated plainly:
//! * The checks read POSIX mode bits and owners only. POSIX ACLs, NFS root
//!   squash / uid mapping, bind mounts and similar are not seen.
//! * root, and any process running as our own uid (including the governed
//!   agent, which shares the runtime's uid), can still read or replace the
//!   files. A `$HOME` writable by another uid is outside the threat model.
//! * An operator path under a shared or group-writable directory (`/tmp`,
//!   `/var/tmp`) is refused: the conditions cannot hold there.

use std::path::Path;
#[cfg(unix)]
use std::path::PathBuf;

use aa_core::private_fs;
use aa_core::storage::{Result, StorageError};

/// SQLite files that live next to the database and inherit its trust boundary.
#[cfg(unix)]
const SIDECAR_SUFFIXES: [&str; 3] = ["-wal", "-shm", "-journal"];

fn refuse(msg: String) -> StorageError {
    StorageError::Backend(msg)
}

fn io_err(what: &str, path: &Path, e: std::io::Error) -> StorageError {
    refuse(format!("{what} {}: {e}", path.display()))
}

#[cfg(unix)]
fn sidecar(db: &Path, suffix: &str) -> PathBuf {
    let mut name = db.as_os_str().to_os_string();
    name.push(suffix);
    PathBuf::from(name)
}

/// Create the buffer directory and database owner-only, then validate them.
///
/// Returns the path SQLite must open: on Unix the canonicalized, validated
/// parent joined with the file name, so a symlink component in the operator's
/// path cannot be retargeted between validation and open. A loose `-journal`
/// is refused, never repaired, even in a default state dir (only the database,
/// `-wal` and `-shm` are tightened there). Missing directories are created
/// (0700) before validation, so a refusal can leave empty private directories
/// behind; it never leaves a database file.
pub(crate) fn prepare(db: &Path) -> Result<PathBuf> {
    // SQLite would treat these as in-memory or URI databases, bypassing every
    // file check below.
    let raw = db.to_string_lossy();
    if raw.is_empty() || raw == ":memory:" || raw.starts_with("file:") || raw.contains('?') {
        return Err(refuse(format!(
            "refusing audit buffer path {raw:?}: it must be a plain filesystem path (no ':memory:', 'file:' URI or '?')"
        )));
    }
    let parent = match db.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    let file_name = db
        .file_name()
        .ok_or_else(|| refuse(format!("refusing audit buffer path {}: no file name", db.display())))?;
    private_fs::create_private_dir_all(parent).map_err(|e| io_err("create buffer directory", parent, e))?;
    #[cfg(unix)]
    {
        let euid = private_fs::effective_uid();
        validate_parent_dir(parent, euid)?;
        let canonical = std::fs::canonicalize(parent).map_err(|e| io_err("resolve buffer directory", parent, e))?;
        // The directory actually opened, not just the configured path to it.
        validate_parent_dir(&canonical, euid)?;
        validate_ancestors(&canonical, euid)?;
        let db = canonical.join(file_name);
        // Only a database inside a default state dir is tightened (private_fs
        // rules); anywhere else a too-loose file is refused below, not changed.
        private_fs::tighten_sqlite_family_if_default(&db, &private_fs::default_state_dirs())
            .map_err(|e| io_err("tighten buffer files", &db, e))?;
        // Validate what already exists first so a refusal leaves no new file.
        validate_files(&db, euid)?;
        // Create 0600 *before* SQLite opens it so the -wal/-shm it derives
        // from this file start private rather than umask-dependent.
        private_fs::ensure_private_file(&db).map_err(|e| io_err("create buffer database", &db, e))?;
        // Again: covers a file that appeared between the two steps.
        validate_files(&db, euid)?;
        Ok(db)
    }
    #[cfg(not(unix))]
    {
        private_fs::ensure_private_file(db).map_err(|e| io_err("create buffer database", db, e))?;
        let _ = file_name;
        Ok(db.to_path_buf())
    }
}

/// The parent must be a real directory owned by `euid` that no other uid can
/// write to. Group/other *read* is allowed: file modes protect the contents.
#[cfg(unix)]
pub(crate) fn validate_parent_dir(parent: &Path, euid: u32) -> Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let md = std::fs::symlink_metadata(parent).map_err(|e| io_err("inspect buffer directory", parent, e))?;
    let hint = "use a private directory owned by the runtime user (for example ~/.aa/audit-buffer)";
    if !md.file_type().is_dir() {
        return Err(refuse(format!(
            "refusing audit buffer: {} is not a real directory (symlink or other file type); {hint}",
            parent.display()
        )));
    }
    if md.uid() != euid {
        return Err(refuse(format!(
            "refusing audit buffer: directory {} is owned by uid {}, not the effective uid {euid}; {hint}",
            parent.display(),
            md.uid()
        )));
    }
    let mode = md.permissions().mode() & 0o7777;
    if mode & 0o022 != 0 {
        return Err(refuse(format!(
            "refusing audit buffer: directory {} is writable by group/other (mode {mode:04o}); {hint}",
            parent.display()
        )));
    }
    Ok(())
}

/// Every ancestor of `parent`'s canonical path (symlinks resolved once) must be
/// owned by `euid` or root and be either free of group/other write bits or
/// sticky, so no other uid can rename the validated directory out from under
/// the open. Mode bits and owners only; see the module docs for the limits.
#[cfg(unix)]
pub(crate) fn validate_ancestors(parent: &Path, euid: u32) -> Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let canonical = std::fs::canonicalize(parent).map_err(|e| io_err("resolve buffer directory", parent, e))?;
    for ancestor in canonical.ancestors().skip(1) {
        let md = std::fs::metadata(ancestor).map_err(|e| io_err("inspect buffer ancestor", ancestor, e))?;
        let shown = ancestor.display();
        if md.uid() != euid && md.uid() != 0 {
            return Err(refuse(format!(
                "refusing audit buffer: ancestor {shown} is owned by uid {}, not the effective uid {euid} or root; \
                 use a private directory (for example ~/.aa/audit-buffer)",
                md.uid()
            )));
        }
        let mode = md.permissions().mode() & 0o7777;
        if mode & 0o022 != 0 && mode & 0o1000 == 0 {
            return Err(refuse(format!(
                "refusing audit buffer: ancestor {shown} is writable by group/other without the sticky bit \
                 (mode {mode:04o}), so another user could replace the buffer directory; use a private directory"
            )));
        }
    }
    Ok(())
}

/// The database and any existing sidecar must be regular, singly-linked files
/// owned by `euid` with no group/other access at all.
#[cfg(unix)]
pub(crate) fn validate_files(db: &Path, euid: u32) -> Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let family = std::iter::once(db.to_path_buf()).chain(SIDECAR_SUFFIXES.iter().map(|s| sidecar(db, s)));
    for path in family {
        let md = match std::fs::symlink_metadata(&path) {
            Ok(md) => md,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(io_err("inspect buffer file", &path, e)),
        };
        let shown = path.display();
        if !md.file_type().is_file() {
            return Err(refuse(format!(
                "refusing audit buffer: {shown} is not a regular file (symlink or other file type)"
            )));
        }
        if md.uid() != euid {
            return Err(refuse(format!(
                "refusing audit buffer: {shown} is owned by uid {}, not the effective uid {euid}",
                md.uid()
            )));
        }
        if md.nlink() > 1 {
            return Err(refuse(format!(
                "refusing audit buffer: {shown} has {} hard links",
                md.nlink()
            )));
        }
        let mode = md.permissions().mode() & 0o7777;
        if mode & 0o077 != 0 {
            return Err(refuse(format!(
                "refusing audit buffer: {shown} is accessible to group/other (mode {mode:04o}); \
                 restrict it to 0600 or use a private directory"
            )));
        }
    }
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    fn euid() -> u32 {
        private_fs::effective_uid()
    }

    #[test]
    fn a_directory_owned_by_another_uid_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        assert!(validate_parent_dir(dir.path(), euid()).is_ok());
        let err = validate_parent_dir(dir.path(), euid().wrapping_add(1)).unwrap_err();
        assert!(err.to_string().contains("owned by uid"), "{err}");
    }

    fn chmod(p: &Path, m: u32) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(m)).unwrap();
    }

    /// `<tmp>/anc` (mode `ancestor_mode`) / `p` (0700), both ours.
    fn chain(ancestor_mode: u32) -> (tempfile::TempDir, PathBuf) {
        let root = tempfile::tempdir().unwrap();
        let anc = root.path().join("anc");
        let parent = anc.join("p");
        std::fs::create_dir_all(&parent).unwrap();
        chmod(&parent, 0o700);
        chmod(&anc, ancestor_mode);
        (root, parent)
    }

    #[test]
    fn prepare_returns_the_canonical_path_through_a_symlinked_component() {
        let root = tempfile::tempdir().unwrap();
        let real = root.path().join("real");
        std::fs::create_dir(&real).unwrap();
        chmod(&real, 0o700);
        let link = root.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let opened = prepare(&link.join("sub/buffer.db")).unwrap();
        assert_eq!(opened, std::fs::canonicalize(&real).unwrap().join("sub/buffer.db"));
        assert_ne!(opened, link.join("sub/buffer.db"));
    }

    #[test]
    fn a_loose_leaf_behind_a_symlinked_component_is_refused() {
        for m in [0o777, 0o775] {
            let root = tempfile::tempdir().unwrap();
            let real = root.path().join("real");
            std::fs::create_dir_all(real.join("sub")).unwrap();
            chmod(&real, 0o700);
            chmod(&real.join("sub"), m);
            let link = root.path().join("link");
            std::os::unix::fs::symlink(&real, &link).unwrap();
            let err = prepare(&link.join("sub/buffer.db")).unwrap_err();
            assert!(err.to_string().contains("writable by group/other"), "{m:o}: {err}");
            assert!(!real.join("sub/buffer.db").exists());
        }
    }

    #[test]
    fn a_refused_sidecar_leaves_no_database_behind() {
        let root = tempfile::tempdir().unwrap();
        chmod(root.path(), 0o700);
        let db = root.path().join("buffer.db");
        let wal = sidecar(&db, "-wal");
        std::fs::write(&wal, b"").unwrap();
        chmod(&wal, 0o666);
        assert!(prepare(&db).is_err());
        assert!(!db.exists(), "validation runs before the database is created");
    }

    #[test]
    fn a_non_sticky_writable_ancestor_above_a_private_parent_is_refused() {
        for m in [0o777, 0o770, 0o707] {
            let (_root, parent) = chain(m);
            assert!(
                validate_parent_dir(&parent, euid()).is_ok(),
                "the parent itself is fine"
            );
            let err = validate_ancestors(&parent, euid()).unwrap_err();
            assert!(err.to_string().contains("without the sticky bit"), "{m:o}: {err}");
            assert!(err.to_string().contains("anc"), "names the ancestor: {err}");
        }
    }

    #[test]
    fn a_sticky_or_non_writable_ancestor_is_accepted() {
        for m in [0o1777, 0o755, 0o700] {
            let (_root, parent) = chain(m);
            validate_ancestors(&parent, euid()).unwrap_or_else(|e| panic!("{m:o}: {e}"));
        }
    }

    #[test]
    fn a_symlinked_ancestor_path_is_checked_on_the_real_chain() {
        let (root, parent) = chain(0o777);
        let link = root.path().join("link");
        std::os::unix::fs::symlink(parent.parent().unwrap(), &link).unwrap();
        // Reached through the symlink, the unsafe real ancestor is still found.
        assert!(validate_ancestors(&link.join("p"), euid()).is_err());
    }

    #[test]
    fn an_ancestor_owned_by_another_uid_is_refused() {
        if euid() == 0 {
            eprintln!("SKIPPED: running as root, where root-owned ancestors are always trusted");
            return;
        }
        let (_root, parent) = chain(0o755);
        let err = validate_ancestors(&parent, euid().wrapping_add(1)).unwrap_err();
        assert!(err.to_string().contains("owned by uid"), "{err}");
    }

    #[test]
    fn a_database_or_sidecar_owned_by_another_uid_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("b.db");
        private_fs::ensure_private_file(&db).unwrap();
        assert!(validate_files(&db, euid()).is_ok());
        assert!(validate_files(&db, euid().wrapping_add(1)).is_err());

        let wal = sidecar(&db, "-wal");
        private_fs::ensure_private_file(&wal).unwrap();
        // db passes for its owner; the check must also cover the sidecar.
        std::fs::remove_file(&db).unwrap();
        let err = validate_files(&db, euid().wrapping_add(1)).unwrap_err();
        assert!(err.to_string().contains("-wal"), "{err}");
    }
}
