//! Ownership and permission checks for the buffer's on-disk files (AAASM-6460).
//!
//! The audit buffer holds interception records. If another local uid could
//! pre-create the database, its `-wal`/`-shm` sidecars, or the directory they
//! live in (the old default was a file in the shared temp dir), it could read
//! the records, feed forged ones into the replay, or redirect writes through a
//! symlink. [`prepare`] therefore creates what is missing owner-only and
//! *refuses* anything that is not ours, before SQLite opens the file.
//!
//! # Why check-then-open is sound here
//!
//! The parent directory must be owned by the effective uid and not writable by
//! group/other. Only a process with our uid (or root) can then create, rename
//! or unlink entries in it, so no other uid can swap a validated file for a
//! symlink or hardlink between the check and SQLite's `open`. A process running
//! as our own uid is outside this guarantee by construction: the governed agent
//! shares the runtime's uid and can already read or write anything the runtime
//! can. An operator-configured path whose parent is shared or group-writable
//! (`/tmp`, `/var/tmp`) is refused for the same reason: the guarantee cannot
//! hold there.

use std::path::{Path, PathBuf};

use aa_core::private_fs;
use aa_core::storage::{Result, StorageError};

/// SQLite files that live next to the database and inherit its trust boundary.
const SIDECAR_SUFFIXES: [&str; 3] = ["-wal", "-shm", "-journal"];

fn refuse(msg: String) -> StorageError {
    StorageError::Backend(msg)
}

fn io_err(what: &str, path: &Path, e: std::io::Error) -> StorageError {
    refuse(format!("{what} {}: {e}", path.display()))
}

fn sidecar(db: &Path, suffix: &str) -> PathBuf {
    let mut name = db.as_os_str().to_os_string();
    name.push(suffix);
    PathBuf::from(name)
}

/// Create the buffer directory and database owner-only, then validate them.
/// Returns once SQLite may safely open `db`.
pub(crate) fn prepare(db: &Path) -> Result<()> {
    let parent = match db.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    private_fs::create_private_dir_all(parent).map_err(|e| io_err("create buffer directory", parent, e))?;
    #[cfg(unix)]
    {
        let euid = private_fs::effective_uid();
        validate_parent_dir(parent, euid)?;
        // Only a database inside a default state dir is tightened (private_fs
        // rules); anywhere else a too-loose file is refused below, not changed.
        private_fs::tighten_sqlite_family_if_default(db, &private_fs::default_state_dirs())
            .map_err(|e| io_err("tighten buffer files", db, e))?;
        // Create 0600 *before* SQLite opens it so the -wal/-shm it derives
        // from this file start private rather than umask-dependent.
        private_fs::ensure_private_file(db).map_err(|e| io_err("create buffer database", db, e))?;
        validate_files(db, euid)?;
    }
    #[cfg(not(unix))]
    private_fs::ensure_private_file(db).map_err(|e| io_err("create buffer database", db, e))?;
    Ok(())
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
