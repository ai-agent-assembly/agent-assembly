//! Per-transaction private state directory: creation, ownership/mode
//! verification, and an exclusive lock.
//!
//! # Why not `std::env::temp_dir()`
//!
//! On a multi-user Linux host `std::env::temp_dir()` is `/tmp`, world-
//! writable with the sticky bit. Anything staged there is readable by every
//! local user unless every single file and directory created underneath
//! re-applies a restrictive mode by hand — one missed `set_permissions` call
//! and a staged copy of the base workspace (which may contain secrets the
//! confined process legitimately had access to) leaks cross-user. This
//! crate's caller supplies `state_root` explicitly instead (the real
//! `aa-cli` integration is expected to use `$XDG_STATE_HOME/aasm/tx` or
//! `~/.aasm/tx`, per the ticket's design notes); this crate does not compute
//! that default itself, so a test fixture can never share a directory with a
//! real user's transactions by accident.
//!
//! # `create_dir`, not `create_dir_all`, for the transaction directory itself
//!
//! `create_dir_all` silently succeeds if the target already exists — exactly
//! the case this code must refuse, because an existing directory could be a
//! symlink planted by another user, or a leftover from a previous run whose
//! ownership was never verified. `create_dir` fails with `AlreadyExists`
//! instead, which this module treats as "reuse only after verifying
//! ownership and mode", never as "proceed".

use std::fs;
use std::io;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use aa_isolation::TransactionId;

/// Mode a transaction's private state directory must have: owner
/// read/write/execute, nothing for group or other.
const PRIVATE_DIR_MODE: u32 = 0o700;

/// Everything that can go wrong creating or reusing a transaction's state
/// directory.
#[derive(Debug, thiserror::Error)]
pub enum StateError {
    /// The state root itself does not exist and could not be created.
    #[error("state root {path} could not be created: {source}")]
    RootUnavailable { path: PathBuf, source: io::Error },
    /// The transaction directory already exists and is not this process's
    /// own private state (wrong owner, or mode looser than 0700).
    #[error("transaction directory {path} exists and is not verified private state: {detail}")]
    NotPrivate { path: PathBuf, detail: String },
    /// The transaction directory could not be created for a reason other
    /// than already existing.
    #[error("transaction directory {path} could not be created: {source}")]
    CreateFailed { path: PathBuf, source: io::Error },
    /// The exclusive lock on the transaction directory could not be
    /// acquired — held by another process, or the lock file could not be
    /// opened.
    #[error("could not acquire exclusive lock on {path}: {detail}")]
    LockUnavailable { path: PathBuf, detail: String },
    /// A filesystem operation on the state directory failed.
    #[error("state directory I/O error: {0}")]
    Io(#[from] io::Error),
}

/// A created-and-verified, exclusively-locked transaction state directory.
///
/// The lock is held for the lifetime of this value (released on `Drop` by
/// closing the file descriptor, which releases a `flock`).
#[derive(Debug)]
pub struct StateDir {
    root: PathBuf,
    staged: PathBuf,
    _lock: fs::File,
}

impl StateDir {
    /// Create a fresh, private, exclusively-locked state directory for
    /// `id` under `state_root`.
    ///
    /// Fails closed on every ambiguity: an existing directory is reused only
    /// if it is verified as this UID's own 0700 directory; the lock is
    /// acquired non-blocking, so a directory another process already holds
    /// is reported as [`StateError::LockUnavailable`] rather than hung on.
    pub fn create(state_root: &Path, id: &TransactionId) -> Result<Self, StateError> {
        ensure_root(state_root)?;

        let root = state_root.join(id.as_str());
        match fs::create_dir(&root) {
            Ok(()) => {
                let mut perms = fs::metadata(&root)?.permissions();
                perms.set_mode(PRIVATE_DIR_MODE);
                fs::set_permissions(&root, perms)?;
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                verify_private(&root).map_err(|detail| StateError::NotPrivate {
                    path: root.clone(),
                    detail,
                })?;
            }
            Err(source) => {
                return Err(StateError::CreateFailed { path: root, source });
            }
        }

        let lock = acquire_exclusive_lock(&root)?;

        let staged = root.join("staged");
        if !staged.exists() {
            fs::create_dir(&staged).map_err(StateError::Io)?;
        }

        Ok(Self {
            root,
            staged,
            _lock: lock,
        })
    }

    /// The transaction's private state root.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The staged workspace directory, inside the state root.
    pub fn staged_dir(&self) -> &Path {
        &self.staged
    }

    /// Remove the staged workspace tree (used by discard).
    pub fn remove_staged(&self) -> io::Result<()> {
        if self.staged.exists() {
            fs::remove_dir_all(&self.staged)?;
        }
        Ok(())
    }
}

fn ensure_root(state_root: &Path) -> Result<(), StateError> {
    if !state_root.exists() {
        fs::create_dir_all(state_root).map_err(|source| StateError::RootUnavailable {
            path: state_root.to_path_buf(),
            source,
        })?;
        let mut perms = fs::metadata(state_root)
            .map_err(|source| StateError::RootUnavailable {
                path: state_root.to_path_buf(),
                source,
            })?
            .permissions();
        perms.set_mode(PRIVATE_DIR_MODE);
        fs::set_permissions(state_root, perms).map_err(|source| StateError::RootUnavailable {
            path: state_root.to_path_buf(),
            source,
        })?;
    }
    Ok(())
}

/// Verify an already-existing directory is this process's own private
/// (0700-or-tighter) state, refusing on any ambiguity rather than assuming
/// it is safe to reuse.
fn verify_private(path: &Path) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path).map_err(|e| format!("cannot stat: {e}"))?;
    if metadata.file_type().is_symlink() {
        return Err("refusing a symlink where a real directory is required".to_string());
    }
    if !metadata.is_dir() {
        return Err("existing path is not a directory".to_string());
    }
    let current_uid = unsafe { libc::getuid() };
    if metadata.uid() != current_uid {
        return Err(format!(
            "owned by uid {}, not the current uid {current_uid}",
            metadata.uid()
        ));
    }
    let mode = metadata.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(format!("mode {mode:o} grants access to group or other"));
    }
    Ok(())
}

/// Acquire a non-blocking exclusive `flock` on a lock file inside the
/// transaction directory.
///
/// Non-blocking on purpose: a caller waiting indefinitely on someone else's
/// lock is indistinguishable from a hang, and the fail-closed answer to "is
/// this transaction already in use" is "refuse now", not "wait and hope".
fn acquire_exclusive_lock(root: &Path) -> Result<fs::File, StateError> {
    use std::os::fd::AsRawFd;

    let lock_path = root.join(".lock");
    let file = fs::OpenOptions::new()
        .create(true)
        .write(true)
        // The lock file's content is never read — it exists only as an
        // flock() target — so truncating it on reopen would discard nothing
        // meaningful; false is explicit that this call never intends to
        // clear a concurrent lock-holder's file out from under it.
        .truncate(false)
        .open(&lock_path)
        .map_err(|e| StateError::LockUnavailable {
            path: root.to_path_buf(),
            detail: format!("could not open lock file: {e}"),
        })?;

    let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if rc != 0 {
        let errno = io::Error::last_os_error();
        return Err(StateError::LockUnavailable {
            path: root.to_path_buf(),
            detail: format!("flock failed: {errno}"),
        });
    }
    Ok(file)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_root() -> tempfile::TempDir {
        tempfile::tempdir().expect("tempdir")
    }

    #[test]
    fn create_makes_a_0700_directory() {
        let root = temp_root();
        let state = StateDir::create(root.path(), &TransactionId::new("tx-a")).expect("create");
        let mode = fs::metadata(state.root()).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
    }

    #[test]
    fn a_second_open_of_the_same_id_refuses_the_lock() {
        let root = temp_root();
        let id = TransactionId::new("tx-b");
        let first = StateDir::create(root.path(), &id).expect("first create");
        let second = StateDir::create(root.path(), &id);
        assert!(matches!(second, Err(StateError::LockUnavailable { .. })));
        drop(first);
        // Once the first handle drops (releasing the flock), reuse succeeds.
        let third = StateDir::create(root.path(), &id);
        assert!(third.is_ok(), "lock should be released after drop: {third:?}");
    }

    #[test]
    fn an_existing_directory_with_loose_permissions_is_refused() {
        let root = temp_root();
        let id = TransactionId::new("tx-c");
        let dir = root.path().join(id.as_str());
        fs::create_dir(&dir).unwrap();
        let mut perms = fs::metadata(&dir).unwrap().permissions();
        perms.set_mode(0o755); // group/other readable — must be refused
        fs::set_permissions(&dir, perms).unwrap();

        let result = StateDir::create(root.path(), &id);
        assert!(matches!(result, Err(StateError::NotPrivate { .. })));
    }
}
