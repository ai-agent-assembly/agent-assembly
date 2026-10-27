//! Owner-only creation of the local data directory and database files
//! (AAASM-6387).
//!
//! The primitives, the exact rules for what may be tightened, and their tests
//! live in [`aa_core::private_fs`] (shared with `aa-cli`, which sits below this
//! crate); this module adds the async entry points used on start-up paths so a
//! runtime worker never blocks on them.
//!
//! In short: missing directories are created `0700` and new files `0600`
//! whatever the umask; an *existing* default state location (`~/.aasm`, `~/.aa`,
//! the default audit directory) and the known database/audit files in it are
//! tightened (bits removed, never added) when owned by this user and not a
//! symlink; anything outside those defaults is never touched. A group-shared
//! deployment must therefore keep its data somewhere else (`AA_GATEWAY_DB_PATH`,
//! `AA_AUDIT_DIR`, the configured storage path).

use std::io;
use std::path::{Path, PathBuf};

pub use aa_core::private_fs::{
    create_private_dir_all as create_private_dir_all_sync, default_state_dirs,
    ensure_private_file as ensure_private_file_sync, tighten_dir_if_owned, tighten_file_if_in_default_dir,
    tighten_file_if_owned, tighten_sqlite_family_if_default,
};

async fn blocking<T: Send + 'static>(f: impl FnOnce() -> io::Result<T> + Send + 'static) -> io::Result<T> {
    tokio::task::spawn_blocking(f)
        .await
        .unwrap_or_else(|e| Err(io::Error::other(e)))
}

/// Async [`aa_core::private_fs::create_private_dir_all`].
pub async fn create_private_dir_all(path: &Path) -> io::Result<()> {
    let path: PathBuf = path.to_path_buf();
    blocking(move || aa_core::private_fs::create_private_dir_all(&path)).await
}

/// Async [`aa_core::private_fs::ensure_private_file`].
pub async fn ensure_private_file(path: &Path) -> io::Result<()> {
    let path: PathBuf = path.to_path_buf();
    blocking(move || aa_core::private_fs::ensure_private_file(&path)).await
}

/// Test helper: run `f` with the process umask forced to 022 (the common host
/// default) and restore it. Serialised, because umask is process-global; without
/// it a host umask of 077 would make a reverted fix pass.
#[cfg(all(test, unix))]
pub(crate) fn with_umask_022<T>(f: impl FnOnce() -> T) -> T {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    // SAFETY: umask only swaps the process file-creation mask.
    let old = unsafe { libc::umask(0o022) };
    let out = f();
    // SAFETY: as above.
    unsafe { libc::umask(old) };
    out
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn mode(p: &Path) -> u32 {
        std::fs::metadata(p).unwrap().permissions().mode() & 0o777
    }

    #[tokio::test]
    async fn async_entry_points_create_owner_only_objects() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("x/y");
        create_private_dir_all(&dir).await.unwrap();
        assert_eq!(mode(&dir), 0o700);
        let f = dir.join("db");
        ensure_private_file(&f).await.unwrap();
        assert_eq!(mode(&f), 0o600);
    }

    #[test]
    fn sync_entry_point_creates_owner_only_directories() {
        let tmp = tempfile::tempdir().unwrap();
        let nested = tmp.path().join("x/y");
        create_private_dir_all_sync(&nested).unwrap();
        assert_eq!(mode(&nested), 0o700);
    }
}
