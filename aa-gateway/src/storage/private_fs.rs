//! Owner-only creation of the local data directory and database files
//! (AAASM-6387).
//!
//! The local store under `~/.aasm/` holds the agent registry, approvals and
//! audit rows. Creating it with the process umask (commonly `022`) left the
//! directory `0755` and the SQLite files `0644`, so any other local user could
//! read them. The modes are set explicitly at creation rather than by
//! changing the umask, so the result does not depend on the caller's
//! environment.
//!
//! Only objects this code creates are given the private mode. A directory or
//! file that already exists is left as the operator made it: tightening it
//! would silently change access for a group-shared deployment, and loosening
//! it is never done.
//!
//! SQLite creates the `-wal` and `-shm` sidecars with the permissions of the
//! main database file, so pre-creating that file `0600` covers all three.

use std::io;
use std::path::Path;

/// Mode for directories created by [`create_private_dir_all`].
#[cfg(unix)]
pub const PRIVATE_DIR_MODE: u32 = 0o700;
/// Mode for files created by [`ensure_private_file`].
#[cfg(unix)]
pub const PRIVATE_FILE_MODE: u32 = 0o600;

/// `mkdir -p` that creates every missing component `0700` on Unix.
///
/// Existing components keep their mode. On other platforms this is plain
/// `create_dir_all`.
pub async fn create_private_dir_all(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        tokio::fs::DirBuilder::new()
            .recursive(true)
            .mode(PRIVATE_DIR_MODE)
            .create(path)
            .await
    }
    #[cfg(not(unix))]
    {
        tokio::fs::create_dir_all(path).await
    }
}

/// Synchronous twin of [`create_private_dir_all`] for the non-async start-up
/// path.
pub fn create_private_dir_all_sync(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(PRIVATE_DIR_MODE)
            .create(path)
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(path)
    }
}

/// Create `path` empty with mode `0600` if it does not exist; leave an
/// existing file untouched (contents and mode).
///
/// Called before SQLite opens the file, so that SQLite finds it already
/// present and derives the `-wal`/`-shm` modes from it.
pub async fn ensure_private_file(path: &Path) -> io::Result<()> {
    let mut opts = tokio::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(false);
    #[cfg(unix)]
    opts.mode(PRIVATE_FILE_MODE);
    opts.open(path).await.map(|_| ())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn mode(p: &Path) -> u32 {
        std::fs::metadata(p).unwrap().permissions().mode() & 0o777
    }

    #[tokio::test]
    async fn new_directories_are_owner_only_whatever_the_umask() {
        let tmp = tempfile::tempdir().unwrap();
        let nested = tmp.path().join("a/b");
        create_private_dir_all(&nested).await.unwrap();
        assert_eq!(mode(&tmp.path().join("a")), 0o700);
        assert_eq!(mode(&nested), 0o700);
    }

    #[test]
    fn sync_variant_creates_owner_only_directories() {
        let tmp = tempfile::tempdir().unwrap();
        let nested = tmp.path().join("x/y");
        create_private_dir_all_sync(&nested).unwrap();
        assert_eq!(mode(&nested), 0o700);
    }

    #[tokio::test]
    async fn existing_directory_and_file_keep_their_mode() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("shared");
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        let file = dir.join("db");
        std::fs::write(&file, b"keep").unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();

        create_private_dir_all(&dir).await.unwrap();
        ensure_private_file(&file).await.unwrap();

        assert_eq!(mode(&dir), 0o755);
        assert_eq!(mode(&file), 0o644);
        assert_eq!(std::fs::read(&file).unwrap(), b"keep");
    }

    #[tokio::test]
    async fn new_file_is_owner_only() {
        let tmp = tempfile::tempdir().unwrap();
        let file = tmp.path().join("local.db");
        ensure_private_file(&file).await.unwrap();
        assert_eq!(mode(&file), 0o600);
    }
}
