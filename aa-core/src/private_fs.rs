//! Owner-only creation and tightening of local state (AAASM-6387).
//!
//! The local stores under `~/.aasm`, `~/.aa` and the default audit directory hold
//! the agent registry, approvals, escalation rows and the audit trail. Created
//! with the process umask (commonly `022`) they were `0755`/`0644`, readable by
//! any local user. The modes are set explicitly at creation instead of by
//! changing the umask, so the result does not depend on the caller's environment.
//!
//! # What is and is not touched
//!
//! * **Creation** always makes missing directories `0700` and new files `0600`.
//! * **Tightening** an *existing* object (removing group/other bits, never adding
//!   any) happens only for the exact default state locations
//!   ([`default_state_dirs`]: `~/.aasm`, `~/.aa`, `<data dir>/aa/audit`) and the
//!   known files inside them, only when the object is owned by the effective uid,
//!   and never through a symlink (`O_NOFOLLOW`, then `fstat`/`fchmod` on the open
//!   descriptor, so there is no check-then-use gap). A parent of a default
//!   directory is never changed.
//! * Anything outside those locations (a deployment that points
//!   `AA_GATEWAY_DB_PATH` or `AA_AUDIT_DIR` elsewhere, a group-shared directory)
//!   is left exactly as the operator made it; such deployments keep their own
//!   modes by configuring their own directory.
//!
//! SQLite creates the `-wal` and `-shm` sidecars with the permissions of the main
//! database file, so a database pre-created `0600` gets `0600` sidecars.

use std::io;
use std::path::{Path, PathBuf};

/// Mode for directories created here.
#[cfg(unix)]
pub const PRIVATE_DIR_MODE: u32 = 0o700;
/// Mode for files created here.
#[cfg(unix)]
pub const PRIVATE_FILE_MODE: u32 = 0o600;

/// The exact default state locations that may be tightened when they already
/// exist: `~/.aasm`, `~/.aa` and `<data dir>/aa/audit`.
pub fn default_state_dirs() -> Vec<PathBuf> {
    let mut dirs_out = Vec::new();
    if let Some(home) = dirs::home_dir() {
        dirs_out.push(home.join(".aasm"));
        dirs_out.push(home.join(".aa"));
    }
    if let Some(data) = dirs::data_dir() {
        dirs_out.push(data.join("aa").join("audit"));
    }
    dirs_out
}

/// `mkdir -p` with every missing component `0700`, then tighten any default
/// state directory among `path`'s ancestors (see the module docs).
pub fn create_private_dir_all(path: &Path) -> io::Result<()> {
    create_private_dir_all_in(path, &default_state_dirs())
}

/// [`create_private_dir_all`] with the default locations supplied, so tests can
/// use a temporary HOME.
pub fn create_private_dir_all_in(path: &Path, defaults: &[PathBuf]) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(PRIVATE_DIR_MODE)
            .create(path)?;
    }
    #[cfg(not(unix))]
    std::fs::create_dir_all(path)?;
    for ancestor in path.ancestors() {
        if defaults.iter().any(|d| d == ancestor) {
            tighten_dir_if_owned(ancestor)?;
        }
    }
    Ok(())
}

/// Create `path` empty with mode `0600` if it does not exist. An existing file
/// is left untouched (contents, mode) and does not need to be writable: SQLite
/// can open a read-only database, so requiring write access here would turn that
/// into a hard failure.
pub fn ensure_private_file(path: &Path) -> io::Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => return Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(PRIVATE_FILE_MODE).custom_flags(libc::O_NOFOLLOW);
    }
    match opts.open(path) {
        Ok(_) => Ok(()),
        // Created by another process between the check and the open.
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Ok(()),
        Err(e) => Err(e),
    }
}

/// Write `contents` to `path` as an owner-only file: created `0600`, and an
/// existing looser file is rewritten in place and set `0600` first (it is being
/// replaced by this very call, so this is not a change of someone else's mode).
pub fn write_private_file(path: &Path, contents: &[u8]) -> io::Result<()> {
    use std::io::Write;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(PRIVATE_FILE_MODE).custom_flags(libc::O_NOFOLLOW);
    }
    let mut f = opts.open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        f.set_permissions(std::fs::Permissions::from_mode(PRIVATE_FILE_MODE))?;
    }
    f.write_all(contents)
}

/// Remove group/other permission bits from the directory at `path`, only if it
/// is a real directory (not a symlink) owned by the effective uid. Returns
/// whether a mode was changed. Never adds a bit.
pub fn tighten_dir_if_owned(path: &Path) -> io::Result<bool> {
    tighten_if_owned(path, true)
}

/// [`tighten_dir_if_owned`] for a regular file.
pub fn tighten_file_if_owned(path: &Path) -> io::Result<bool> {
    tighten_if_owned(path, false)
}

#[cfg(unix)]
fn tighten_if_owned(path: &Path, want_dir: bool) -> io::Result<bool> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
    let mut flags = libc::O_NOFOLLOW;
    if want_dir {
        flags |= libc::O_DIRECTORY;
    }
    let f = match std::fs::OpenOptions::new().read(true).custom_flags(flags).open(path) {
        Ok(f) => f,
        // Absent, or a symlink (ELOOP) / wrong type: nothing of ours to tighten.
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(e) if matches!(e.raw_os_error(), Some(libc::ELOOP) | Some(libc::ENOTDIR)) => return Ok(false),
        Err(e) => return Err(e),
    };
    let md = f.metadata()?;
    // SAFETY: geteuid has no preconditions and cannot fail.
    if md.uid() != unsafe { libc::geteuid() } || (want_dir && !md.is_dir()) || (!want_dir && !md.is_file()) {
        return Ok(false);
    }
    let mode = md.permissions().mode() & 0o7777;
    let tightened = mode & !0o077;
    if tightened == mode {
        return Ok(false);
    }
    f.set_permissions(std::fs::Permissions::from_mode(tightened))?;
    Ok(true)
}

#[cfg(not(unix))]
fn tighten_if_owned(_path: &Path, _want_dir: bool) -> io::Result<bool> {
    Ok(false)
}

/// Tighten `path` (a file) when it lives directly in one of `defaults`.
pub fn tighten_file_if_in_default_dir(path: &Path, defaults: &[PathBuf]) -> io::Result<bool> {
    match path.parent() {
        Some(parent) if defaults.iter().any(|d| d == parent) => tighten_file_if_owned(path),
        _ => Ok(false),
    }
}

/// Tighten a SQLite database and its `-wal`/`-shm` sidecars when the database
/// lives directly in a default state directory.
pub fn tighten_sqlite_family_if_default(db: &Path, defaults: &[PathBuf]) -> io::Result<()> {
    for suffix in ["", "-wal", "-shm"] {
        let mut name = db.as_os_str().to_os_string();
        name.push(suffix);
        tighten_file_if_in_default_dir(Path::new(&name), defaults)?;
    }
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};

    fn mode(p: &Path) -> u32 {
        std::fs::metadata(p).unwrap().permissions().mode() & 0o777
    }

    fn chmod(p: &Path, m: u32) {
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(m)).unwrap();
    }

    /// Run `f` with the process umask forced to 022 (the common host default) and
    /// restore it. Serialised: umask is process-global, and a host umask of 077
    /// would otherwise make a reverted fix pass.
    fn with_umask_022(f: impl FnOnce()) {
        static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // SAFETY: umask only swaps the process mask; no memory is involved.
        let old = unsafe { libc::umask(0o022) };
        f();
        unsafe { libc::umask(old) };
    }

    #[test]
    fn new_directories_are_owner_only_even_under_umask_022() {
        with_umask_022(|| {
            let tmp = tempfile::tempdir().unwrap();
            let nested = tmp.path().join("a/b");
            create_private_dir_all_in(&nested, &[]).unwrap();
            assert_eq!(mode(&tmp.path().join("a")), 0o700);
            assert_eq!(mode(&nested), 0o700);
        });
    }

    #[test]
    fn new_files_are_owner_only_even_under_umask_022() {
        with_umask_022(|| {
            let tmp = tempfile::tempdir().unwrap();
            let f = tmp.path().join("db");
            ensure_private_file(&f).unwrap();
            assert_eq!(mode(&f), 0o600);
        });
    }

    #[test]
    fn an_existing_file_is_not_modified_and_need_not_be_writable() {
        let tmp = tempfile::tempdir().unwrap();
        let f = tmp.path().join("db");
        std::fs::write(&f, b"keep").unwrap();
        chmod(&f, 0o444);
        ensure_private_file(&f).unwrap();
        assert_eq!(mode(&f), 0o444);
        assert_eq!(std::fs::read(&f).unwrap(), b"keep");
    }

    #[test]
    fn an_existing_default_dir_is_tightened_but_its_parent_and_others_are_not() {
        let home = tempfile::tempdir().unwrap();
        chmod(home.path(), 0o755);
        let aasm = home.path().join(".aasm");
        std::fs::create_dir(&aasm).unwrap();
        chmod(&aasm, 0o755);
        let other = home.path().join("shared");
        std::fs::create_dir(&other).unwrap();
        chmod(&other, 0o775);
        let defaults = vec![aasm.clone(), home.path().join(".aa")];

        create_private_dir_all_in(&aasm.join("logs"), &defaults).unwrap();
        assert_eq!(mode(&aasm), 0o700, "default dir tightened");
        assert_eq!(mode(&aasm.join("logs")), 0o700);
        assert_eq!(mode(home.path()), 0o755, "parent untouched");

        create_private_dir_all_in(&other, &defaults).unwrap();
        assert_eq!(mode(&other), 0o775, "non-default dir untouched");
    }

    #[test]
    fn tightening_only_removes_bits_and_never_adds() {
        let tmp = tempfile::tempdir().unwrap();
        let d = tmp.path().join("d");
        std::fs::create_dir(&d).unwrap();
        chmod(&d, 0o500);
        assert!(!tighten_dir_if_owned(&d).unwrap(), "already group/other free");
        assert_eq!(mode(&d), 0o500, "no owner bit added");
        chmod(&d, 0o750);
        assert!(tighten_dir_if_owned(&d).unwrap());
        assert_eq!(mode(&d), 0o700 & 0o750);
        chmod(&d, 0o700);
    }

    #[test]
    fn a_symlinked_default_dir_is_not_followed() {
        let tmp = tempfile::tempdir().unwrap();
        let target = tmp.path().join("elsewhere");
        std::fs::create_dir(&target).unwrap();
        chmod(&target, 0o755);
        let link = tmp.path().join(".aasm");
        symlink(&target, &link).unwrap();
        assert!(!tighten_dir_if_owned(&link).unwrap());
        assert_eq!(mode(&target), 0o755, "the link's target must not be chmod'ed");

        let file_target = tmp.path().join("real.db");
        std::fs::write(&file_target, b"x").unwrap();
        chmod(&file_target, 0o644);
        let file_link = tmp.path().join("local.db");
        symlink(&file_target, &file_link).unwrap();
        assert!(!tighten_file_if_owned(&file_link).unwrap());
        assert_eq!(mode(&file_target), 0o644);
    }

    #[test]
    fn objects_owned_by_someone_else_are_left_alone() {
        // /private/etc (macOS) and /etc (Linux) are root-owned and group/other
        // readable; tightening must refuse them without changing or failing.
        let root_owned = Path::new("/etc");
        let before = mode(root_owned);
        assert!(!tighten_dir_if_owned(root_owned).unwrap());
        assert_eq!(mode(root_owned), before);
    }

    #[test]
    fn sqlite_family_is_tightened_only_in_a_default_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let dflt = tmp.path().join(".aasm");
        let custom = tmp.path().join("custom");
        for d in [&dflt, &custom] {
            std::fs::create_dir(d).unwrap();
            for n in ["local.db", "local.db-wal", "local.db-shm"] {
                std::fs::write(d.join(n), b"x").unwrap();
                chmod(&d.join(n), 0o644);
            }
        }
        let defaults = vec![dflt.clone()];
        tighten_sqlite_family_if_default(&dflt.join("local.db"), &defaults).unwrap();
        tighten_sqlite_family_if_default(&custom.join("local.db"), &defaults).unwrap();
        for n in ["local.db", "local.db-wal", "local.db-shm"] {
            assert_eq!(mode(&dflt.join(n)), 0o600, "{n}");
            assert_eq!(mode(&custom.join(n)), 0o644, "{n}");
        }
    }
}
