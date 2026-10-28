//! Where a per-launch proxy's revoke-only control socket lives (AAASM-6262, AC3).
//!
//! A Unix socket address holds about 100 bytes, and the launch directory
//! (`${AASM_STATE_DIR:-~/.aasm}/runs/<agent>-<suffix>/`) can be longer than that
//! (a long state path, a long agent id). Without a socket a brokered credential
//! could not be revoked while the launch runs, and for a long time that was
//! silent.
//!
//! The socket is therefore placed, in order of preference:
//!
//! 1. inside the launch directory (`ctl.sock`), when that path fits;
//! 2. otherwise in a short, private, per-user directory, `<base>/aa-ctl-<euid>/`,
//!    under a name derived from the launch directory name, so the operator-side
//!    command finds it again without any pointer file that could be forged.
//!
//! The fallback directory is created `0700` and must, every time it is used, be a
//! real directory (not a symlink) owned by the current user with no group or
//! other access; anything else is an error, never silently accepted. The proxy
//! repeats the check on the socket's parent directory before it binds.
//!
//! What this does not do: it does not stop a process of the same user, which can
//! unlink or replace the socket (the accepted boundary documented in ADR 0038).
//! It adds no new capability to such a process, since the launch directory
//! itself is equally open to it.

use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use aa_proxy::control::MAX_SOCKET_PATH_BYTES;

/// Parent of the per-user fallback directory. Short, and present on every Unix
/// host this ships on. It is world-writable, which is why the directory under it
/// is verified on every use rather than trusted because it exists.
pub const FALLBACK_BASE: &str = "/tmp";

/// How much of the agent label the fallback name keeps; the launch suffix keeps it unique.
const LABEL_MAX: usize = 24;

/// Why no usable control-socket path could be produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CtlPathError {
    /// The launch directory name does not have the `<label>-<suffix>` shape.
    UnnamedLaunchDir,
    /// Even the fallback path would not fit a socket address.
    TooLong,
    /// The fallback directory exists but cannot be trusted.
    InsecureFallbackDir(String),
    /// The fallback directory could not be created or inspected.
    Io(String),
}

impl std::fmt::Display for CtlPathError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnnamedLaunchDir => write!(f, "the launch directory name cannot be mapped to a short socket path"),
            Self::TooLong => write!(
                f,
                "even the short fallback socket path would exceed {MAX_SOCKET_PATH_BYTES} bytes"
            ),
            Self::InsecureFallbackDir(why) => write!(f, "the fallback socket directory is not trustworthy ({why})"),
            Self::Io(e) => write!(f, "the fallback socket directory could not be prepared ({e})"),
        }
    }
}

impl std::error::Error for CtlPathError {}

/// Where the control socket of one launch goes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Plan {
    /// `<launch dir>/ctl.sock`.
    Primary(PathBuf),
    /// A short path in the per-user fallback directory.
    Fallback(PathBuf),
}

impl Plan {
    /// The socket path.
    pub fn path(&self) -> &Path {
        match self {
            Self::Primary(p) | Self::Fallback(p) => p,
        }
    }

    /// Whether the socket lives outside the launch directory (and so must be
    /// removed by whoever removes the launch).
    pub fn is_fallback(&self) -> bool {
        matches!(self, Self::Fallback(_))
    }
}

fn fits(path: &Path) -> bool {
    use std::os::unix::ffi::OsStrExt;
    path.as_os_str().as_bytes().len() <= MAX_SOCKET_PATH_BYTES
}

fn euid() -> u32 {
    // SAFETY: geteuid has no preconditions and cannot fail.
    unsafe { libc::geteuid() }
}

/// The per-user fallback directory under `base`.
pub fn fallback_dir_in(base: &Path) -> PathBuf {
    base.join(format!("aa-ctl-{}", euid()))
}

/// `<launch dir>/ctl.sock` when that path fits a socket address.
pub fn primary_socket(launch_dir: &Path) -> Option<PathBuf> {
    let socket = launch_dir.join("ctl.sock");
    fits(&socket).then_some(socket)
}

/// The fallback socket path for `launch_dir`, derived from its name only.
///
/// `None` when the name is not `<label>-<suffix>` of plain `[A-Za-z0-9_-]`
/// characters (so nothing in it can climb out of the directory) or the result
/// would still not fit. Pure: creates nothing.
pub fn fallback_socket_in(base: &Path, launch_dir: &Path) -> Option<PathBuf> {
    let name = launch_dir.file_name()?.to_str()?;
    let (label, suffix) = name.rsplit_once('-')?;
    let plain = |s: &str| !s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
    if !plain(label) || !plain(suffix) {
        return None;
    }
    let label: String = label.chars().take(LABEL_MAX).collect();
    let socket = fallback_dir_in(base).join(format!("{label}-{suffix}.sock"));
    fits(&socket).then_some(socket)
}

/// Require that `dir` is a real directory owned by this user with no group or
/// other access.
///
/// # Errors
///
/// [`CtlPathError::InsecureFallbackDir`] naming which property failed, or
/// [`CtlPathError::Io`] when it cannot be inspected.
pub fn verify_fallback_dir(dir: &Path) -> Result<(), CtlPathError> {
    let meta = std::fs::symlink_metadata(dir).map_err(|e| CtlPathError::Io(e.to_string()))?;
    if !meta.file_type().is_dir() {
        return Err(CtlPathError::InsecureFallbackDir("not a real directory".into()));
    }
    if meta.uid() != euid() {
        return Err(CtlPathError::InsecureFallbackDir("owned by another user".into()));
    }
    if meta.mode() & 0o077 != 0 {
        return Err(CtlPathError::InsecureFallbackDir(
            "accessible to group or others".into(),
        ));
    }
    Ok(())
}

/// Create the fallback directory `0700` if absent, then verify it.
///
/// An existing directory is never adopted on trust: another user may have made
/// it first, so it is verified exactly like one this call created.
fn ensure_fallback_dir(dir: &Path) -> Result<(), CtlPathError> {
    match std::fs::symlink_metadata(dir) {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            match std::fs::DirBuilder::new().mode(0o700).create(dir) {
                // Only a directory THIS call created is adjusted, so a symlink planted in the gap
                // between the check and the create is never followed by a chmod.
                Ok(()) => std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
                    .map_err(|e| CtlPathError::Io(e.to_string()))?,
                // Lost a race with another creator; verification below decides.
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(CtlPathError::Io(e.to_string())),
            }
        }
        Err(e) => return Err(CtlPathError::Io(e.to_string())),
    }
    verify_fallback_dir(dir)
}

/// Decide where `launch_dir`'s control socket goes.
///
/// * `required == false` (nothing is brokered, so nothing needs revoking): the
///   launch-directory socket when it fits, else `Ok(None)`. No fallback
///   directory is created, so the default behaviour of a launch that brokers no
///   credential is exactly what it was before the fallback existed.
/// * `required == true`: a path that works, or an error. Never `Ok(None)`.
///
/// # Errors
///
/// Only when `required`: [`CtlPathError`] saying why no trustworthy path exists.
pub fn plan(launch_dir: &Path, required: bool, base: &Path) -> Result<Option<Plan>, CtlPathError> {
    if let Some(socket) = primary_socket(launch_dir) {
        return Ok(Some(Plan::Primary(socket)));
    }
    if !required {
        return Ok(None);
    }
    let socket = fallback_socket_in(base, launch_dir).ok_or_else(|| {
        if launch_dir
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.contains('-'))
        {
            CtlPathError::TooLong
        } else {
            CtlPathError::UnnamedLaunchDir
        }
    })?;
    let dir = socket
        .parent()
        .map(Path::to_path_buf)
        .ok_or(CtlPathError::UnnamedLaunchDir)?;
    ensure_fallback_dir(&dir)?;
    Ok(Some(Plan::Fallback(socket)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn long_launch_dir(root: &Path) -> PathBuf {
        root.join("s".repeat(MAX_SOCKET_PATH_BYTES))
            .join("runs")
            .join("agent-x-AbC123")
    }

    #[test]
    fn a_short_launch_dir_keeps_its_own_socket_and_creates_nothing() {
        let base = tempfile::tempdir().unwrap();
        let launch = Path::new("/tmp/runs/agent-AbC123");
        for required in [false, true] {
            let plan = plan(launch, required, base.path()).unwrap().unwrap();
            assert_eq!(plan, Plan::Primary(PathBuf::from("/tmp/runs/agent-AbC123/ctl.sock")));
            assert!(!plan.is_fallback());
        }
        assert!(
            !fallback_dir_in(base.path()).exists(),
            "no fallback directory is made when it is not needed"
        );
    }

    #[test]
    fn a_long_launch_dir_gets_a_short_private_fallback_when_revocation_is_required() {
        let base = tempfile::tempdir().unwrap();
        let launch = long_launch_dir(base.path());
        assert!(
            primary_socket(&launch).is_none(),
            "precondition: the primary path does not fit"
        );

        let first = plan(&launch, true, base.path()).unwrap().unwrap();
        let second = plan(&launch, true, base.path()).unwrap().unwrap();
        assert_eq!(
            first, second,
            "deterministic, so the operator command finds the same path"
        );
        assert!(first.is_fallback());
        let socket = first.path();
        assert!(fits(socket), "{} bytes", socket.as_os_str().len());
        assert_eq!(socket.file_name().unwrap(), "agent-x-AbC123.sock");
        let dir = fallback_dir_in(base.path());
        assert_eq!(socket.parent().unwrap(), dir);
        assert_eq!(std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777, 0o700);
        // Two launches never share a name.
        let other = base
            .path()
            .join("s".repeat(MAX_SOCKET_PATH_BYTES))
            .join("runs")
            .join("agent-x-ZzZ999");
        assert_ne!(plan(&other, true, base.path()).unwrap().unwrap(), first);
    }

    #[test]
    fn without_a_requirement_a_long_launch_dir_gets_no_socket_and_no_side_effects() {
        let base = tempfile::tempdir().unwrap();
        let launch = long_launch_dir(base.path());
        assert_eq!(plan(&launch, false, base.path()), Ok(None));
        assert!(
            !fallback_dir_in(base.path()).exists(),
            "the non-brokered default must not touch the filesystem"
        );
    }

    #[test]
    fn an_untrustworthy_fallback_directory_is_an_error_never_adopted() {
        let base = tempfile::tempdir().unwrap();
        let launch = long_launch_dir(base.path());
        let dir = fallback_dir_in(base.path());

        // Positive control: the same directory, correctly private, is accepted.
        std::fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
        assert!(plan(&launch, true, base.path()).is_ok());

        // Group/other access.
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(matches!(
            plan(&launch, true, base.path()),
            Err(CtlPathError::InsecureFallbackDir(_))
        ));
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();

        // A symlink standing in for the directory, even to a perfectly private target.
        std::fs::remove_dir(&dir).unwrap();
        let elsewhere = base.path().join("elsewhere");
        std::fs::DirBuilder::new().mode(0o700).create(&elsewhere).unwrap();
        std::os::unix::fs::symlink(&elsewhere, &dir).unwrap();
        assert!(matches!(
            plan(&launch, true, base.path()),
            Err(CtlPathError::InsecureFallbackDir(_))
        ));
        std::fs::remove_file(&dir).unwrap();

        // The symlink's target must not have been touched by the attempt (no chmod through it).
        let target_file = base.path().join("victim.txt");
        std::fs::write(&target_file, b"x").unwrap();
        std::fs::set_permissions(&target_file, std::fs::Permissions::from_mode(0o644)).unwrap();
        std::os::unix::fs::symlink(&target_file, &dir).unwrap();
        assert!(plan(&launch, true, base.path()).is_err());
        assert_eq!(
            std::fs::metadata(&target_file).unwrap().permissions().mode() & 0o777,
            0o644
        );
        std::fs::remove_file(&dir).unwrap();

        // A plain file in its place.
        std::fs::write(&dir, b"x").unwrap();
        assert!(matches!(
            plan(&launch, true, base.path()),
            Err(CtlPathError::InsecureFallbackDir(_))
        ));
    }

    #[test]
    fn names_that_could_climb_out_of_the_directory_are_not_mapped() {
        let base = Path::new("/tmp");
        for bad in ["../x-AbC123", "no-suffix-", "-AbC123", "nodash", "a b-AbC123", "a-b/c"] {
            let launch = Path::new("/very/long").join(bad);
            // `file_name()` of "a-b/c" is "c": still no dash, so unmapped either way.
            if let Some(socket) = fallback_socket_in(base, &launch) {
                assert!(socket.starts_with(fallback_dir_in(base)), "{bad} escaped: {socket:?}");
            }
        }
        assert_eq!(fallback_socket_in(base, Path::new("/x/nodash")), None);
        assert_eq!(fallback_socket_in(base, Path::new("/x/a b-AbC123")), None);
    }

    #[test]
    fn a_long_agent_label_is_truncated_but_the_suffix_keeps_the_name_unique() {
        let base = Path::new("/tmp");
        let name = format!("{}-AbC123", "a".repeat(80));
        let socket = fallback_socket_in(base, &Path::new("/x").join(&name)).unwrap();
        let file = socket.file_name().unwrap().to_str().unwrap();
        assert_eq!(file, format!("{}-AbC123.sock", "a".repeat(LABEL_MAX)));
    }
}
