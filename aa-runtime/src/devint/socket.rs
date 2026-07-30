//! Where the DI-API socket lives, and the OS half of its trust model
//! (ADR 0030 §5.1, §5.2, §5.3 layer 1).
//!
//! # The path
//!
//! `~/.aa/run/devint.sock`, under the same `~/.aa/` root `aa-proxy` already
//! uses for its CA — deliberately **not** world-writable `/tmp`, unlike the
//! legacy `/tmp/aa-runtime-{agent_id}.sock`. `AA_DEVINT_SOCKET` overrides it
//! for tests and unusual deployments; ADR 0030's operational guidance is that
//! an override must preserve both permission bits, so [`bind`] enforces them
//! wherever the socket ends up rather than trusting the location.
//!
//! It is a **separate socket from the SDK fast path**, and that separation is
//! a security property rather than tidiness: a DI client never holds a file
//! descriptor onto agent-action or policy-decision traffic, so that traffic is
//! unreachable to it by construction instead of by an authorization rule
//! someone has to remember to write.
//!
//! # Discovery
//!
//! [`discover`] answers "is the runtime there?" without connecting. A missing
//! socket means *the runtime is not running* — a bootstrap prompt, not an error
//! to retry silently — because the thin client is the only layer that exists
//! when the runtime does not (ADR 0030 matrix row 4).
//!
//! # The permission gate
//!
//! Directory `0700`, socket `0600`, created under a tightened `umask` so the
//! inode is never group- or world-accessible even momentarily — the same
//! construction (and the same AAASM-3581 reasoning) as
//! [`crate::ipc::server::IpcServer::bind`].
//!
//! Both modes are **re-asserted on every bind**, not assumed from the last one.
//! That mirrors the AAASM-4936 fix in `aa-proxy/src/tls/ca.rs`: permissions
//! enforced only at creation time are permissions a backup restore, an older
//! build or a careless `cp` can quietly loosen. A relaxed mode here would
//! delete the OS layer of the two-layer authentication and leave only the
//! token, so [`assert_owner_only`] fails the bind rather than serving on a
//! socket other users can reach.
//!
//! Loopback TCP is not offered at all. It is reachable by every local user and
//! by a browser, the kernel supplies no peer identity for it, and it adds
//! port-scanning, CSRF and DNS-rebinding surface — ADR 0030 forbidden design 7.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use tokio::net::UnixListener;

/// Environment variable that overrides the DI-API socket path.
pub const SOCKET_PATH_ENV: &str = "AA_DEVINT_SOCKET";

/// Directory under `$HOME` that holds runtime sockets.
const RUN_DIR: &str = ".aa/run";

/// The socket file name inside [`RUN_DIR`].
const SOCKET_FILE: &str = "devint.sock";

/// Required mode for the directory holding the socket.
pub const REQUIRED_DIR_MODE: u32 = 0o700;

/// Required mode for the socket itself.
pub const REQUIRED_SOCKET_MODE: u32 = 0o600;

/// What went wrong preparing or binding the DI-API socket.
///
/// Hand-written rather than derived, matching [`crate::ipc::codec::CodecError`]
/// — `aa-runtime` does not depend on `thiserror`.
#[derive(Debug)]
pub enum SocketError {
    /// No home directory could be resolved and no override was set, so there is
    /// no defensible place to put the socket. Deliberately an error rather than
    /// a fallback to a shared directory.
    NoHome,
    /// The socket path has no parent directory to enforce `0700` on.
    NoParent {
        /// The offending path.
        path: PathBuf,
    },
    /// The directory or socket is not owner-only. Fails the bind: without this
    /// the OS layer of the two-layer authentication is gone.
    Permissions {
        /// "directory" or "socket".
        what: &'static str,
        /// What was inspected.
        path: PathBuf,
        /// What it actually is.
        actual: u32,
        /// What it must be.
        expected: u32,
    },
    /// Anything the filesystem or the listener reported.
    Io(std::io::Error),
}

impl std::fmt::Display for SocketError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SocketError::NoHome => write!(
                f,
                "cannot resolve a home directory for {RUN_DIR}; set {SOCKET_PATH_ENV} explicitly"
            ),
            SocketError::NoParent { path } => {
                write!(f, "socket path {} has no parent directory", path.display())
            }
            SocketError::Permissions {
                what,
                path,
                actual,
                expected,
            } => write!(f, "{what} {} is mode {actual:o}, expected {expected:o}", path.display()),
            SocketError::Io(e) => write!(f, "DI-API socket I/O error: {e}"),
        }
    }
}

impl std::error::Error for SocketError {}

impl From<std::io::Error> for SocketError {
    fn from(e: std::io::Error) -> Self {
        SocketError::Io(e)
    }
}

/// Whether the runtime appears to be listening.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SocketDiscovery {
    /// A socket exists at this path. The client should connect; a refused
    /// connection then means a stale socket file, which is a different problem
    /// from "not installed".
    Present(PathBuf),
    /// No socket exists. The runtime is not running: prompt to bootstrap it,
    /// do not retry in a loop.
    RuntimeNotRunning(PathBuf),
}

impl SocketDiscovery {
    /// The path that was probed, present or not.
    pub fn path(&self) -> &Path {
        match self {
            SocketDiscovery::Present(p) | SocketDiscovery::RuntimeNotRunning(p) => p,
        }
    }
}

/// Resolve the DI-API socket path: `$AA_DEVINT_SOCKET`, else
/// `$HOME/.aa/run/devint.sock`.
pub fn devint_socket_path() -> Result<PathBuf, SocketError> {
    if let Some(explicit) = std::env::var_os(SOCKET_PATH_ENV) {
        return Ok(PathBuf::from(explicit));
    }
    let home = std::env::var_os("HOME").ok_or(SocketError::NoHome)?;
    Ok(PathBuf::from(home).join(RUN_DIR).join(SOCKET_FILE))
}

/// Probe for a listening runtime without connecting to it.
pub fn discover(path: &Path) -> SocketDiscovery {
    if path.exists() {
        SocketDiscovery::Present(path.to_path_buf())
    } else {
        SocketDiscovery::RuntimeNotRunning(path.to_path_buf())
    }
}

/// Create the socket's parent directory `0700` if it is missing, and re-assert
/// `0700` on it if it already exists.
pub fn prepare_socket_dir(socket_path: &Path) -> Result<PathBuf, SocketError> {
    let dir = socket_path.parent().ok_or_else(|| SocketError::NoParent {
        path: socket_path.to_path_buf(),
    })?;
    if !dir.exists() {
        std::fs::create_dir_all(dir)?;
    }
    // Re-assert rather than assume: `create_dir_all` honours the process umask
    // for intermediate components, and an existing directory may predate this
    // requirement entirely.
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(REQUIRED_DIR_MODE))?;
    Ok(dir.to_path_buf())
}

/// Verify that `path` is exactly `expected`, ignoring file-type bits.
///
/// Read back from the filesystem on purpose. The value that matters is what the
/// kernel will enforce for the next `connect()`, not what this process believes
/// it set.
pub fn assert_owner_only(path: &Path, expected: u32, what: &'static str) -> Result<(), SocketError> {
    let actual = std::fs::metadata(path)?.permissions().mode() & 0o777;
    if actual != expected {
        return Err(SocketError::Permissions {
            what,
            path: path.to_path_buf(),
            actual,
            expected,
        });
    }
    Ok(())
}

/// Bind the DI-API listener at `socket_path`, owner-only end to end.
///
/// Removes a stale socket file, ensures the parent directory is `0700`, binds
/// under `umask(0o077)` so the inode is `0600` from its first instant, and then
/// reads both modes back and fails if either is wrong.
pub fn bind(socket_path: &Path) -> Result<UnixListener, SocketError> {
    let dir = prepare_socket_dir(socket_path)?;
    assert_owner_only(&dir, REQUIRED_DIR_MODE, "directory")?;

    if socket_path.exists() {
        std::fs::remove_file(socket_path)?;
        tracing::info!(path = %socket_path.display(), "removed stale DI-API socket file");
    }

    let listener = {
        // AAASM-3581's construction: no bind→chmod window during which another
        // local process could connect.
        //
        // SAFETY: `umask` cannot fail and has no preconditions. It is
        // process-global, so the previous value is restored immediately —
        // including on a failed bind — to avoid leaking a tightened umask into
        // unrelated file creation elsewhere in the runtime.
        let prev_umask = unsafe { libc::umask(0o077) };
        let result = UnixListener::bind(socket_path);
        unsafe { libc::umask(prev_umask) };
        result?
    };

    std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(REQUIRED_SOCKET_MODE))?;
    assert_owner_only(socket_path, REQUIRED_SOCKET_MODE, "socket")?;

    tracing::info!(
        path = %socket_path.display(),
        "DI-API socket bound (dir 0700, socket 0600)"
    );
    Ok(listener)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discovery_reports_an_absent_socket_as_runtime_not_running() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("devint.sock");
        assert_eq!(discover(&path), SocketDiscovery::RuntimeNotRunning(path.clone()));
        assert_eq!(discover(&path).path(), path.as_path());
    }

    #[tokio::test]
    async fn a_bound_socket_is_0600_in_a_0700_directory() {
        let root = tempfile::tempdir().expect("tempdir");
        let path = root.path().join("run").join("devint.sock");
        let _listener = bind(&path).expect("bind");

        // Asserted by reading the filesystem back, not by trusting the setter.
        let socket_mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        let dir_mode = std::fs::metadata(path.parent().unwrap()).unwrap().permissions().mode() & 0o777;
        assert_eq!(socket_mode, 0o600, "socket must be owner-only");
        assert_eq!(dir_mode, 0o700, "socket directory must be owner-only");
        assert_eq!(discover(&path), SocketDiscovery::Present(path.clone()));
    }

    #[tokio::test]
    async fn binding_tightens_a_loose_pre_existing_directory() {
        let root = tempfile::tempdir().expect("tempdir");
        let dir = root.path().join("run");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777)).unwrap();

        let path = dir.join("devint.sock");
        let _listener = bind(&path).expect("bind");
        let dir_mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(dir_mode, 0o700, "a pre-existing loose directory must be tightened");
    }

    #[tokio::test]
    async fn binding_replaces_a_stale_socket_file() {
        let root = tempfile::tempdir().expect("tempdir");
        let path = root.path().join("run").join("devint.sock");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, b"stale").unwrap();

        let _listener = bind(&path).expect("bind over a stale file");
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn a_loose_mode_is_rejected_rather_than_served() {
        let root = tempfile::tempdir().expect("tempdir");
        let file = root.path().join("loose");
        std::fs::write(&file, b"x").unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();

        let err = assert_owner_only(&file, REQUIRED_SOCKET_MODE, "socket").expect_err("must reject 0644");
        match err {
            SocketError::Permissions { actual, expected, .. } => {
                assert_eq!(actual, 0o644);
                assert_eq!(expected, 0o600);
            }
            other => panic!("expected a permissions error, got {other:?}"),
        }
    }

    #[test]
    fn the_override_wins_over_the_home_convention() {
        // `devint_socket_path` reads process-global env, so this test asserts
        // the resolution rule directly rather than mutating the environment
        // under a parallel test runner.
        let overridden = PathBuf::from("/somewhere/else/devint.sock");
        assert_eq!(overridden.file_name().unwrap(), SOCKET_FILE);
        assert_eq!(SOCKET_PATH_ENV, "AA_DEVINT_SOCKET");
        assert_eq!(
            PathBuf::from("/h").join(RUN_DIR).join(SOCKET_FILE).to_string_lossy(),
            "/h/.aa/run/devint.sock"
        );
    }
}
