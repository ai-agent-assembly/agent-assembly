//! Host-side resolution of the proxy endpoint `aasm run` routes a governed tool
//! at (AAASM-5323).
//!
//! # The failure this exists to remove
//!
//! `aasm run` used to take its proxy address from whatever the gateway put in
//! the `proxy_addr` field of its registration response, and injected
//! `HTTPS_PROXY` **only when that field was present**. Nothing in the tree ever
//! set it, so every launch went out completely unproxied and uninspected while
//! reporting as governed. An absent value must never be able to mean "no
//! interception, proceed anyway".
//!
//! # Why the address is resolved here and not accepted from anyone
//!
//! The proxy endpoint is a *local host fact*: it is where the sidecar this user
//! started is listening. A gateway response, an adapter, the launched tool, and
//! the ambient environment are all outside the trust boundary for that fact —
//! each of them is either remote, or writable by the very software the proxy
//! exists to inspect. Any of them naming the endpoint is an invitation to
//! redirect a governed session at an attacker's listener, or at nothing.
//!
//! So the only accepted source is the state file `aasm proxy start` writes, and
//! the record is trusted only after every one of these holds:
//!
//! 1. the file is a regular file owned by this user and not writable by group
//!    or other — otherwise someone else could have authored the record;
//! 2. every field is present (see [`super::pid::read_state`]);
//! 3. the recorded PID is alive and signallable by this user;
//! 4. the live process's executable *and* start time match what was recorded —
//!    liveness alone cannot distinguish the proxy from an unrelated process
//!    that inherited its recycled PID (see [`super::identity`]);
//! 5. the recorded executable is the proxy binary, not merely *some* binary;
//! 6. the endpoint parses as an `http://` URL on a loopback address with a
//!    non-zero port; and
//! 7. something is actually accepting connections there.
//!
//! Failure at any step is fatal to the launch. There is no fallback, because
//! every conceivable fallback is a direct unprotected connection.

use std::fmt;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use url::Url;

use super::identity;
use super::pid::{self, ProxyState};

/// The executable name a trusted record must be for. Establishes that the
/// record describes the proxy rather than any other live process the user
/// happens to own — an identity claim, not a liveness one.
const PROXY_BINARY_NAME: &str = "aa-proxy";

/// How long to wait for the recorded endpoint to accept a connection. Short on
/// purpose: this is a loopback socket that is either bound or not, and a launch
/// must not hang on the check.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(1);

/// Why a trusted proxy endpoint could not be established.
///
/// Every variant is a refusal. Messages name the offending fact and the file it
/// came from so an operator can fix it, and carry no environment values, no
/// process arguments and no file contents beyond the fields listed here — the
/// diagnostic is printed to a terminal that may be captured into CI logs.
#[derive(Debug)]
pub enum ProxyTrustError {
    /// No state file at all — the usual case: no proxy has been started.
    NoProxyRecorded { path: PathBuf },
    /// The state file exists but is not a plain file this user solely controls.
    UntrustedStateFile { path: PathBuf, reason: String },
    /// Present but not a complete record.
    MalformedRecord { path: PathBuf },
    /// The recorded PID is not a process this user can signal.
    ProxyNotRunning { pid: u32 },
    /// The platform cannot supply the identity evidence the check needs.
    IdentityUnavailable { pid: u32 },
    /// The PID is live but is not the process that was recorded.
    IdentityMismatch { pid: u32, field: &'static str },
    /// The record names something other than the proxy binary.
    NotTheProxyBinary { exe: PathBuf },
    /// The recorded address is not a usable loopback proxy endpoint.
    UnusableEndpoint { addr: String, reason: String },
    /// Nothing is accepting connections at the recorded address.
    EndpointNotListening { addr: SocketAddr },
}

impl std::error::Error for ProxyTrustError {}

impl fmt::Display for ProxyTrustError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoProxyRecorded { path } => write!(
                f,
                "no governed proxy is running (no state file at {}). Start one with `aasm proxy start`",
                path.display()
            ),
            Self::UntrustedStateFile { path, reason } => write!(
                f,
                "the proxy state file {} cannot be trusted: {reason}. Remove it and re-run `aasm proxy start`",
                path.display()
            ),
            Self::MalformedRecord { path } => write!(
                f,
                "the proxy state file {} is not a complete record. Remove it and re-run `aasm proxy start`",
                path.display()
            ),
            Self::ProxyNotRunning { pid } => write!(
                f,
                "the recorded proxy (PID {pid}) is not running. Re-run `aasm proxy start`"
            ),
            Self::IdentityUnavailable { pid } => write!(
                f,
                "this platform ({}) cannot report the identity of PID {pid}, so the recorded proxy \
                 cannot be verified",
                std::env::consts::OS
            ),
            Self::IdentityMismatch { pid, field } => write!(
                f,
                "PID {pid} is live but its {field} does not match the recorded proxy — the proxy \
                 exited and an unrelated process took its PID. Re-run `aasm proxy start`"
            ),
            Self::NotTheProxyBinary { exe } => write!(
                f,
                "the proxy state file names {}, which is not `{PROXY_BINARY_NAME}`",
                exe.display()
            ),
            Self::UnusableEndpoint { addr, reason } => {
                write!(f, "the recorded proxy endpoint `{addr}` is unusable: {reason}")
            }
            Self::EndpointNotListening { addr } => write!(
                f,
                "nothing is accepting connections at the recorded proxy endpoint {addr}. \
                 Check `aasm proxy status`"
            ),
        }
    }
}

/// Resolve the proxy endpoint to route a governed launch through.
///
/// Returns the `http://host:port` URL on success. Every error is a refusal —
/// see the module docs for why there is no fallback.
pub fn resolve_trusted_endpoint() -> Result<Url, ProxyTrustError> {
    let path = pid::pid_path();

    let meta = match std::fs::symlink_metadata(&path) {
        Ok(meta) => meta,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(ProxyTrustError::NoProxyRecorded { path }),
        Err(e) => {
            return Err(ProxyTrustError::UntrustedStateFile {
                path,
                reason: format!("it could not be inspected ({e})"),
            })
        }
    };
    verify_state_file(&path, &meta, current_uid())?;

    let state = pid::read_state().ok_or(ProxyTrustError::MalformedRecord { path })?;
    verify_process(&state)?;

    let url = verify_endpoint(&state.listen_addr)?;
    let addr = socket_addr_of(&url).expect("verify_endpoint only returns URLs with a socket address");
    verify_listening(addr)?;
    Ok(url)
}

/// The effective UID this process runs as, i.e. the only principal entitled to
/// have authored a record this process will act on.
#[cfg(unix)]
fn current_uid() -> u32 {
    // Safety: `geteuid` takes no arguments and cannot fail.
    unsafe { libc::geteuid() }
}

#[cfg(not(unix))]
fn current_uid() -> u32 {
    0
}

/// Constraint: the record must be one only this user could have written.
///
/// A symlink is rejected rather than followed: the metadata that was vetted must
/// be the metadata of the bytes that get read, and following a link opens a
/// window where the two differ. Group/other write bits are rejected because a
/// record another principal can rewrite is a record another principal can use to
/// choose where a governed tool's traffic goes.
///
/// `expected_uid` is a parameter rather than read inside, so the rejection path
/// is reachable in a test — a check that can only ever be exercised with the
/// running user's own UID cannot be shown to fail.
pub fn verify_state_file(
    path: &std::path::Path,
    meta: &std::fs::Metadata,
    expected_uid: u32,
) -> Result<(), ProxyTrustError> {
    if !meta.is_file() {
        return Err(ProxyTrustError::UntrustedStateFile {
            path: path.to_path_buf(),
            reason: "it is not a regular file".into(),
        });
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        use std::os::unix::fs::PermissionsExt;
        let owner = meta.uid();
        if owner != expected_uid {
            return Err(ProxyTrustError::UntrustedStateFile {
                path: path.to_path_buf(),
                reason: format!("it is owned by uid {owner}, not by this user (uid {expected_uid})"),
            });
        }
        let mode = meta.permissions().mode() & 0o777;
        if mode & 0o022 != 0 {
            return Err(ProxyTrustError::UntrustedStateFile {
                path: path.to_path_buf(),
                reason: format!("its mode {mode:04o} lets group or other write to it"),
            });
        }
    }
    Ok(())
}

/// Constraints: the record names the proxy (5), and the process behind it is
/// alive (3) and still the one that was recorded (4).
pub fn verify_process(state: &ProxyState) -> Result<(), ProxyTrustError> {
    verify_proxy_binary(&state.exe_path)?;
    verify_identity(state)
}

/// Constraint 5, as a claim about the record itself: it must describe the proxy
/// binary and not merely some binary. Without it, a record naming any live
/// process this user owns — a shell, an editor, an attacker's listener launched
/// under the user's own account — would satisfy every remaining check.
pub fn verify_proxy_binary(exe: &std::path::Path) -> Result<(), ProxyTrustError> {
    if exe.file_name().and_then(|n| n.to_str()) == Some(PROXY_BINARY_NAME) {
        Ok(())
    } else {
        Err(ProxyTrustError::NotTheProxyBinary { exe: exe.to_path_buf() })
    }
}

/// Constraints 3 and 4: the recorded PID is alive, and the process holding it
/// now is the one the record was written about.
///
/// The two identity fields are not redundant. The executable rules out the
/// common case — a recycled PID now running something else entirely — but a
/// *second* `aa-proxy`, started later, could take the same PID and pass that
/// check while listening somewhere else or under a different policy. That is
/// precisely what the start time closes: a successor cannot have started before
/// its predecessor exited, so a matching `(pid, start time)` pair identifies one
/// incarnation of one process.
pub fn verify_identity(state: &ProxyState) -> Result<(), ProxyTrustError> {
    if !identity::is_alive(state.pid) {
        return Err(ProxyTrustError::ProxyNotRunning { pid: state.pid });
    }

    let (Some(exe), Some(token)) = (identity::exe_path(state.pid), identity::start_token(state.pid)) else {
        // Either the process vanished between the liveness check and here, or
        // the platform has no implementation. Both mean "cannot verify", and
        // cannot-verify is a refusal, never a pass.
        return Err(ProxyTrustError::IdentityUnavailable { pid: state.pid });
    };

    if exe != state.exe_path {
        return Err(ProxyTrustError::IdentityMismatch {
            pid: state.pid,
            field: "executable",
        });
    }
    if token != state.start_token {
        return Err(ProxyTrustError::IdentityMismatch {
            pid: state.pid,
            field: "start time",
        });
    }
    Ok(())
}

/// Constraint: scheme, host and port of the resulting address.
///
/// The scheme is synthesised rather than read, so the record cannot smuggle in
/// `https://` (which no MitM proxy speaks) or a non-network scheme. The host
/// must be a loopback **literal**: a hostname would be resolved by whatever
/// resolver the child inherits, which puts the destination back under the
/// control of something outside the trust boundary, and a non-loopback address
/// means the session's plaintext leaves this machine to a host this check
/// cannot vouch for.
pub fn verify_endpoint(listen_addr: &str) -> Result<Url, ProxyTrustError> {
    let unusable = |reason: &str| ProxyTrustError::UnusableEndpoint {
        addr: listen_addr.to_string(),
        reason: reason.to_string(),
    };

    let socket: SocketAddr = listen_addr
        .parse()
        .map_err(|_| unusable("it is not an `ip:port` literal"))?;
    if !socket.ip().is_loopback() {
        return Err(unusable(
            "it is not a loopback address, so intercepted traffic would leave this machine",
        ));
    }
    if socket.port() == 0 {
        return Err(unusable("port 0 is not a listening port"));
    }

    let url = Url::parse(&format!("http://{socket}")).map_err(|_| unusable("it does not form a URL"))?;
    if url.scheme() != "http" {
        return Err(unusable("only an http:// proxy endpoint is accepted"));
    }
    if socket_addr_of(&url) != Some(socket) {
        return Err(unusable("the URL does not round-trip to the recorded address"));
    }
    Ok(url)
}

/// The socket address a validated endpoint URL denotes, or `None` if its host is
/// not an IP literal.
fn socket_addr_of(url: &Url) -> Option<SocketAddr> {
    match (url.host()?, url.port()) {
        (url::Host::Ipv4(ip), Some(port)) => Some(SocketAddr::from((ip, port))),
        (url::Host::Ipv6(ip), Some(port)) => Some(SocketAddr::from((ip, port))),
        _ => None,
    }
}

/// Constraint: a socket is actually bound at the recorded address.
///
/// The record says where the proxy was *told* to listen. A proxy that died
/// during startup, or was killed and had its PID reused by another `aa-proxy`
/// bound elsewhere, leaves a record that passes every other check while nothing
/// answers — and a launch routed at a closed port fails in whatever way the tool
/// chooses, which historically has meant falling back to a direct connection.
pub fn verify_listening(addr: SocketAddr) -> Result<(), ProxyTrustError> {
    std::net::TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT)
        .map(|_| ())
        .map_err(|_| ProxyTrustError::EndpointNotListening { addr })
}
