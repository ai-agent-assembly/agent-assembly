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

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;

    /// A record that describes this very test process truthfully: alive, real
    /// executable, current start token. Every identity test starts from a
    /// record that *passes* and breaks exactly one field, so a test that fails
    /// names the field that mattered.
    ///
    /// The `aa-proxy` file-name rule is asserted separately
    /// ([`verify_proxy_binary`]) rather than being folded in here: the test
    /// binary is not named `aa-proxy` and cannot honestly claim to be, and
    /// faking it would leave the identity comparison measuring a fixture rather
    /// than the kernel.
    fn truthful_state_for_self() -> ProxyState {
        let pid = std::process::id();
        ProxyState {
            pid,
            listen_addr: "127.0.0.1:8899".into(),
            start_token: identity::start_token(pid).expect("own start token"),
            exe_path: identity::exe_path(pid).expect("own exe path"),
        }
    }

    // ---- constraint 6: scheme / host / port ----

    #[test]
    fn a_loopback_endpoint_resolves_to_an_http_url() {
        let url = verify_endpoint("127.0.0.1:8899").expect("loopback endpoint must be accepted");
        assert_eq!(url.as_str(), "http://127.0.0.1:8899/");
        assert_eq!(url.scheme(), "http");
    }

    #[test]
    fn a_non_loopback_endpoint_is_refused() {
        let err = verify_endpoint("10.0.0.5:8899").expect_err("a routable address must be refused");
        assert!(
            matches!(err, ProxyTrustError::UnusableEndpoint { .. }),
            "expected UnusableEndpoint, got {err:?}"
        );
        assert!(
            err.to_string().contains("loopback"),
            "the diagnostic must say why: {err}"
        );
    }

    #[test]
    fn a_wildcard_bind_is_refused() {
        // `0.0.0.0` is reachable from off-box, so a proxy bound there is not a
        // loopback endpoint even though `aasm proxy start --listen` accepts it.
        assert!(verify_endpoint("0.0.0.0:8899").is_err());
    }

    #[test]
    fn a_hostname_endpoint_is_refused() {
        // Resolution would be performed by the child's resolver, which is
        // outside the trust boundary.
        assert!(verify_endpoint("localhost:8899").is_err());
        assert!(verify_endpoint("proxy.internal:8899").is_err());
    }

    #[test]
    fn port_zero_is_refused() {
        assert!(verify_endpoint("127.0.0.1:0").is_err());
    }

    #[test]
    fn a_bare_url_in_the_address_field_is_refused() {
        // The scheme is synthesised, never read from the record.
        assert!(verify_endpoint("http://127.0.0.1:8899").is_err());
        assert!(verify_endpoint("https://127.0.0.1:8899").is_err());
    }

    // ---- constraint 2: state-file ownership and permissions ----

    fn write_mode(path: &Path, mode: u32) {
        std::fs::write(path, "unused").unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    #[test]
    fn a_private_file_owned_by_this_user_is_accepted() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("proxy.pid");
        write_mode(&path, 0o600);
        let meta = std::fs::symlink_metadata(&path).unwrap();
        verify_state_file(&path, &meta, current_uid()).expect("0600 file owned by us must be accepted");
    }

    #[test]
    fn a_file_owned_by_another_user_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("proxy.pid");
        write_mode(&path, 0o600);
        let meta = std::fs::symlink_metadata(&path).unwrap();
        // Chowning to another user needs privileges no test has, so the
        // *expectation* is moved instead — the comparison under test is the
        // same one either way.
        let err = verify_state_file(&path, &meta, current_uid().wrapping_add(1))
            .expect_err("a file owned by someone else must be refused");
        assert!(
            matches!(err, ProxyTrustError::UntrustedStateFile { .. }),
            "expected UntrustedStateFile, got {err:?}"
        );
        assert!(
            err.to_string().contains("owned by uid"),
            "diagnostic must say why: {err}"
        );
    }

    #[test]
    fn a_group_or_world_writable_file_is_refused() {
        for mode in [0o620, 0o602, 0o666, 0o777] {
            let tmp = tempfile::tempdir().unwrap();
            let path = tmp.path().join("proxy.pid");
            write_mode(&path, mode);
            let meta = std::fs::symlink_metadata(&path).unwrap();
            let Err(err) = verify_state_file(&path, &meta, current_uid()) else {
                panic!("mode {mode:o} lets another principal rewrite the record; it must be refused");
            };
            assert!(
                matches!(err, ProxyTrustError::UntrustedStateFile { .. }),
                "mode {mode:o}: expected UntrustedStateFile, got {err:?}"
            );
        }
    }

    #[test]
    fn a_directory_is_not_a_state_file() {
        let tmp = tempfile::tempdir().unwrap();
        let meta = std::fs::symlink_metadata(tmp.path()).unwrap();
        assert!(verify_state_file(tmp.path(), &meta, current_uid()).is_err());
    }

    #[test]
    fn a_symlink_is_refused_rather_than_followed() {
        let tmp = tempfile::tempdir().unwrap();
        let real = tmp.path().join("real.pid");
        write_mode(&real, 0o600);
        let link = tmp.path().join("proxy.pid");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let meta = std::fs::symlink_metadata(&link).unwrap();
        assert!(
            verify_state_file(&link, &meta, current_uid()).is_err(),
            "a symlink must be refused; vetting the target's metadata is not vetting the link"
        );
    }

    // ---- constraints 3, 4, 5: process liveness and identity ----

    /// The fixture's own honesty check: the record every identity test starts
    /// from must *pass*, or the tests below would be reporting a refusal that
    /// the field they broke had nothing to do with.
    #[test]
    fn a_truthful_record_about_a_live_process_is_accepted() {
        verify_identity(&truthful_state_for_self()).expect(
            "a record describing this live process truthfully must be accepted; if it is not, \
             every refusal asserted below proves nothing about the field it broke",
        );
    }

    #[test]
    fn a_record_naming_a_binary_other_than_the_proxy_is_refused() {
        for exe in ["/bin/sh", "/usr/bin/nc", "/tmp/aa-proxy-lookalike"] {
            let err = verify_proxy_binary(Path::new(exe)).expect_err("only the proxy binary may be trusted");
            assert!(
                matches!(err, ProxyTrustError::NotTheProxyBinary { .. }),
                "{exe}: expected NotTheProxyBinary, got {err:?}"
            );
        }
        verify_proxy_binary(Path::new("/usr/local/bin/aa-proxy")).expect("the proxy binary must be accepted");
    }

    /// Stale state: the record names a PID whose process has exited. Nothing
    /// about it is verifiable, so it is refused rather than probed further.
    #[test]
    fn a_stale_pid_is_refused() {
        let mut child = std::process::Command::new("true").spawn().expect("spawn `true`");
        let pid = child.id();
        child.wait().expect("reap `true`");

        let mut state = truthful_state_for_self();
        state.pid = pid;
        let err = verify_identity(&state).expect_err("a dead PID must be refused");
        assert!(
            matches!(
                err,
                ProxyTrustError::ProxyNotRunning { .. } | ProxyTrustError::IdentityUnavailable { .. }
            ),
            "expected the record to be refused as not-running, got {err:?}"
        );
    }

    /// PID reuse, executable-visible case: the number is live but is running
    /// some other image. This is the shape of the attack a liveness-only check
    /// waves through.
    #[test]
    fn a_live_pid_running_a_different_executable_is_refused() {
        let mut state = truthful_state_for_self();
        state.exe_path = PathBuf::from(format!("/opt/{PROXY_BINARY_NAME}"));
        let err = verify_identity(&state).expect_err("a different executable must be refused");
        assert!(
            matches!(
                err,
                ProxyTrustError::IdentityMismatch {
                    field: "executable",
                    ..
                }
            ),
            "expected an executable mismatch, got {err:?}"
        );
    }

    /// PID reuse, executable-invisible case: a *second* proxy took the recycled
    /// PID, so the image matches and only the start time can tell the two
    /// incarnations apart. Without this comparison the record would be trusted.
    #[test]
    fn a_live_pid_with_a_different_start_time_is_refused() {
        let mut state = truthful_state_for_self();
        state.start_token = format!("{}-earlier-incarnation", state.start_token);
        let err = verify_identity(&state).expect_err("a recycled PID must be refused");
        assert!(
            matches!(
                err,
                ProxyTrustError::IdentityMismatch {
                    field: "start time",
                    ..
                }
            ),
            "expected a start-time mismatch, got {err:?}"
        );
    }

    // ---- constraint 4: the socket is actually bound ----

    #[test]
    fn a_bound_loopback_socket_passes_the_listening_check() {
        let _lock = crate::test_support::net_guard();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("local_addr");
        verify_listening(addr).expect("a bound socket must pass");
    }

    #[test]
    fn an_unbound_endpoint_is_refused() {
        let _lock = crate::test_support::net_guard();
        // Bind then drop, so the port is one nothing is listening on.
        let addr = {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
            listener.local_addr().expect("local_addr")
        };
        let err = verify_listening(addr).expect_err("an unbound port must be refused");
        assert!(
            matches!(err, ProxyTrustError::EndpointNotListening { .. }),
            "expected EndpointNotListening, got {err:?}"
        );
    }

    // ---- end to end: the resolver refuses when no proxy has been started ----

    #[test]
    fn resolution_refuses_when_no_state_file_exists() {
        let _lock = crate::test_support::env_guard();
        let prior = std::env::var("AA_DATA_DIR").ok();
        let tmp = tempfile::tempdir().unwrap();
        std::env::set_var("AA_DATA_DIR", tmp.path());

        let result = resolve_trusted_endpoint();

        match prior {
            Some(v) => std::env::set_var("AA_DATA_DIR", v),
            None => std::env::remove_var("AA_DATA_DIR"),
        }

        let err = result.expect_err("with no proxy started there is no endpoint to trust");
        assert!(
            matches!(err, ProxyTrustError::NoProxyRecorded { .. }),
            "expected NoProxyRecorded, got {err:?}"
        );
    }

    #[test]
    fn resolution_refuses_a_record_without_identity_evidence() {
        let _lock = crate::test_support::env_guard();
        let prior = std::env::var("AA_DATA_DIR").ok();
        let tmp = tempfile::tempdir().unwrap();
        std::env::set_var("AA_DATA_DIR", tmp.path());
        let path = tmp.path().join("proxy.pid");
        std::fs::write(&path, format!("{}\n127.0.0.1:8899\n", std::process::id())).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();

        let result = resolve_trusted_endpoint();

        match prior {
            Some(v) => std::env::set_var("AA_DATA_DIR", v),
            None => std::env::remove_var("AA_DATA_DIR"),
        }

        let err = result.expect_err("a two-line record carries no identity evidence");
        assert!(
            matches!(err, ProxyTrustError::MalformedRecord { .. }),
            "expected MalformedRecord, got {err:?}"
        );
    }

    #[test]
    fn resolution_refuses_an_over_permissive_record() {
        let _lock = crate::test_support::env_guard();
        let prior = std::env::var("AA_DATA_DIR").ok();
        let tmp = tempfile::tempdir().unwrap();
        std::env::set_var("AA_DATA_DIR", tmp.path());
        let path = tmp.path().join("proxy.pid");
        std::fs::write(
            &path,
            format!(
                "{}\n127.0.0.1:8899\nlinux-starttime:1\n/usr/local/bin/{PROXY_BINARY_NAME}\n",
                std::process::id()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();

        let result = resolve_trusted_endpoint();

        match prior {
            Some(v) => std::env::set_var("AA_DATA_DIR", v),
            None => std::env::remove_var("AA_DATA_DIR"),
        }

        let err = result.expect_err("a world-writable record must not be trusted");
        assert!(
            matches!(err, ProxyTrustError::UntrustedStateFile { .. }),
            "expected UntrustedStateFile, got {err:?}"
        );
    }
}
