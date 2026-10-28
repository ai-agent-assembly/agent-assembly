//! `aasm proxy revoke-credential` — revoke a brokered provider credential in a
//! running aa-proxy (AAASM-6262, J84 AC3).
//!
//! Talks to the proxy's revoke-only control socket
//! ([`aa_proxy::control`]). The command can only remove access: it cannot
//! install, rotate or read a credential, and nothing it prints is derived from a
//! secret.
//!
//! Exit status, because a script has to tell these apart:
//!
//! | code | meaning |
//! |---|---|
//! | 0 | revoked (or already revoked) and written to the durable record |
//! | 1 | nothing was revoked: no credential for the host, request refused, or the proxy could not be reached |
//! | 3 | revoked in the running proxy, but **not** written to a durable record, so a restart can bring the credential back |

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use aa_proxy::control::{Outcome, Response, MAX_REQUEST_BYTES};
use clap::Args;

use super::pid::pid_path;

/// How long to wait for the proxy to answer before giving up.
const IO_TIMEOUT: Duration = Duration::from_secs(5);

/// Arguments for `aasm proxy revoke-credential`.
#[derive(Debug, Args)]
pub struct RevokeArgs {
    /// Host whose brokered credential to revoke, for example `api.anthropic.com`.
    #[arg(long)]
    pub host: String,
    /// Control socket of the running proxy. Defaults to the one
    /// `aasm proxy start` configures.
    #[arg(long, conflicts_with = "agent")]
    pub socket: Option<PathBuf>,
    /// Revoke in the proxy `aasm run` started for this registered agent id,
    /// instead of the standalone proxy. Picks the newest of that agent's launches
    /// whose proxy still answers.
    #[arg(long)]
    pub agent: Option<String>,
}

/// Where `aasm proxy start` tells the proxy to listen for control requests.
///
/// A sibling of the proxy's state file, so it follows `AA_DATA_DIR` exactly the
/// way that file does.
pub fn control_socket_path() -> PathBuf {
    pid_path().with_file_name("proxy.ctl")
}

/// Where `aasm proxy start` tells the proxy to keep its durable revocation
/// record, beside the state file for the same reason.
pub fn revocations_path() -> PathBuf {
    pid_path().with_file_name("proxy-revoked-credentials")
}

/// Control sockets of `agent`'s `aasm run` launches under `runs_root`, newest first.
///
/// A launch directory is `<sanitized agent id>-<random alphanumerics>`, so a
/// directory belongs to `agent` only when what follows the agent's prefix is
/// purely alphanumeric: agent `a` must not claim the directory of agent `a-b`.
/// Only entries that are really sockets are returned; whether anything still
/// listens on one is for [`ping`] to say, since a crashed proxy leaves its
/// socket file behind.
pub fn candidate_sockets(runs_root: &Path, agent: &str) -> Vec<PathBuf> {
    candidate_sockets_in(runs_root, agent, Path::new(super::ctl_path::FALLBACK_BASE))
}

/// [`candidate_sockets`] with the base of the short-path fallback named by the
/// caller, so tests never read the real `/tmp`.
pub fn candidate_sockets_in(runs_root: &Path, agent: &str, fallback_base: &Path) -> Vec<PathBuf> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    let prefix = format!("{}-", super::launch_state::sanitize_label(agent));
    let Ok(entries) = std::fs::read_dir(runs_root) else {
        return Vec::new();
    };
    let mut found: Vec<(std::time::SystemTime, PathBuf)> = entries
        .filter_map(Result::ok)
        .filter_map(|entry| {
            let name = entry.file_name().to_string_lossy().into_owned();
            let suffix = name.strip_prefix(&prefix)?;
            if suffix.is_empty() || !suffix.chars().all(|c| c.is_ascii_alphanumeric()) {
                return None;
            }
            // Only a launch directory this user owns and nobody else can write:
            // `aasm run` creates it 0700, so anything else was not made by it.
            let dir_meta = std::fs::symlink_metadata(entry.path()).ok()?;
            // SAFETY: geteuid has no preconditions and cannot fail.
            if !dir_meta.is_dir() || dir_meta.uid() != unsafe { libc::geteuid() } || dir_meta.mode() & 0o077 != 0 {
                return None;
            }
            // The socket is in the launch directory, or, when that path was too long
            // for a socket address, at the short path `ctl_path` derives from the
            // directory's name (only trusted from a fallback directory that verifies).
            let in_launch = entry.path().join("ctl.sock");
            let fallback = super::ctl_path::fallback_socket_in(fallback_base, &entry.path()).filter(|socket| {
                socket
                    .parent()
                    .is_some_and(|d| super::ctl_path::verify_fallback_dir(d).is_ok())
            });
            [Some(in_launch), fallback].into_iter().flatten().find_map(|socket| {
                let metadata = std::fs::symlink_metadata(&socket).ok()?;
                (metadata.file_type().is_socket() && metadata.uid() == unsafe { libc::geteuid() })
                    .then(|| (metadata.modified().unwrap_or(std::time::UNIX_EPOCH), socket))
            })
        })
        .collect();
    found.sort_by_key(|entry| std::cmp::Reverse(entry.0));
    found.into_iter().map(|(_, socket)| socket).collect()
}

/// Whether a proxy answers a ping on `socket`.
pub fn ping(socket: &Path) -> bool {
    ping_as(socket, None)
}

/// Whether a proxy answers a ping on `socket`, and, when `expected_pid` is given
/// and the kernel reports the peer's pid, that it is that process.
///
/// A per-launch proxy is a child `aasm` spawned, so its pid is known: requiring it
/// stops another process that took over the path from being mistaken for the
/// proxy. Where the platform reports no peer pid the answer alone decides.
pub fn ping_as(socket: &Path, expected_pid: Option<u32>) -> bool {
    let Ok(mut stream) = std::os::unix::net::UnixStream::connect(socket) else {
        return false;
    };
    if let (Some(expected), Some(actual)) = (expected_pid, peer_pid(&stream)) {
        if expected != actual {
            return false;
        }
    }
    if stream.set_read_timeout(Some(IO_TIMEOUT)).is_err() || stream.set_write_timeout(Some(IO_TIMEOUT)).is_err() {
        return false;
    }
    if stream.write_all(b"{\"op\":\"ping\"}\n").is_err() {
        return false;
    }
    let mut raw = String::new();
    if stream.read_to_string(&mut raw).is_err() {
        return false;
    }
    serde_json::from_str::<Response>(raw.trim()).is_ok_and(|r| r.outcome == Outcome::Pong)
}

/// Every live control socket for `agent`, or why there is none.
///
/// All of them, not the newest, so a stale or extra socket cannot make the
/// command pick the wrong one. This is NOT a defence against a process running
/// as the same user: it can unlink the real `ctl.sock` and bind its own, which
/// leaves the real proxy unreachable while the impostor answers "revoked". No
/// launch record the agent cannot forge exists without confinement, so `--agent`
/// does not verify who answers (the default standalone path does; see
/// [`verify_standalone_peer`]). Under isolation `none` revocation of a
/// per-launch proxy is therefore best-effort against a hostile same-user agent.
fn resolve_agent_sockets(agent: &str) -> Result<Vec<PathBuf>, String> {
    let root =
        super::launch_state::runs_root().map_err(|e| format!("cannot locate the launch state directory: {e}"))?;
    let candidates = candidate_sockets(&root, agent);
    if candidates.is_empty() {
        return Err(format!(
            "no control socket found for agent {agent} under {}. A launch that brokers a credential has one in \
             its launch directory or, when that path is too long for a socket address, in the per-user fallback \
             directory; a launch that brokers nothing may have none. Revoke in a standalone proxy with --socket \
             or without flags.",
            root.display()
        ));
    }
    let live: Vec<PathBuf> = candidates.iter().filter(|s| ping(s)).cloned().collect();
    if live.is_empty() {
        return Err(format!(
            "found {} launch(es) for agent {agent} but no proxy answers on any control socket; \
             the launch has probably ended",
            candidates.len()
        ));
    }
    Ok(live)
}

/// The process id of the peer connected to `stream`.
///
/// The kernel reports it for a local socket and the peer cannot choose it, so an
/// impostor that unlinked the real socket and bound its own is a different pid
/// from the proxy the state file records.
#[cfg(target_os = "macos")]
pub fn peer_pid(stream: &std::os::unix::net::UnixStream) -> Option<u32> {
    use std::os::fd::AsRawFd;
    let mut pid: libc::pid_t = 0;
    let mut len = std::mem::size_of::<libc::pid_t>() as libc::socklen_t;
    // SAFETY: `pid` and `len` are valid for the call and sized as the option requires.
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_LOCAL,
            libc::LOCAL_PEERPID,
            (&mut pid as *mut libc::pid_t).cast(),
            &mut len,
        )
    };
    (rc == 0 && pid > 0).then_some(pid as u32)
}

/// The process id of the peer connected to `stream` (Linux: `SO_PEERCRED`).
#[cfg(target_os = "linux")]
pub fn peer_pid(stream: &std::os::unix::net::UnixStream) -> Option<u32> {
    use std::os::fd::AsRawFd;
    let mut cred = libc::ucred { pid: 0, uid: 0, gid: 0 };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: `cred` and `len` are valid for the call and sized as the option requires.
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut cred as *mut libc::ucred).cast(),
            &mut len,
        )
    };
    (rc == 0 && cred.pid > 0).then_some(cred.pid as u32)
}

/// No peer credential on this platform: the answer cannot be verified.
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub fn peer_pid(_stream: &std::os::unix::net::UnixStream) -> Option<u32> {
    None
}

/// Require that the process on `stream` is the standalone proxy the state file
/// records, using the same trust rules the other `aasm proxy` commands apply
/// (the record names the proxy binary and the recorded PID is still the same
/// live incarnation), plus that the socket's peer IS that pid.
///
/// This stops a stale, second or accidentally substituted socket from answering.
/// It is not proof against a hostile same-user process: the existing trust model
/// already concedes a same-user process can forge a record, so this raises the
/// bar and removes the silent failures without claiming more.
fn verify_standalone_peer(stream: &std::os::unix::net::UnixStream) -> Result<(), String> {
    let state = super::pid::read_state().ok_or("no readable proxy state record; is the proxy running?")?;
    super::trust::verify_process(&state).map_err(|e| format!("the recorded proxy cannot be trusted: {e}"))?;
    let peer = peer_pid(stream).ok_or("cannot determine which process is on the control socket")?;
    if peer == state.pid {
        Ok(())
    } else {
        Err(format!(
            "the control socket is answered by pid {peer}, not the recorded proxy (pid {})",
            state.pid
        ))
    }
}

/// Why a revoke request produced no answer.
#[derive(Debug)]
pub enum RevokeError {
    /// Could not connect to, write to, or read from the socket.
    Io(std::io::Error),
    /// The proxy answered with something that is not a control response.
    BadResponse(String),
    /// Whoever answered could not be shown to be the recorded proxy, so nothing
    /// was sent to it.
    Unverified(String),
}

impl std::fmt::Display for RevokeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "{e}"),
            Self::BadResponse(raw) => write!(f, "unexpected control response: {raw}"),
            Self::Unverified(why) => write!(f, "refusing to trust the control socket: {why}"),
        }
    }
}

/// Send one revoke request and return the proxy's answer.
///
/// # Errors
///
/// [`RevokeError`] when the socket cannot be used or the answer is not a
/// control response.
pub fn request_revoke(socket: &Path, host: &str) -> Result<Response, RevokeError> {
    request(socket, host, false)
}

/// Like [`request_revoke`], but first requires that whoever answers on `socket`
/// is the standalone proxy recorded in the state file, before the host name is
/// sent to it.
///
/// # Errors
///
/// [`RevokeError::Unverified`] when the recorded proxy cannot be trusted or the
/// peer is a different process; otherwise as [`request_revoke`].
pub fn request_revoke_verified(socket: &Path, host: &str) -> Result<Response, RevokeError> {
    request(socket, host, true)
}

fn request(socket: &Path, host: &str, verify_peer: bool) -> Result<Response, RevokeError> {
    let mut stream = std::os::unix::net::UnixStream::connect(socket).map_err(RevokeError::Io)?;
    if verify_peer {
        verify_standalone_peer(&stream).map_err(RevokeError::Unverified)?;
    }
    stream.set_read_timeout(Some(IO_TIMEOUT)).map_err(RevokeError::Io)?;
    stream.set_write_timeout(Some(IO_TIMEOUT)).map_err(RevokeError::Io)?;
    let mut line = serde_json::to_vec(&serde_json::json!({ "op": "revoke_credential", "host": host }))
        .map_err(|e| RevokeError::BadResponse(e.to_string()))?;
    line.push(b'\n');
    // The proxy refuses a request over its cap; say so here instead of sending it.
    if line.len() as u64 > MAX_REQUEST_BYTES {
        return Err(RevokeError::BadResponse("host name too long".to_string()));
    }
    stream.write_all(&line).map_err(RevokeError::Io)?;
    let mut raw = String::new();
    stream.read_to_string(&mut raw).map_err(RevokeError::Io)?;
    serde_json::from_str(raw.trim()).map_err(|_| RevokeError::BadResponse(raw.trim().chars().take(200).collect()))
}

/// The process exit status for an answer; see the module table.
pub fn exit_code_for(response: &Response) -> u8 {
    match (response.outcome, response.persisted) {
        (Outcome::Revoked | Outcome::AlreadyRevoked, Some(true)) => 0,
        (Outcome::Revoked | Outcome::AlreadyRevoked, _) => 3,
        _ => 1,
    }
}

/// Combine the per-socket results of one `--agent` revoke into one exit status.
///
/// Each element is `(exit code for that socket, whether it was a hard failure)`.
/// A hard failure (unreachable, refused or unparseable) makes the whole command
/// fail: it cannot claim the credential is revoked everywhere. A socket that
/// merely held no credential for the host is not a failure, but at least one
/// socket must have revoked for the command to succeed. When several succeeded,
/// the weakest guarantee wins: any memory-only revocation makes the status `3`.
pub fn combine_exit_codes(results: &[(u8, bool)]) -> u8 {
    if results.iter().any(|(_, hard)| *hard) {
        return 1;
    }
    results
        .iter()
        .map(|(code, _)| *code)
        .filter(|code| matches!(code, 0 | 3))
        .max()
        .unwrap_or(1)
}

/// Send the revoke to one socket, print what happened, and return the exit code
/// for it and whether it was a hard failure.
fn revoke_on(socket: &Path, host: &str, label: &str, verify_peer: bool) -> (u8, bool) {
    let sent = if verify_peer {
        request_revoke_verified(socket, host)
    } else {
        request_revoke(socket, host)
    };
    let response = match sent {
        Ok(response) => response,
        Err(e) => {
            eprintln!(
                "error: could not revoke the credential for {host}{label}: {e}\n\
                 Is the proxy running with a control socket? `aasm proxy start` configures one at {}.",
                socket.display()
            );
            return (1, true);
        }
    };
    let named = response.host.as_deref().unwrap_or(host);
    match response.outcome {
        Outcome::Revoked => println!("Revoked the credential for {named}{label}: later requests to it are refused."),
        Outcome::AlreadyRevoked => println!("The credential for {named}{label} was already revoked."),
        Outcome::NotConfigured => eprintln!("No credential is configured for {named}{label}; nothing was revoked."),
        Outcome::Pong => eprintln!("error: the proxy answered a ping instead of a revocation{label}"),
        Outcome::Rejected => eprintln!(
            "error: the proxy refused the request{label}: {}",
            response.error.as_deref().unwrap_or("no reason given")
        ),
    }
    if matches!(response.outcome, Outcome::Revoked | Outcome::AlreadyRevoked) && response.persisted != Some(true) {
        eprintln!(
            "warning: {} A restart of the proxy can bring the credential back.",
            response
                .error
                .as_deref()
                .unwrap_or("the revocation was not written to a durable record.")
        );
    }
    let hard = matches!(response.outcome, Outcome::Pong | Outcome::Rejected);
    (exit_code_for(&response), hard)
}

/// Run `aasm proxy revoke-credential`.
pub fn dispatch(args: RevokeArgs) -> ExitCode {
    let host = args.host.as_str();
    let results: Vec<(u8, bool)> = match (&args.socket, &args.agent) {
        (Some(socket), _) => vec![revoke_on(socket, host, "", false)],
        (None, Some(agent)) => match resolve_agent_sockets(agent) {
            Ok(sockets) => sockets
                .iter()
                .map(|socket| revoke_on(socket, host, &format!(" (launch {})", launch_name(socket)), false))
                .collect(),
            Err(reason) => {
                eprintln!("error: {reason}");
                return ExitCode::FAILURE;
            }
        },
        (None, None) => vec![revoke_on(&control_socket_path(), host, "", true)],
    };
    ExitCode::from(combine_exit_codes(&results))
}

/// The launch directory name a socket belongs to, for messages.
fn launch_name(socket: &Path) -> String {
    socket
        .parent()
        .and_then(Path::file_name)
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use aa_proxy::control;
    use aa_proxy::credentials::{CredentialStore, Injection};

    use super::*;

    fn response(outcome: Outcome, persisted: Option<bool>) -> Response {
        Response {
            outcome,
            host: Some("api.anthropic.com".to_string()),
            persisted,
            error: None,
        }
    }

    #[test]
    fn exit_codes_separate_durable_from_memory_only_from_nothing_revoked() {
        assert_eq!(exit_code_for(&response(Outcome::Revoked, Some(true))), 0);
        assert_eq!(exit_code_for(&response(Outcome::AlreadyRevoked, Some(true))), 0);
        assert_eq!(exit_code_for(&response(Outcome::Revoked, Some(false))), 3);
        assert_eq!(exit_code_for(&response(Outcome::Revoked, None)), 3);
        assert_eq!(exit_code_for(&response(Outcome::NotConfigured, None)), 1);
        assert_eq!(exit_code_for(&response(Outcome::Rejected, None)), 1);
        assert_eq!(exit_code_for(&response(Outcome::Pong, None)), 1);
    }

    #[test]
    fn the_control_paths_sit_beside_the_state_file() {
        assert_eq!(control_socket_path().parent(), pid_path().parent());
        assert_eq!(revocations_path().parent(), pid_path().parent());
    }

    fn bind_socket(path: &Path) -> std::os::unix::net::UnixListener {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::os::unix::net::UnixListener::bind(path).unwrap()
    }

    /// A launch directory as `aasm run` makes it: owner-only.
    fn private(dir: &Path) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    }

    #[test]
    fn candidate_sockets_belong_to_exactly_one_agent_and_skip_non_sockets() {
        let root = tempfile::tempdir().unwrap();
        let mine = root.path().join("agent_one-Ab12Cd");
        let _a = bind_socket(&mine.join("ctl.sock"));
        private(&mine);
        // Agent `agent` must not claim the directory of agent `agent-one`.
        let other = root.path().join("agent_one-x-Ef34Gh");
        let _other = bind_socket(&other.join("ctl.sock"));
        private(&other);
        // A regular file named ctl.sock is not a socket.
        let plain = root.path().join("agent_one-Zz99Zz");
        std::fs::create_dir_all(&plain).unwrap();
        std::fs::write(plain.join("ctl.sock"), b"x").unwrap();
        private(&plain);
        // Positive control: the right agent finds its own socket.
        assert_eq!(candidate_sockets(root.path(), "agent_one"), vec![mine.join("ctl.sock")]);
        // Prefix collision in the other direction yields nothing.
        assert!(candidate_sockets(root.path(), "agent").is_empty());
        assert!(candidate_sockets(root.path(), "nobody").is_empty());
    }

    #[test]
    fn a_launch_directory_others_can_write_is_not_trusted() {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().unwrap();
        let trusted = root.path().join("agent_two-Ab12Cd");
        let planted = root.path().join("agent_two-Zz99Zz");
        let _a = bind_socket(&trusted.join("ctl.sock"));
        let _b = bind_socket(&planted.join("ctl.sock"));
        std::fs::set_permissions(&trusted, std::fs::Permissions::from_mode(0o700)).unwrap();
        // Positive control: with both private, both are candidates.
        std::fs::set_permissions(&planted, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(candidate_sockets(root.path(), "agent_two").len(), 2);
        std::fs::set_permissions(&planted, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert_eq!(
            candidate_sockets(root.path(), "agent_two"),
            vec![trusted.join("ctl.sock")]
        );
        std::fs::set_permissions(&planted, std::fs::Permissions::from_mode(0o700)).unwrap();
    }

    #[test]
    fn several_sockets_combine_so_one_failure_or_all_nothing_revoked_fails_the_command() {
        // Every socket revoked durably.
        assert_eq!(combine_exit_codes(&[(0, false), (0, false)]), 0);
        // One memory-only revocation among durable ones: the weakest guarantee wins.
        assert_eq!(combine_exit_codes(&[(0, false), (3, false)]), 3);
        // A socket that held no credential is not a failure while another revoked.
        assert_eq!(combine_exit_codes(&[(1, false), (3, false)]), 3);
        // Nothing revoked anywhere.
        assert_eq!(combine_exit_codes(&[(1, false), (1, false)]), 1);
        // A hard failure on any socket means revoked-everywhere cannot be claimed.
        assert_eq!(combine_exit_codes(&[(3, false), (1, true)]), 1);
        assert_eq!(combine_exit_codes(&[]), 1);
    }

    #[test]
    fn the_peer_of_a_local_server_is_reported_as_that_process() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("ctl.sock");
        let _server = bind_socket(&socket);
        let client = std::os::unix::net::UnixStream::connect(&socket).unwrap();
        // The server is this process, so its pid is ours: the kernel's answer, not the peer's claim.
        assert_eq!(peer_pid(&client), Some(std::process::id()));
    }

    #[test]
    fn a_standalone_revoke_with_no_state_record_refuses_before_sending_anything() {
        let _lock = crate::test_support::env_guard();
        let state = tempfile::tempdir().unwrap();
        let prior = std::env::var_os("AA_DATA_DIR");
        std::env::set_var("AA_DATA_DIR", state.path());
        let socket = state.path().join("ctl.sock");
        let _server = bind_socket(&socket);
        let result = request_revoke_verified(&socket, "api.anthropic.com");
        match prior {
            Some(v) => std::env::set_var("AA_DATA_DIR", v),
            None => std::env::remove_var("AA_DATA_DIR"),
        }
        assert!(matches!(result, Err(RevokeError::Unverified(_))), "{result:?}");
    }

    #[test]
    fn a_stale_socket_file_is_not_a_live_proxy() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("ctl.sock");
        drop(bind_socket(&socket)); // the file remains, nothing listens
        assert!(socket.exists());
        assert!(!ping(&socket));
    }

    #[test]
    fn a_missing_socket_is_an_io_error_not_a_panic() {
        let dir = tempfile::tempdir().unwrap();
        let err = request_revoke(&dir.path().join("absent.sock"), "api.anthropic.com").unwrap_err();
        assert!(matches!(err, RevokeError::Io(_)));
    }

    /// Run the real proxy control server on its own runtime thread and revoke
    /// through the real client, so the wire format both sides share is exercised.
    #[test]
    fn the_client_revokes_through_the_real_control_server() {
        let credentials = Arc::new(CredentialStore::from_pairs([(
            "api.anthropic.com".to_string(),
            b"sk-ant-QA6262-cli-synthetic".to_vec(),
        )]));
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("ctl.sock");
        let record = dir.path().join("revoked-credentials");

        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        let listener = {
            let _guard = runtime.enter();
            control::bind_hardened(&socket).unwrap()
        };
        runtime.spawn(control::serve(listener, Arc::clone(&credentials), Some(record.clone())));

        // Positive control: injecting before the request.
        assert!(matches!(
            credentials.injection_for("api.anthropic.com"),
            Injection::Inject(..)
        ));
        let reply = request_revoke(&socket, "api.anthropic.com").unwrap();
        assert_eq!(reply.outcome, Outcome::Revoked);
        assert_eq!(exit_code_for(&reply), 0);
        assert!(matches!(
            credentials.injection_for("api.anthropic.com"),
            Injection::Revoked
        ));

        let unknown = request_revoke(&socket, "api.mistral.ai").unwrap();
        assert_eq!(unknown.outcome, Outcome::NotConfigured);
        assert_eq!(exit_code_for(&unknown), 1);
    }
    /// A listener that answers every ping with a pong, in this process.
    fn pong_listener(path: &Path) -> std::os::unix::net::UnixListener {
        let listener = std::os::unix::net::UnixListener::bind(path).unwrap();
        let accept = listener.try_clone().unwrap();
        std::thread::spawn(move || {
            while let Ok((mut stream, _)) = accept.accept() {
                let mut buf = [0u8; 256];
                let _ = std::io::Read::read(&mut stream, &mut buf);
                let _ = stream.write_all(b"{\"outcome\":\"pong\"}\n");
            }
        });
        listener
    }

    #[test]
    fn ping_as_accepts_the_expected_pid_and_rejects_another_process_on_the_path() {
        let dir = tempfile::tempdir_in("/tmp").unwrap();
        let socket = dir.path().join("p.sock");
        let _listener = pong_listener(&socket);
        let me = std::process::id();
        // Positive controls: with no expectation, and with the real owner's pid, it answers.
        assert!(ping_as(&socket, None));
        if peer_pid(&std::os::unix::net::UnixStream::connect(&socket).unwrap()).is_some() {
            assert!(
                ping_as(&socket, Some(me)),
                "the listening process is the one that answers"
            );
            // An impostor holding the path has a different pid than the proxy we spawned.
            assert!(
                !ping_as(&socket, Some(me.wrapping_add(1))),
                "a different pid must not pass as the proxy"
            );
        }
    }

    #[test]
    fn a_fallback_socket_is_discovered_only_from_a_trustworthy_fallback_directory() {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        let runs = tempfile::tempdir_in("/tmp").unwrap();
        let base = tempfile::tempdir_in("/tmp").unwrap();
        let launch = runs.path().join("agent-AbC123");
        std::fs::create_dir(&launch).unwrap();
        std::fs::set_permissions(&launch, std::fs::Permissions::from_mode(0o700)).unwrap();
        let fdir = super::super::ctl_path::fallback_dir_in(base.path());
        std::fs::DirBuilder::new().mode(0o700).create(&fdir).ok();
        std::fs::set_permissions(&fdir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let socket = super::super::ctl_path::fallback_socket_in(base.path(), &launch).unwrap();
        let _listener = pong_listener(&socket);

        // Positive control: a private fallback directory yields the socket for this launch.
        assert_eq!(
            candidate_sockets_in(runs.path(), "agent", base.path()),
            vec![socket.clone()]
        );
        // Another agent does not claim it.
        assert!(candidate_sockets_in(runs.path(), "nobody", base.path()).is_empty());
        // The same socket in a directory others can enter is not trusted.
        std::fs::set_permissions(&fdir, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(candidate_sockets_in(runs.path(), "agent", base.path()).is_empty());
        std::fs::set_permissions(&fdir, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
}
