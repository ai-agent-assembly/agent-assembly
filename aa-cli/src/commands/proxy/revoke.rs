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
    use std::os::unix::fs::FileTypeExt;
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
            let socket = entry.path().join("ctl.sock");
            let metadata = std::fs::symlink_metadata(&socket).ok()?;
            metadata
                .file_type()
                .is_socket()
                .then(|| (metadata.modified().unwrap_or(std::time::UNIX_EPOCH), socket))
        })
        .collect();
    found.sort_by(|a, b| b.0.cmp(&a.0));
    found.into_iter().map(|(_, socket)| socket).collect()
}

/// Whether a proxy answers a ping on `socket`.
pub fn ping(socket: &Path) -> bool {
    let Ok(mut stream) = std::os::unix::net::UnixStream::connect(socket) else {
        return false;
    };
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

/// The newest live control socket for `agent`, or why there is none.
fn resolve_agent_socket(agent: &str) -> Result<PathBuf, String> {
    let root =
        super::launch_state::runs_root().map_err(|e| format!("cannot locate the launch state directory: {e}"))?;
    let candidates = candidate_sockets(&root, agent);
    if candidates.is_empty() {
        return Err(format!(
            "no control socket found for agent {agent} under {}. A launch only has one when its path fits a \
             Unix socket address; revoke in a standalone proxy with --socket or without flags.",
            root.display()
        ));
    }
    candidates.iter().find(|s| ping(s)).cloned().ok_or_else(|| {
        format!(
            "found {} launch(es) for agent {agent} but no proxy answers on any control socket; \
             the launch has probably ended",
            candidates.len()
        )
    })
}

/// Why a revoke request produced no answer.
#[derive(Debug)]
pub enum RevokeError {
    /// Could not connect to, write to, or read from the socket.
    Io(std::io::Error),
    /// The proxy answered with something that is not a control response.
    BadResponse(String),
}

impl std::fmt::Display for RevokeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "{e}"),
            Self::BadResponse(raw) => write!(f, "unexpected control response: {raw}"),
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
    let mut stream = std::os::unix::net::UnixStream::connect(socket).map_err(RevokeError::Io)?;
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

/// Run `aasm proxy revoke-credential`.
pub fn dispatch(args: RevokeArgs) -> ExitCode {
    let socket = match (args.socket, &args.agent) {
        (Some(socket), _) => socket,
        (None, Some(agent)) => match resolve_agent_socket(agent) {
            Ok(socket) => socket,
            Err(reason) => {
                eprintln!("error: {reason}");
                return ExitCode::FAILURE;
            }
        },
        (None, None) => control_socket_path(),
    };
    let response = match request_revoke(&socket, &args.host) {
        Ok(response) => response,
        Err(e) => {
            eprintln!(
                "error: could not revoke the credential for {}: {e}\n\
                 Is the proxy running with a control socket? `aasm proxy start` configures one at {}.",
                args.host,
                socket.display()
            );
            return ExitCode::FAILURE;
        }
    };
    let host = response.host.as_deref().unwrap_or(&args.host);
    match response.outcome {
        Outcome::Revoked => println!("Revoked the credential for {host}: later requests to it are refused."),
        Outcome::AlreadyRevoked => println!("The credential for {host} was already revoked."),
        Outcome::NotConfigured => eprintln!("No credential is configured for {host}; nothing was revoked."),
        Outcome::Pong => eprintln!("error: the proxy answered a ping instead of a revocation"),
        Outcome::Rejected => eprintln!(
            "error: the proxy refused the request: {}",
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
    ExitCode::from(exit_code_for(&response))
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

    #[test]
    fn candidate_sockets_belong_to_exactly_one_agent_and_skip_non_sockets() {
        let root = tempfile::tempdir().unwrap();
        let mine = root.path().join("agent_one-Ab12Cd");
        let _a = bind_socket(&mine.join("ctl.sock"));
        // Agent `agent` must not claim the directory of agent `agent-one`.
        let _other = bind_socket(&root.path().join("agent_one-x-Ef34Gh").join("ctl.sock"));
        // A regular file named ctl.sock is not a socket.
        let plain = root.path().join("agent_one-Zz99Zz");
        std::fs::create_dir_all(&plain).unwrap();
        std::fs::write(plain.join("ctl.sock"), b"x").unwrap();
        // Positive control: the right agent finds its own socket.
        assert_eq!(candidate_sockets(root.path(), "agent_one"), vec![mine.join("ctl.sock")]);
        // Prefix collision in the other direction yields nothing.
        assert!(candidate_sockets(root.path(), "agent").is_empty());
        assert!(candidate_sockets(root.path(), "nobody").is_empty());
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
}
