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
    #[arg(long)]
    pub socket: Option<PathBuf>,
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
    let socket = args.socket.unwrap_or_else(control_socket_path);
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
