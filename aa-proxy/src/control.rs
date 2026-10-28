//! Revoke-only control channel for a running proxy (AAASM-6262, J84 AC3).
//!
//! The credential store is moved into the proxy by value at start, so an
//! operator has no handle on a running proxy: without this channel the only way
//! to revoke a brokered credential is to restart the proxy. This is the smallest
//! surface that closes that gap, and it is deliberately narrow:
//!
//! * **Revoke and ping only.** There is no install, rotate or un-revoke
//!   operation, and no response ever carries anything derived from a secret. A
//!   caller who reaches the socket can therefore only remove access, never
//!   grant or read it.
//! * **Opt-in.** The socket exists only when `AA_PROXY_CONTROL_SOCKET` is set.
//! * **Owner-only.** The socket is created `0600` under a tight umask and every
//!   accepted peer must have the proxy's own effective UID.
//! * **Bounded.** One JSON line of at most [`MAX_REQUEST_BYTES`], read under a
//!   timeout.
//!
//! What this does not do: under `--isolation none` the agent runs as the same
//! UID and can connect. Because the protocol only ever removes access, the worst
//! such a caller can do is deny service to itself; the socket does not
//! authenticate the operator and the docs must not claim it does.
//!
//! A revocation is applied in memory first and then written to the durable
//! record ([`crate::revocations`]) when `AA_PROXY_REVOCATIONS_FILE` is set. If
//! the write fails the credential stays revoked in memory and the response says
//! `persisted: false`: reporting that the revocation may not survive a restart
//! is honest, undoing it would not be.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};

use crate::credentials::{CredentialStore, RevokeOutcome};
use crate::revocations::{self, RevocationFileError};

/// Largest request line accepted, newline included.
pub const MAX_REQUEST_BYTES: u64 = 1024;

/// How long a peer has to deliver its request line.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

/// How long to keep discarding a peer's leftover request bytes after replying.
const DRAIN_TIMEOUT: Duration = Duration::from_millis(250);

/// `sockaddr_un.sun_path` is 104 bytes on macOS and 108 on Linux; stay under the
/// smaller so a path that works on one host does not fail to bind on the other.
const MAX_SOCKET_PATH_BYTES: usize = 100;

/// What the proxy was asked to do, read from the environment like the other
/// enforcement-adjacent settings (the credential store, the telemetry endpoint)
/// so it stays off the `ProxyConfig` surface.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ControlConfig {
    /// `AA_PROXY_CONTROL_SOCKET`: where to listen, when set.
    pub socket: Option<PathBuf>,
    /// `AA_PROXY_REVOCATIONS_FILE`: the durable record, when set.
    pub revocations_file: Option<PathBuf>,
}

impl ControlConfig {
    /// Read both settings; an empty value counts as unset.
    pub fn from_env() -> Self {
        let get = |name: &str| std::env::var_os(name).filter(|v| !v.is_empty()).map(PathBuf::from);
        Self {
            socket: get("AA_PROXY_CONTROL_SOCKET"),
            revocations_file: get("AA_PROXY_REVOCATIONS_FILE"),
        }
    }
}

/// A request line.
#[derive(Debug, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
enum Request {
    /// Revoke the credential configured for `host`.
    RevokeCredential { host: String },
    /// Liveness probe.
    Ping,
}

/// What happened to a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    /// A live credential was revoked.
    Revoked,
    /// The credential was already revoked.
    AlreadyRevoked,
    /// No credential is configured for the host; nothing changed.
    NotConfigured,
    /// Answer to `ping`.
    Pong,
    /// The request was refused (malformed, too large, unknown, or invalid host).
    Rejected,
}

/// The single response line.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Response {
    /// What happened.
    pub outcome: Outcome,
    /// The normalized host the request named, when it named a valid one.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub host: Option<String>,
    /// Whether the revocation reached the durable record. Present only for a
    /// revocation outcome; `false` means it may not survive a restart.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub persisted: Option<bool>,
    /// A short reason for a rejection or a failed persist. Never a secret.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub error: Option<String>,
}

impl Response {
    fn outcome(outcome: Outcome) -> Self {
        Self {
            outcome,
            host: None,
            persisted: None,
            error: None,
        }
    }

    fn rejected(reason: &str) -> Self {
        Self {
            error: Some(reason.to_string()),
            ..Self::outcome(Outcome::Rejected)
        }
    }
}

/// Re-apply the durable record to `credentials` before the proxy accepts a
/// connection, returning how many credentials it revoked.
///
/// A recorded host the store holds no credential for is skipped: it has nothing
/// to inject, so the agent's own headers pass through exactly as they did before
/// the revocation, and the host stays in the record in case a credential for it
/// is configured later.
///
/// # Errors
///
/// [`RevocationFileError`] when the record cannot be trusted. The caller must
/// refuse to start.
pub fn apply_persisted(credentials: &CredentialStore, path: &Path) -> Result<usize, RevocationFileError> {
    let hosts = revocations::load(path)?;
    let mut revoked = 0;
    for host in &hosts {
        if credentials.revoke(host) == RevokeOutcome::Revoked {
            revoked += 1;
        }
    }
    Ok(revoked)
}

/// Bind the control socket at `path`, owner-only from its first instant.
///
/// # Errors
///
/// An I/O error, or `InvalidInput` when `path` is too long for `sun_path`.
pub fn bind_hardened(path: &Path) -> std::io::Result<UnixListener> {
    use std::os::unix::ffi::OsStrExt;
    if path.as_os_str().as_bytes().len() > MAX_SOCKET_PATH_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("control socket path longer than {MAX_SOCKET_PATH_BYTES} bytes"),
        ));
    }
    // The socket's own 0600 mode is not enough if another user can write its
    // directory: they could remove it and bind their own in its place.
    revocations::verify_private_parent(path)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::PermissionDenied, e.to_string()))?;
    // A stale socket from a previous run would make bind fail.
    if path.exists() {
        std::fs::remove_file(path)?;
    }
    // Tighten the umask so the inode is created 0600 and never group/other
    // accessible between bind and the explicit chmod below (the same window
    // `aa-runtime`'s IPC socket and the eBPF control socket close).
    let listener = {
        // SAFETY: umask is process-global but has no memory-safety preconditions.
        let previous = unsafe { libc::umask(0o077) };
        let bound = UnixListener::bind(path);
        // SAFETY: restoring the value returned above.
        unsafe { libc::umask(previous) };
        bound?
    };
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(listener)
}

/// Accept connections until the listener closes, one task per connection.
pub async fn serve(listener: UnixListener, credentials: Arc<CredentialStore>, revocations_file: Option<PathBuf>) {
    // SAFETY: geteuid has no preconditions and cannot fail.
    let own_uid = unsafe { libc::geteuid() };
    // Serializes writes to the durable record so two concurrent revocations
    // cannot interleave a read-modify-rename and lose one.
    let persist_lock = Arc::new(tokio::sync::Mutex::new(()));
    loop {
        let (stream, _) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(e) => {
                tracing::error!(error = %e, "control socket accept failed; control channel stopped");
                return;
            }
        };
        let credentials = Arc::clone(&credentials);
        let revocations_file = revocations_file.clone();
        let persist_lock = Arc::clone(&persist_lock);
        tokio::spawn(async move {
            match stream.peer_cred() {
                Ok(cred) if cred.uid() == own_uid => {}
                _ => {
                    tracing::warn!("control socket peer rejected: not the proxy's own user");
                    return;
                }
            }
            handle(stream, &credentials, revocations_file.as_deref(), &persist_lock).await;
        });
    }
}

async fn handle(
    stream: UnixStream,
    credentials: &CredentialStore,
    revocations_file: Option<&Path>,
    persist_lock: &tokio::sync::Mutex<()>,
) {
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half.take(MAX_REQUEST_BYTES));
    let mut line = String::new();
    let read = tokio::time::timeout(REQUEST_TIMEOUT, reader.read_line(&mut line)).await;
    let response = match read {
        Err(_) => Response::rejected("request timed out"),
        Ok(Err(_)) => Response::rejected("request was not valid UTF-8 text"),
        // The cap cut the line off before its newline: refuse rather than act on
        // a truncated request.
        Ok(Ok(n)) if n as u64 >= MAX_REQUEST_BYTES && !line.ends_with('\n') => Response::rejected("request too large"),
        Ok(Ok(_)) => dispatch(&line, credentials, revocations_file, persist_lock).await,
    };
    if let Ok(mut bytes) = serde_json::to_vec(&response) {
        bytes.push(b'\n');
        let _ = write_half.write_all(&bytes).await;
    }
    let _ = write_half.shutdown().await;
    // Closing a socket that still holds unread request bytes makes the kernel
    // reset the connection, which can discard the reply the peer has not read
    // yet. After a rejection for size there are such bytes, so read the rest
    // (bounded in time and discarded, never parsed) until the peer closes.
    let mut rest = reader.into_inner().into_inner();
    let _ = tokio::time::timeout(DRAIN_TIMEOUT, tokio::io::copy(&mut rest, &mut tokio::io::sink())).await;
}

async fn dispatch(
    line: &str,
    credentials: &CredentialStore,
    revocations_file: Option<&Path>,
    persist_lock: &tokio::sync::Mutex<()>,
) -> Response {
    let request: Request = match serde_json::from_str(line.trim()) {
        Ok(request) => request,
        Err(_) => return Response::rejected("unknown or malformed request"),
    };
    match request {
        Request::Ping => Response::outcome(Outcome::Pong),
        Request::RevokeCredential { host } => {
            let Some(host) = revocations::normalize_host(&host) else {
                return Response::rejected("not a valid host name");
            };
            let outcome = credentials.revoke(&host);
            // An already-revoked host is persisted again on purpose: the first
            // attempt may have failed after the in-memory revoke succeeded. A
            // host with no configured credential changed nothing, so there is
            // nothing to record.
            let (persisted, error) = if matches!(outcome, RevokeOutcome::Revoked | RevokeOutcome::AlreadyRevoked) {
                match revocations_file {
                    None => (
                        Some(false),
                        Some("revoked in memory only; no durable record configured".to_string()),
                    ),
                    Some(path) => {
                        let _guard = persist_lock.lock().await;
                        match revocations::record(path, &host) {
                            Ok(()) => (Some(true), None),
                            Err(e) => {
                                tracing::error!(%host, error = %e, "revoked in memory but the durable record was not written");
                                (
                                    Some(false),
                                    Some("revoked in memory; could not write the durable record".to_string()),
                                )
                            }
                        }
                    }
                }
            } else {
                (None, None)
            };
            let response = Response {
                outcome: match outcome {
                    RevokeOutcome::Revoked => Outcome::Revoked,
                    RevokeOutcome::AlreadyRevoked => Outcome::AlreadyRevoked,
                    RevokeOutcome::NotConfigured => Outcome::NotConfigured,
                },
                host: Some(host.clone()),
                persisted,
                error,
            };
            tracing::info!(
                %host,
                outcome = ?response.outcome,
                persisted = ?response.persisted,
                "credential revocation requested over the control socket",
            );
            response
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credentials::Injection;

    const SYNTHETIC: &[u8] = b"sk-ant-QA6262-control-synthetic";

    fn store() -> Arc<CredentialStore> {
        Arc::new(CredentialStore::from_pairs([
            ("api.anthropic.com".to_string(), SYNTHETIC.to_vec()),
            ("api.openai.com".to_string(), b"sk-synthetic".to_vec()),
        ]))
    }

    /// Bind in a fresh temp dir and serve; returns the socket path.
    async fn start(
        credentials: Arc<CredentialStore>,
        revocations_file: Option<PathBuf>,
    ) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("ctl.sock");
        let listener = bind_hardened(&socket).unwrap();
        tokio::spawn(serve(listener, credentials, revocations_file));
        (dir, socket)
    }

    async fn ask(socket: &Path, raw: &[u8]) -> Response {
        let mut stream = UnixStream::connect(socket).await.unwrap();
        stream.write_all(raw).await.unwrap();
        let mut out = String::new();
        stream.read_to_string(&mut out).await.unwrap();
        serde_json::from_str(out.trim()).unwrap_or_else(|e| panic!("unparseable response {out:?}: {e}"))
    }

    #[tokio::test]
    async fn revoking_over_the_socket_flips_the_store_to_revoked() {
        let credentials = store();
        let (_dir, socket) = start(Arc::clone(&credentials), None).await;
        // Positive control: injecting before the request.
        assert!(matches!(
            credentials.injection_for("api.anthropic.com"),
            Injection::Inject(..)
        ));
        let reply = ask(
            &socket,
            b"{\"op\":\"revoke_credential\",\"host\":\"API.Anthropic.com\"}\n",
        )
        .await;
        assert_eq!(reply.outcome, Outcome::Revoked);
        assert_eq!(reply.host.as_deref(), Some("api.anthropic.com"));
        assert!(matches!(
            credentials.injection_for("api.anthropic.com"),
            Injection::Revoked
        ));
        // Revoking one host leaves the other injecting.
        assert!(matches!(
            credentials.injection_for("api.openai.com"),
            Injection::Inject(..)
        ));
    }

    #[tokio::test]
    async fn an_unconfigured_host_is_reported_and_changes_nothing() {
        let credentials = store();
        let (_dir, socket) = start(Arc::clone(&credentials), None).await;
        let reply = ask(&socket, b"{\"op\":\"revoke_credential\",\"host\":\"api.mistral.ai\"}\n").await;
        assert_eq!(reply.outcome, Outcome::NotConfigured);
        assert_eq!(reply.persisted, None);
        assert!(matches!(
            credentials.injection_for("api.mistral.ai"),
            Injection::NotConfigured
        ));
    }

    #[tokio::test]
    async fn ping_answers_and_changes_nothing() {
        let credentials = store();
        let (_dir, socket) = start(Arc::clone(&credentials), None).await;
        assert_eq!(ask(&socket, b"{\"op\":\"ping\"}\n").await.outcome, Outcome::Pong);
        assert!(matches!(
            credentials.injection_for("api.anthropic.com"),
            Injection::Inject(..)
        ));
    }

    #[tokio::test]
    async fn only_revoke_and_ping_exist_so_no_request_can_grant_or_read_access() {
        let credentials = store();
        let (_dir, socket) = start(Arc::clone(&credentials), None).await;
        for raw in [
            &b"{\"op\":\"rotate_credential\",\"host\":\"api.anthropic.com\",\"secret\":\"x\"}\n"[..],
            b"{\"op\":\"get_credential\",\"host\":\"api.anthropic.com\"}\n",
            b"{\"op\":\"revoke_credential\",\"host\":\"api.anthropic.com\",\"extra\":1}\n",
            b"not json\n",
            b"{\"op\":\"revoke_credential\",\"host\":\"host:443\"}\n",
        ] {
            let reply = ask(&socket, raw).await;
            assert_eq!(reply.outcome, Outcome::Rejected, "{}", String::from_utf8_lossy(raw));
        }
        assert!(matches!(
            credentials.injection_for("api.anthropic.com"),
            Injection::Inject(..)
        ));
    }

    #[tokio::test]
    async fn an_oversized_request_is_rejected_and_acted_on_by_nobody() {
        let credentials = store();
        let (_dir, socket) = start(Arc::clone(&credentials), None).await;
        let mut big = b"{\"op\":\"revoke_credential\",\"host\":\"api.anthropic.com\",\"pad\":\"".to_vec();
        big.extend_from_slice(&[b'a'; 2048]);
        big.extend_from_slice(b"\"}\n");
        assert_eq!(ask(&socket, &big).await.outcome, Outcome::Rejected);
        assert!(matches!(
            credentials.injection_for("api.anthropic.com"),
            Injection::Inject(..)
        ));
    }

    #[tokio::test]
    async fn the_socket_is_owner_only() {
        let credentials = store();
        let (_dir, socket) = start(credentials, None).await;
        let mode = std::fs::metadata(&socket).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[tokio::test]
    async fn a_revocation_survives_a_restart_through_the_durable_record() {
        let dir = tempfile::tempdir().unwrap();
        let record = dir.path().join("revoked-credentials");
        let first = store();
        let (_sock_dir, socket) = start(Arc::clone(&first), Some(record.clone())).await;
        let reply = ask(
            &socket,
            b"{\"op\":\"revoke_credential\",\"host\":\"api.anthropic.com\"}\n",
        )
        .await;
        assert_eq!(reply.outcome, Outcome::Revoked);
        assert_eq!(reply.persisted, Some(true));

        // A "restart": a brand-new store built from the same configuration, as
        // `AA_PROXY_PROVIDER_KEYS` would rebuild it. Without the record it injects.
        let restarted = store();
        assert!(
            matches!(restarted.injection_for("api.anthropic.com"), Injection::Inject(..)),
            "positive control: a fresh store injects before the record is applied"
        );
        assert_eq!(apply_persisted(&restarted, &record).unwrap(), 1);
        assert!(matches!(
            restarted.injection_for("api.anthropic.com"),
            Injection::Revoked
        ));
        assert!(matches!(
            restarted.injection_for("api.openai.com"),
            Injection::Inject(..)
        ));
    }

    #[tokio::test]
    async fn without_a_durable_record_the_reply_says_the_revocation_may_not_survive() {
        let credentials = store();
        let (_dir, socket) = start(Arc::clone(&credentials), None).await;
        let reply = ask(
            &socket,
            b"{\"op\":\"revoke_credential\",\"host\":\"api.anthropic.com\"}\n",
        )
        .await;
        assert_eq!(reply.outcome, Outcome::Revoked);
        assert_eq!(reply.persisted, Some(false));
        assert!(reply.error.is_some());
    }

    #[tokio::test]
    async fn a_failed_write_keeps_the_credential_revoked_and_says_so() {
        let credentials = store();
        let dir = tempfile::tempdir().unwrap();
        // A record path inside a directory that does not exist cannot be written.
        let record = dir.path().join("missing-dir").join("revoked-credentials");
        let (_sock_dir, socket) = start(Arc::clone(&credentials), Some(record)).await;
        let reply = ask(
            &socket,
            b"{\"op\":\"revoke_credential\",\"host\":\"api.anthropic.com\"}\n",
        )
        .await;
        assert_eq!(reply.outcome, Outcome::Revoked);
        assert_eq!(reply.persisted, Some(false));
        assert!(matches!(
            credentials.injection_for("api.anthropic.com"),
            Injection::Revoked
        ));
    }

    #[test]
    fn a_recorded_host_with_no_configured_credential_is_skipped_not_invented() {
        let dir = tempfile::tempdir().unwrap();
        let record = dir.path().join("revoked-credentials");
        revocations::record(&record, "api.mistral.ai").unwrap();
        let credentials = store();
        assert_eq!(apply_persisted(&credentials, &record).unwrap(), 0);
        assert!(matches!(
            credentials.injection_for("api.mistral.ai"),
            Injection::NotConfigured
        ));
    }

    #[test]
    fn an_untrusted_record_stops_the_apply_instead_of_being_ignored() {
        let dir = tempfile::tempdir().unwrap();
        let record = dir.path().join("revoked-credentials");
        std::fs::write(&record, "api.anthropic.com\n").unwrap();
        std::fs::set_permissions(&record, std::fs::Permissions::from_mode(0o666)).unwrap();
        assert!(apply_persisted(&store(), &record).is_err());
    }

    #[test]
    fn a_socket_in_a_world_writable_directory_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("ctl.sock");
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o777)).unwrap();
        let err = bind_hardened(&socket).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
        assert!(!socket.exists(), "a refused bind must not leave a socket behind");
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    }

    #[test]
    fn an_over_long_socket_path_is_refused_up_front() {
        let long = Path::new("/tmp").join("a".repeat(120));
        let err = bind_hardened(&long).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    }
}
