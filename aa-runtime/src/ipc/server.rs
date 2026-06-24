//! Unix domain socket IPC server.
//!
//! `IpcServer` binds to a UDS path, enforces connection limits via a semaphore,
//! and dispatches each connection to a pair of reader/writer tasks.

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::Arc;

use tokio::net::UnixListener;
use tokio::sync::{mpsc, Semaphore};
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

use crate::ipc::message::{IpcFrame, IpcResponse};
use crate::ipc::ResponseRouter;

/// Configuration for the IPC server.
#[derive(Debug, Clone)]
pub struct IpcServerConfig {
    /// Absolute path to the Unix domain socket file.
    pub socket_path: PathBuf,
    /// The agent identity (AA_AGENT_ID) this runtime serves. The socket path is
    /// scoped to it, and the per-session handshake (AAASM-3585) verifies the
    /// SDK's proof against the Ed25519 key deterministically derived from it.
    pub agent_id: String,
    /// Maximum number of concurrent SDK connections.
    pub max_connections: usize,
    /// Channel capacity for decoded inbound frames.
    pub inbound_channel_capacity: usize,
}

impl IpcServerConfig {
    /// Build an `IpcServerConfig` from a `RuntimeConfig`.
    pub fn from_runtime_config(config: &crate::config::RuntimeConfig) -> Self {
        Self {
            socket_path: PathBuf::from(format!("/tmp/aa-runtime-{}.sock", config.agent_id)),
            agent_id: config.agent_id.clone(),
            max_connections: config.ipc_max_connections,
            inbound_channel_capacity: 256,
        }
    }
}

/// The IPC server handle. Owns the bound `UnixListener`.
pub struct IpcServer {
    config: IpcServerConfig,
    listener: UnixListener,
}

impl IpcServer {
    /// Bind the Unix domain socket, removing any stale socket file first.
    ///
    /// The socket is created owner-only (`0600`) with **no permission window**:
    /// a restrictive `umask(0o077)` is applied around `bind` so the file is never
    /// group/world-accessible even momentarily (AAASM-3581). The previous
    /// bind→`set_permissions(0o600)` sequence left a brief TOCTOU window during
    /// which another local process could connect; the umask closes it. The
    /// explicit `set_permissions` is kept as belt-and-suspenders.
    pub fn bind(config: IpcServerConfig) -> std::io::Result<Self> {
        let path = &config.socket_path;

        // Remove stale socket if it exists.
        if path.exists() {
            std::fs::remove_file(path)?;
            tracing::info!(path = %path.display(), "removed stale socket file");
        }

        // AAASM-3581: tighten the umask so the socket inode is created 0600 from
        // the very first instant — no world/group-accessible window between bind
        // and chmod. Restore the prior umask immediately after bind.
        let listener = {
            let prev_umask = unsafe { libc::umask(0o077) };
            let result = UnixListener::bind(path);
            // Restore regardless of bind outcome so we never leak the tightened
            // umask into the rest of the process.
            unsafe { libc::umask(prev_umask) };
            result?
        };

        // Belt-and-suspenders: assert the final owner-only mode explicitly.
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;

        // AAASM-3581: the socket path is derived from the configured agent id
        // (AA_AGENT_ID) by `IpcServerConfig::from_runtime_config`; bind only the
        // identity-scoped path so a different agent cannot squat it.
        debug_assert!(
            config.agent_id.is_empty() || path.to_string_lossy().contains(config.agent_id.as_str()),
            "IPC socket path must contain the configured agent id"
        );

        tracing::info!(
            path = %path.display(),
            agent_id = %config.agent_id,
            max_connections = config.max_connections,
            "IPC server bound"
        );

        Ok(Self { config, listener })
    }

    /// Run the accept loop until the cancellation token fires.
    ///
    /// Each accepted connection is handed off to a pair of reader/writer tasks
    /// registered with the provided `TaskTracker`.
    pub async fn run(
        self,
        tracker: TaskTracker,
        token: CancellationToken,
        inbound_tx: mpsc::Sender<(u64, IpcFrame)>,
        active_connections: Arc<AtomicI64>,
        response_router: ResponseRouter,
        verified_identities: crate::ipc::VerifiedIdentityStore,
    ) {
        let semaphore = Arc::new(Semaphore::new(self.config.max_connections));
        let listener = self.listener;
        let socket_path = self.config.socket_path.clone();
        let inbound_channel_capacity = self.config.inbound_channel_capacity;
        let max_connections = self.config.max_connections;
        // Monotonically increasing connection ID — unique per accepted connection.
        let next_conn_id = Arc::new(AtomicU64::new(0));
        // AAASM-3579: the UID every accepted peer must match.
        let runtime_uid = crate::ipc::peercred::current_runtime_uid();
        // AAASM-3585: the Ed25519 verifying key every peer must prove possession
        // of, derived deterministically from this runtime's agent id.
        let expected_key = crate::ipc::handshake::expected_verifying_key(&self.config.agent_id);

        tracing::info!("IPC server accept loop started");

        loop {
            tokio::select! {
                _ = token.cancelled() => {
                    tracing::info!("IPC server shutting down — cancellation received");
                    break;
                }
                result = listener.accept() => {
                    match result {
                        Err(e) => {
                            tracing::error!(error = %e, "accept error");
                            continue;
                        }
                        Ok((stream, _addr)) => {
                            // AAASM-3579: reject any peer whose process UID does
                            // not match the runtime's own UID before doing any
                            // work for it. Defence-in-depth over the 0600 socket
                            // perms — closes the "other local process forges
                            // events / impersonates the runtime" vector.
                            match stream.peer_cred() {
                                Ok(cred) => {
                                    let peer_uid = cred.uid();
                                    if !crate::ipc::peercred::peer_uid_is_allowed(peer_uid, runtime_uid) {
                                        tracing::warn!(
                                            peer_uid,
                                            runtime_uid,
                                            "rejecting IPC connection — peer UID does not match runtime UID"
                                        );
                                        drop(stream);
                                        continue;
                                    }
                                }
                                Err(e) => {
                                    tracing::warn!(
                                        error = %e,
                                        "rejecting IPC connection — could not read peer credentials"
                                    );
                                    drop(stream);
                                    continue;
                                }
                            }

                            // Acquire a connection permit (non-blocking try first).
                            let permit = match Arc::clone(&semaphore).try_acquire_owned() {
                                Ok(p) => p,
                                Err(_) => {
                                    tracing::warn!(
                                        max = max_connections,
                                        "connection limit reached — dropping new connection"
                                    );
                                    drop(stream);
                                    continue;
                                }
                            };

                            let connection_id = next_conn_id.fetch_add(1, Ordering::Relaxed);
                            let frame_tx = inbound_tx.clone();
                            let conn_token = token.child_token();

                            // AAASM-3585: gate the connection on the session
                            // handshake INSIDE the spawned task, so a slow or
                            // hostile peer can never stall the accept loop. The
                            // response router is registered and the active-conn
                            // counter incremented only after the handshake
                            // succeeds — an unauthenticated peer is never wired
                            // into the dispatch path.
                            let conn_router = Arc::clone(&response_router);
                            let conn_verified = Arc::clone(&verified_identities);
                            let conn_active = Arc::clone(&active_connections);
                            spawn_connection(
                                &tracker,
                                stream,
                                frame_tx,
                                conn_token,
                                permit,
                                conn_active,
                                connection_id,
                                conn_router,
                                conn_verified,
                                expected_key,
                                inbound_channel_capacity,
                            );
                        }
                    }
                }
            }
        }

        // Clean up socket file on shutdown.
        if let Err(e) = std::fs::remove_file(&socket_path) {
            tracing::warn!(error = %e, "failed to remove socket file on shutdown");
        }

        tracing::info!("IPC server accept loop stopped");
    }
}

/// Maximum time the SDK has to complete the session handshake before the runtime
/// drops the connection — bounds slow-loris holds (AAASM-3585).
const HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Spawn a single coordinating task that first gates the connection on the
/// session handshake (AAASM-3585) and only then registers it and runs the
/// reader/writer dispatch tasks.
///
/// The handshake runs in this spawned task (never on the accept loop), the
/// response router entry and active-connection counter are added only after a
/// valid proof, and any failure/timeout drops the connection without dispatching
/// a single frame.
#[allow(clippy::too_many_arguments)]
pub(super) fn spawn_connection(
    tracker: &TaskTracker,
    stream: tokio::net::UnixStream,
    frame_tx: mpsc::Sender<(u64, IpcFrame)>,
    token: CancellationToken,
    permit: tokio::sync::OwnedSemaphorePermit,
    active_connections: Arc<AtomicI64>,
    connection_id: u64,
    response_router: ResponseRouter,
    verified_identities: crate::ipc::VerifiedIdentityStore,
    expected_key: ed25519_dalek::VerifyingKey,
    inbound_channel_capacity: usize,
) {
    let tracker_inner = tracker.clone();
    tracker.spawn(async move {
        let _permit = permit; // held for the lifetime of this connection.

        let (mut read_half, mut write_half) = stream.into_split();

        // AAASM-3585: challenge the peer and verify its signed proof before any
        // application frame is served. Bounded by HANDSHAKE_TIMEOUT.
        let verified_identity = match tokio::time::timeout(
            HANDSHAKE_TIMEOUT,
            perform_handshake(&mut read_half, &mut write_half, &expected_key),
        )
        .await
        {
            Ok(Some(identity)) => {
                tracing::debug!(connection_id, "IPC handshake succeeded");
                identity
            }
            Ok(None) => {
                tracing::warn!(connection_id, "IPC handshake failed — dropping connection");
                return;
            }
            Err(_) => {
                tracing::warn!(connection_id, "IPC handshake timed out — dropping connection");
                return;
            }
        };

        // Handshake passed: now wire this connection into the dispatch path.
        let (resp_tx, resp_rx) = mpsc::channel::<IpcResponse>(inbound_channel_capacity);
        response_router.write().await.insert(connection_id, resp_tx.clone());
        // AAASM-3640: record the handshake-verified identity for this connection
        // so the pipeline can recompute the SDK-identity verdict against it.
        verified_identities
            .write()
            .await
            .insert(connection_id, verified_identity);
        active_connections.fetch_add(1, Ordering::Relaxed);

        // Reader task: decode frames from socket → inbound channel.
        let reader_token = token.clone();
        tracker_inner.spawn(async move {
            run_reader(
                read_half,
                frame_tx,
                reader_token,
                active_connections,
                connection_id,
                response_router,
                verified_identities,
            )
            .await;
        });

        // Writer task: outbound responses → socket. resp_tx is held here to keep
        // the channel alive while the writer is running.
        let _resp_tx = resp_tx;
        tracker_inner.spawn(async move {
            run_writer(write_half, resp_rx, token).await;
        });
    });
}

/// Run the runtime side of the session handshake: send a fresh nonce challenge,
/// await the SDK's `HandshakeProof`, and verify it against `expected_key`.
///
/// Returns `Some(VerifiedSdkIdentity)` only on a valid proof — the identity the
/// authenticated channel established (AAASM-3640 consumes it). The current
/// handshake proof authenticates the agent's Ed25519 key possession but carries
/// no SDK version on the wire, so the returned identity has `version: None`
/// (a present-but-not-versioned attestation). Any I/O error, a non-handshake
/// first frame, or a signature that does not verify returns `None`
/// (fail-closed).
pub(super) async fn perform_handshake(
    read_half: &mut tokio::net::unix::OwnedReadHalf,
    write_half: &mut tokio::net::unix::OwnedWriteHalf,
    expected_key: &ed25519_dalek::VerifyingKey,
) -> Option<aa_security::sdk_identity::VerifiedSdkIdentity> {
    use crate::ipc::handshake;
    use aa_proto::assembly::ipc::v1::HandshakeChallenge;

    // 1. Send the challenge nonce.
    let nonce = handshake::generate_nonce();
    let challenge = IpcResponse::HandshakeChallenge(HandshakeChallenge { nonce: nonce.to_vec() });
    if let Err(e) = super::codec::write_response(write_half, challenge).await {
        tracing::warn!(error = %e, "failed to send handshake challenge");
        return None;
    }

    // 2. Await the proof. The first frame MUST be a HandshakeProof — anything
    //    else (e.g. an EventReport from a peer skipping the handshake) is
    //    rejected without dispatch.
    match super::codec::read_frame(read_half).await {
        Ok(IpcFrame::HandshakeProof(proof)) => {
            if handshake::verify_proof(&nonce, &proof, expected_key) {
                // Authenticated. The proof carries no version, so the verified
                // reference is present-without-version (version: None).
                Some(aa_security::sdk_identity::VerifiedSdkIdentity::none())
            } else {
                tracing::warn!("handshake proof did not verify against the expected agent key");
                None
            }
        }
        Ok(other) => {
            tracing::warn!(
                frame = ?std::mem::discriminant(&other),
                "first IPC frame was not a handshake proof — rejecting unauthenticated peer"
            );
            None
        }
        Err(e) => {
            tracing::warn!(error = %e, "failed to read handshake proof");
            None
        }
    }
}

/// Reader task: reads frames from the socket and sends them to the inbound channel.
pub(super) async fn run_reader(
    mut stream: tokio::net::unix::OwnedReadHalf,
    frame_tx: mpsc::Sender<(u64, IpcFrame)>,
    token: CancellationToken,
    active_connections: Arc<AtomicI64>,
    connection_id: u64,
    response_router: ResponseRouter,
    verified_identities: crate::ipc::VerifiedIdentityStore,
) {
    loop {
        tokio::select! {
            _ = token.cancelled() => {
                tracing::debug!("reader task cancelled");
                break;
            }
            result = super::codec::read_frame(&mut stream) => {
                match result {
                    Ok(frame) => {
                        if frame_tx.send((connection_id, frame)).await.is_err() {
                            tracing::debug!("inbound channel closed — reader exiting");
                            break;
                        }
                    }
                    Err(super::codec::CodecError::Io(e))
                        if e.kind() == std::io::ErrorKind::UnexpectedEof
                            || e.kind() == std::io::ErrorKind::ConnectionReset =>
                    {
                        tracing::debug!("SDK client disconnected");
                        break;
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "frame decode error — closing connection");
                        break;
                    }
                }
            }
        }
    }
    // Remove this connection from the response router and the verified-identity
    // store before signalling shutdown.
    response_router.write().await.remove(&connection_id);
    verified_identities.write().await.remove(&connection_id);
    token.cancel(); // Signal the paired writer to stop.
    active_connections.fetch_sub(1, Ordering::Relaxed);
}

/// Writer task: reads responses from the channel and writes them to the socket.
pub(super) async fn run_writer(
    mut stream: tokio::net::unix::OwnedWriteHalf,
    mut resp_rx: mpsc::Receiver<IpcResponse>,
    token: CancellationToken,
) {
    loop {
        tokio::select! {
            _ = token.cancelled() => {
                tracing::debug!("writer task cancelled");
                break;
            }
            maybe_resp = resp_rx.recv() => {
                match maybe_resp {
                    None => {
                        tracing::debug!("response channel closed — writer exiting");
                        break;
                    }
                    Some(response) => {
                        if let Err(e) = super::codec::write_response(&mut stream, response).await {
                            tracing::warn!(error = %e, "failed to write response — closing connection");
                            break;
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipc::codec::{TAG_EVENT_REPORT, TAG_HEARTBEAT, TAG_POLICY_QUERY};
    use crate::ipc::message::IpcFrame;
    use aa_proto::assembly::audit::v1::AuditEvent;
    use aa_proto::assembly::policy::v1::CheckActionRequest;
    use prost::Message;
    use std::time::Duration;
    use tokio::net::UnixStream;
    use tokio::sync::mpsc;

    /// Build a temporary socket path unique per test to avoid collisions.
    ///
    /// The path embeds [`TEST_AGENT_ID`] so it satisfies the production
    /// agent-id-scoping invariant asserted in `IpcServer::bind` (AAASM-3581).
    fn temp_socket_path(name: &str) -> std::path::PathBuf {
        std::path::PathBuf::from(format!("/tmp/aa-runtime-{TEST_AGENT_ID}-{name}.sock"))
    }

    /// The agent id every test server in this module is configured with.
    const TEST_AGENT_ID: &str = "test-agent";

    /// Perform the SDK side of the AAASM-3585 session handshake on a freshly
    /// connected stream: read the runtime's nonce challenge and reply with a
    /// valid Ed25519 proof signed by the `agent_id`'s deterministic key.
    ///
    /// Mirrors what the real `aa-sdk-client` does on connect, so the existing
    /// dispatch tests can talk to the now-gated server.
    async fn do_client_handshake(stream: &mut UnixStream, agent_id: &str) {
        use crate::ipc::codec::{TAG_HANDSHAKE_CHALLENGE, TAG_HANDSHAKE_PROOF};
        use aa_proto::assembly::ipc::v1::{HandshakeChallenge, HandshakeProof};
        use ed25519_dalek::Signer;
        use sha2::{Digest, Sha256};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        // Read the challenge frame: tag, varint len, payload.
        let tag = stream.read_u8().await.expect("read challenge tag");
        assert_eq!(tag, TAG_HANDSHAKE_CHALLENGE, "expected handshake challenge first");
        let len = read_varint_stream(stream).await;
        let mut buf = vec![0u8; len];
        stream.read_exact(&mut buf).await.expect("read challenge payload");
        let challenge = HandshakeChallenge::decode(buf.as_ref()).expect("decode challenge");

        // Sign the nonce with the deterministic agent key.
        let seed: [u8; 32] = Sha256::digest(agent_id.as_bytes()).into();
        let sk = ed25519_dalek::SigningKey::from_bytes(&seed);
        let sig = sk.sign(&challenge.nonce);
        let proof = HandshakeProof {
            agent_did: format!("did:key:{agent_id}"),
            public_key: hex::encode(sk.verifying_key().to_bytes()),
            signature: sig.to_bytes().to_vec(),
        };

        // Write the proof frame.
        let payload = proof.encode_to_vec();
        stream.write_u8(TAG_HANDSHAKE_PROOF).await.unwrap();
        write_varint_stream(stream, payload.len() as u64).await;
        stream.write_all(&payload).await.unwrap();
        stream.flush().await.unwrap();
    }

    /// Read a varint directly from a full `UnixStream` (test helper).
    async fn read_varint_stream(stream: &mut UnixStream) -> usize {
        use tokio::io::AsyncReadExt;
        let mut result: u64 = 0;
        let mut shift = 0u32;
        loop {
            let byte = stream.read_u8().await.unwrap();
            result |= ((byte & 0x7F) as u64) << shift;
            if byte & 0x80 == 0 {
                break;
            }
            shift += 7;
        }
        result as usize
    }

    /// Write a varint directly to a full `UnixStream` (test helper).
    async fn write_varint_stream(stream: &mut UnixStream, mut value: u64) {
        use tokio::io::AsyncWriteExt;
        loop {
            let byte = (value & 0x7F) as u8;
            value >>= 7;
            if value == 0 {
                stream.write_u8(byte).await.unwrap();
                break;
            } else {
                stream.write_u8(byte | 0x80).await.unwrap();
            }
        }
    }

    /// Helper: connect a mock SDK client to the server socket (retrying briefly)
    /// and complete the session handshake as `TEST_AGENT_ID`.
    async fn connect_client(path: &std::path::Path) -> UnixStream {
        for _ in 0..20 {
            if let Ok(mut stream) = UnixStream::connect(path).await {
                do_client_handshake(&mut stream, TEST_AGENT_ID).await;
                return stream;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("could not connect to test IPC server at {}", path.display());
    }

    /// Start a test IpcServer and return the inbound frame receiver plus response router.
    async fn start_server(
        socket_path: std::path::PathBuf,
        token: CancellationToken,
        active_connections: Arc<AtomicI64>,
    ) -> (
        mpsc::Receiver<(u64, IpcFrame)>,
        crate::ipc::ResponseRouter,
        crate::ipc::VerifiedIdentityStore,
    ) {
        let config = IpcServerConfig {
            socket_path,
            agent_id: "test-agent".to_string(),
            max_connections: 64,
            inbound_channel_capacity: 16,
        };
        let server = IpcServer::bind(config).expect("bind failed");
        let (tx, rx) = mpsc::channel(16);
        let router = crate::ipc::new_response_router();
        let router_clone = Arc::clone(&router);
        let verified = crate::ipc::new_verified_identity_store();
        let verified_clone = Arc::clone(&verified);
        let tracker = TaskTracker::new();
        let tracker_clone = tracker.clone();
        tracker.spawn(async move {
            server
                .run(
                    tracker_clone,
                    token,
                    tx,
                    active_connections,
                    router_clone,
                    verified_clone,
                )
                .await;
        });
        (rx, router, verified)
    }

    /// Write a raw inbound frame (tag + varint len + payload) to the socket.
    async fn write_raw_frame(stream: &mut tokio::net::unix::OwnedWriteHalf, tag: u8, payload: &[u8]) {
        use tokio::io::AsyncWriteExt;
        stream.write_u8(tag).await.unwrap();
        // Write varint length
        let mut len = payload.len() as u64;
        loop {
            let byte = (len & 0x7F) as u8;
            len >>= 7;
            if len == 0 {
                stream.write_u8(byte).await.unwrap();
                break;
            } else {
                stream.write_u8(byte | 0x80).await.unwrap();
            }
        }
        stream.write_all(payload).await.unwrap();
        stream.flush().await.unwrap();
    }

    /// AAASM-3581: the socket file must be exactly mode 0600 immediately after
    /// bind (no permission window), and its path must be scoped to the agent id.
    #[tokio::test]
    async fn bind_creates_socket_with_0600_and_agent_scoped_path() {
        let socket_path = temp_socket_path("perm-check");
        let _ = std::fs::remove_file(&socket_path);
        let config = IpcServerConfig {
            socket_path: socket_path.clone(),
            agent_id: "perm-check".to_string(),
            max_connections: 8,
            inbound_channel_capacity: 8,
        };
        let _server = IpcServer::bind(config).expect("bind failed");

        let mode = std::fs::metadata(&socket_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "socket must be owner-only (0600), got {mode:o}");
        assert!(
            socket_path.to_string_lossy().contains("perm-check"),
            "socket path must be scoped to the agent id"
        );

        let _ = std::fs::remove_file(&socket_path);
    }

    #[tokio::test]
    async fn heartbeat_frame_arrives_on_inbound_channel() {
        let socket_path = temp_socket_path("heartbeat");
        let token = CancellationToken::new();
        let counter = Arc::new(AtomicI64::new(0));
        let (mut rx, _router, _verified) = start_server(socket_path.clone(), token.clone(), Arc::clone(&counter)).await;

        let client = connect_client(&socket_path).await;
        let (_, mut write_half) = client.into_split();

        // Heartbeat has tag only, no payload or length field.
        use tokio::io::AsyncWriteExt;
        write_half.write_u8(TAG_HEARTBEAT).await.unwrap();
        write_half.flush().await.unwrap();

        let (_conn_id, frame) = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("timed out waiting for frame")
            .expect("channel closed");

        assert!(matches!(frame, IpcFrame::Heartbeat));
        token.cancel();
    }

    #[tokio::test]
    async fn policy_query_arrives_decoded_on_inbound_channel() {
        let socket_path = temp_socket_path("policy-query");
        let token = CancellationToken::new();
        let counter = Arc::new(AtomicI64::new(0));
        let (mut rx, _router, _verified) = start_server(socket_path.clone(), token.clone(), Arc::clone(&counter)).await;

        let client = connect_client(&socket_path).await;
        let (_, mut write_half) = client.into_split();

        let request = CheckActionRequest {
            trace_id: "trace-xyz".to_string(),
            ..Default::default()
        };
        let payload = request.encode_to_vec();
        write_raw_frame(&mut write_half, TAG_POLICY_QUERY, &payload).await;

        let (_conn_id, frame) = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("timed out")
            .expect("channel closed");

        match frame {
            IpcFrame::PolicyQuery(decoded) => assert_eq!(decoded.trace_id, "trace-xyz"),
            other => panic!("expected PolicyQuery, got {other:?}"),
        }
        token.cancel();
    }

    #[tokio::test]
    async fn event_report_arrives_decoded_on_inbound_channel() {
        let socket_path = temp_socket_path("event-report");
        let token = CancellationToken::new();
        let counter = Arc::new(AtomicI64::new(0));
        let (mut rx, _router, _verified) = start_server(socket_path.clone(), token.clone(), Arc::clone(&counter)).await;

        let client = connect_client(&socket_path).await;
        let (_, mut write_half) = client.into_split();

        let event = AuditEvent {
            event_id: "evt-456".to_string(),
            ..Default::default()
        };
        let payload = event.encode_to_vec();
        write_raw_frame(&mut write_half, TAG_EVENT_REPORT, &payload).await;

        let (_conn_id, frame) = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("timed out")
            .expect("channel closed");

        match frame {
            IpcFrame::EventReport(decoded) => assert_eq!(decoded.event_id, "evt-456"),
            other => panic!("expected EventReport, got {other:?}"),
        }
        token.cancel();
    }

    #[tokio::test]
    async fn concurrent_connections_up_to_limit() {
        let socket_path = temp_socket_path("concurrent");
        let token = CancellationToken::new();
        let counter = Arc::new(AtomicI64::new(0));
        let (_rx, _router, _verified) = start_server(socket_path.clone(), token.clone(), Arc::clone(&counter)).await;

        const CONN_COUNT: usize = 5;
        let mut clients = Vec::new();
        for _ in 0..CONN_COUNT {
            clients.push(connect_client(&socket_path).await);
        }

        // All connections should succeed (well below max of 64).
        assert_eq!(clients.len(), CONN_COUNT);
        token.cancel();
    }

    /// Round-trip latency test. Marked #[ignore] — run explicitly only.
    #[tokio::test]
    #[ignore]
    async fn round_trip_latency_under_1ms() {
        let socket_path = temp_socket_path("latency");
        let token = CancellationToken::new();
        let counter = Arc::new(AtomicI64::new(0));
        let (mut rx, _router, _verified) = start_server(socket_path.clone(), token.clone(), Arc::clone(&counter)).await;

        let client = connect_client(&socket_path).await;
        let (_, mut write_half) = client.into_split();

        const ITERATIONS: u32 = 1000;
        let start = std::time::Instant::now();

        for _ in 0..ITERATIONS {
            use tokio::io::AsyncWriteExt;
            write_half.write_u8(TAG_HEARTBEAT).await.unwrap();
            write_half.flush().await.unwrap();
            tokio::time::timeout(Duration::from_millis(100), rx.recv())
                .await
                .expect("timed out")
                .expect("channel closed"); // returns (conn_id, frame) — result unused in latency test
        }

        let elapsed = start.elapsed();
        let avg_us = elapsed.as_micros() / ITERATIONS as u128;
        println!("Average round-trip: {avg_us} µs");

        assert!(avg_us < 1000, "average round-trip {avg_us} µs exceeded 1ms threshold");

        token.cancel();
    }

    #[tokio::test]
    async fn active_connections_increments_on_accept() {
        let socket_path = temp_socket_path("counter-increment");
        let token = CancellationToken::new();
        let counter = Arc::new(AtomicI64::new(0));
        let (_rx, _router, _verified) = start_server(socket_path.clone(), token.clone(), Arc::clone(&counter)).await;

        const CONN_COUNT: usize = 3;
        let mut clients = Vec::new();
        for _ in 0..CONN_COUNT {
            clients.push(connect_client(&socket_path).await);
        }

        // Poll briefly for the server accept loop to process all connections.
        let mut observed = 0i64;
        for _ in 0..50 {
            observed = counter.load(Ordering::Relaxed);
            if observed == CONN_COUNT as i64 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        assert_eq!(
            observed, CONN_COUNT as i64,
            "counter should equal number of accepted connections"
        );

        token.cancel();
        drop(clients);
    }

    #[tokio::test]
    async fn active_connections_decrements_on_disconnect() {
        let socket_path = temp_socket_path("counter-decrement");
        let token = CancellationToken::new();
        let counter = Arc::new(AtomicI64::new(0));
        let (_rx, _router, _verified) = start_server(socket_path.clone(), token.clone(), Arc::clone(&counter)).await;

        let client = connect_client(&socket_path).await;

        // Wait for counter to reach 1.
        for _ in 0..50 {
            if counter.load(Ordering::Relaxed) == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(
            counter.load(Ordering::Relaxed),
            1,
            "counter should be 1 after one connection"
        );

        // Drop the client to trigger disconnect.
        drop(client);

        // Poll for counter to return to 0.
        let mut observed = 1i64;
        for _ in 0..100 {
            observed = counter.load(Ordering::Relaxed);
            if observed == 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        assert_eq!(observed, 0, "counter should return to 0 after client disconnects");

        token.cancel();
    }

    #[tokio::test]
    async fn response_router_has_entry_after_accept() {
        let socket_path = temp_socket_path("router-insert");
        let token = CancellationToken::new();
        let counter = Arc::new(AtomicI64::new(0));
        let (_rx, router, _verified) = start_server(socket_path.clone(), token.clone(), Arc::clone(&counter)).await;

        let _client = connect_client(&socket_path).await;

        // Poll until the server has processed the accept (counter reaches 1).
        for _ in 0..50 {
            if counter.load(Ordering::Relaxed) == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        let map = router.read().await;
        assert_eq!(map.len(), 1, "router should contain one entry after one connection");
        token.cancel();
    }

    #[tokio::test]
    async fn response_router_entry_removed_after_disconnect() {
        let socket_path = temp_socket_path("router-remove");
        let token = CancellationToken::new();
        let counter = Arc::new(AtomicI64::new(0));
        let (_rx, router, _verified) = start_server(socket_path.clone(), token.clone(), Arc::clone(&counter)).await;

        let client = connect_client(&socket_path).await;

        // Wait for entry to appear.
        for _ in 0..50 {
            if router.read().await.len() == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(router.read().await.len(), 1);

        // Drop client — triggers disconnect → router removal.
        drop(client);

        // Poll for the entry to be removed.
        let mut observed_len = 1usize;
        for _ in 0..100 {
            observed_len = router.read().await.len();
            if observed_len == 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(
            observed_len, 0,
            "router entry should be removed after client disconnects"
        );

        token.cancel();
    }

    #[tokio::test]
    async fn verified_identity_recorded_after_handshake() {
        // AAASM-3640: a connection that completes the authenticated handshake
        // has its verified identity recorded in the store, keyed by connection_id.
        let socket_path = temp_socket_path("verified-insert");
        let token = CancellationToken::new();
        let counter = Arc::new(AtomicI64::new(0));
        let (_rx, _router, verified) = start_server(socket_path.clone(), token.clone(), Arc::clone(&counter)).await;

        let _client = connect_client(&socket_path).await;

        for _ in 0..50 {
            if counter.load(Ordering::Relaxed) == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        let map = verified.read().await;
        assert_eq!(
            map.len(),
            1,
            "verified-identity store should hold one entry after a handshake"
        );
        token.cancel();
    }

    #[tokio::test]
    async fn verified_identity_removed_after_disconnect() {
        let socket_path = temp_socket_path("verified-remove");
        let token = CancellationToken::new();
        let counter = Arc::new(AtomicI64::new(0));
        let (_rx, _router, verified) = start_server(socket_path.clone(), token.clone(), Arc::clone(&counter)).await;

        let client = connect_client(&socket_path).await;

        for _ in 0..50 {
            if verified.read().await.len() == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(verified.read().await.len(), 1);

        drop(client);

        let mut observed_len = 1usize;
        for _ in 0..100 {
            observed_len = verified.read().await.len();
            if observed_len == 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(
            observed_len, 0,
            "verified-identity entry should be removed after client disconnects"
        );

        token.cancel();
    }

    /// Spin up an IPC server + pipeline and verify that a violation EventReport
    /// results in a ViolationAlert (tag 4) arriving on the same connection
    /// within 100 ms.
    #[tokio::test]
    async fn violation_event_triggers_alert_within_100ms() {
        use crate::ipc::codec::{TAG_EVENT_REPORT, TAG_VIOLATION_ALERT};
        use crate::pipeline::{PipelineConfig, PipelineMetrics};
        use aa_proto::assembly::audit::v1::{audit_event::Detail, PolicyViolation};
        use prost::Message;
        use std::sync::Arc;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let socket_path = temp_socket_path("violation-alert");
        let token = CancellationToken::new();
        let counter = Arc::new(AtomicI64::new(0));
        let (inbound_rx, router, verified) =
            start_server(socket_path.clone(), token.clone(), Arc::clone(&counter)).await;

        // Spin up the pipeline.
        let pipeline_config = PipelineConfig {
            input_buffer: 64,
            batch_size: 100,
            flush_interval: std::time::Duration::from_secs(60),
            broadcast_capacity: 64,
            agent_id: "test-agent".to_string(),
            enforcement: crate::pipeline::enforcement::EnforcementConfig::default(),
            gateway_fail_closed: true,
            min_sdk_version: None,
        };
        let pipeline_metrics = Arc::new(PipelineMetrics::default());
        let (broadcast_tx, _broadcast_rx) = tokio::sync::broadcast::channel::<crate::pipeline::PipelineEvent>(64);
        let pipeline_router = Arc::clone(&router);
        let pipeline_token = token.clone();
        tokio::spawn(crate::pipeline::run(
            inbound_rx,
            broadcast_tx,
            pipeline_config,
            pipeline_metrics,
            pipeline_token,
            Arc::new(crate::policy::PolicyRules::default()),
            pipeline_router,
            crate::approval::ApprovalQueue::new(),
            None,
            crate::op_control::OpControlStore::new(),
            Arc::new(std::sync::atomic::AtomicU64::new(0)),
            Arc::clone(&verified),
        ));

        // Connect a client.
        let client = connect_client(&socket_path).await;
        let (mut read_half, mut write_half) = client.into_split();

        // Wait for the connection to be registered.
        for _ in 0..50 {
            if counter.load(Ordering::Relaxed) == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        // Build a PolicyViolation event.
        let violation = PolicyViolation {
            policy_rule: "test-rule".to_string(),
            blocked_action: "FILE_OPERATION".to_string(),
            reason: "blocked".to_string(),
            latency_ms: 0,
        };
        let event = AuditEvent {
            detail: Some(Detail::Violation(violation)),
            ..Default::default()
        };
        let payload = event.encode_to_vec();

        // Send as EventReport frame.
        write_half.write_u8(TAG_EVENT_REPORT).await.unwrap();
        let mut len = payload.len() as u64;
        loop {
            let byte = (len & 0x7F) as u8;
            len >>= 7;
            if len == 0 {
                write_half.write_u8(byte).await.unwrap();
                break;
            } else {
                write_half.write_u8(byte | 0x80).await.unwrap();
            }
        }
        write_half.write_all(&payload).await.unwrap();
        write_half.flush().await.unwrap();

        // The pipeline should detect the violation and push ViolationAlert (tag 4) back.
        let tag = tokio::time::timeout(Duration::from_millis(100), read_half.read_u8())
            .await
            .expect("ViolationAlert did not arrive within 100ms")
            .expect("read error");

        assert_eq!(tag, TAG_VIOLATION_ALERT, "expected ViolationAlert tag (4)");

        token.cancel();
    }

    /// A normal (non-violation) EventReport must NOT produce any response
    /// on the same connection.
    #[tokio::test]
    async fn normal_event_produces_no_response() {
        use crate::ipc::codec::TAG_EVENT_REPORT;
        use crate::pipeline::{PipelineConfig, PipelineMetrics};
        use prost::Message;
        use std::sync::Arc;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let socket_path = temp_socket_path("no-alert");
        let token = CancellationToken::new();
        let counter = Arc::new(AtomicI64::new(0));
        let (inbound_rx, router, verified) =
            start_server(socket_path.clone(), token.clone(), Arc::clone(&counter)).await;

        // Spin up the pipeline.
        let pipeline_config = PipelineConfig {
            input_buffer: 64,
            batch_size: 100,
            flush_interval: std::time::Duration::from_secs(60),
            broadcast_capacity: 64,
            agent_id: "test-agent".to_string(),
            enforcement: crate::pipeline::enforcement::EnforcementConfig::default(),
            gateway_fail_closed: true,
            min_sdk_version: None,
        };
        let pipeline_metrics = Arc::new(PipelineMetrics::default());
        let (broadcast_tx, _broadcast_rx) = tokio::sync::broadcast::channel::<crate::pipeline::PipelineEvent>(64);
        let pipeline_router = Arc::clone(&router);
        let pipeline_token = token.clone();
        tokio::spawn(crate::pipeline::run(
            inbound_rx,
            broadcast_tx,
            pipeline_config,
            pipeline_metrics,
            pipeline_token,
            Arc::new(crate::policy::PolicyRules::default()),
            pipeline_router,
            crate::approval::ApprovalQueue::new(),
            None,
            crate::op_control::OpControlStore::new(),
            Arc::new(std::sync::atomic::AtomicU64::new(0)),
            Arc::clone(&verified),
        ));

        // Connect a client.
        let client = connect_client(&socket_path).await;
        let (mut read_half, mut write_half) = client.into_split();

        // Wait for the connection to be registered.
        for _ in 0..50 {
            if counter.load(Ordering::Relaxed) == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        // Send a normal (non-violation) event.
        let event = AuditEvent::default();
        let payload = event.encode_to_vec();
        write_half.write_u8(TAG_EVENT_REPORT).await.unwrap();
        let mut len = payload.len() as u64;
        loop {
            let byte = (len & 0x7F) as u8;
            len >>= 7;
            if len == 0 {
                write_half.write_u8(byte).await.unwrap();
                break;
            } else {
                write_half.write_u8(byte | 0x80).await.unwrap();
            }
        }
        write_half.write_all(&payload).await.unwrap();
        write_half.flush().await.unwrap();

        // No ViolationAlert should arrive — read should time out.
        let result = tokio::time::timeout(Duration::from_millis(100), read_half.read_u8()).await;
        assert!(
            result.is_err(),
            "expected no response for a normal event, but received one"
        );

        token.cancel();
    }

    /// Full approval round-trip over the IPC socket:
    /// SDK sends PolicyQuery → pipeline responds PENDING → CLI calls
    /// ApprovalQueue::decide() → pipeline pushes ApprovalDecision back
    /// over the same Unix socket connection.
    #[tokio::test]
    async fn approval_round_trip_over_ipc_socket() {
        use crate::approval::ApprovalDecision as RuntimeApprovalDecision;
        use crate::ipc::codec::{TAG_APPROVAL_DECISION, TAG_POLICY_QUERY, TAG_POLICY_RESPONSE};
        use crate::pipeline::{PipelineConfig, PipelineMetrics};
        use crate::policy::{PolicyRule, PolicyRules};
        use aa_proto::assembly::common::v1::{ActionType, Decision};
        use aa_proto::assembly::event::v1::ApprovalDecision as ProtoApprovalDecision;
        use aa_proto::assembly::policy::v1::{CheckActionRequest, CheckActionResponse};
        use prost::Message;
        use std::sync::Arc;
        use tokio::io::AsyncReadExt;

        let socket_path = temp_socket_path("approval-roundtrip");
        let token = CancellationToken::new();
        let counter = Arc::new(AtomicI64::new(0));
        let (inbound_rx, router, verified) =
            start_server(socket_path.clone(), token.clone(), Arc::clone(&counter)).await;

        // Policy: TOOL_CALL requires approval.
        let policy = Arc::new(PolicyRules {
            rules: vec![PolicyRule {
                name: "approve-tool".to_string(),
                requires_approval_actions: vec![ActionType::ToolCall.as_str_name().to_string()],
                approval_timeout_secs: 60,
                ..Default::default()
            }],
        });

        let approval_queue = crate::approval::ApprovalQueue::new();
        let queue_ref = Arc::clone(&approval_queue);

        let pipeline_config = PipelineConfig {
            input_buffer: 64,
            batch_size: 100,
            flush_interval: std::time::Duration::from_secs(60),
            broadcast_capacity: 64,
            agent_id: "test-agent".to_string(),
            enforcement: crate::pipeline::enforcement::EnforcementConfig::default(),
            gateway_fail_closed: true,
            min_sdk_version: None,
        };
        let pipeline_metrics = Arc::new(PipelineMetrics::default());
        let (broadcast_tx, _broadcast_rx) = tokio::sync::broadcast::channel::<crate::pipeline::PipelineEvent>(64);
        let pipeline_router = Arc::clone(&router);
        let pipeline_token = token.clone();
        tokio::spawn(crate::pipeline::run(
            inbound_rx,
            broadcast_tx,
            pipeline_config,
            pipeline_metrics,
            pipeline_token,
            policy,
            pipeline_router,
            approval_queue,
            None,
            crate::op_control::OpControlStore::new(),
            Arc::new(std::sync::atomic::AtomicU64::new(0)),
            Arc::clone(&verified),
        ));

        // Connect a client.
        let client = connect_client(&socket_path).await;
        let (mut read_half, mut write_half) = client.into_split();

        // Wait for the connection to be registered.
        for _ in 0..50 {
            if counter.load(Ordering::Relaxed) == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        // Step 1: Send a PolicyQuery for TOOL_CALL.
        let request = CheckActionRequest {
            action_type: ActionType::ToolCall as i32,
            trace_id: "trace-approval-roundtrip".to_string(),
            ..Default::default()
        };
        let payload = request.encode_to_vec();
        write_raw_frame(&mut write_half, TAG_POLICY_QUERY, &payload).await;

        // Step 2: Read the PENDING response.
        let tag = tokio::time::timeout(Duration::from_millis(200), read_half.read_u8())
            .await
            .expect("PENDING response timed out")
            .expect("read error");
        assert_eq!(tag, TAG_POLICY_RESPONSE, "expected PolicyResponse tag");

        // Read varint length + payload.
        let mut resp_len: u64 = 0;
        let mut shift = 0u32;
        loop {
            let byte = read_half.read_u8().await.unwrap();
            resp_len |= ((byte & 0x7F) as u64) << shift;
            if byte & 0x80 == 0 {
                break;
            }
            shift += 7;
        }
        let mut resp_buf = vec![0u8; resp_len as usize];
        read_half.read_exact(&mut resp_buf).await.unwrap();
        let pending_resp = CheckActionResponse::decode(resp_buf.as_ref()).unwrap();

        assert_eq!(pending_resp.decision, Decision::Pending as i32);
        assert!(!pending_resp.approval_id.is_empty(), "approval_id must be set");

        let approval_id = uuid::Uuid::parse_str(&pending_resp.approval_id).expect("invalid UUID in approval_id");

        // Step 3: Approve via the queue (simulates CLI calling ApprovalQueue::decide).
        queue_ref
            .decide(
                approval_id,
                RuntimeApprovalDecision::Approved {
                    by: "cli-operator".to_string(),
                    reason: Some("approved via IPC test".to_string()),
                },
            )
            .expect("decide should succeed");

        // Step 4: Read the ApprovalDecision pushed back over the socket.
        let tag2 = tokio::time::timeout(Duration::from_millis(200), read_half.read_u8())
            .await
            .expect("ApprovalDecision response timed out")
            .expect("read error");
        assert_eq!(tag2, TAG_APPROVAL_DECISION, "expected ApprovalDecision tag");

        let mut dec_len: u64 = 0;
        shift = 0;
        loop {
            let byte = read_half.read_u8().await.unwrap();
            dec_len |= ((byte & 0x7F) as u64) << shift;
            if byte & 0x80 == 0 {
                break;
            }
            shift += 7;
        }
        let mut dec_buf = vec![0u8; dec_len as usize];
        read_half.read_exact(&mut dec_buf).await.unwrap();
        let decision = ProtoApprovalDecision::decode(dec_buf.as_ref()).unwrap();

        assert!(decision.approved, "decision should be approved");
        assert_eq!(decision.decided_by, "cli-operator");
        assert_eq!(decision.approval_id, approval_id.to_string());

        token.cancel();
    }

    // ── AAASM-3589: impersonation / forged-event rejection ──────────────────────

    /// A peer that connects and immediately sends an EventReport WITHOUT
    /// completing the handshake must NOT have its event dispatched, and its
    /// connection is dropped. Closes the "connect and flood forged audit
    /// events" vector.
    #[tokio::test]
    async fn event_without_handshake_is_not_dispatched() {
        let socket_path = temp_socket_path("no-handshake-event");
        let token = CancellationToken::new();
        let counter = Arc::new(AtomicI64::new(0));
        let (mut rx, _router, _verified) = start_server(socket_path.clone(), token.clone(), Arc::clone(&counter)).await;

        // Connect WITHOUT performing the handshake.
        let stream = {
            let mut s = None;
            for _ in 0..20 {
                if let Ok(st) = UnixStream::connect(&socket_path).await {
                    s = Some(st);
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            s.expect("connect failed")
        };
        let (_read_half, mut write_half) = stream.into_split();

        // Skip the handshake; send an EventReport as the very first frame.
        let event = AuditEvent {
            event_id: "forged-no-handshake".to_string(),
            ..Default::default()
        };
        let payload = event.encode_to_vec();
        write_raw_frame(&mut write_half, TAG_EVENT_REPORT, &payload).await;

        // The event must NOT arrive on the inbound channel — the server rejects
        // the connection at the handshake gate before any dispatch.
        let result = tokio::time::timeout(Duration::from_millis(300), rx.recv()).await;
        assert!(
            result.is_err(),
            "an un-handshaked peer's event must never be dispatched"
        );

        token.cancel();
    }

    /// A peer that sends a HandshakeProof with a signature that does not verify
    /// against the agent key is rejected — no session, no dispatch.
    #[tokio::test]
    async fn forged_handshake_signature_is_rejected() {
        use crate::ipc::codec::TAG_HANDSHAKE_PROOF;
        use aa_proto::assembly::ipc::v1::HandshakeProof;
        use ed25519_dalek::Signer;
        use sha2::{Digest, Sha256};

        let socket_path = temp_socket_path("forged-handshake");
        let token = CancellationToken::new();
        let counter = Arc::new(AtomicI64::new(0));
        let (mut rx, _router, _verified) = start_server(socket_path.clone(), token.clone(), Arc::clone(&counter)).await;

        let mut stream = {
            let mut s = None;
            for _ in 0..20 {
                if let Ok(st) = UnixStream::connect(&socket_path).await {
                    s = Some(st);
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            s.expect("connect failed")
        };

        // Read the challenge (so we consume the nonce), then reply with a proof
        // whose signature is corrupted.
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let tag = stream.read_u8().await.unwrap();
        assert_eq!(tag, crate::ipc::codec::TAG_HANDSHAKE_CHALLENGE);
        let clen = read_varint_stream(&mut stream).await;
        let mut cbuf = vec![0u8; clen];
        stream.read_exact(&mut cbuf).await.unwrap();
        let challenge = aa_proto::assembly::ipc::v1::HandshakeChallenge::decode(cbuf.as_ref()).unwrap();

        let seed: [u8; 32] = Sha256::digest(TEST_AGENT_ID.as_bytes()).into();
        let sk = ed25519_dalek::SigningKey::from_bytes(&seed);
        let mut sig = sk.sign(&challenge.nonce).to_bytes().to_vec();
        sig[0] ^= 0xFF; // corrupt the signature

        let proof = HandshakeProof {
            agent_did: format!("did:key:{TEST_AGENT_ID}"),
            public_key: hex::encode(sk.verifying_key().to_bytes()),
            signature: sig,
        };
        let payload = proof.encode_to_vec();
        stream.write_u8(TAG_HANDSHAKE_PROOF).await.unwrap();
        write_varint_stream(&mut stream, payload.len() as u64).await;
        stream.write_all(&payload).await.unwrap();
        stream.flush().await.unwrap();

        // Now try to send an event over the same (rejected) connection.
        let (_r, mut w) = stream.into_split();
        let event = AuditEvent {
            event_id: "forged-sig".to_string(),
            ..Default::default()
        };
        let payload = event.encode_to_vec();
        // Best-effort write — the server may have already dropped the connection.
        let _ = w.write_u8(TAG_EVENT_REPORT).await;
        let mut len = payload.len() as u64;
        loop {
            let byte = (len & 0x7F) as u8;
            len >>= 7;
            if len == 0 {
                let _ = w.write_u8(byte).await;
                break;
            } else {
                let _ = w.write_u8(byte | 0x80).await;
            }
        }
        let _ = w.write_all(&payload).await;
        let _ = w.flush().await;

        // No frame must be dispatched for a forged handshake.
        let result = tokio::time::timeout(Duration::from_millis(300), rx.recv()).await;
        assert!(result.is_err(), "a forged-signature peer must never be dispatched");

        token.cancel();
    }

    /// Happy path: a peer that completes a valid handshake then sends an event
    /// has that event dispatched on the inbound channel.
    #[tokio::test]
    async fn valid_handshake_then_event_is_dispatched() {
        let socket_path = temp_socket_path("valid-handshake-event");
        let token = CancellationToken::new();
        let counter = Arc::new(AtomicI64::new(0));
        let (mut rx, _router, _verified) = start_server(socket_path.clone(), token.clone(), Arc::clone(&counter)).await;

        // connect_client performs the valid handshake as TEST_AGENT_ID.
        let client = connect_client(&socket_path).await;
        let (_read_half, mut write_half) = client.into_split();

        let event = AuditEvent {
            event_id: "authenticated-event".to_string(),
            ..Default::default()
        };
        let payload = event.encode_to_vec();
        write_raw_frame(&mut write_half, TAG_EVENT_REPORT, &payload).await;

        let (_conn_id, frame) = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("authenticated event timed out")
            .expect("channel closed");
        match frame {
            IpcFrame::EventReport(decoded) => assert_eq!(decoded.event_id, "authenticated-event"),
            other => panic!("expected EventReport, got {other:?}"),
        }

        token.cancel();
    }
}
