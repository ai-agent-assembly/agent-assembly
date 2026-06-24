//! IPC client for communicating with aa-runtime over a Unix domain socket.
//!
//! The client runs on a dedicated background OS thread with its own Tokio
//! current-thread runtime. The calling thread communicates with the background
//! thread via an mpsc command channel.

use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::mpsc as blocking_mpsc;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use tokio::sync::mpsc;

use aa_proto::assembly::policy::v1::{CheckActionRequest, CheckActionResponse};

use crate::codec;

/// Commands sent from the calling thread to the background IPC thread.
///
/// `Debug` is hand-written (not derived) so the `QueryPolicy` variant never
/// prints its `CheckActionRequest.credential_token` — a derived `Debug` would
/// emit the gateway auth token verbatim into any `{:?}`/`tracing` log at
/// `RUST_LOG=debug` (AAASM-3634). Only the non-sensitive `action_type` shape is
/// shown; the token (and the rest of the request body) is elided.
pub enum IpcCommand {
    /// Send an audit event to the runtime.
    SendEvent(Box<aa_proto::assembly::audit::v1::AuditEvent>),
    /// Synchronously query the runtime for a policy decision on an action. The
    /// `CheckActionResponse` is delivered on `resp`; the calling thread blocks
    /// on it (see [`crate::client::AssemblyClient::query_policy`]).
    QueryPolicy {
        request: Box<CheckActionRequest>,
        resp: blocking_mpsc::Sender<CheckActionResponse>,
    },
    /// Gracefully shut down the IPC connection.
    Shutdown,
}

impl std::fmt::Debug for IpcCommand {
    /// Scrubbing `Debug`: prints the variant + non-sensitive shape only and
    /// never the `credential_token` carried by the `QueryPolicy` request
    /// (AAASM-3634).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IpcCommand::SendEvent(event) => {
                f.debug_tuple("SendEvent").field(&event.event_id).finish()
            }
            IpcCommand::QueryPolicy { request, .. } => f
                .debug_struct("QueryPolicy")
                .field("action_type", &request.action_type)
                .finish_non_exhaustive(),
            IpcCommand::Shutdown => f.write_str("Shutdown"),
        }
    }
}

/// Response senders awaiting a synchronous policy decision, in FIFO order.
///
/// The command loop pushes one when it writes a `PolicyQuery`; the reader pops
/// the oldest when a `PolicyResponse` arrives. The wire carries no correlation
/// id, so responses match queries by order over the single connection.
type PendingQueries = Arc<Mutex<VecDeque<blocking_mpsc::Sender<CheckActionResponse>>>>;

/// Handle to the background IPC thread.
///
/// Holds the command sender and thread join handle so the owning
/// `AssemblyClient` can enqueue events and shut down cleanly.
pub struct IpcHandle {
    pub cmd_tx: mpsc::Sender<IpcCommand>,
    pub thread: Option<JoinHandle<()>>,
}

/// Spawn the background IPC thread.
///
/// Creates an mpsc channel, spawns an OS thread running a Tokio
/// current-thread runtime, connects to the runtime socket, and runs
/// the event loop. Returns an `IpcHandle` for the caller.
///
/// `agent_id` is the agent identity (AA_AGENT_ID); the loop derives the
/// deterministic Ed25519 keypair from it to complete the runtime's session
/// handshake before sending any traffic (AAASM-3587).
pub fn spawn_ipc_thread(socket_path: PathBuf, agent_id: String) -> Result<IpcHandle, std::io::Error> {
    let (cmd_tx, cmd_rx) = mpsc::channel::<IpcCommand>(256);

    let thread = std::thread::Builder::new().name("aa-ipc".to_string()).spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("failed to build Tokio runtime for IPC thread");
        rt.block_on(ipc_loop(socket_path, agent_id, cmd_rx));
    })?;

    Ok(IpcHandle {
        cmd_tx,
        thread: Some(thread),
    })
}

/// The async event loop running on the background thread.
///
/// Connects to the runtime socket, sends an initial heartbeat, then ships event
/// reports **fire-and-forget** — it does not block waiting for a per-event
/// acknowledgement. `aa-runtime` does not ack heartbeats or event reports; it
/// only emits *unsolicited* responses (violation alerts, policy/approval
/// decisions), which a dedicated reader task drains so the socket never backs
/// up. Blocking on an ack the runtime never sends would deadlock this loop and
/// hang `shutdown()` (AAASM-3000).
async fn ipc_loop(socket_path: PathBuf, agent_id: String, mut cmd_rx: mpsc::Receiver<IpcCommand>) {
    use tokio::net::UnixStream;

    let stream = match UnixStream::connect(&socket_path).await {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(
                path = %socket_path.display(),
                error = %e,
                "failed to connect to aa-runtime socket"
            );
            return;
        }
    };

    // Owned halves let the reader run on its own task without racing the writer.
    let (mut reader, mut writer) = stream.into_split();

    // AAASM-3587: complete the session handshake BEFORE any other traffic. Read
    // the runtime's nonce challenge, sign it with the agent's key, and send the
    // proof. Fail-closed — if the handshake fails, abort the loop rather than
    // leak heartbeats/events onto an unauthenticated channel.
    if let Err(e) = perform_handshake(&mut reader, &mut writer, &agent_id).await {
        tracing::error!(error = %e, "IPC handshake failed — aborting (fail-closed)");
        return;
    }

    // Send the initial heartbeat (fire-and-forget — the runtime does not ack it).
    if let Err(e) = codec::write_heartbeat(&mut writer).await {
        tracing::error!(error = %e, "failed to send initial heartbeat");
        return;
    }

    // Pending synchronous policy queries, routed back by the reader task.
    let pending: PendingQueries = Arc::new(Mutex::new(VecDeque::new()));

    // Drain unsolicited runtime responses (and route policy responses to their
    // waiting queries) on a dedicated task: reads never race writes (no
    // cancellation hazard) and the connection cannot stall.
    let reader_task = tokio::spawn(drain_responses(reader, Arc::clone(&pending)));

    // Process commands from the calling thread. Event reports are fire-and-forget;
    // policy queries register a waiter and write a `PolicyQuery`.
    while let Some(cmd) = cmd_rx.recv().await {
        match cmd {
            IpcCommand::SendEvent(event) => {
                if let Err(e) = codec::write_event_report(&mut writer, &event).await {
                    tracing::error!(error = %e, "failed to send event report");
                }
            }
            IpcCommand::QueryPolicy { request, resp } => {
                // Queue the response sender BEFORE writing, so the reader can
                // never observe the response before the sender is registered.
                if let Ok(mut q) = pending.lock() {
                    q.push_back(resp);
                }
                if let Err(e) = codec::write_policy_query(&mut writer, &request).await {
                    tracing::error!(error = %e, "failed to send policy query");
                    // The query never went out — drop the sender we just queued
                    // so the caller unblocks with QueryFailed instead of hanging.
                    if let Ok(mut q) = pending.lock() {
                        q.pop_back();
                    }
                }
            }
            IpcCommand::Shutdown => {
                tracing::debug!("IPC shutdown requested");
                break;
            }
        }
    }

    reader_task.abort();
}

/// Complete the SDK side of the runtime session handshake (AAASM-3587).
///
/// Reads the runtime's nonce challenge, signs it with the agent's deterministic
/// Ed25519 key, and writes back a `HandshakeProof`. Returns an error if the
/// challenge cannot be read or the proof cannot be sent — the caller treats this
/// as fail-closed and aborts the loop.
async fn perform_handshake(
    reader: &mut tokio::net::unix::OwnedReadHalf,
    writer: &mut tokio::net::unix::OwnedWriteHalf,
    agent_id: &str,
) -> Result<(), codec::CodecError> {
    let nonce = codec::read_handshake_challenge(reader).await?;
    let proof = build_handshake_proof(agent_id, &nonce);
    codec::write_handshake_proof(writer, &proof).await?;
    tracing::debug!("IPC session handshake completed");
    Ok(())
}

/// Build a `HandshakeProof` for `agent_id` over the runtime-issued `nonce`,
/// using the agent's deterministic Ed25519 keypair (AAASM-3587).
fn build_handshake_proof(agent_id: &str, nonce: &[u8]) -> aa_proto::assembly::ipc::v1::HandshakeProof {
    let keypair = crate::keypair::AgentKeypair::derive(agent_id);
    aa_proto::assembly::ipc::v1::HandshakeProof {
        agent_did: keypair.did_key(),
        public_key: keypair.public_key_hex(),
        signature: keypair.sign(nonce).to_vec(),
    }
}

/// Read responses from the runtime: route each `PolicyResponse` to the oldest
/// waiting synchronous query, and drain everything else (violation alerts,
/// approval decisions) so the connection does not stall.
///
/// Exits on EOF or a read error (e.g. the runtime closing the connection), or
/// when aborted on shutdown.
async fn drain_responses(mut reader: tokio::net::unix::OwnedReadHalf, pending: PendingQueries) {
    loop {
        match codec::read_response(&mut reader).await {
            Ok(codec::RuntimeResponse::PolicyResponse(resp)) => {
                let waiting = pending.lock().ok().and_then(|mut q| q.pop_front());
                match waiting {
                    Some(tx) => {
                        // Ignore send errors: the caller may have already timed out.
                        let _ = tx.send(resp);
                    }
                    None => tracing::debug!("policy response with no pending query — dropping"),
                }
            }
            Ok(other) => {
                tracing::debug!(?other, "received unsolicited runtime response");
            }
            Err(e) => {
                tracing::debug!(error = %e, "runtime response stream ended");
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipc_command_send_event_is_debug() {
        let event = aa_proto::assembly::audit::v1::AuditEvent {
            event_id: "test".to_string(),
            ..Default::default()
        };
        let cmd = IpcCommand::SendEvent(Box::new(event));
        let debug = format!("{:?}", cmd);
        assert!(debug.contains("SendEvent"));
    }

    #[test]
    fn ipc_command_shutdown_is_debug() {
        let cmd = IpcCommand::Shutdown;
        assert_eq!(format!("{:?}", cmd), "Shutdown");
    }

    /// The agent id the mock-server tests handshake as.
    const TEST_AGENT_ID: &str = "test-agent";

    /// Server-side handshake (AAASM-3587): send a nonce challenge, read the
    /// client's proof, and verify it signs the nonce under the agent key. Mock
    /// servers call this first so the now-handshaking client can proceed.
    async fn server_handshake<S>(stream: &mut S, agent_id: &str)
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};
        use prost::Message;
        use sha2::{Digest, Sha256};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        // Send HandshakeChallenge{nonce}.
        let mut nonce = vec![0u8; 32];
        getrandom::getrandom(&mut nonce).expect("OS RNG must be available for the handshake nonce");
        let challenge = aa_proto::assembly::ipc::v1::HandshakeChallenge { nonce: nonce.clone() };
        let payload = challenge.encode_to_vec();
        stream.write_u8(codec::TAG_HANDSHAKE_CHALLENGE).await.unwrap();
        assert!(payload.len() < 128);
        stream.write_u8(payload.len() as u8).await.unwrap();
        stream.write_all(&payload).await.unwrap();
        stream.flush().await.unwrap();

        // Read the proof frame. The proof payload exceeds 127 bytes (did:key +
        // 64-char pubkey hex + 64-byte sig), so the length prefix is a varint.
        assert_eq!(stream.read_u8().await.unwrap(), codec::TAG_HANDSHAKE_PROOF);
        let mut len: u64 = 0;
        let mut shift = 0u32;
        loop {
            let byte = stream.read_u8().await.unwrap();
            len |= ((byte & 0x7F) as u64) << shift;
            if byte & 0x80 == 0 {
                break;
            }
            shift += 7;
        }
        let mut buf = vec![0u8; len as usize];
        stream.read_exact(&mut buf).await.unwrap();
        let proof = aa_proto::assembly::ipc::v1::HandshakeProof::decode(buf.as_ref()).unwrap();

        // Verify the proof against the expected agent key.
        let seed: [u8; 32] = Sha256::digest(agent_id.as_bytes()).into();
        let vk = ed25519_dalek::SigningKey::from_bytes(&seed).verifying_key();
        assert_eq!(proof.public_key, hex::encode(vk.to_bytes()));
        let sig_bytes: [u8; 64] = proof.signature.as_slice().try_into().unwrap();
        let vk2 = VerifyingKey::from_bytes(&vk.to_bytes()).unwrap();
        vk2.verify(&nonce, &Signature::from_bytes(&sig_bytes))
            .expect("client proof must verify");
    }

    #[tokio::test]
    async fn spawn_ipc_thread_fails_on_nonexistent_socket() {
        // spawn_ipc_thread should succeed (thread spawns), but the thread
        // will fail to connect and exit. We verify the handle is returned.
        let handle = spawn_ipc_thread(
            PathBuf::from("/tmp/nonexistent-aa-test.sock"),
            TEST_AGENT_ID.to_string(),
        );
        assert!(handle.is_ok());
        let mut handle = handle.unwrap();
        // Send shutdown to cleanly stop the thread (it may have already exited
        // due to connection failure).
        let _ = handle.cmd_tx.send(IpcCommand::Shutdown).await;
        if let Some(thread) = handle.thread.take() {
            thread.join().expect("IPC thread panicked");
        }
    }

    #[tokio::test]
    async fn ipc_loop_with_mock_server() {
        use tokio::net::UnixListener;

        let socket_path = format!("/tmp/aa-test-ipc-{}.sock", std::process::id());
        let _ = std::fs::remove_file(&socket_path);

        let listener = UnixListener::bind(&socket_path).unwrap();

        // Spawn the IPC client thread.
        let handle = spawn_ipc_thread(PathBuf::from(&socket_path), TEST_AGENT_ID.to_string()).unwrap();

        // Accept the connection on the mock server side.
        let (mut stream, _) = listener.accept().await.unwrap();

        // AAASM-3587: the client completes the handshake before any heartbeat.
        server_handshake(&mut stream, TEST_AGENT_ID).await;

        let (mut reader, mut writer) = tokio::io::split(stream);

        // The client sends a heartbeat next — read the tag byte.
        use tokio::io::AsyncReadExt;
        let tag = reader.read_u8().await.unwrap();
        assert_eq!(tag, codec::TAG_HEARTBEAT);

        // Respond with Ack: [TAG_ACK][varint 0]
        use tokio::io::AsyncWriteExt;
        writer.write_all(&[codec::TAG_ACK, 0x00]).await.unwrap();
        writer.flush().await.unwrap();

        // Send a shutdown command.
        handle.cmd_tx.send(IpcCommand::Shutdown).await.unwrap();

        // Clean up.
        let _ = std::fs::remove_file(&socket_path);
    }

    /// Regression for AAASM-3000: a runtime that never acks (like the real
    /// `aa-runtime`, which ignores heartbeats and only emits unsolicited
    /// responses) must not deadlock the client — events ship fire-and-forget
    /// and shutdown returns promptly. The pre-fix loop blocked forever reading
    /// a heartbeat ack that never came, so `shutdown()` hung.
    #[tokio::test]
    async fn shutdown_is_clean_when_runtime_never_acks() {
        use std::time::Duration;
        use tokio::io::AsyncReadExt;
        use tokio::net::UnixListener;

        let socket_path = format!("/tmp/aa-test-noack-{}.sock", std::process::id());
        let _ = std::fs::remove_file(&socket_path);
        let listener = UnixListener::bind(&socket_path).unwrap();

        // Mock runtime mimicking the real one: complete the handshake, then read
        // whatever the client sends and never reply with an ack.
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            server_handshake(&mut stream, TEST_AGENT_ID).await;
            let mut buf = [0u8; 1024];
            while let Ok(n) = stream.read(&mut buf).await {
                if n == 0 {
                    break; // client closed the connection
                }
            }
        });

        let mut handle = spawn_ipc_thread(PathBuf::from(&socket_path), TEST_AGENT_ID.to_string()).unwrap();

        // Ship several events — fire-and-forget, must not block.
        for i in 0..5 {
            let event = aa_proto::assembly::audit::v1::AuditEvent {
                event_id: format!("evt-{i}"),
                ..Default::default()
            };
            handle
                .cmd_tx
                .send(IpcCommand::SendEvent(Box::new(event)))
                .await
                .unwrap();
        }

        // Shutdown must return promptly (pre-fix: hung forever on the ack read).
        handle.cmd_tx.send(IpcCommand::Shutdown).await.unwrap();
        let thread = handle.thread.take().unwrap();
        let joined = tokio::time::timeout(
            Duration::from_secs(5),
            tokio::task::spawn_blocking(move || thread.join()),
        )
        .await;

        assert!(
            joined.is_ok(),
            "IPC thread did not shut down within 5s — deadlock regression (AAASM-3000)"
        );
        joined
            .unwrap()
            .expect("join task panicked")
            .expect("IPC thread panicked");

        server.abort();
        let _ = std::fs::remove_file(&socket_path);
    }

    /// A synchronous `query_policy` against a runtime that answers `PolicyQuery`
    /// with a `PolicyResponse` returns that decision to the blocking caller.
    #[tokio::test]
    async fn query_policy_returns_runtime_decision() {
        use std::time::Duration;

        use prost::Message;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::UnixListener;

        use crate::client::AssemblyClient;

        let socket_path = format!("/tmp/aa-test-query-{}.sock", std::process::id());
        let _ = std::fs::remove_file(&socket_path);
        let listener = UnixListener::bind(&socket_path).unwrap();

        // Mock runtime: read the heartbeat + the PolicyQuery, then reply with a
        // Deny CheckActionResponse. Bodies here are < 128 bytes, so the
        // length-delimiter varint is a single byte.
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            server_handshake(&mut stream, TEST_AGENT_ID).await;
            assert_eq!(stream.read_u8().await.unwrap(), codec::TAG_HEARTBEAT);
            assert_eq!(stream.read_u8().await.unwrap(), codec::TAG_POLICY_QUERY);
            let len = stream.read_u8().await.unwrap() as usize;
            if len > 0 {
                let mut body = vec![0u8; len];
                stream.read_exact(&mut body).await.unwrap();
            }

            let resp = aa_proto::assembly::policy::v1::CheckActionResponse {
                decision: aa_proto::assembly::common::v1::Decision::Deny as i32,
                ..Default::default()
            };
            let mut buf = Vec::new();
            resp.encode(&mut buf).unwrap();
            assert!(buf.len() < 128, "test assumes a single-byte length varint");
            stream.write_u8(codec::TAG_POLICY_RESPONSE).await.unwrap();
            stream.write_u8(buf.len() as u8).await.unwrap();
            stream.write_all(&buf).await.unwrap();
            stream.flush().await.unwrap();
            // Keep the connection open so the client can read the reply.
            tokio::time::sleep(Duration::from_millis(200)).await;
        });

        let handle = spawn_ipc_thread(PathBuf::from(&socket_path), TEST_AGENT_ID.to_string()).unwrap();
        let client = AssemblyClient::new(handle, Vec::new());

        // query_policy blocks the calling thread, so run it off the async runtime.
        let decision = tokio::task::spawn_blocking(move || {
            client.query_policy(aa_proto::assembly::policy::v1::CheckActionRequest::default())
        })
        .await
        .unwrap();

        server.abort();
        let _ = std::fs::remove_file(&socket_path);

        let resp = decision.expect("query_policy should return the runtime decision");
        assert_eq!(resp.decision, aa_proto::assembly::common::v1::Decision::Deny as i32);
    }
}
