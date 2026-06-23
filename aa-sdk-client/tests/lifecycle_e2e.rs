//! AAASM-2570 acceptance: `AssemblyClient` drives a full session against a mock
//! `UnixListener` "runtime" — connect → heartbeat → report event → shutdown.

use std::path::PathBuf;
use std::sync::Arc;

use aa_sdk_client::codec::{TAG_ACK, TAG_EVENT_REPORT, TAG_HANDSHAKE_CHALLENGE, TAG_HANDSHAKE_PROOF, TAG_HEARTBEAT};
use aa_sdk_client::ipc::spawn_ipc_thread;
use aa_sdk_client::AssemblyClient;
use prost::Message;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixListener;

/// The agent id the e2e client handshakes as.
const TEST_AGENT_ID: &str = "e2e-agent";

/// Read a prost varint length prefix from `reader`.
async fn read_varint<R: AsyncReadExt + Unpin>(reader: &mut R) -> usize {
    let mut result: u64 = 0;
    let mut shift = 0u32;
    loop {
        let byte = reader.read_u8().await.unwrap();
        result |= ((byte & 0x7F) as u64) << shift;
        if byte & 0x80 == 0 {
            break;
        }
        shift += 7;
    }
    result as usize
}

/// Server side of the AAASM-3587 session handshake: send a nonce challenge, read
/// the client's signed proof, and verify it under the agent's deterministic key.
async fn server_handshake<S>(stream: &mut S, agent_id: &str)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    use ed25519_dalek::{Signature, Verifier};
    use sha2::{Digest, Sha256};

    let nonce = vec![9u8; 32];
    let challenge = aa_proto::assembly::ipc::v1::HandshakeChallenge { nonce: nonce.clone() };
    let payload = challenge.encode_to_vec();
    stream.write_u8(TAG_HANDSHAKE_CHALLENGE).await.unwrap();
    stream.write_u8(payload.len() as u8).await.unwrap();
    stream.write_all(&payload).await.unwrap();
    stream.flush().await.unwrap();

    assert_eq!(stream.read_u8().await.unwrap(), TAG_HANDSHAKE_PROOF);
    let len = read_varint(stream).await;
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await.unwrap();
    let proof = aa_proto::assembly::ipc::v1::HandshakeProof::decode(buf.as_ref()).unwrap();

    let seed: [u8; 32] = Sha256::digest(agent_id.as_bytes()).into();
    let vk = ed25519_dalek::SigningKey::from_bytes(&seed).verifying_key();
    assert_eq!(proof.public_key, hex::encode(vk.to_bytes()));
    let sig: [u8; 64] = proof.signature.as_slice().try_into().unwrap();
    vk.verify(&nonce, &Signature::from_bytes(&sig))
        .expect("client handshake proof must verify");
}

#[tokio::test]
async fn client_ships_event_to_mock_runtime_and_shuts_down() {
    let socket_path = format!("/tmp/aa-sdk-client-e2e-{}.sock", std::process::id());
    let _ = std::fs::remove_file(&socket_path);
    let listener = UnixListener::bind(&socket_path).unwrap();

    let ipc = spawn_ipc_thread(PathBuf::from(&socket_path), TEST_AGENT_ID.to_string()).unwrap();
    let client = Arc::new(AssemblyClient::new(ipc, vec!["openai".to_string()]));
    assert_eq!(client.detected_frameworks(), vec!["openai".to_string()]);

    let (mut stream, _) = listener.accept().await.unwrap();

    // 0. AAASM-3587: complete the session handshake before any application frame.
    server_handshake(&mut stream, TEST_AGENT_ID).await;

    let (mut reader, mut writer) = tokio::io::split(stream);

    // 1. Heartbeat.
    assert_eq!(reader.read_u8().await.unwrap(), TAG_HEARTBEAT);
    writer.write_all(&[TAG_ACK, 0x00]).await.unwrap();
    writer.flush().await.unwrap();

    // 2. Report an event. `report_event` issues a blocking send, so it must run
    //    off the async runtime thread.
    let ship = {
        let c = Arc::clone(&client);
        tokio::task::spawn_blocking(move || c.report_event("tool_call".into(), "searched for cats".into()))
    };

    // 3. Server reads the event-report frame (tag + length-delimited payload) and acks.
    assert_eq!(reader.read_u8().await.unwrap(), TAG_EVENT_REPORT);
    let len = read_varint(&mut reader).await;
    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf).await.unwrap();
    assert!(!buf.is_empty(), "event report payload should be non-empty");
    writer.write_all(&[TAG_ACK, 0x00]).await.unwrap();
    writer.flush().await.unwrap();

    ship.await.unwrap().expect("report_event should succeed");

    // 4. Shutdown joins the background thread — also off the runtime.
    let c = Arc::clone(&client);
    tokio::task::spawn_blocking(move || c.shutdown())
        .await
        .unwrap()
        .expect("shutdown should succeed");

    let _ = std::fs::remove_file(&socket_path);
}
