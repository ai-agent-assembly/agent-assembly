//! AAASM-2570 acceptance: `AssemblyClient` drives a full session against a mock
//! `UnixListener` "runtime" — connect → heartbeat → report event → shutdown.

use std::path::PathBuf;
use std::sync::Arc;

use aa_sdk_client::codec::{TAG_ACK, TAG_EVENT_REPORT, TAG_HEARTBEAT};
use aa_sdk_client::ipc::spawn_ipc_thread;
use aa_sdk_client::AssemblyClient;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixListener;

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

#[tokio::test]
async fn client_ships_event_to_mock_runtime_and_shuts_down() {
    let socket_path = format!("/tmp/aa-sdk-client-e2e-{}.sock", std::process::id());
    let _ = std::fs::remove_file(&socket_path);
    let listener = UnixListener::bind(&socket_path).unwrap();

    let ipc = spawn_ipc_thread(PathBuf::from(&socket_path)).unwrap();
    let client = Arc::new(AssemblyClient::new(ipc, vec!["openai".to_string()]));
    assert_eq!(client.detected_frameworks(), vec!["openai".to_string()]);

    let (stream, _) = listener.accept().await.unwrap();
    let (mut reader, mut writer) = tokio::io::split(stream);

    // 1. Heartbeat handshake.
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
