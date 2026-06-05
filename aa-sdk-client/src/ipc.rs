//! IPC client for communicating with aa-runtime over a Unix domain socket.
//!
//! The client runs on a dedicated background OS thread with its own Tokio
//! current-thread runtime. The calling thread communicates with the background
//! thread via an mpsc command channel.

use std::path::PathBuf;
use std::thread::JoinHandle;

use tokio::sync::mpsc;

use crate::codec;

/// Commands sent from the calling thread to the background IPC thread.
#[derive(Debug)]
pub enum IpcCommand {
    /// Send an audit event to the runtime.
    SendEvent(Box<aa_proto::assembly::audit::v1::AuditEvent>),
    /// Gracefully shut down the IPC connection.
    Shutdown,
}

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
pub fn spawn_ipc_thread(socket_path: PathBuf) -> Result<IpcHandle, std::io::Error> {
    let (cmd_tx, cmd_rx) = mpsc::channel::<IpcCommand>(256);

    let thread = std::thread::Builder::new().name("aa-ipc".to_string()).spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("failed to build Tokio runtime for IPC thread");
        rt.block_on(ipc_loop(socket_path, cmd_rx));
    })?;

    Ok(IpcHandle {
        cmd_tx,
        thread: Some(thread),
    })
}

/// The async event loop running on the background thread.
///
/// Connects to the runtime socket, sends an initial heartbeat, then
/// processes commands from the mpsc channel until shutdown.
async fn ipc_loop(socket_path: PathBuf, mut cmd_rx: mpsc::Receiver<IpcCommand>) {
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

    let (mut reader, mut writer) = tokio::io::split(stream);

    // Send initial heartbeat to verify connection.
    if let Err(e) = codec::write_heartbeat(&mut writer).await {
        tracing::error!(error = %e, "failed to send initial heartbeat");
        return;
    }

    // Read the Ack response.
    match codec::read_response(&mut reader).await {
        Ok(codec::RuntimeResponse::Ack) => {
            tracing::debug!("connected to aa-runtime, heartbeat acknowledged");
        }
        Ok(other) => {
            tracing::warn!(?other, "unexpected response to heartbeat");
        }
        Err(e) => {
            tracing::error!(error = %e, "failed to read heartbeat ack");
            return;
        }
    }

    // Process commands from the calling thread.
    while let Some(cmd) = cmd_rx.recv().await {
        match cmd {
            IpcCommand::SendEvent(event) => {
                if let Err(e) = codec::write_event_report(&mut writer, &event).await {
                    tracing::error!(error = %e, "failed to send event report");
                }
                // Read Ack.
                match codec::read_response(&mut reader).await {
                    Ok(codec::RuntimeResponse::Ack) => {}
                    Ok(other) => {
                        tracing::warn!(?other, "unexpected response to event report");
                    }
                    Err(e) => {
                        tracing::error!(error = %e, "failed to read event report ack");
                    }
                }
            }
            IpcCommand::Shutdown => {
                tracing::debug!("IPC shutdown requested");
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

    #[tokio::test]
    async fn spawn_ipc_thread_fails_on_nonexistent_socket() {
        // spawn_ipc_thread should succeed (thread spawns), but the thread
        // will fail to connect and exit. We verify the handle is returned.
        let handle = spawn_ipc_thread(PathBuf::from("/tmp/nonexistent-aa-test.sock"));
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
        let handle = spawn_ipc_thread(PathBuf::from(&socket_path)).unwrap();

        // Accept the connection on the mock server side.
        let (stream, _) = listener.accept().await.unwrap();
        let (mut reader, mut writer) = tokio::io::split(stream);

        // The client sends a heartbeat first — read the tag byte.
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
}
