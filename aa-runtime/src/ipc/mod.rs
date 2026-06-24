//! Unix domain socket IPC server for local SDK-to-runtime communication.

pub mod codec;
pub mod handshake;
pub mod message;
pub mod peercred;
pub mod server;

pub use message::{IpcFrame, IpcResponse};
pub use server::IpcServer;

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};

/// Shared map from connection ID to the per-connection outbound response sender.
///
/// The IPC server inserts an entry when a connection is accepted and removes it
/// when the connection closes. The pipeline reads from this map to route
/// `IpcResponse::ViolationAlert` back to the originating SDK client.
pub type ResponseRouter = Arc<RwLock<HashMap<u64, mpsc::Sender<IpcResponse>>>>;

/// Create an empty [`ResponseRouter`].
pub fn new_response_router() -> ResponseRouter {
    Arc::new(RwLock::new(HashMap::new()))
}
