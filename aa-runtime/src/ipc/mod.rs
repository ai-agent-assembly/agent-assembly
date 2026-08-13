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

/// Shared map from connection ID to the SDK identity the AAASM-3569 session
/// handshake *verified* for that connection.
///
/// Populated by the IPC server when a connection completes the authenticated
/// handshake (the peer proved possession of the agent's Ed25519 key) and
/// removed when the connection closes — the same lifecycle as
/// [`ResponseRouter`]. The pipeline reads it by `connection_id` to recompute
/// the SDK-identity verdict (AAASM-3640) against a trusted reference instead of
/// the attacker-controlled observed claim. When a connection has no entry (no
/// handshake / unsupported), the classifier falls back to `Unverifiable`.
pub type VerifiedIdentityStore = Arc<RwLock<HashMap<u64, aa_security::sdk_identity::VerifiedSdkIdentity>>>;

/// Create an empty [`VerifiedIdentityStore`].
pub fn new_verified_identity_store() -> VerifiedIdentityStore {
    Arc::new(RwLock::new(HashMap::new()))
}
