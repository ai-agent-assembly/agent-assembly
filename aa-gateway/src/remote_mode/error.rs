//! Errors that can interrupt the remote control-plane bootstrap.
//!
//! Owned by [`super::server::start_remote`] and the test-friendly
//! `start_remote_with_handle`. Each variant maps to a single failure
//! mode an operator running `aasm-gateway --mode remote` might hit, so
//! `tracing::error!` formatted output and `aasm status` JSON encoding
//! can point at the exact step that broke.

use std::io;
use std::net::SocketAddr;

use thiserror::Error;

use super::tls::TlsError;
use crate::storage::StorageError;

/// Failures emitted by `start_remote()` and friends.
#[derive(Debug, Error)]
pub enum GatewayError {
    /// Pre-flight [`super::tls::validate`] reported a hard cert / key
    /// failure. Wraps the underlying [`TlsError`] so the variant
    /// (missing file, parse error, etc.) is preserved.
    #[error("TLS preflight failed: {0}")]
    Tls(#[from] TlsError),

    /// Loading the rustls cert / key into an `axum_server::tls_rustls::RustlsConfig`
    /// failed at handshake-config build time. Distinct from [`Self::Tls`]
    /// (which is the file-level preflight) — this is the rustls-side
    /// rejection (e.g. cert / key mismatch).
    #[error("failed to load rustls TLS config: {0}")]
    TlsLoad(#[source] io::Error),

    /// `TcpListener::bind` / `axum_server::bind` failed for the
    /// configured `listen_addr` — port already in use, permission
    /// denied, or address malformed.
    #[error("failed to bind remote gateway to {addr}: {source}")]
    Bind {
        /// The socket address the gateway tried to bind.
        addr: SocketAddr,
        /// Underlying `std::io::Error` from the bind attempt.
        #[source]
        source: io::Error,
    },

    /// `axum_server::serve` returned an error after binding. Includes
    /// graceful-shutdown cleanup failures.
    #[error("remote gateway serve loop failed: {0}")]
    Serve(#[source] io::Error),

    /// Installing the SIGTERM / SIGINT handler failed (Unix only).
    #[error("shutdown signal handler installation failed: {0}")]
    Signal(#[source] io::Error),

    /// The PostgreSQL storage backend (`PostgresBackend::connect` /
    /// `StorageBackend::migrate`) failed during boot. Introduced by
    /// Epic 18 Story S-I.1: the remote control plane now opens its
    /// durable backend before binding the listener.
    #[error("storage backend error: {0}")]
    Storage(#[source] StorageError),
}
