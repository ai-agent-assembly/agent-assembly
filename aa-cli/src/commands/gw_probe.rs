//! Readiness probe for the locally-managed `aasm` gateway process.
//!
//! Used by `aasm start` (Impl-3, AAASM-1717) to confirm the spawned
//! gateway is accepting traffic before the command exits. While
//! `/healthz` is still pending (AAASM-1577 / S-C), this probe uses
//! TCP-listener detection as the readiness signal — the API is
//! shaped so swapping in an HTTP probe later is a one-line change.

use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

/// Errors that can occur while probing the gateway for readiness.
#[derive(Debug, thiserror::Error)]
pub enum ProbeError {
    /// `wait_for_ready` exhausted its overall timeout without ever
    /// observing a successful probe.
    #[error("gateway did not become ready within {elapsed:?}")]
    Timeout {
        /// Time spent polling before giving up.
        elapsed: Duration,
    },
}

/// One-shot probe — returns `true` if a TCP listener at `addr`
/// accepts a connection within `connect_timeout`.
///
/// Any failure (connection refused, timeout, network error) is
/// folded to `false`; callers only care about a single liveness
/// bit, not the reason it failed. The connected socket is dropped
/// immediately so the probe leaves no lingering state on the
/// listener side.
pub fn probe_tcp(addr: SocketAddr, connect_timeout: Duration) -> bool {
    TcpStream::connect_timeout(&addr, connect_timeout).is_ok()
}
