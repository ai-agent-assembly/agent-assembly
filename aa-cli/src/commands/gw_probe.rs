//! Readiness probe for the locally-managed `aasm` gateway process.
//!
//! Used by `aasm start` (Impl-3, AAASM-1717) to confirm the spawned
//! gateway is accepting traffic before the command exits. While
//! `/healthz` is still pending (AAASM-1577 / S-C), this probe uses
//! TCP-listener detection as the readiness signal — the API is
//! shaped so swapping in an HTTP probe later is a one-line change.

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
