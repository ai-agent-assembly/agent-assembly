//! Error type for the SDK client.

/// Errors returned by [`AssemblyClient`](crate::client::AssemblyClient)
/// operations.
///
/// The crate is FFI-agnostic, so these are plain Rust errors. The per-language
/// shims map them onto their native exception types (e.g. the pyo3 shim
/// converts them to `RuntimeError`).
#[derive(Debug)]
pub enum SdkClientError {
    /// The client has been shut down; no further events can be reported.
    Shutdown,
    /// An internal lock was poisoned by a panic in another thread.
    LockPoisoned,
    /// The background IPC thread's command channel is closed, so the event
    /// could not be enqueued.
    ChannelClosed,
    /// A synchronous policy query did not complete: the runtime did not answer
    /// within the timeout, or the IPC connection closed before a response
    /// arrived. This is a non-OK sentinel, not an implicit allow: callers resolve
    /// it through [`resolve_decision`](crate::decision::resolve_decision), which
    /// fails *closed* under enforce and preserves fail-open only when fail-closed
    /// is disabled (AAASM-3958).
    QueryFailed,
    /// The gateway gRPC endpoint could not be reached for registration.
    GatewayUnreachable,
    /// The gateway rejected the `Register` call. Carries the gRPC status message
    /// (e.g. an invalid did:key or public_key).
    RegisterFailed(String),
}

impl std::fmt::Display for SdkClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SdkClientError::Shutdown => {
                write!(f, "AssemblyClient is shut down; cannot report events")
            }
            SdkClientError::LockPoisoned => write!(f, "AssemblyClient lock was poisoned"),
            SdkClientError::ChannelClosed => {
                write!(f, "failed to enqueue event: IPC channel is closed")
            }
            SdkClientError::QueryFailed => {
                write!(f, "policy query failed: runtime did not respond in time")
            }
            SdkClientError::GatewayUnreachable => {
                write!(f, "gateway gRPC endpoint is unreachable for registration")
            }
            SdkClientError::RegisterFailed(msg) => {
                write!(f, "gateway rejected registration: {msg}")
            }
        }
    }
}

impl std::error::Error for SdkClientError {}
