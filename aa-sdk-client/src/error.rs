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
    /// The agent's durable identity key could not be established, so there is
    /// nothing to register as (AAASM-5332). Carries the store's reason —
    /// unresolvable state directory, a key file owned by another user or
    /// readable beyond its owner, a revoked identity, or an unreadable CSPRNG.
    ///
    /// Always a refusal. There is deliberately no weaker identity to fall back
    /// to: the whole point of the durable key is that an agent which cannot
    /// prove possession of a secret does not get to register.
    IdentityUnavailable(String),
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
            SdkClientError::IdentityUnavailable(reason) => {
                write!(f, "this agent has no usable durable identity key: {reason}")
            }
        }
    }
}

impl std::error::Error for SdkClientError {}
