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
        }
    }
}

impl std::error::Error for SdkClientError {}
