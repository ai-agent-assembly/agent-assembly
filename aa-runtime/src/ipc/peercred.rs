//! Peer-credential check for accepted IPC connections (AAASM-3579).
//!
//! The runtime's Unix domain socket is owner-only (`0600`), but a peer-credential
//! check is defence-in-depth: it makes the trust boundary explicit and testable
//! and rejects any connection whose process UID does not match the UID the
//! runtime itself runs as (the intended agent process). This closes the "another
//! local process connects to the runtime UDS and forges events / answers allow
//! for everything" vectors named in the Story even on hosts where the filesystem
//! permission alone would not be enough.
//!
//! Portability: the peer UID is read via tokio's `UnixStream::peer_cred`, which
//! is backed by `SO_PEERCRED` on Linux and `getpeereid`/`LOCAL_PEERCRED` on
//! macOS/BSD, so this module compiles and runs on every Unix target.

/// Decide whether a peer connection should be admitted, given the peer UID and
/// the runtime's own effective UID.
///
/// Returns `true` only when the peer UID equals the runtime UID. Kept as a pure
/// function so the policy is unit-testable without opening a real socket.
pub fn peer_uid_is_allowed(peer_uid: u32, runtime_uid: u32) -> bool {
    peer_uid == runtime_uid
}

/// The effective UID of the current (runtime) process.
#[cfg(unix)]
pub fn current_runtime_uid() -> u32 {
    // SAFETY: `geteuid` is always-successful and has no preconditions.
    unsafe { libc::geteuid() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matching_uid_is_allowed() {
        assert!(peer_uid_is_allowed(1000, 1000));
    }

    #[test]
    fn mismatched_uid_is_rejected() {
        assert!(!peer_uid_is_allowed(1001, 1000));
    }

    #[test]
    fn root_peer_against_nonroot_runtime_is_rejected() {
        assert!(!peer_uid_is_allowed(0, 1000));
    }
}
