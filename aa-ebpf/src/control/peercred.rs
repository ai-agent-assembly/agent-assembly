//! Peer-credential check for accepted loaderd control connections (AAASM-3918).
//!
//! The privileged `aa-ebpf-loaderd` control socket is owner-only (`0600`), but a
//! peer-credential check is defence-in-depth: it makes the trust boundary
//! explicit and testable and rejects any connection whose process UID does not
//! match the UID the daemon itself runs as. Because `dispatch` performs no
//! caller authentication of its own, the socket permission was previously the
//! *entire* trust boundary; under a permissive daemon umask there is a window
//! where the `0600` mode is not yet applied (closed separately by the umask-
//! tightened bind), so this UID check closes the residual "another local process
//! connects to the highest-privilege control socket and issues Detach / replaces
//! deny rules" vector.
//!
//! This mirrors the runtime IPC hardening in
//! `aa-runtime/src/ipc/peercred.rs` (AAASM-3579); the helper there is private to
//! that crate, so the minimal policy is replicated here.
//!
//! Portability: the peer UID is read via tokio's `UnixStream::peer_cred`, which
//! is backed by `SO_PEERCRED` on Linux and `getpeereid`/`LOCAL_PEERCRED` on
//! macOS/BSD, so this module compiles and runs on every Unix target.

/// Decide whether a peer connection should be admitted, given the peer UID and
/// the daemon's own effective UID.
///
/// Returns `true` only when the peer UID equals the daemon UID. Kept as a pure
/// function so the policy is unit-testable without opening a real socket.
pub fn peer_uid_is_allowed(peer_uid: u32, daemon_uid: u32) -> bool {
    peer_uid == daemon_uid
}

/// The effective UID of the current (daemon) process.
#[cfg(unix)]
pub fn current_daemon_uid() -> u32 {
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
    fn nonroot_peer_against_root_daemon_is_rejected() {
        // The common attack: an unprivileged agent process trying to reach the
        // root-owned loaderd control socket.
        assert!(!peer_uid_is_allowed(1000, 0));
    }
}
