//! Privilege-separated control channel between `aa-runtime` (unprivileged
//! client) and `aa-ebpf-loaderd` (privileged server) — AAASM-3604.
//!
//! # Privilege boundary
//!
//! The daemon owns every `aya::Ebpf` handle and holds the only `CAP_BPF` /
//! `CAP_PERFMON` in the system. `aa-runtime` connects as a client over a
//! root-owned `0600` Unix socket and may *request* probe lifecycle operations
//! (load / update-map / detach) — but it cannot itself touch BPF, and no raw
//! fd or `aya` handle ever crosses the boundary. Because the socket is
//! `root:root 0600`, an adversarial agent process under the runtime cannot
//! reach the daemon to detach the probes (AAASM-3561 AC #2).
//!
//! The wire protocol lives in [`protocol`]; framing in [`codec`]; the privileged
//! server in `server` (Linux only); the client connector in [`client`].

pub mod codec;
pub mod protocol;

pub use protocol::{ControlRequest, ControlResponse, PathRuleWire, ProbeSet, DEFAULT_SOCKET_PATH};

#[cfg(unix)]
pub mod client;

// AAASM-3918: peer-credential policy for the privileged control socket. Lives
// in its own `#[cfg(unix)]` module so the pure UID check is unit-testable on
// non-Linux dev hosts even though `server` (which enforces it) is Linux only.
#[cfg(unix)]
pub mod peercred;

#[cfg(target_os = "linux")]
pub mod server;
