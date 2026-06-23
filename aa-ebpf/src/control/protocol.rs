//! Wire protocol for the privilege-separated eBPF control channel (AAASM-3604).
//!
//! The (unprivileged) `aa-runtime` is the *client*; the (privileged)
//! `aa-ebpf-loaderd` daemon is the *server*. The client may ask the daemon to
//! load a probe set, update the path deny/allow map, or detach — but no raw fd
//! or `aya` handle ever crosses the boundary. Only these typed messages do.

use serde::{Deserialize, Serialize};

/// Default root-owned control socket path. The daemon creates it `0600`,
/// `root:root`, so an adversarial agent process running under the runtime
/// cannot reach the daemon to detach probes.
pub const DEFAULT_SOCKET_PATH: &str = "/run/aa-ebpf-loaderd.sock";

/// The probe sets the daemon can manage. Mirrors the three embedded objects.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProbeSet {
    /// File-I/O kprobes (`aa-file-io`).
    FileIo,
    /// Exec tracepoints (`aa-exec-probes`).
    Exec,
    /// TLS uprobes (`aa-tls-probes`).
    Tls,
}

/// A single path rule pushed into a BPF path map. Mirrors
/// `aa_security::policy::PathRule` on the wire so the loader daemon can apply
/// rules lowered from the canonical policy AST.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PathRuleWire {
    /// Path prefix to match.
    pub pattern: String,
    /// `true` = deny (blocklist), `false` = allow (allowlist).
    pub deny: bool,
}

/// A control request from `aa-runtime` to the loader daemon.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ControlRequest {
    /// Load + integrity-verify + attach the named probe set, then begin
    /// streaming its events back on the same connection.
    LoadProbeSet {
        /// Which probe set to bring up.
        set: ProbeSet,
        /// Target PID to scope the probe to (and its descendants).
        target_pid: u32,
    },
    /// Replace the path deny/allow map contents with `rules`.
    UpdatePathMap {
        /// The full desired rule set (the daemon clears + reapplies).
        rules: Vec<PathRuleWire>,
    },
    /// Detach + unload the named probe set.
    Detach {
        /// Which probe set to tear down.
        set: ProbeSet,
    },
    /// Liveness probe — the daemon replies [`ControlResponse::Pong`].
    Ping,
}

/// A control response from the loader daemon to `aa-runtime`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ControlResponse {
    /// The request succeeded.
    Ok,
    /// Liveness reply to [`ControlRequest::Ping`].
    Pong,
    /// The request failed; `message` describes why (no privileged detail).
    Error {
        /// Human-readable failure reason.
        message: String,
    },
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_round_trips_through_json() {
        let req = ControlRequest::UpdatePathMap {
            rules: vec![PathRuleWire {
                pattern: "/etc".to_string(),
                deny: true,
            }],
        };
        let bytes = serde_json::to_vec(&req).unwrap();
        let back: ControlRequest = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(req, back);
    }

    #[test]
    fn load_request_round_trips() {
        let req = ControlRequest::LoadProbeSet {
            set: ProbeSet::FileIo,
            target_pid: 4321,
        };
        let bytes = serde_json::to_vec(&req).unwrap();
        assert_eq!(serde_json::from_slice::<ControlRequest>(&bytes).unwrap(), req);
    }

}
