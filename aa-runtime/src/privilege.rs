//! Least-privilege enforcement for `aa-runtime` (AAASM-3605).
//!
//! # Privilege model
//!
//! Probe loading no longer happens in-process. The privileged
//! `aa-ebpf-loaderd` daemon (AAASM-3603) is the sole holder of `CAP_BPF` /
//! `CAP_PERFMON`; `aa-runtime` drives it over the root-owned control socket
//! (AAASM-3604). The runtime is therefore the component exposed to potentially
//! adversarial agents over `/tmp/aa-runtime-*.sock`, and it must hold **no**
//! BPF privilege — otherwise a compromised runtime/agent could detach or
//! replace the probes and blind the monitor (AAASM-3561 AC #2).
//!
//! At startup the runtime:
//! 1. drops `CAP_BPF` / `CAP_PERFMON` / `CAP_SYS_ADMIN` from its bounding set
//!    (best-effort — they should never have been granted in the first place), and
//! 2. asserts it does not hold them in its effective set, failing fast if it does.
//!
//! On non-Linux these are no-ops (there is no eBPF and no Linux capabilities).

/// A capability the runtime must NOT hold, with its `CAP_*` constant value.
///
/// Values are the stable Linux capability numbers (see `<linux/capability.h>`).
#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy)]
struct ForbiddenCap {
    name: &'static str,
    value: i32,
}

#[cfg(target_os = "linux")]
const FORBIDDEN: &[ForbiddenCap] = &[
    ForbiddenCap {
        name: "CAP_SYS_ADMIN",
        value: 21,
    },
    ForbiddenCap {
        name: "CAP_BPF",
        value: 39,
    },
    ForbiddenCap {
        name: "CAP_PERFMON",
        value: 38,
    },
];

/// Error returned when the runtime unexpectedly holds a BPF-class capability.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivilegeError {
    /// Names of the forbidden capabilities found in the effective set.
    pub held: Vec<String>,
}

impl std::fmt::Display for PrivilegeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "aa-runtime must not hold BPF-class capabilities (delegated to aa-ebpf-loaderd), \
             but the effective set contains: {}",
            self.held.join(", ")
        )
    }
}

impl std::error::Error for PrivilegeError {}

/// Drop the forbidden capabilities from the bounding set, then assert none
/// remain in the effective set. Fail-fast if the invariant is violated.
///
/// Returns `Ok(())` on success. On Linux, returns [`PrivilegeError`] if a
/// forbidden capability is still effective after the drop. On non-Linux this is
/// an unconditional `Ok(())`.
pub fn enforce_least_privilege() -> Result<(), PrivilegeError> {
    #[cfg(target_os = "linux")]
    {
        drop_forbidden_from_bounding_set();
        let held = effective_forbidden_caps();
        if !held.is_empty() {
            return Err(PrivilegeError { held });
        }
        tracing::info!("least-privilege self-check passed: no CAP_BPF/CAP_PERFMON/CAP_SYS_ADMIN held");
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        Ok(())
    }
}

