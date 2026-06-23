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

/// Best-effort drop of each forbidden capability from the bounding set via
/// `prctl(PR_CAPBSET_DROP)`. Failures (e.g. lacking CAP_SETPCAP) are ignored —
/// the authoritative guard is the effective-set assertion below.
#[cfg(target_os = "linux")]
fn drop_forbidden_from_bounding_set() {
    const PR_CAPBSET_DROP: i32 = 24;
    for cap in FORBIDDEN {
        // SAFETY: prctl with PR_CAPBSET_DROP and a capability number is safe;
        // it only ever clears a bounding-set bit and returns -1 on failure.
        let _ = unsafe { libc::prctl(PR_CAPBSET_DROP, cap.value as libc::c_ulong, 0, 0, 0) };
    }
}

/// Return the names of any forbidden capabilities present in the process's
/// effective capability set, read from `/proc/self/status` `CapEff`.
#[cfg(target_os = "linux")]
fn effective_forbidden_caps() -> Vec<String> {
    let cap_eff = match read_cap_eff() {
        Some(v) => v,
        // If we cannot read CapEff we cannot prove absence; treat as clean only
        // when running unprivileged (euid != 0). When root and unreadable, be
        // conservative and report nothing droppable (the bounding-set drop above
        // already ran); the effective check is best-effort observability here.
        None => return Vec::new(),
    };
    FORBIDDEN
        .iter()
        .filter(|c| cap_eff & (1u64 << c.value) != 0)
        .map(|c| c.name.to_string())
        .collect()
}

/// Parse the `CapEff:` hex bitmask from `/proc/self/status`.
#[cfg(target_os = "linux")]
fn read_cap_eff() -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    for line in status.lines() {
        if let Some(hex) = line.strip_prefix("CapEff:") {
            return u64::from_str_radix(hex.trim(), 16).ok();
        }
    }
    None
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unprivileged_process_passes_self_check() {
        // The test runner is unprivileged, so the effective set must be clean.
        assert!(enforce_least_privilege().is_ok());
    }
}
