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
