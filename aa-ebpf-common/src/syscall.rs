//! Shared constants for the seccomp-style syscall-allowlist enforcement probe
//! (AAASM-3631).
//!
//! The `SYSCALL_ALLOWLIST` BPF map is keyed by syscall number (`u32`); a
//! present key means "this syscall is permitted for monitored PIDs". The
//! enforcement probe attached at `raw_syscalls/sys_enter` default-denies any
//! syscall NOT in the map for a PID in `PID_FILTER`, killing the offending
//! process — the post-escape kernel-layer second line.
//!
//! Userspace populates the map from the policy AST lowering
//! (`aa_security::policy::lower_to_ebpf().syscall_allowlist`, AAASM-3635) via
//! the privileged loader daemon (AAASM-3603/3604); `aa-runtime` never loads
//! BPF itself.

/// Maximum number of syscall-allowlist entries in the `SYSCALL_ALLOWLIST` BPF
/// map. The Linux x86_64 syscall table is well under this; the cap bounds the
/// map's kernel memory.
pub const MAX_SYSCALL_ALLOWLIST: u32 = 512;

/// Map value marking a syscall number as permitted. Stored as `u8` to keep the
/// map entry minimal; only presence/absence of the key matters to the probe.
pub const SYSCALL_ALLOWED: u8 = 1;
