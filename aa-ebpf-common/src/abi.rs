//! Syscall ABI classification for the seccomp-style enforcement probe
//! (AAASM-3631; hardened in AAASM-3872).
//!
//! The `SYSCALL_ALLOWLIST` BPF map is keyed by **x86_64 native** syscall
//! numbers. The `raw_syscalls:sys_enter` tracepoint, however, fires for
//! *every* ABI a task can use on an x86_64 kernel:
//!
//! - **native x86_64** — plain syscall numbers (`read = 0`, `write = 1`, …).
//! - **x32** — the 64-bit handlers invoked with 32-bit pointers; x32 syscall
//!   numbers carry the [`X32_SYSCALL_BIT`] (`__X32_SYSCALL_BIT`, bit 30).
//! - **i386 compat** (`int 0x80` / `ia32`) — an entirely *separate* number
//!   space (`exit = 1`, `fork = 2`, `execve = 11`, …) that overlaps the
//!   x86_64 numbers but means different things.
//!
//! Without an ABI check the allowlist suffers compat-ABI confusion: a compat
//! syscall whose number happens to collide with an allow-listed x86_64 number
//! is wrongly permitted (e.g. i386 `execve = 11` aliases x86_64
//! `munmap = 11`). [`native_syscall_nr`] rejects the *detectable* compat ABI
//! (x32) so only native x86_64 numbers are ever matched against the allowlist;
//! the enforcement probe default-denies everything else.
//!
//! ## Known limitation — i386 `int 0x80`
//!
//! i386 compat syscalls carry **no distinguishing bit** in the tracepoint
//! `id`; disambiguating them from native x86_64 requires reading the task's
//! `TS_COMPAT` thread-info flag (a CO-RE task-struct walk), which is out of
//! scope for this change. See AAASM-3872 for the follow-up. Hosts that do not
//! need 32-bit compat should disable it at the kernel/seccomp layer in the
//! meantime.

/// The x32 ABI ORs this bit (`__X32_SYSCALL_BIT`, bit 30) into every syscall
/// number so the kernel can route 64-bit-register / 32-bit-pointer calls.
pub const X32_SYSCALL_BIT: u64 = 0x4000_0000;

/// ABI a `raw_syscalls:sys_enter` `id` was issued under, to the extent it is
/// distinguishable from the tracepoint `id` alone.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SyscallAbi {
    /// Native x86_64 — the only ABI the `SYSCALL_ALLOWLIST` map describes.
    NativeX86_64,
    /// x32 compat — detected via [`X32_SYSCALL_BIT`]; must not be matched
    /// against the x86_64-keyed allowlist.
    X32,
}

/// Classify a raw `sys_enter` `id`.
///
/// Ids carrying [`X32_SYSCALL_BIT`] are reported as [`SyscallAbi::X32`];
/// everything else (including negative sentinels) is reported as
/// [`SyscallAbi::NativeX86_64`]. This **cannot** detect i386 `int 0x80`
/// compat — see the module docs.
#[inline]
#[must_use]
pub fn classify_syscall_abi(raw_id: i64) -> SyscallAbi {
    if raw_id >= 0 && (raw_id as u64) & X32_SYSCALL_BIT != 0 {
        SyscallAbi::X32
    } else {
        SyscallAbi::NativeX86_64
    }
}

/// Resolve the native x86_64 syscall number to match against
/// `SYSCALL_ALLOWLIST`, or `None` when `raw_id` is not a native x86_64 call.
///
/// Returns `None` for a negative sentinel (the kernel reports `-1` for an
/// unmapped/seccomp-trap entry) and for any id carrying [`X32_SYSCALL_BIT`]
/// (x32 compat). The enforcement probe treats `None` as "not allow-listed"
/// and default-denies, so a compat-ABI number can never alias an allow-listed
/// native one.
#[inline]
#[must_use]
pub fn native_syscall_nr(raw_id: i64) -> Option<u32> {
    if raw_id < 0 {
        return None;
    }
    if (raw_id as u64) & X32_SYSCALL_BIT != 0 {
        // x32 compat — not a native x86_64 number.
        return None;
    }
    u32::try_from(raw_id as u64).ok()
}
