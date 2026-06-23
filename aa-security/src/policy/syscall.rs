//! Syscall-allowlist node for the canonical policy AST (AAASM-3624).
//!
//! A [`SyscallAllowlist`] is a per-workload set of permitted syscalls. It lives
//! on the same [`PolicyDocument`](super::document::PolicyDocument) as the
//! path/egress rules so the kernel-layer syscall allowlist is expressed in the
//! ONE policy source — there is no second policy path. The AAASM-3635 lowering
//! compiles this node into the `SYSCALL_ALLOWLIST` eBPF map entries the
//! AAASM-3631 enforcement probe consumes.
//!
//! Naming mirrors the lowercase syscall names used elsewhere
//! (`aa-ebpf::syscall::SyscallKind`) so a policy reads `read` / `write` /
//! `close`, not raw numbers. Each known name carries its x86_64 syscall number
//! for the lowering step. Unknown names are rejected at parse/validation time
//! so a typo cannot silently widen the allowlist.

use std::collections::BTreeSet;
use std::fmt;
use std::str::FromStr;

/// A syscall permitted by a [`SyscallAllowlist`].
///
/// The variant set is deliberately the small, audited vocabulary a sandboxed
/// workload legitimately needs; it carries the x86_64 syscall number so the
/// eBPF lowering (AAASM-3635) can emit `SYSCALL_ALLOWLIST` map keys without a
/// second name table. Adding a syscall is an explicit, reviewable change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Syscall {
    /// `read` — read from a file descriptor.
    Read,
    /// `write` — write to a file descriptor.
    Write,
    /// `close` — close a file descriptor.
    Close,
    /// `openat` — open a file relative to a directory fd.
    Openat,
    /// `fstat` — get file status.
    Fstat,
    /// `lseek` — reposition a file offset.
    Lseek,
    /// `mmap` — map memory.
    Mmap,
    /// `munmap` — unmap memory.
    Munmap,
    /// `brk` — change the data segment size.
    Brk,
    /// `rt_sigaction` — examine/change a signal action.
    RtSigaction,
    /// `rt_sigprocmask` — examine/change blocked signals.
    RtSigprocmask,
    /// `exit` — terminate the calling thread.
    Exit,
    /// `exit_group` — terminate all threads in the process.
    ExitGroup,
    /// `clock_gettime` — read a clock.
    ClockGettime,
    /// `getrandom` — obtain random bytes.
    Getrandom,
}

impl Syscall {
    /// The x86_64 syscall number for this syscall.
    ///
    /// These are the stable Linux x86_64 (`__NR_*`) numbers, used by the
    /// AAASM-3635 lowering to populate the `SYSCALL_ALLOWLIST` eBPF map.
    pub fn number(self) -> u32 {
        match self {
            Syscall::Read => 0,
            Syscall::Write => 1,
            Syscall::Close => 3,
            Syscall::Fstat => 5,
            Syscall::Lseek => 8,
            Syscall::Mmap => 9,
            Syscall::Munmap => 11,
            Syscall::Brk => 12,
            Syscall::RtSigaction => 13,
            Syscall::RtSigprocmask => 14,
            Syscall::Openat => 257,
            Syscall::ClockGettime => 228,
            Syscall::ExitGroup => 231,
            Syscall::Exit => 60,
            Syscall::Getrandom => 318,
        }
    }

    /// The lowercase policy name for this syscall.
    pub fn name(self) -> &'static str {
        match self {
            Syscall::Read => "read",
            Syscall::Write => "write",
            Syscall::Close => "close",
            Syscall::Openat => "openat",
            Syscall::Fstat => "fstat",
            Syscall::Lseek => "lseek",
            Syscall::Mmap => "mmap",
            Syscall::Munmap => "munmap",
            Syscall::Brk => "brk",
            Syscall::RtSigaction => "rt_sigaction",
            Syscall::RtSigprocmask => "rt_sigprocmask",
            Syscall::Exit => "exit",
            Syscall::ExitGroup => "exit_group",
            Syscall::ClockGettime => "clock_gettime",
            Syscall::Getrandom => "getrandom",
        }
    }
}

impl fmt::Display for Syscall {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

impl FromStr for Syscall {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "read" => Ok(Syscall::Read),
            "write" => Ok(Syscall::Write),
            "close" => Ok(Syscall::Close),
            "openat" => Ok(Syscall::Openat),
            "fstat" => Ok(Syscall::Fstat),
            "lseek" => Ok(Syscall::Lseek),
            "mmap" => Ok(Syscall::Mmap),
            "munmap" => Ok(Syscall::Munmap),
            "brk" => Ok(Syscall::Brk),
            "rt_sigaction" => Ok(Syscall::RtSigaction),
            "rt_sigprocmask" => Ok(Syscall::RtSigprocmask),
            "exit" => Ok(Syscall::Exit),
            "exit_group" => Ok(Syscall::ExitGroup),
            "clock_gettime" => Ok(Syscall::ClockGettime),
            "getrandom" => Ok(Syscall::Getrandom),
            _ => Err(format!("unknown syscall: '{s}'")),
        }
    }
}

/// A per-workload kernel syscall allowlist node on the canonical policy AST.
///
/// Membership is the set of permitted syscalls; the enforcement probe
/// default-denies any syscall *not* in this set for a monitored PID. The set
/// is a [`BTreeSet`] so it is inherently de-duplicated and order-stable, which
/// keeps the AAASM-3635 lowering deterministic.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SyscallAllowlist {
    /// The permitted syscalls.
    pub syscalls: BTreeSet<Syscall>,
}

impl SyscallAllowlist {
    /// Build an allowlist from syscall name strings, validating each name and
    /// de-duplicating. Returns the first unknown name as an error so a typo
    /// can never silently widen (or no-op) the allowlist.
    pub fn from_names<I, S>(names: I) -> Result<Self, String>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut syscalls = BTreeSet::new();
        for name in names {
            syscalls.insert(Syscall::from_str(name.as_ref())?);
        }
        Ok(Self { syscalls })
    }

    /// Whether the allowlist permits the given syscall.
    pub fn permits(&self, syscall: Syscall) -> bool {
        self.syscalls.contains(&syscall)
    }

    /// The permitted syscalls, ordered, as an iterator.
    pub fn iter(&self) -> impl Iterator<Item = Syscall> + '_ {
        self.syscalls.iter().copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_names_parse_and_round_trip() {
        for name in [
            "read",
            "write",
            "close",
            "openat",
            "fstat",
            "lseek",
            "mmap",
            "munmap",
            "brk",
            "rt_sigaction",
            "rt_sigprocmask",
            "exit",
            "exit_group",
            "clock_gettime",
            "getrandom",
        ] {
            let sc = Syscall::from_str(name).unwrap();
            assert_eq!(sc.name(), name);
            assert_eq!(sc.to_string(), name);
        }
    }

    #[test]
    fn unknown_name_is_rejected() {
        assert!(Syscall::from_str("ptrace").is_err());
        assert!(SyscallAllowlist::from_names(["read", "execve"]).is_err());
    }

    #[test]
    fn from_names_dedups_and_validates() {
        let allow = SyscallAllowlist::from_names(["read", "write", "read", "close"]).unwrap();
        assert_eq!(allow.syscalls.len(), 3);
        assert!(allow.permits(Syscall::Read));
        assert!(allow.permits(Syscall::Write));
        assert!(allow.permits(Syscall::Close));
        assert!(!allow.permits(Syscall::Openat));
    }

    #[test]
    fn iter_is_order_stable() {
        let allow = SyscallAllowlist::from_names(["write", "read", "close"]).unwrap();
        // BTreeSet orders by enum declaration order (derive Ord): Read, Write, Close.
        let order: Vec<Syscall> = allow.iter().collect();
        assert_eq!(order, vec![Syscall::Read, Syscall::Write, Syscall::Close]);
    }

    #[test]
    fn known_syscall_numbers_are_x86_64() {
        assert_eq!(Syscall::Read.number(), 0);
        assert_eq!(Syscall::Write.number(), 1);
        assert_eq!(Syscall::Close.number(), 3);
        assert_eq!(Syscall::Exit.number(), 60);
        assert_eq!(Syscall::Openat.number(), 257);
        assert_eq!(Syscall::ExitGroup.number(), 231);
    }
}
