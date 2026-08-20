//! Turning a permitted syscall set into the cBPF program that enforces it, and
//! installing it on this process.
//!
//! Split in two, the same way [`crate::rules`] splits filesystem enforcement:
//! [`program`] is pure, total and platform-free — it computes the instruction
//! vector and is unit-testable on any host, including this crate's macOS
//! development machine. [`install`] is the only function that calls the
//! kernel, gated to `Linux` + `x86_64` (Finding 3), and does nothing but load
//! what [`program`] already built.
//!
//! # Deviation from ADR 0035's literal "Seccomp model" text (AAASM-5803)
//!
//! ADR 0035 describes the syscall filter as enforcing exactly the policy
//! allowlist. That is not what this module installs. The launcher's own
//! `execve` of the confined program, and the dynamic loader that runs before
//! the program's first instruction, both happen *inside* the filter this
//! module installs on itself before `execve` — a seccomp filter is inherited
//! across `execve`, it does not reset at it. `aa_security::policy::syscall::Syscall`
//! is a 15-name vocabulary with no `execve` in it, so a filter built from
//! policy alone would kill the launcher's own `execve` on every launch.
//!
//! The filter this module installs is therefore `policy names ∪
//! `[`STARTUP_BASELINE`]`, not the policy names alone. This is a real,
//! deliberate widening beyond what the ADR's text describes, and it is
//! reported as a [`SupportLevel::Partial`](aa_isolation::SupportLevel::Partial)
//! limitation on the syscall capability report (`crate::capability::syscall`)
//! as well as here. See [`STARTUP_BASELINE`]'s own documentation for the
//! stronger, load-bearing invariant that keeps this widening from swallowing
//! the policy vocabulary whole.
//!
//! # This is not a process-creation control
//!
//! [`STARTUP_BASELINE`] carries `clone`, `clone3` and `wait4` so that a
//! grandchild can exist at all — `crate::capability`'s syscall report only
//! claims [`DescendantCoverage::ProcessTree`](aa_isolation::DescendantCoverage::ProcessTree)
//! when a grandchild was actually observed being denied, and a probe cannot
//! observe a grandchild that was never allowed to be created. This does not
//! make the syscall filter a process-creation control: `aa_isolation`'s
//! `ProcessCreation` domain stays an explicit
//! [`LoweringGap`](crate::lower::LoweringGap) in `crate::lower`, unchanged by
//! this module. The syscall control does not double as a process-creation
//! control — it merely does not accidentally forbid the process tree the
//! filesystem domains already claim to cover.

use std::collections::BTreeSet;

#[cfg(test)]
use aa_security::policy::syscall::Syscall;

use crate::launch::SyscallFilter;

// ---------------------------------------------------------------------------
// cBPF opcodes and kernel-ABI constants. Defined locally rather than pulled
// from `libc`: the instruction *shape* (`sock_filter`'s four fields) is
// platform-independent kernel ABI, or hand-rolled a repeat pass, and this
// module's pure half (`program`) must compile and be testable on every host
// this crate builds on, including macOS, where `libc`'s Linux-only seccomp
// items are not present at all. `install`, which is Linux+x86_64-gated, reads
// `libc::{SECCOMP_SET_MODE_FILTER, sock_filter, sock_fprog}` instead of
// redefining them, because at that point the platform is no longer in
// question.
// ---------------------------------------------------------------------------

// The individual cBPF instruction-class/size/mode/operator bits, named exactly
// as `linux/bpf_common.h` names them, so the combined opcodes below read as
// the kernel header's own vocabulary rather than as bare hex.
const BPF_LD: u16 = 0x00;
const BPF_JMP: u16 = 0x05;
const BPF_RET: u16 = 0x06;
const BPF_W: u16 = 0x00;
const BPF_ABS: u16 = 0x20;
const BPF_JEQ: u16 = 0x10;
const BPF_JGE: u16 = 0x30;
const BPF_K: u16 = 0x00;

/// `BPF_LD | BPF_W | BPF_ABS`: load a 32-bit word from a fixed offset into the
/// filter's implicit accumulator. Source: `linux/filter.h` / `linux/bpf_common.h`.
const OP_LD_W_ABS: u16 = BPF_LD | BPF_W | BPF_ABS;
/// `BPF_JMP | BPF_JEQ | BPF_K`: jump on equality with an immediate.
const OP_JEQ_K: u16 = BPF_JMP | BPF_JEQ | BPF_K;
/// `BPF_JMP | BPF_JGE | BPF_K`: jump when the accumulator is `>=` an immediate.
const OP_JGE_K: u16 = BPF_JMP | BPF_JGE | BPF_K;
/// `BPF_RET | BPF_K`: return an immediate verdict.
const OP_RET_K: u16 = BPF_RET | BPF_K;

/// The byte offset of `seccomp_data.nr` — always the first field, `int`.
/// Fixed by the kernel ABI (`include/uapi/linux/seccomp.h`), not by the build
/// host, so this is safe to hardcode rather than compute with `offsetof`.
const SECCOMP_DATA_NR_OFFSET: u32 = 0;
/// The byte offset of `seccomp_data.arch` — the second field, `__u32`,
/// immediately after `nr` with no padding (both are 4-byte aligned).
const SECCOMP_DATA_ARCH_OFFSET: u32 = 4;

/// `AUDIT_ARCH_X86_64`, from `linux/audit.h`. Not in `libc`, so it is defined
/// here rather than adding a dependency for one constant (Finding 3).
///
/// `EM_X86_64 (62) | __AUDIT_ARCH_64BIT (0x8000_0000) | __AUDIT_ARCH_LE (0x4000_0000)`.
pub const AUDIT_ARCH_X86_64: u32 = 0xC000_003E;

/// The x32 ABI marker bit (`__X32_SYSCALL_BIT`, `linux/unistd.h`). A syscall
/// number with this bit set is an x32 (32-bit userspace on the x86_64 kernel
/// entry point) call, which this backend's rules were not built against
/// (Finding 3.2) and which must be killed regardless of its low bits, because
/// the same low bits mean a different call under the x32 ABI.
pub const X32_SYSCALL_BIT: u32 = 0x4000_0000;

/// The kernel's own instruction-count ceiling for one filter
/// (`BPF_MAXINSNS`, `linux/bpf_common.h`). [`program`] checks against it
/// explicitly rather than relying on the kernel to reject an oversized
/// program at [`install`] time, so a caller sees a `program()` error instead
/// of an `install()` error for the same root cause.
const BPF_MAXINSNS: usize = 4096;

/// One cBPF instruction, laid out exactly like the kernel's `struct sock_filter`
/// (`linux/filter.h`): a 16-bit opcode, two 8-bit relative jump targets used only
/// by `BPF_JMP`, and a 32-bit generic field used by `BPF_LD`/`BPF_JMP`/`BPF_RET`
/// depending on the opcode.
///
/// A local type rather than `libc::sock_filter` so [`program`] compiles on every
/// host this crate builds on; [`install`] converts to `libc::sock_filter` at the
/// point the kernel is actually asked, where the layout equivalence stops being
/// merely documented and becomes something the compiler checks via `#[repr(C)]`.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Instruction {
    /// The cBPF opcode (`BPF_LD | BPF_W | BPF_ABS`, etc.).
    pub code: u16,
    /// Relative jump-forward distance taken when the comparison is true.
    /// Meaningless outside `BPF_JMP` instructions.
    pub jt: u8,
    /// Relative jump-forward distance taken when the comparison is false.
    /// Meaningless outside `BPF_JMP` instructions.
    pub jf: u8,
    /// The generic operand: a byte offset for `BPF_LD`, a comparison value for
    /// `BPF_JMP`, or a verdict for `BPF_RET`.
    pub k: u32,
}

/// Syscalls this launcher permits regardless of what policy named, so that its
/// own `execve` of the confined program — and the dynamic loader that runs
/// before the program's first instruction — are not killed by a filter the
/// launcher just installed on itself.
///
/// # The invariant that keeps the policy allowlist load-bearing
///
/// **`STARTUP_BASELINE` never carries a syscall number `aa_security::policy::syscall::Syscall`
/// can name.** [`tests::startup_baseline_never_shadows_a_name_policy_could_write`]
/// asserts the intersection is empty. Without this, a policy author who wrote
/// `syscalls.allow: [read]` intending to permit reading and nothing else would
/// find `write` silently permitted too, the moment `write` happened to be on
/// this list for an unrelated reason — the exact failure mode the vocabulary's
/// closed-set design (`aa-security/src/policy/syscall.rs`) exists to prevent.
///
/// # A stricter set than Finding 1's candidate list, and why
///
/// AAASM-5803's own investigation named a "known-necessary set" for a
/// dynamically-linked `/bin/echo`/`/bin/sh` launch, empirically reasoned from
/// `strace -f -e trace=all` on an x86_64 glibc host (this backend's development
/// machine is macOS, so this is the documented worst-case set from that
/// investigation, not a trace taken by this change — see the ticket for the
/// full list and the `strace` command that would confirm it on a Linux runner).
/// That candidate list is **not** disjoint from the policy vocabulary: it
/// includes `read`, `openat`, `close`, `fstat`, `lseek`, `mmap`, `munmap`,
/// `brk`, `getrandom`, `exit_group`, `rt_sigaction`, `rt_sigprocmask` and
/// `clock_gettime` — thirteen of the vocabulary's fifteen names.
///
/// This constant deliberately **excludes** every one of those thirteen, to hold
/// the invariant above. The thing that remains — `arch_prctl`, `mprotect`,
/// `set_tid_address`, `set_robust_list`, `rseq`, `prlimit64`, `newfstatat`,
/// `pread64`, `faccessat2`, `futex`, `execve`, `clone`, `clone3`, `wait4` — is
/// exactly the set the vocabulary has no name for at all, so a policy author
/// can never be surprised by it appearing to widen a name they wrote.
///
/// **The practical consequence, stated rather than discovered by a broken
/// launch**: because the thirteen loader-critical calls above are *not*
/// baselined, a policy whose `syscalls.allow` omits any of them will see the
/// confined program killed during dynamic linking, before its own code runs —
/// `execve` itself, `clone`/`clone3`/`wait4` and the handful of calls with no
/// vocabulary name are the only things this backend grants for free. A policy
/// author who wants the syscall filter to be survivable at all must include
/// the loader-critical names their program needs, same as any other syscall
/// their program needs. This is the ADR 0035 deviation named in this module's
/// documentation, restated as its sharpest edge.
pub const STARTUP_BASELINE: &[(&str, u32)] = &[
    // Thread-local storage / stack-protector setup the dynamic loader performs
    // before it can call anything else meaningfully.
    ("arch_prctl", 158),
    // The loader maps and then re-protects the segments of every ELF object it
    // loads (the confined program and every shared library it links against).
    ("mprotect", 10),
    // `clone`'s `CLONE_CHILD_CLEARTID`/`set_tid_address` bookkeeping the glibc
    // startup path performs even for a single-threaded process.
    ("set_tid_address", 218),
    ("set_robust_list", 273),
    // Restartable sequences: glibc probes for `rseq` support at startup on
    // modern distributions regardless of whether the program uses it.
    ("rseq", 334),
    // glibc's startup path reads the stack-size limit to size the initial
    // thread's guard page.
    ("prlimit64", 302),
    // The loader's own `stat`-family calls when resolving shared library
    // paths on a kernel new enough to prefer `newfstatat` over `fstat`.
    ("newfstatat", 262),
    // `pread64` is how the loader reads ELF program headers without disturbing
    // the file offset a subsequent `read` would use.
    ("pread64", 17),
    // The loader's search-path probing (`/etc/ld.so.cache` and each
    // `LD_LIBRARY_PATH` entry) uses the `*at2` access check on modern glibc.
    ("faccessat2", 439),
    // glibc's startup path touches the per-thread futex used by the loader's
    // own lock, even with one thread.
    ("futex", 202),
    // The launcher's own `execve` of the confined program. Without this the
    // filter this launcher just installed on itself would kill the very call
    // that becomes the confined program (Finding 2).
    ("execve", 59),
    // A grandchild needs `clone`/`clone3` to exist and `wait4` for its parent
    // to reap it, so that a policy's descendant-coverage claim
    // (`aa_isolation::DescendantCoverage::ProcessTree`) can be *measured* by
    // this backend's probe at all (Finding 2). This is deliberately not a
    // process-creation control — see this module's own documentation.
    ("clone", 56),
    ("clone3", 435),
    ("wait4", 61),
    // glibc's dynamic loader checks for a preload list before anything else it
    // does with a file descriptor — measured live on a real x86_64 Ubuntu
    // kernel (AAASM-5803's own CI lane): the very first thing a filter this
    // launcher installed killed was this call.
    ("access", 21),
    // A POSIX shell's own `>` redirection: open the target, then move it onto
    // the descriptor the redirected command expects.
    ("dup2", 33),
    ("dup3", 292),
    // A shell checks whether its stdio descriptors are a terminal
    // (`TCGETS`) before deciding whether to behave interactively.
    ("ioctl", 16),
    // Descriptor-flag bookkeeping (`FD_CLOEXEC` and similar) that both the
    // loader and a shell perform on descriptors they open.
    ("fcntl", 72),
    ("getpid", 39),
    ("gettid", 186),
    ("readlink", 89),
    ("lstat", 6),
    ("stat", 4),
    // A shell's own privilege checks (e.g. deciding whether `$0` starting with
    // `-` means a login shell may drop privileges) — measured live, the second
    // gap this ticket's own CI lane found past the loader.
    ("getuid", 102),
    ("geteuid", 107),
    ("getgid", 104),
    ("getegid", 108),
    // A shell's job-control and signal-disposition bookkeeping at startup —
    // measured live, the third round of gaps this ticket's own CI lane found.
    ("getppid", 110),
    ("getpgrp", 111),
    ("setpgid", 109),
    ("umask", 95),
    ("sigaltstack", 131),
    ("rt_sigreturn", 15),
    ("getsid", 124),
];

/// Build the cBPF program a [`SyscallFilter`] compiles to.
///
/// Pure and total: no filesystem or kernel call is made, so the same filter
/// produces the same program on every host and in every test — including this
/// crate's macOS development host.
///
/// The kill instruction always precedes the allow instruction (per the module
/// documentation's filter shape), so falling off the end of the program — which
/// cannot happen here, since every path terminates at one `RET` or the other,
/// but is the property that keeps a future edit fail-closed — lands on a kill.
///
/// # Errors
///
/// A sentence naming what failed. At this vocabulary's size (15 policy names
/// plus [`STARTUP_BASELINE`]'s 14, so at most 29 distinct instructions per
/// permitted number, plus 6 fixed ones) a `u8` jump-offset overflow or a
/// `BPF_MAXINSNS` overflow is structurally impossible — checked explicitly
/// rather than assumed, the same way `crate::rules::install`'s
/// `LandlockStatus` contradiction arm states an unreachable condition instead
/// of asserting it away.
pub fn program(filter: &SyscallFilter) -> Result<FilterProgram, String> {
    let mut policy_numbers: BTreeSet<u32> = BTreeSet::new();
    let mut policy_names: Vec<String> = Vec::new();
    if let SyscallFilter::Allow(syscalls) = filter {
        for syscall in syscalls {
            policy_numbers.insert(syscall.number());
            policy_names.push(syscall.name().to_string());
        }
    }
    policy_names.sort();

    let mut permitted: BTreeSet<u32> = policy_numbers;
    permitted.extend(STARTUP_BASELINE.iter().map(|(_, nr)| *nr));

    let permitted_count = permitted.len();
    let total_instructions = 6 + permitted_count;
    if total_instructions > BPF_MAXINSNS {
        return Err(format!(
            "the syscall filter would need {total_instructions} instructions, above the kernel's \
             BPF_MAXINSNS ceiling of {BPF_MAXINSNS}; refusing rather than installing a truncated program"
        ));
    }

    // Layout: [0] LD arch, [1] JEQ arch, [2] LD nr, [3] JGE x32, [4..4+N) JEQ
    // per permitted number (ascending), [4+N] RET KILL, [5+N] RET ALLOW.
    let kill_index = 4 + permitted_count;
    let allow_index = kill_index + 1;

    let mut instructions = Vec::with_capacity(total_instructions);
    instructions.push(Instruction {
        code: OP_LD_W_ABS,
        jt: 0,
        jf: 0,
        k: SECCOMP_DATA_ARCH_OFFSET,
    });
    instructions.push(Instruction {
        code: OP_JEQ_K,
        jt: 0,
        jf: offset(kill_index, 1)?,
        k: AUDIT_ARCH_X86_64,
    });
    instructions.push(Instruction {
        code: OP_LD_W_ABS,
        jt: 0,
        jf: 0,
        k: SECCOMP_DATA_NR_OFFSET,
    });
    instructions.push(Instruction {
        code: OP_JGE_K,
        jt: offset(kill_index, 3)?,
        jf: 0,
        k: X32_SYSCALL_BIT,
    });
    for (position, nr) in permitted.iter().enumerate() {
        let index = 4 + position;
        instructions.push(Instruction {
            code: OP_JEQ_K,
            jt: offset(allow_index, index)?,
            jf: 0,
            k: *nr,
        });
    }
    instructions.push(Instruction {
        code: OP_RET_K,
        jt: 0,
        jf: 0,
        k: SECCOMP_RET_KILL_PROCESS,
    });
    instructions.push(Instruction {
        code: OP_RET_K,
        jt: 0,
        jf: 0,
        k: SECCOMP_RET_ALLOW,
    });

    Ok(FilterProgram {
        instructions,
        permitted,
        policy_names,
    })
}

/// `SECCOMP_RET_KILL_PROCESS`, from `linux/seccomp.h`. Kills the whole process,
/// not merely the thread — `SECCOMP_RET_KILL_THREAD`'s target, a multi-threaded
/// program with one thread killed and the others left running the loader's own
/// state, is a worse failure mode than the process ending.
const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
/// `SECCOMP_RET_ALLOW`, from `linux/seccomp.h`.
const SECCOMP_RET_ALLOW: u32 = 0x7FFF_0000;

/// The relative forward jump distance from just after `from_index` to
/// `to_index`, refusing rather than truncating a distance that does not fit a
/// cBPF jump's `u8`.
fn offset(to_index: usize, from_index: usize) -> Result<u8, String> {
    let distance = to_index
        .checked_sub(from_index + 1)
        .ok_or_else(|| format!("jump target {to_index} is not after instruction {from_index}"))?;
    u8::try_from(distance).map_err(|_| {
        format!(
            "a jump offset of {distance} instructions does not fit this filter format's u8 jump field; \
             refusing rather than installing a program whose control flow does not mean what it says"
        )
    })
}

/// The complete, checked cBPF program one [`SyscallFilter`] compiles to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilterProgram {
    instructions: Vec<Instruction>,
    permitted: BTreeSet<u32>,
    /// The syscall names policy itself named, sorted — excludes
    /// [`STARTUP_BASELINE`], which carries no name a policy author could have
    /// written.
    policy_names: Vec<String>,
}

impl FilterProgram {
    /// The instructions, in the exact order [`install`] loads them.
    pub fn instructions(&self) -> &[Instruction] {
        &self.instructions
    }

    /// Every syscall number this program permits — policy-named and baseline
    /// alike. The union [`crate::seccomp`]'s module documentation describes.
    pub fn permitted_numbers(&self) -> &BTreeSet<u32> {
        &self.permitted
    }

    /// One sentence per named group, for [`aa_isolation::Lowering`] and for
    /// evidence — mirrors [`crate::rules::RulePlan::describe`].
    pub fn describe(&self) -> Vec<String> {
        vec![
            format!(
                "{} syscall(s) permitted by policy: {}",
                self.policy_names.len(),
                if self.policy_names.is_empty() {
                    "none".to_string()
                } else {
                    self.policy_names.join(", ")
                }
            ),
            format!(
                "{} startup-baseline syscall(s) permitted unconditionally, none of which policy could \
                 have named: {}",
                STARTUP_BASELINE.len(),
                STARTUP_BASELINE
                    .iter()
                    .map(|(name, _)| *name)
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        ]
    }
}

/// What installing a filter produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Installed {
    /// How many distinct syscall numbers the installed filter permits.
    pub permitted: usize,
    /// The action taken on anything not permitted, in words rather than a
    /// mechanism-specific constant.
    pub default_action: &'static str,
}

/// Install a filter on the calling thread group, or fail without installing a
/// partial one.
///
/// Sets `PR_SET_NO_NEW_PRIVS` explicitly before loading the filter — this
/// crate's convention is to re-check a precondition at the point of the syscall
/// that depends on it rather than assume a sibling module already established
/// it, the same way `crate::rules::install`'s own doc comment explains why it
/// checks `no_new_privs` itself rather than trusting the caller.
///
/// # Errors
///
/// A sentence naming what failed, suitable for [`crate::launch::FAILURE_MARKER`]
/// output. Nothing is executed after an error.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub fn install(program: &FilterProgram) -> Result<Installed, String> {
    let rc = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if rc != 0 {
        return Err(format!(
            "PR_SET_NO_NEW_PRIVS could not be set: {}",
            std::io::Error::last_os_error()
        ));
    }

    let filter: Vec<libc::sock_filter> = program
        .instructions()
        .iter()
        .map(|instruction| libc::sock_filter {
            code: instruction.code,
            jt: instruction.jt,
            jf: instruction.jf,
            k: instruction.k,
        })
        .collect();
    let fprog = libc::sock_fprog {
        len: u16::try_from(filter.len()).map_err(|_| {
            format!(
                "the syscall filter has {} instructions, which does not fit the kernel's u16 program \
                 length field",
                filter.len()
            )
        })?,
        filter: filter.as_ptr() as *mut libc::sock_filter,
    };

    // Safety: `SYS_seccomp` with `SECCOMP_SET_MODE_FILTER` and flags `0` reads
    // `fprog` (a valid `sock_fprog` pointing at `filter`, both alive for the
    // duration of this call) and either installs the program on this thread
    // group or returns a negative error; nothing is written through the
    // pointer and nothing outlives this call. Raw-syscall style rather than a
    // higher-level binding, mirroring `crate::host::measure_abi`'s own
    // `libc::syscall` probe.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            libc::SECCOMP_SET_MODE_FILTER,
            0u32,
            &fprog as *const libc::sock_fprog,
        )
    };
    if rc != 0 {
        return Err(format!(
            "the syscall filter could not be installed: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(Installed {
        permitted: program.permitted_numbers().len(),
        default_action: "kill the process (SECCOMP_RET_KILL_PROCESS)",
    })
}

/// The non-Linux/non-x86_64 arm. Never reached through this backend's own
/// launcher, which is Linux+x86_64-gated one level up
/// (`src/bin/aa-isolation-launch.rs`); present so this crate compiles
/// everywhere and so a caller that reaches this directly gets a refusal naming
/// the measured platform rather than a missing symbol.
#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
pub fn install(_program: &FilterProgram) -> Result<Installed, String> {
    Err(format!(
        "this backend's syscall filter is built for Linux on x86_64; this host is {} on {}",
        std::env::consts::OS,
        std::env::consts::ARCH
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **The load-bearing invariant this module exists to hold.** If this ever
    /// fails, a policy author's `syscalls.allow` selection stops meaning what it
    /// says the moment the overlapping name is baselined for an unrelated
    /// reason.
    #[test]
    fn startup_baseline_never_shadows_a_name_policy_could_write() {
        let vocabulary: BTreeSet<u32> = [
            Syscall::Read,
            Syscall::Write,
            Syscall::Close,
            Syscall::Openat,
            Syscall::Fstat,
            Syscall::Lseek,
            Syscall::Mmap,
            Syscall::Munmap,
            Syscall::Brk,
            Syscall::RtSigaction,
            Syscall::RtSigprocmask,
            Syscall::Exit,
            Syscall::ExitGroup,
            Syscall::ClockGettime,
            Syscall::Getrandom,
        ]
        .iter()
        .map(|s| s.number())
        .collect();
        assert_eq!(vocabulary.len(), 15, "the vocabulary sweep above must name all 15");

        for (name, nr) in STARTUP_BASELINE {
            assert!(
                !vocabulary.contains(nr),
                "STARTUP_BASELINE's `{name}` ({nr}) is a number the policy vocabulary can also name; \
                 the disjointness invariant is broken"
            );
        }
        // The control: `write` — the syscall this invariant's own documentation
        // calls out — really is in the vocabulary and really is absent from the
        // baseline, not merely disjoint by accident of which numbers happened
        // to be picked.
        assert!(vocabulary.contains(&Syscall::Write.number()));
        assert!(!STARTUP_BASELINE.iter().any(|(_, nr)| *nr == Syscall::Write.number()));
    }

    /// The instruction vector for a known, small allowlist, checked
    /// instruction-by-instruction rather than by shape alone.
    #[test]
    fn a_known_allowlist_produces_the_documented_instruction_shape() {
        let filter = SyscallFilter::Allow([Syscall::Read].into_iter().collect());
        let built = program(&filter).expect("a one-syscall filter always fits");
        let instructions = built.instructions();

        // [0] LD arch
        assert_eq!(instructions[0].code, OP_LD_W_ABS);
        assert_eq!(instructions[0].k, SECCOMP_DATA_ARCH_OFFSET);
        // [1] JEQ arch
        assert_eq!(instructions[1].code, OP_JEQ_K);
        assert_eq!(instructions[1].k, AUDIT_ARCH_X86_64);
        assert_eq!(instructions[1].jt, 0, "a matching arch must fall through, not jump");
        // [2] LD nr
        assert_eq!(instructions[2].code, OP_LD_W_ABS);
        assert_eq!(instructions[2].k, SECCOMP_DATA_NR_OFFSET);
        // [3] JGE x32
        assert_eq!(instructions[3].code, OP_JGE_K);
        assert_eq!(instructions[3].k, X32_SYSCALL_BIT);
        assert_eq!(instructions[3].jf, 0, "a non-x32 number must fall through, not jump");

        let permitted_count = built.permitted_numbers().len();
        assert_eq!(instructions.len(), 6 + permitted_count);

        let kill = &instructions[4 + permitted_count];
        assert_eq!(kill.code, OP_RET_K);
        assert_eq!(kill.k, SECCOMP_RET_KILL_PROCESS);
        let allow = &instructions[5 + permitted_count];
        assert_eq!(allow.code, OP_RET_K);
        assert_eq!(allow.k, SECCOMP_RET_ALLOW);

        // Every permitted-number JEQ jumps to ALLOW on match and falls through
        // (toward KILL) otherwise.
        for instruction in &instructions[4..4 + permitted_count] {
            assert_eq!(instruction.code, OP_JEQ_K);
            assert_eq!(instruction.jf, 0);
        }
    }

    /// **Both mismatch conditions land on the kill instruction**, and neither
    /// is expressible as "falls through to allow" — the property that makes
    /// this filter fail closed rather than fail open on an unrecognised arch or
    /// an x32 call.
    #[test]
    fn a_mismatched_arch_and_an_x32_number_both_jump_toward_kill() {
        let filter = SyscallFilter::Allow([Syscall::Read].into_iter().collect());
        let built = program(&filter).expect("fits");
        let instructions = built.instructions();
        let kill_index = 4 + built.permitted_numbers().len();

        // The arch check jumps FORWARD on failure (`jf`), landing exactly on
        // the kill instruction.
        let arch_check = &instructions[1];
        let arch_kill_target = 1 + 1 + arch_check.jf as usize;
        assert_eq!(
            arch_kill_target, kill_index,
            "a mismatched arch does not land on RET KILL_PROCESS"
        );

        // The x32 check jumps forward on MATCH (`jt`) — matching means the bit
        // is set, which is the failure condition here.
        let x32_check = &instructions[3];
        let x32_kill_target = 3 + 1 + x32_check.jt as usize;
        assert_eq!(
            x32_kill_target, kill_index,
            "an x32-flagged number does not land on RET KILL_PROCESS"
        );
    }

    /// Every jump offset this vocabulary's size produces stays within `u8`,
    /// asserted rather than merely relied upon.
    #[test]
    fn jump_offsets_stay_within_u8_at_this_vocabularys_size() {
        let all: BTreeSet<Syscall> = [
            Syscall::Read,
            Syscall::Write,
            Syscall::Close,
            Syscall::Openat,
            Syscall::Fstat,
            Syscall::Lseek,
            Syscall::Mmap,
            Syscall::Munmap,
            Syscall::Brk,
            Syscall::RtSigaction,
            Syscall::RtSigprocmask,
            Syscall::Exit,
            Syscall::ExitGroup,
            Syscall::ClockGettime,
            Syscall::Getrandom,
        ]
        .into_iter()
        .collect();
        let built = program(&SyscallFilter::Allow(all)).expect("the full vocabulary plus the baseline still fits");
        assert!(built.instructions().len() < BPF_MAXINSNS);
        for instruction in built.instructions() {
            // `jt`/`jf` are already `u8` by type; this asserts the vector built
            // successfully rather than erroring, i.e. no offset overflowed.
            let _ = (instruction.jt, instruction.jf);
        }
    }

    /// The kill instruction always precedes the allow instruction — falling
    /// off the end of the permitted-number checks reaches KILL first.
    #[test]
    fn kill_precedes_allow() {
        let built =
            program(&SyscallFilter::NotRequested).expect("even an empty policy allowlist plus the baseline fits");
        let permitted_count = built.permitted_numbers().len();
        let instructions = built.instructions();
        assert_eq!(instructions[4 + permitted_count].k, SECCOMP_RET_KILL_PROCESS);
        assert_eq!(instructions[5 + permitted_count].k, SECCOMP_RET_ALLOW);
    }

    /// A filter with no policy names still permits exactly the baseline — the
    /// launcher can still `execve`, but nothing else.
    #[test]
    fn not_requested_permits_only_the_baseline() {
        let built = program(&SyscallFilter::NotRequested).expect("fits");
        assert_eq!(built.permitted_numbers().len(), STARTUP_BASELINE.len());
        for (_, nr) in STARTUP_BASELINE {
            assert!(built.permitted_numbers().contains(nr));
        }
    }

    /// `describe()` must name every policy syscall and must not claim the
    /// baseline is policy-visible.
    #[test]
    fn describe_names_policy_syscalls_and_states_the_baseline_separately() {
        let built = program(&SyscallFilter::Allow(
            [Syscall::Read, Syscall::Write].into_iter().collect(),
        ))
        .expect("fits");
        let lines = built.describe();
        assert!(lines[0].contains("read") && lines[0].contains("write"));
        assert!(lines[1].contains("startup-baseline"));
        let baseline_tokens: Vec<&str> = lines[1].split([',', ' ']).collect();
        assert!(
            !baseline_tokens.contains(&"read") && !baseline_tokens.contains(&"write"),
            "the baseline line must not repeat a name policy already named: {}",
            lines[1]
        );
    }
}
