//! Helper functions for BPF kprobe programs.

use aa_ebpf_common::file::FileIoEventRaw;
use aya_ebpf::{helpers::bpf_ktime_get_ns, programs::ProbeContext, EbpfContext, PtRegs};

use crate::maps::EVENTS;

/// Set the timestamp on a caller-constructed [`FileIoEventRaw`] and
/// submit it to the perf event array.
///
/// Generic over the BPF context type so it works from both kprobes
/// (`ProbeContext`) and kretprobes (`RetProbeContext`).
///
/// Accepts only two arguments (ctx + event) so it stays within the
/// BPF calling convention limit of 5 register arguments.
///
/// `#[inline(never)]` keeps this in its own stack frame. The caller
/// owns the `FileIoEventRaw` (~290 bytes), and this function adds
/// almost nothing — so neither frame exceeds the 512-byte BPF limit.
#[inline(never)]
pub fn emit_event<C: EbpfContext>(ctx: &C, event: &mut FileIoEventRaw) {
    event.timestamp_ns = unsafe { bpf_ktime_get_ns() };
    EVENTS.output(ctx, event, 0);
}

/// Extract (pid, tgid) from the current BPF context.
///
/// Returns `(tgid, pid)` where `tgid` is the userspace PID and `pid` is
/// the kernel thread ID.
#[inline(always)]
pub fn get_pid_tgid() -> (u32, u32) {
    let pid_tgid = aya_ebpf::helpers::bpf_get_current_pid_tgid();
    let tgid = (pid_tgid >> 32) as u32;
    let pid = pid_tgid as u32;
    (tgid, pid)
}

/// Check if the given tgid is in the PID filter map.
/// Returns `true` if monitoring is enabled for this process.
#[inline(always)]
pub fn should_monitor(tgid: u32) -> bool {
    unsafe { crate::maps::PID_FILTER.get(&tgid).is_some() }
}

/// Wrap the inner `pt_regs *` of a `__x64_sys_*` kprobe context.
///
/// On any Linux kernel with `CONFIG_SYSCALL_WRAPPER=y` (default since
/// 4.17, every modern x86_64 distro including `ubuntu-latest`), the
/// syscall entry has signature `__x64_sys_<name>(const struct pt_regs
/// *regs)` — the real userspace syscall args live inside `*regs`.
/// Calling `ctx.arg(n)` for `n > 0` therefore returns the wrapper's
/// own register state (garbage from whatever was last in rsi/rdx/...),
/// not the user's syscall args.
///
/// This helper reads the inner `pt_regs *` from `ctx.arg(0)` (rdi) and
/// wraps it as [`PtRegs`]. Callers reading a **userspace pointer** arg
/// should chain `.arg::<*const T>(n)` — that impl uses
/// `bpf_probe_read` internally and passes the BPF verifier when the
/// underlying `PtRegs` was obtained via this helper. For integer args
/// (e.g. a fd) use [`syscall_arg_u64`] instead — the primitive impl
/// of `PtRegs::arg<u64>` emits a direct memory load that the verifier
/// rejects on a scalar `pt_regs *`. Tracked as **AAASM-1552**.
#[inline(always)]
pub fn syscall_pt_regs(ctx: &ProbeContext) -> Option<PtRegs> {
    let inner = ctx.arg::<*const u8>(0)? as *mut _;
    Some(PtRegs::new(inner))
}

/// Read the `n`th userspace syscall argument as a `u64` from a
/// `__x64_sys_*` kprobe context.
///
/// `PtRegs::arg::<u64>(n)` emits a direct memory load (`ctx.rdi as
/// *const u64 as _`) which the BPF verifier rejects with
/// `R1 invalid mem access 'scalar'` when the underlying pt_regs is a
/// scalar pointer (i.e. the inner pt_regs we got from another
/// `bpf_probe_read`). The `*const T` impl, by contrast, routes the
/// load through `bpf_probe_read`, which the verifier accepts.
///
/// So we read as `*const u64` (verifier-safe) and reinterpret the
/// pointer bits as the u64 syscall arg they actually hold. Tracked
/// as **AAASM-1552**.
#[inline(always)]
pub fn syscall_arg_u64(ctx: &ProbeContext, n: usize) -> Option<u64> {
    let ptr: *const u64 = syscall_pt_regs(ctx)?.arg(n)?;
    Some(ptr as u64)
}
