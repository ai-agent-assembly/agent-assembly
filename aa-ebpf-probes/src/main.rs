#![no_std]
#![no_main]

mod helpers;
mod maps;

use aa_ebpf_common::file::{FdPathKey, FileIoEventRaw, SyscallType, MAX_PATH_LEN};
use aya_ebpf::{
    helpers::{bpf_ktime_get_ns, bpf_probe_read_user_str_bytes},
    macros::{kprobe, kretprobe},
    programs::{ProbeContext, RetProbeContext},
};

use crate::helpers::{emit_event, get_pid_tgid, should_monitor, syscall_pt_regs};
use crate::maps::{
    FD_PATH_MAP, OPENAT_ENTRY_TS, OPENAT_TMP, PATH_ALLOWLIST, PATH_BLOCKLIST, READ_ENTRY_TS,
    READ_TMP, RENAME_ENTRY_TS, RENAME_TMP, UNLINK_ENTRY_TS, UNLINK_TMP, WRITE_ENTRY_TS, WRITE_TMP,
};

/// kprobe on `sys_openat` — captures the filename argument and stashes
/// it in `OPENAT_TMP` keyed by `pid_tgid` so the kretprobe can pair it
/// with the returned fd.
#[kprobe]
pub fn aa_sys_openat(ctx: ProbeContext) -> u32 {
    match try_sys_openat(&ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_sys_openat(ctx: &ProbeContext) -> Result<u32, u32> {
    let (tgid, _pid) = get_pid_tgid();
    if !should_monitor(tgid) {
        return Ok(0);
    }

    // openat(int dirfd, const char *filename, int flags, mode_t mode)
    // — pull filename (arg1 = rsi) via pt_regs deref; ctx.arg(1) is
    // garbage on SYSCALL_WRAPPER kernels. AAASM-1552.
    let filename_ptr: *const u8 = syscall_pt_regs(ctx).ok_or(1u32)?.arg(1).ok_or(1u32)?;

    let mut buf = [0u8; MAX_PATH_LEN];
    unsafe {
        let _ = bpf_probe_read_user_str_bytes(filename_ptr, &mut buf);
    }

    let pid_tgid = aya_ebpf::helpers::bpf_get_current_pid_tgid();
    let _ = OPENAT_TMP.insert(&pid_tgid, &buf, 0);

    // Stash the entry timestamp so the kretprobe can compute duration.
    let entry_ts = unsafe { bpf_ktime_get_ns() };
    let _ = OPENAT_ENTRY_TS.insert(&pid_tgid, &entry_ts, 0);

    Ok(0)
}

/// kretprobe on `sys_openat` — pairs the returned fd with the filename
/// captured by the entry kprobe, caches it in `FD_PATH_MAP`, checks the
/// path blocklist, and emits a `FileIoEventRaw`.
#[kretprobe]
pub fn aa_sys_openat_ret(ctx: RetProbeContext) -> u32 {
    match try_sys_openat_ret(&ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_sys_openat_ret(ctx: &RetProbeContext) -> Result<u32, u32> {
    let (tgid, pid) = get_pid_tgid();
    if !should_monitor(tgid) {
        return Ok(0);
    }

    let pid_tgid = aya_ebpf::helpers::bpf_get_current_pid_tgid();

    // Retrieve the filename stashed by the entry kprobe and build the
    // event directly so the path lives inside the event struct (no
    // separate 256-byte buffer on this stack frame).
    let path = unsafe { OPENAT_TMP.get(&pid_tgid).ok_or(1u32)? };
    let mut event = FileIoEventRaw {
        pid: tgid,
        tid: pid,
        timestamp_ns: 0,
        syscall: SyscallType::Openat,
        flags: 0,
        return_code: 0,
        duration_ns: 0,
        path: *path,
    };

    // Compute end-to-end syscall duration from the entry-timestamp map.
    if let Some(&entry_ts) = unsafe { OPENAT_ENTRY_TS.get(&pid_tgid) } {
        let now = unsafe { bpf_ktime_get_ns() };
        event.duration_ns = now.saturating_sub(entry_ts);
        let _ = OPENAT_ENTRY_TS.remove(&pid_tgid);
    }

    // Clean up the temporary entry.
    let _ = OPENAT_TMP.remove(&pid_tgid);

    // rc is the returned fd (or negative errno).
    let rc: i64 = ctx.ret().ok_or(1u32)?;
    event.return_code = rc;

    // Cache (pid, fd) → path for read/write fd resolution.
    if rc >= 0 {
        let key = FdPathKey {
            pid: tgid,
            fd: rc as u64,
        };
        let _ = FD_PATH_MAP.insert(&key, &event.path, 0);
    }

    // Allowlist: if the path is explicitly allowed, suppress the event.
    if unsafe { PATH_ALLOWLIST.get(&event.path).is_some() } {
        return Ok(0);
    }

    // Bit 0 = blocklist hit (sensitive path alert).
    if unsafe { PATH_BLOCKLIST.get(&event.path).is_some() } {
        event.flags = 1;
    }

    emit_event(ctx, &mut event);

    Ok(0)
}

/// kprobe on `sys_read` — resolves the fd to a file path via
/// `FD_PATH_MAP`, stashes the path + entry timestamp keyed by
/// `pid_tgid`, and defers event emission to the kretprobe.
#[kprobe]
pub fn aa_sys_read(ctx: ProbeContext) -> u32 {
    match try_sys_read(&ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_sys_read(ctx: &ProbeContext) -> Result<u32, u32> {
    let (tgid, _pid) = get_pid_tgid();
    if !should_monitor(tgid) {
        return Ok(0);
    }

    // read(unsigned int fd, char *buf, size_t count) — pull fd
    // (arg0 = rdi) via pt_regs deref. ctx.arg(0) on __x64_sys_*
    // returns the pt_regs pointer itself, not the fd. AAASM-1552.
    let fd: u64 = syscall_pt_regs(ctx).ok_or(1u32)?.arg(0).ok_or(1u32)?;
    let key = FdPathKey { pid: tgid, fd };

    // Resolve the path now (fd is only available at entry). If the fd
    // wasn't opened through our openat probe we have nothing to record.
    let path = unsafe { FD_PATH_MAP.get(&key).ok_or(1u32)? };

    let pid_tgid = aya_ebpf::helpers::bpf_get_current_pid_tgid();
    let _ = READ_TMP.insert(&pid_tgid, path, 0);

    let entry_ts = unsafe { bpf_ktime_get_ns() };
    let _ = READ_ENTRY_TS.insert(&pid_tgid, &entry_ts, 0);

    Ok(0)
}

/// kretprobe on `sys_read` — pairs the resolved path stashed by the
/// entry kprobe with the syscall return code, computes the end-to-end
/// duration, checks the path lists, and emits a `FileIoEventRaw`.
#[kretprobe]
pub fn aa_sys_read_ret(ctx: RetProbeContext) -> u32 {
    match try_sys_read_ret(&ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_sys_read_ret(ctx: &RetProbeContext) -> Result<u32, u32> {
    let (tgid, pid) = get_pid_tgid();
    if !should_monitor(tgid) {
        return Ok(0);
    }

    let pid_tgid = aya_ebpf::helpers::bpf_get_current_pid_tgid();

    let path = unsafe { READ_TMP.get(&pid_tgid).ok_or(1u32)? };
    let mut event = FileIoEventRaw {
        pid: tgid,
        tid: pid,
        timestamp_ns: 0,
        syscall: SyscallType::Read,
        flags: 0,
        return_code: 0,
        duration_ns: 0,
        path: *path,
    };

    if let Some(&entry_ts) = unsafe { READ_ENTRY_TS.get(&pid_tgid) } {
        let now = unsafe { bpf_ktime_get_ns() };
        event.duration_ns = now.saturating_sub(entry_ts);
        let _ = READ_ENTRY_TS.remove(&pid_tgid);
    }

    let _ = READ_TMP.remove(&pid_tgid);

    // rc is bytes read (>= 0) or negative errno.
    let rc: i64 = ctx.ret().ok_or(1u32)?;
    event.return_code = rc;

    // Allowlist: if the path is explicitly allowed, suppress the event.
    if unsafe { PATH_ALLOWLIST.get(&event.path).is_some() } {
        return Ok(0);
    }

    if unsafe { PATH_BLOCKLIST.get(&event.path).is_some() } {
        event.flags = 1;
    }

    emit_event(ctx, &mut event);

    Ok(0)
}

/// kprobe on `sys_write` — resolves the fd to a file path via
/// `FD_PATH_MAP`, stashes the path + entry timestamp keyed by
/// `pid_tgid`, and defers event emission to the kretprobe.
#[kprobe]
pub fn aa_sys_write(ctx: ProbeContext) -> u32 {
    match try_sys_write(&ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_sys_write(ctx: &ProbeContext) -> Result<u32, u32> {
    let (tgid, _pid) = get_pid_tgid();
    if !should_monitor(tgid) {
        return Ok(0);
    }

    // arg0 = unsigned int fd
    let fd: u64 = ctx.arg(0).ok_or(1u32)?;
    let key = FdPathKey { pid: tgid, fd };

    let path = unsafe { FD_PATH_MAP.get(&key).ok_or(1u32)? };

    let pid_tgid = aya_ebpf::helpers::bpf_get_current_pid_tgid();
    let _ = WRITE_TMP.insert(&pid_tgid, path, 0);

    let entry_ts = unsafe { bpf_ktime_get_ns() };
    let _ = WRITE_ENTRY_TS.insert(&pid_tgid, &entry_ts, 0);

    Ok(0)
}

/// kretprobe on `sys_write` — pairs the resolved path stashed by the
/// entry kprobe with the syscall return code, computes the end-to-end
/// duration, checks the path lists, and emits a `FileIoEventRaw`.
#[kretprobe]
pub fn aa_sys_write_ret(ctx: RetProbeContext) -> u32 {
    match try_sys_write_ret(&ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_sys_write_ret(ctx: &RetProbeContext) -> Result<u32, u32> {
    let (tgid, pid) = get_pid_tgid();
    if !should_monitor(tgid) {
        return Ok(0);
    }

    let pid_tgid = aya_ebpf::helpers::bpf_get_current_pid_tgid();

    let path = unsafe { WRITE_TMP.get(&pid_tgid).ok_or(1u32)? };
    let mut event = FileIoEventRaw {
        pid: tgid,
        tid: pid,
        timestamp_ns: 0,
        syscall: SyscallType::Write,
        flags: 0,
        return_code: 0,
        duration_ns: 0,
        path: *path,
    };

    if let Some(&entry_ts) = unsafe { WRITE_ENTRY_TS.get(&pid_tgid) } {
        let now = unsafe { bpf_ktime_get_ns() };
        event.duration_ns = now.saturating_sub(entry_ts);
        let _ = WRITE_ENTRY_TS.remove(&pid_tgid);
    }

    let _ = WRITE_TMP.remove(&pid_tgid);

    // rc is bytes written (>= 0) or negative errno.
    let rc: i64 = ctx.ret().ok_or(1u32)?;
    event.return_code = rc;

    // Allowlist: if the path is explicitly allowed, suppress the event.
    if unsafe { PATH_ALLOWLIST.get(&event.path).is_some() } {
        return Ok(0);
    }

    if unsafe { PATH_BLOCKLIST.get(&event.path).is_some() } {
        event.flags = 1;
    }

    emit_event(ctx, &mut event);

    Ok(0)
}

/// kprobe on `sys_unlinkat` — captures the filename from the syscall
/// argument, stashes it + the entry timestamp keyed by `pid_tgid`, and
/// defers event emission to the kretprobe.
#[kprobe]
pub fn aa_sys_unlink(ctx: ProbeContext) -> u32 {
    match try_sys_unlink(&ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_sys_unlink(ctx: &ProbeContext) -> Result<u32, u32> {
    let (tgid, _pid) = get_pid_tgid();
    if !should_monitor(tgid) {
        return Ok(0);
    }

    // unlinkat(int dirfd, const char *pathname, int flags) — arg1 = pathname
    let filename_ptr: *const u8 = ctx.arg(1).ok_or(1u32)?;

    let mut buf = [0u8; MAX_PATH_LEN];
    unsafe {
        let _ = bpf_probe_read_user_str_bytes(filename_ptr, &mut buf);
    }

    let pid_tgid = aya_ebpf::helpers::bpf_get_current_pid_tgid();
    let _ = UNLINK_TMP.insert(&pid_tgid, &buf, 0);

    let entry_ts = unsafe { bpf_ktime_get_ns() };
    let _ = UNLINK_ENTRY_TS.insert(&pid_tgid, &entry_ts, 0);

    Ok(0)
}

/// kretprobe on `sys_unlinkat` — pairs the path stashed by the entry
/// kprobe with the syscall return code, computes the end-to-end
/// duration, checks the path lists, and emits a `FileIoEventRaw`.
#[kretprobe]
pub fn aa_sys_unlink_ret(ctx: RetProbeContext) -> u32 {
    match try_sys_unlink_ret(&ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_sys_unlink_ret(ctx: &RetProbeContext) -> Result<u32, u32> {
    let (tgid, pid) = get_pid_tgid();
    if !should_monitor(tgid) {
        return Ok(0);
    }

    let pid_tgid = aya_ebpf::helpers::bpf_get_current_pid_tgid();

    let path = unsafe { UNLINK_TMP.get(&pid_tgid).ok_or(1u32)? };
    let mut event = FileIoEventRaw {
        pid: tgid,
        tid: pid,
        timestamp_ns: 0,
        syscall: SyscallType::Unlink,
        flags: 0,
        return_code: 0,
        duration_ns: 0,
        path: *path,
    };

    if let Some(&entry_ts) = unsafe { UNLINK_ENTRY_TS.get(&pid_tgid) } {
        let now = unsafe { bpf_ktime_get_ns() };
        event.duration_ns = now.saturating_sub(entry_ts);
        let _ = UNLINK_ENTRY_TS.remove(&pid_tgid);
    }

    let _ = UNLINK_TMP.remove(&pid_tgid);

    // rc is 0 on success or negative errno.
    let rc: i64 = ctx.ret().ok_or(1u32)?;
    event.return_code = rc;

    // Allowlist: if the path is explicitly allowed, suppress the event.
    if unsafe { PATH_ALLOWLIST.get(&event.path).is_some() } {
        return Ok(0);
    }

    if unsafe { PATH_BLOCKLIST.get(&event.path).is_some() } {
        event.flags = 1;
    }

    emit_event(ctx, &mut event);

    Ok(0)
}

/// kprobe on `sys_renameat2` — captures the source pathname from the
/// syscall argument, stashes it + the entry timestamp keyed by
/// `pid_tgid`, and defers event emission to the kretprobe.
#[kprobe]
pub fn aa_sys_rename(ctx: ProbeContext) -> u32 {
    match try_sys_rename(&ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_sys_rename(ctx: &ProbeContext) -> Result<u32, u32> {
    let (tgid, _pid) = get_pid_tgid();
    if !should_monitor(tgid) {
        return Ok(0);
    }

    // renameat2(int olddirfd, const char *oldpath, ...) — arg1 = oldpath
    let oldpath_ptr: *const u8 = ctx.arg(1).ok_or(1u32)?;

    let mut buf = [0u8; MAX_PATH_LEN];
    unsafe {
        let _ = bpf_probe_read_user_str_bytes(oldpath_ptr, &mut buf);
    }

    let pid_tgid = aya_ebpf::helpers::bpf_get_current_pid_tgid();
    let _ = RENAME_TMP.insert(&pid_tgid, &buf, 0);

    let entry_ts = unsafe { bpf_ktime_get_ns() };
    let _ = RENAME_ENTRY_TS.insert(&pid_tgid, &entry_ts, 0);

    Ok(0)
}

/// kretprobe on `sys_renameat2` — pairs the source path stashed by
/// the entry kprobe with the syscall return code, computes the
/// end-to-end duration, checks the path lists, and emits a
/// `FileIoEventRaw`.
#[kretprobe]
pub fn aa_sys_rename_ret(ctx: RetProbeContext) -> u32 {
    match try_sys_rename_ret(&ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_sys_rename_ret(ctx: &RetProbeContext) -> Result<u32, u32> {
    let (tgid, pid) = get_pid_tgid();
    if !should_monitor(tgid) {
        return Ok(0);
    }

    let pid_tgid = aya_ebpf::helpers::bpf_get_current_pid_tgid();

    let path = unsafe { RENAME_TMP.get(&pid_tgid).ok_or(1u32)? };
    let mut event = FileIoEventRaw {
        pid: tgid,
        tid: pid,
        timestamp_ns: 0,
        syscall: SyscallType::Rename,
        flags: 0,
        return_code: 0,
        duration_ns: 0,
        path: *path,
    };

    if let Some(&entry_ts) = unsafe { RENAME_ENTRY_TS.get(&pid_tgid) } {
        let now = unsafe { bpf_ktime_get_ns() };
        event.duration_ns = now.saturating_sub(entry_ts);
        let _ = RENAME_ENTRY_TS.remove(&pid_tgid);
    }

    let _ = RENAME_TMP.remove(&pid_tgid);

    // rc is 0 on success or negative errno.
    let rc: i64 = ctx.ret().ok_or(1u32)?;
    event.return_code = rc;

    // Allowlist: if the path is explicitly allowed, suppress the event.
    if unsafe { PATH_ALLOWLIST.get(&event.path).is_some() } {
        return Ok(0);
    }

    if unsafe { PATH_BLOCKLIST.get(&event.path).is_some() } {
        event.flags = 1;
    }

    emit_event(ctx, &mut event);

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
