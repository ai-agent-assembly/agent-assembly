//! Live-process identity evidence for the proxy state file.
//!
//! # Why a PID is not an identity
//!
//! `kill(pid, 0)` succeeding proves only that *some* process currently owns that
//! number. PIDs are recycled — on a busy host the wrap-around is minutes, not
//! days — so a state file that records a PID and nothing else cannot tell "the
//! proxy is still running" from "the proxy died and an unrelated process
//! inherited its number". Routing a governed tool's traffic at whatever now
//! holds the number is the same silent-bypass failure as routing it at nothing:
//! the tool launches, reports as governed, and is inspected by no one.
//!
//! Two facts are therefore pinned in the state file when the proxy is spawned
//! and re-read from the kernel before the endpoint is trusted:
//!
//! * **the executable behind the PID** — a process that merely inherited the
//!   number is running some other program, so this alone rejects the
//!   overwhelming majority of reuse; and
//! * **the process start time** — the field the kernel guarantees distinguishes
//!   a process from its PID's next occupant, because a successor cannot have
//!   started before its predecessor exited. `(pid, start_time)` is the standard
//!   process-identity pair for exactly this reason (it is what `pidfd`, systemd
//!   and every correct pidfile implementation reduce to).
//!
//! # Why per-platform, and why `None` is fatal rather than skippable
//!
//! Neither fact is portable. Each platform reads it natively; a platform with no
//! implementation returns `None`, which the trust check treats as *cannot
//! establish identity* and refuses. An unavailable check must never degrade into
//! a passed check — that is how a guard becomes decoration.

use std::path::PathBuf;

/// Returns `true` when a signal can be delivered to `pid`.
///
/// `kill(pid, 0)` returns 0 only when the caller is permitted to signal the
/// target, which on a non-root caller means the process runs as the same user.
/// A process owned by someone else therefore reports as *not alive* here — the
/// conservative answer, and the one the trust check wants: a proxy this user did
/// not start is not this user's proxy.
#[cfg(unix)]
pub fn is_alive(pid: u32) -> bool {
    // Safety: `kill` with signal 0 performs the permission/existence check
    // without delivering a signal; no memory is dereferenced.
    unsafe { libc::kill(pid as libc::pid_t, 0) == 0 }
}

#[cfg(not(unix))]
pub fn is_alive(_pid: u32) -> bool {
    false
}

/// Absolute path of the executable image `pid` is running, or `None` when the
/// process is gone or the platform cannot report it.
#[cfg(target_os = "linux")]
pub fn exe_path(pid: u32) -> Option<PathBuf> {
    // `/proc/<pid>/exe` is a kernel-maintained symlink to the *resolved* image,
    // so it is immune to the caller's `PATH` and to any symlink the launcher
    // happened to invoke the binary through.
    std::fs::read_link(format!("/proc/{pid}/exe")).ok()
}

/// Absolute path of the executable image `pid` is running, or `None` when the
/// process is gone or the platform cannot report it.
#[cfg(target_os = "macos")]
pub fn exe_path(pid: u32) -> Option<PathBuf> {
    let mut buf = vec![0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
    // Safety: `buf` is a live allocation of exactly the length passed; the call
    // writes at most that many bytes and returns the count written.
    let written = unsafe { libc::proc_pidpath(pid as libc::c_int, buf.as_mut_ptr().cast(), buf.len() as u32) };
    if written <= 0 {
        return None;
    }
    buf.truncate(written as usize);
    String::from_utf8(buf).ok().map(PathBuf::from)
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub fn exe_path(_pid: u32) -> Option<PathBuf> {
    None
}

/// An opaque token identifying *this* incarnation of `pid`.
///
/// The value is only ever compared for equality against a token captured
/// earlier for the same PID, so its encoding is private to this module. It is
/// prefixed with the platform that produced it so a state file carried between
/// hosts of different kinds can never compare equal by coincidence.
#[cfg(target_os = "linux")]
pub fn start_token(pid: u32) -> Option<String> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // Field 2 (`comm`) is parenthesised and may itself contain spaces and even
    // ')', so the only safe split point in `/proc/<pid>/stat` is the *last*
    // ')'. Splitting on whitespace from the left mis-parses any process whose
    // executable name contains a space — including, deliberately, an attacker's.
    let rest = stat.get(stat.rfind(')')? + 1..)?;
    // Tokens after that point start at field 3 (`state`), so field 22
    // (`starttime`, in clock ticks since boot) is at index 19.
    let ticks: u64 = rest.split_whitespace().nth(19)?.parse().ok()?;
    Some(format!("linux-starttime:{ticks}"))
}

/// An opaque token identifying *this* incarnation of `pid`. See the Linux
/// variant for the comparison contract.
#[cfg(target_os = "macos")]
pub fn start_token(pid: u32) -> Option<String> {
    // Safety: `proc_pidinfo` fills the caller-provided `proc_bsdinfo` and is
    // told its exact size; a short return is treated as failure below.
    let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
    let size = std::mem::size_of::<libc::proc_bsdinfo>() as libc::c_int;
    let written = unsafe {
        libc::proc_pidinfo(
            pid as libc::c_int,
            libc::PROC_PIDTBSDINFO,
            0,
            // `addr_of_mut!` rather than `ptr::from_mut`: the latter is stable
            // only since 1.76 and this crate's MSRV is 1.75.
            std::ptr::addr_of_mut!(info).cast(),
            size,
        )
    };
    if written != size {
        return None;
    }
    Some(format!(
        "macos-starttime:{}.{:06}",
        info.pbi_start_tvsec, info.pbi_start_tvusec
    ))
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub fn start_token(_pid: u32) -> Option<String> {
    None
}
