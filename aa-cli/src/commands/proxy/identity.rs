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
//! and read back from the running process before the endpoint is trusted:
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
//! # Why the start time alone is not enough on Linux (AAASM-5333)
//!
//! `/proc/<pid>/stat` publishes the start time in **clock ticks** — `USER_HZ`,
//! which is 100 on every mainstream configuration, so a 10 ms grid. Two
//! processes that started inside the same 10 ms carry byte-identical values, and
//! a token built from that field alone cannot tell them apart. The hole is
//! narrow but real: the executable check already rejects a recycled PID running
//! *something else*, so the start time is the only thing left to reject a
//! *second `aa-proxy`* that took the same number, and two incarnations landing
//! in one tick would pass both checks.
//!
//! Linux exposes no finer start time, so the token pairs the tick with an
//! independent kernel fact rather than a more precise clock: the **pidfs inode**
//! behind `pidfd_open(2)`. From Linux 6.9 each process owns an inode on the
//! `pidfs` filesystem, allocated at process creation from a counter that owes
//! nothing to the clock — so a pair that collides on the tick still differs
//! here, and forging a token now requires forging both. It survives the
//! constraint that shapes the rest of this module, too: `pidfd_open` is not
//! behind the ptrace gate, so it answers for the non-dumpable process every real
//! `aa-proxy` is.
//!
//! Two candidates were measured and rejected. The `/proc/<pid>` directory's own
//! inode is *not* stable — it is allocated at dentry lookup and observably
//! changes when the dentry is evicted, which would turn a running proxy into a
//! refused one. A nonce the proxy generates for itself would move the fact from
//! the kernel to the process: a process can lie about a value it invents, where
//! it cannot lie about its own creation, and identity evidence should not be
//! sourced from the thing being identified.
//!
//! Kernels before 6.9 answer `pidfd_open` with one anonymous inode shared by
//! every pidfd, which discriminates nothing. That case is detected by the
//! filesystem magic rather than guessed at from a version number, and the token
//! then carries a different scheme tag — the resolution it actually has is
//! stated, never assumed.
//!
//! # Why per-platform, and why absent evidence is fatal rather than skippable
//!
//! Neither fact is portable. Each platform reads it natively; a platform with no
//! implementation says so, and the trust check treats that as *cannot establish
//! identity* and refuses. An unavailable check must never degrade into a passed
//! check — that is how a guard becomes decoration.
//!
//! # Why the image evidence is a sum type and not a path
//!
//! On Linux the authoritative source for "what is this PID running" is
//! `/proc/<pid>/exe`, and the kernel gates reading it behind
//! `ptrace_may_access(PTRACE_MODE_READ)`. That gate rejects **even the process's
//! own user** once the target has marked itself non-dumpable — which `aa-proxy`
//! does to itself at startup (`prctl(PR_SET_DUMPABLE, 0)`, AAASM-3584) so that
//! the provider keys in its address space cannot be scraped or core-dumped by a
//! same-uid attacker. The proxy is therefore, by design, the one process on the
//! host that will not name its own image to `aasm run`.
//!
//! Two deliberate protections cannot both be satisfied by that one source, so
//! the evidence records *which* source answered rather than flattening both into
//! `Option<PathBuf>`. [`ImageEvidence::Reported`] is the kernel naming the image
//! it loaded; [`ImageEvidence::InvokedAs`] is `argv[0]` — the one image fact the
//! kernel still publishes for a hidden process — and is only ever produced when
//! the authoritative read was refused *because* the process hid itself. Being
//! unable to read a process at all ([`ImageEvidence::Unreadable`], which is what
//! an exited-but-unreaped zombie yields) stays a refusal, and so does a platform
//! with no implementation ([`ImageEvidence::Unsupported`]).

use std::path::{Path, PathBuf};

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

/// What this host will say about the executable image behind a PID.
///
/// The variants are ordered by authority, and the trust check must branch on
/// them rather than reduce them to "some path or nothing": the two failure
/// variants mean different things to an operator, and the two success variants
/// were answered by different sources.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImageEvidence {
    /// The kernel named the image it loaded. Unforgeable by the process itself.
    Reported(PathBuf),
    /// The process has hidden itself from same-uid inspection, so the kernel
    /// refuses to name its image; this is the path it was **invoked with**,
    /// which the kernel still publishes. See the module docs for why this is
    /// the strongest evidence obtainable about a hardened `aa-proxy`.
    InvokedAs(PathBuf),
    /// Nothing about the image can be read. Carries the reason so the refusal
    /// can say something true instead of blaming the platform.
    Unreadable(&'static str),
    /// This platform has no implementation at all.
    Unsupported,
}

impl ImageEvidence {
    /// The path this host attributes to the process, whichever source answered.
    /// `None` for both failure variants — callers that only need the path must
    /// still treat absence as a refusal.
    pub fn path(&self) -> Option<&Path> {
        match self {
            Self::Reported(p) | Self::InvokedAs(p) => Some(p),
            Self::Unreadable(_) | Self::Unsupported => None,
        }
    }
}

/// Evidence about the executable image `pid` is running.
///
/// `/proc/<pid>/exe` is a kernel-maintained symlink to the *resolved* image, so
/// it is immune to the caller's `PATH` and to any symlink the launcher happened
/// to invoke the binary through. Its three error paths are distinguished
/// because they mean three different things:
///
/// * `EACCES` — the process is alive but non-dumpable, i.e. it has deliberately
///   made itself unreadable to same-uid inspection (what `aa-proxy` does). Fall
///   through to `argv[0]`, which the kernel keeps publishing.
/// * `ENOENT` — the PID exists but has no image: it has exited and is a zombie
///   awaiting reaping, or `/proc` is not mounted. There is nothing to identify.
/// * anything else — `/proc` is unreadable; refuse rather than guess.
#[cfg(target_os = "linux")]
pub fn image(pid: u32) -> ImageEvidence {
    match std::fs::read_link(format!("/proc/{pid}/exe")) {
        Ok(path) => ImageEvidence::Reported(path),
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => invoked_as(pid),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => ImageEvidence::Unreadable(
            "it has no executable image — the process has exited and is awaiting reaping, \
             or /proc is not mounted",
        ),
        Err(_) => ImageEvidence::Unreadable("its /proc entry could not be read"),
    }
}

/// `argv[0]` of `pid`, canonicalised so it is directly comparable with the
/// resolved path `/proc/<pid>/exe` would have given.
///
/// Only reached when the kernel refused the authoritative read *because the
/// target hid itself*, so the two remaining ways to get nothing — a zombie
/// (whose `cmdline` is empty, its address space already gone) and a binary that
/// has since been removed from the path it was launched from — both stay
/// refusals rather than becoming a missing check.
#[cfg(target_os = "linux")]
fn invoked_as(pid: u32) -> ImageEvidence {
    use std::os::unix::ffi::OsStrExt;

    let Ok(cmdline) = std::fs::read(format!("/proc/{pid}/cmdline")) else {
        return ImageEvidence::Unreadable("its command line could not be read");
    };
    // NUL-separated; `argv[0]` is everything up to the first separator.
    let argv0 = cmdline.split(|b| *b == 0).next().unwrap_or_default();
    if argv0.is_empty() {
        return ImageEvidence::Unreadable(
            "it publishes no command line — the process has exited and is awaiting reaping",
        );
    }
    let argv0 = Path::new(std::ffi::OsStr::from_bytes(argv0));
    match std::fs::canonicalize(argv0) {
        Ok(resolved) => ImageEvidence::InvokedAs(resolved),
        Err(_) => ImageEvidence::Unreadable("the executable it was launched from no longer resolves"),
    }
}

/// Evidence about the executable image `pid` is running.
///
/// macOS has no `PR_SET_DUMPABLE` equivalent, so `proc_pidpath` answers for any
/// process this user may signal and there is no second-best source to fall back
/// to — hence no [`ImageEvidence::InvokedAs`] on this platform.
#[cfg(target_os = "macos")]
pub fn image(pid: u32) -> ImageEvidence {
    let mut buf = vec![0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
    // Safety: `buf` is a live allocation of exactly the length passed; the call
    // writes at most that many bytes and returns the count written.
    let written = unsafe { libc::proc_pidpath(pid as libc::c_int, buf.as_mut_ptr().cast(), buf.len() as u32) };
    if written <= 0 {
        return ImageEvidence::Unreadable("the kernel would not name its executable — the process has exited");
    }
    buf.truncate(written as usize);
    match String::from_utf8(buf) {
        Ok(path) => ImageEvidence::Reported(PathBuf::from(path)),
        Err(_) => ImageEvidence::Unreadable("the kernel reported a non-UTF-8 executable path"),
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub fn image(_pid: u32) -> ImageEvidence {
    ImageEvidence::Unsupported
}

/// Scheme tag for a Linux token that carries both the start tick and the
/// kernel's per-process pidfs inode. See the module docs for why the tick alone
/// is not enough.
#[cfg(target_os = "linux")]
const LINUX_SCHEME_PIDFS: &str = "linux-pidfs";

/// Scheme tag for a Linux token carrying the start tick and nothing else,
/// emitted only where the kernel publishes no per-process inode. The tag is
/// distinct so a token never claims a resolution it does not have.
#[cfg(target_os = "linux")]
const LINUX_SCHEME_TICKS: &str = "linux-ticks";

/// Scheme tag for the macOS token. Unchanged: `PROC_PIDTBSDINFO` already
/// answers in microseconds, so there is no tick-collision problem to fix here
/// and no reason to invalidate records written by an earlier build.
#[cfg(target_os = "macos")]
const MACOS_SCHEME: &str = "macos-starttime";

/// Every scheme tag [`start_token`] can emit on this host. A recorded token
/// tagged with anything else was not written here, or not written by this build
/// — see [`scheme_is_current`].
#[cfg(target_os = "linux")]
const CURRENT_SCHEMES: &[&str] = &[LINUX_SCHEME_PIDFS, LINUX_SCHEME_TICKS];

#[cfg(target_os = "macos")]
const CURRENT_SCHEMES: &[&str] = &[MACOS_SCHEME];

/// A platform with no [`start_token`] implementation produces no tokens, so no
/// recorded token can have come from it.
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
const CURRENT_SCHEMES: &[&str] = &[];

/// `f_type` of the `pidfs` filesystem (`"PIDF"`), which is what a `pidfd`
/// reports from Linux 6.9 onwards.
///
/// Before that release `pidfd_open` returned an *anonymous* inode shared by
/// every pidfd on the system, so its inode number is the same for all processes
/// and discriminates nothing. Checking the magic distinguishes "the kernel gave
/// me this process's own identifier" from "the kernel gave me the one global
/// placeholder" — a distinction a bare `fstat` cannot make, and getting it wrong
/// would append a constant to every token while appearing to strengthen it.
#[cfg(target_os = "linux")]
const PID_FS_MAGIC: i64 = 0x5049_4446;

/// Field 22 of `/proc/<pid>/stat` — the process's start time in clock ticks
/// since boot.
///
/// `USER_HZ` is 100 on every mainstream configuration, so this is a 10 ms grid
/// and is *not* on its own a unique per-process value; see the module docs and
/// [`start_token`], which is what callers should use.
#[cfg(target_os = "linux")]
fn start_ticks(pid: u32) -> Option<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // Field 2 (`comm`) is parenthesised and may itself contain spaces and even
    // ')', so the only safe split point in `/proc/<pid>/stat` is the *last*
    // ')'. Splitting on whitespace from the left mis-parses any process whose
    // executable name contains a space — including, deliberately, an attacker's.
    let rest = stat.get(stat.rfind(')')? + 1..)?;
    // Tokens after that point start at field 3 (`state`), so field 22
    // (`starttime`, in clock ticks since boot) is at index 19.
    rest.split_whitespace().nth(19)?.parse().ok()
}

/// The kernel's own globally-unique identifier for the process currently behind
/// `pid`, or `None` if this kernel publishes none.
///
/// This is the pidfs inode reached through `pidfd_open(2)`. Three properties
/// make it the right partner for the start tick:
///
/// * it is allocated when the process is created, from a counter unrelated to
///   the clock, so it cannot collide for the same reason the tick does;
/// * it is stable for the lifetime of the process, so the value recorded at
///   `aasm proxy start` still reads back identically at `aasm run`; and
/// * `pidfd_open` is not behind the ptrace gate, so it answers for a process
///   that has marked itself non-dumpable — which every real `aa-proxy` has
///   (AAASM-3584), and which is precisely why `/proc/<pid>/exe` cannot be the
///   fallback here.
///
/// A reaped PID yields `ESRCH` and therefore `None`; a zombie still answers,
/// which is correct — rejecting a zombie is the image evidence's job, not this
/// one's.
#[cfg(target_os = "linux")]
fn incarnation_inode(pid: u32) -> Option<u64> {
    // Safety: `pidfd_open` takes a PID and a flag word by value and returns a
    // file descriptor or -1. Nothing is dereferenced.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::pid_t, 0 as libc::c_uint) };
    if fd < 0 {
        // ENOSYS on kernels before 5.3, ESRCH once the PID has been reaped.
        return None;
    }
    let fd = fd as libc::c_int;
    let inode = pidfs_inode_of(fd);
    // Safety: `fd` was just returned by the kernel and is not used again.
    unsafe { libc::close(fd) };
    inode
}

/// The inode number behind an open pidfd, but only when it is a genuine `pidfs`
/// inode. See [`PID_FS_MAGIC`] for why the filesystem is checked first.
#[cfg(target_os = "linux")]
fn pidfs_inode_of(fd: libc::c_int) -> Option<u64> {
    // Safety: both calls fill a caller-owned struct of exactly the size the
    // kernel is told, and are checked for failure before the struct is read.
    let mut fs: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatfs(fd, &mut fs) } != 0 || fs.f_type as i64 != PID_FS_MAGIC {
        return None;
    }
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut st) } != 0 {
        return None;
    }
    Some(st.st_ino as u64)
}

/// Whether this host can tell apart two processes that started inside the same
/// kernel clock tick.
///
/// False only on Linux before 6.9, where the tick is genuinely all the kernel
/// offers. Exposed so the property can be asserted rather than assumed.
#[cfg(target_os = "linux")]
pub fn distinguishes_within_a_tick() -> bool {
    incarnation_inode(std::process::id()).is_some()
}

/// See the Linux variant. macOS start times are microsecond-resolution, so the
/// tick-collision case does not arise.
#[cfg(target_os = "macos")]
pub fn distinguishes_within_a_tick() -> bool {
    true
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub fn distinguishes_within_a_tick() -> bool {
    false
}

/// An opaque token identifying *this* incarnation of `pid`.
///
/// The value is only ever compared for equality against a token captured
/// earlier for the same PID, so its encoding is private to this module. It is
/// prefixed with a scheme tag naming the evidence inside it, so that a record
/// carried between hosts of different kinds — or written by a build that
/// gathered different evidence — is recognised as such by
/// [`scheme_is_current`] instead of silently comparing unequal.
#[cfg(target_os = "linux")]
pub fn start_token(pid: u32) -> Option<String> {
    // Read the tick first: it is the fact whose absence means "there is no such
    // process", and it must keep deciding that. `pidfd_open` still answers for a
    // zombie, so consulting it first would turn a reaped PID into a token.
    let ticks = start_ticks(pid)?;
    Some(match incarnation_inode(pid) {
        Some(inode) => format!("{LINUX_SCHEME_PIDFS}:{ticks}.{inode}"),
        None => format!("{LINUX_SCHEME_TICKS}:{ticks}"),
    })
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
        "{MACOS_SCHEME}:{}.{:06}",
        info.pbi_start_tvsec, info.pbi_start_tvusec
    ))
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub fn start_token(_pid: u32) -> Option<String> {
    None
}

/// Whether `token` was produced by a scheme [`start_token`] still emits on this
/// host.
///
/// A recorded token that fails this test cannot support a trust decision, and —
/// this is the point — cannot be *compared* into one either: it would simply
/// differ from every fresh reading, which reads as "the PID was recycled" and
/// sends an operator hunting a process-identity problem that does not exist.
/// Callers must refuse such a record with a diagnostic of its own (see
/// [`super::trust::ProxyTrustError::IdentityEvidenceUnrecognised`]) rather than
/// let it fall through to the equality comparison.
///
/// It fires for a record written by an `aasm` that gathered different evidence
/// (before AAASM-5333, Linux tokens carried the start tick alone), and for one
/// carried over from a host of another kind. Migration is deliberately not
/// attempted: the older evidence is a strict subset, so honouring it would mean
/// re-admitting exactly the weakness the new scheme exists to close.
pub fn scheme_is_current(token: &str) -> bool {
    match token.split_once(':') {
        // An empty value is not a token: it names a scheme and then says
        // nothing, which would compare equal to another empty one.
        Some((scheme, value)) => !value.is_empty() && CURRENT_SCHEMES.contains(&scheme),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn this_process_is_alive() {
        assert!(is_alive(std::process::id()));
    }

    /// PID 0 is never a signallable user process; `kill(0, 0)` addresses the
    /// caller's whole process group, so a naive implementation would report it
    /// alive. Kept as a guard against exactly that mistake.
    #[test]
    fn a_reaped_child_is_not_alive() {
        let mut child = std::process::Command::new("true").spawn().expect("spawn `true`");
        let pid = child.id();
        child.wait().expect("wait for `true`");
        assert!(!is_alive(pid), "a reaped child must not report as alive; pid {pid} did");
    }

    #[test]
    fn the_image_of_this_process_is_the_test_binary() {
        let evidence = image(std::process::id());
        let seen = evidence
            .path()
            .unwrap_or_else(|| panic!("this platform must report its own executable; got {evidence:?}"));
        let expected = std::env::current_exe().expect("current_exe");
        assert_eq!(
            std::fs::canonicalize(seen).unwrap_or_else(|_| seen.to_path_buf()),
            std::fs::canonicalize(&expected).unwrap_or_else(|_| expected.clone()),
            "the image evidence must name the running image; saw {seen:?} vs {expected:?}"
        );
    }

    /// A process asking about *itself* is exempt from the ptrace gate
    /// (`same_thread_group`), so a self-read can never exercise the hidden-process
    /// path. Pin that the ordinary case is still answered by the authoritative
    /// source, so a regression that made every read fall through to `argv[0]`
    /// would be visible here rather than silently downgrading every check.
    #[test]
    fn a_process_that_hides_nothing_is_named_by_the_kernel() {
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("spawn sleep");
        let evidence = image(child.id());
        let _ = child.kill();
        let _ = child.wait();
        assert!(
            matches!(evidence, ImageEvidence::Reported(_)),
            "an ordinary process must be named by the kernel, not by its own argv; got {evidence:?}"
        );
    }

    #[test]
    fn start_token_is_stable_across_reads_for_the_same_process() {
        let pid = std::process::id();
        let first = start_token(pid).expect("this platform must report its own start time");
        std::thread::sleep(std::time::Duration::from_millis(20));
        let second = start_token(pid).expect("start token must remain readable");
        assert_eq!(first, second, "a process's start time must not change under it");
    }

    /// A `sleep` child killed and reaped when it goes out of scope, so the retry
    /// loop below cannot leave strays behind on a busy CI host.
    struct SleepingChild(std::process::Child);

    impl SleepingChild {
        fn spawn() -> Self {
            Self(
                std::process::Command::new("sleep")
                    .arg("30")
                    .spawn()
                    .expect("spawn sleep"),
            )
        }
        fn pid(&self) -> u32 {
            self.0.id()
        }
    }

    impl Drop for SleepingChild {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    /// Two live processes the kernel recorded as having started inside the same
    /// clock tick.
    ///
    /// The collision is *verified* rather than hoped for. That is the whole
    /// defect in the test this replaces: it assumed two separately-spawned
    /// processes would land in different ticks, so on the runs where they did
    /// the assertion held for a reason that had nothing to do with the token.
    #[cfg(target_os = "linux")]
    fn pair_started_in_one_tick() -> (SleepingChild, SleepingChild) {
        for _ in 0..64 {
            let first = SleepingChild::spawn();
            let second = SleepingChild::spawn();
            let (a, b) = (start_ticks(first.pid()), start_ticks(second.pid()));
            assert!(
                a.is_some() && b.is_some(),
                "both children must publish a start tick, or the pair proves nothing"
            );
            if a == b {
                return (first, second);
            }
        }
        panic!(
            "could not start two processes inside one 10 ms tick in 64 attempts — the collision \
             this test exists to close could not be constructed, so it would have measured nothing"
        );
    }

    /// macOS records start times in microseconds, so two processes spawned
    /// back-to-back are already the closest-together case the platform has;
    /// there is no coarse grid to deliberately land them both in.
    #[cfg(not(target_os = "linux"))]
    fn pair_started_in_one_tick() -> (SleepingChild, SleepingChild) {
        (SleepingChild::spawn(), SleepingChild::spawn())
    }

    /// AAASM-5333 regression, and the reason the token is more than a start tick.
    ///
    /// `/proc/<pid>/stat` measures start time on a 10 ms grid, and under
    /// `cargo nextest` each test runs in a process that is itself only
    /// milliseconds old — so a test binary and the child it spawns land in one
    /// tick as the *normal* case, not the rare one. The predecessor of this test
    /// therefore failed on Linux CI on every attempt, including retries.
    ///
    /// The fix is not to give the two processes more distance. It is to make the
    /// token survive having none, so this test removes the distance on purpose
    /// and requires the token to hold.
    #[test]
    fn processes_started_in_the_same_clock_tick_do_not_share_a_start_token() {
        let (first, second) = pair_started_in_one_tick();
        let a = start_token(first.pid()).expect("first child's start token");
        let b = start_token(second.pid()).expect("second child's start token");

        if !distinguishes_within_a_tick() {
            // Linux before 6.9 publishes nothing finer than the tick, so on such
            // a host the collision is real and cannot be closed. Pin that the
            // token *admits* it — a coarse token wearing the fine scheme's tag
            // would be the genuine defect, and is what this branch exists to
            // catch. Never reached on CI, which runs a kernel that can.
            #[cfg(target_os = "linux")]
            assert!(
                a.starts_with(&format!("{LINUX_SCHEME_TICKS}:")),
                "a host that cannot separate two same-tick processes must not emit a token \
                 claiming that it can; got {a}"
            );
            return;
        }

        assert_ne!(
            a, b,
            "two processes are two incarnations even when the kernel clock cannot separate them — \
             a shared token is a PID-reuse guard that waves the second incarnation through"
        );
    }

    /// The compatibility gate. Evidence gathered under any scheme this host does
    /// not currently emit — a record from before AAASM-5333, or one carried over
    /// from another kind of host — must be recognised as foreign, because the
    /// alternative is comparing it and reporting a PID reuse that never happened.
    #[test]
    fn only_the_scheme_this_host_emits_is_current() {
        assert!(
            scheme_is_current(&start_token(std::process::id()).expect("own start token")),
            "whatever this platform emits must be recognised as its own"
        );
        // The superseded Linux scheme: the same start tick, without the
        // per-process inode that makes it discriminating.
        assert!(!scheme_is_current("linux-starttime:112163742"));
        #[cfg(target_os = "linux")]
        assert!(
            !scheme_is_current("macos-starttime:1750000000.000001"),
            "a record carried from another kind of host must not be honoured"
        );
        for malformed in ["", "not-a-token", "linux-pidfs:", ":112163742"] {
            assert!(
                !scheme_is_current(malformed),
                "a token with no readable scheme and value must not pass: {malformed:?}"
            );
        }
    }

    #[test]
    fn identity_of_a_dead_pid_is_unavailable() {
        let mut child = std::process::Command::new("true").spawn().expect("spawn `true`");
        let pid = child.id();
        child.wait().expect("wait for `true`");
        assert!(start_token(pid).is_none(), "a dead pid must yield no start token");
        assert!(image(pid).path().is_none(), "a dead pid must yield no executable path");
    }

    /// AAASM-5323 regression. `aa-proxy` marks itself non-dumpable at startup
    /// (`prctl(PR_SET_DUMPABLE, 0)`, AAASM-3584), and the Linux kernel then
    /// refuses `readlink("/proc/<pid>/exe")` to *every* caller without
    /// `CAP_SYS_PTRACE` — including the user who started it. The first cut of
    /// this module read only that symlink, so on Linux it reported "no identity"
    /// for every genuine proxy and `aasm run` refused to launch, always.
    ///
    /// macOS has no equivalent, which is exactly why the defect was invisible
    /// there; the case is therefore pinned on Linux specifically.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_process_that_hides_itself_from_ptrace_is_still_identifiable() {
        let expected = std::fs::canonicalize(std::env::current_exe().expect("current_exe")).expect("canonicalize");
        let child = NonDumpableChild::spawn();

        // Precondition, not decoration: if the authoritative source still
        // answered, the fallback below would never run and this test would pass
        // while measuring nothing.
        let denied = std::fs::read_link(format!("/proc/{}/exe", child.pid))
            .expect_err("the child was supposed to have hidden its image from us");
        assert_eq!(
            denied.kind(),
            std::io::ErrorKind::PermissionDenied,
            "expected the ptrace gate to refuse the read, got {denied}"
        );

        let evidence = image(child.pid);
        assert_eq!(
            evidence,
            ImageEvidence::InvokedAs(expected),
            "a live process that hid itself must still be identifiable, and must be reported as \
             identified by its argv rather than by the kernel"
        );
        assert!(is_alive(child.pid), "the child must still be running");
        assert!(
            start_token(child.pid).is_some(),
            "/proc/<pid>/stat is not behind the ptrace gate, so the start time must still read"
        );
    }

    /// The fallback must not be a way in for a process that is *gone*. A zombie
    /// still answers `kill(pid, 0)` and still has a readable `stat` (so the start
    /// time alone would wave it through), but its address space is released, so
    /// it has neither an executable link nor a command line.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_zombie_has_no_image_evidence() {
        let mut child = std::process::Command::new("true").spawn().expect("spawn `true`");
        let pid = child.id();
        wait_for_state(pid, b'Z');

        let evidence = image(pid);
        child.wait().expect("reap `true`");

        assert!(
            matches!(evidence, ImageEvidence::Unreadable(_)),
            "an exited-but-unreaped process must yield no image; got {evidence:?}"
        );
    }

    /// Block until `/proc/<pid>/stat` reports `state`, so a test that depends on
    /// a process having reached it is not racing the scheduler.
    #[cfg(target_os = "linux")]
    fn wait_for_state(pid: u32, state: u8) {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while std::time::Instant::now() < deadline {
            let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap_or_default();
            if let Some(rest) = stat.rfind(')').and_then(|i| stat.get(i + 2..)) {
                if rest.as_bytes().first() == Some(&state) {
                    return;
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        panic!("pid {pid} never reached state {}", state as char);
    }

    /// A child of this process that has applied the same hardening `aa-proxy`
    /// applies to itself, so the ptrace gate the fix has to survive is the real
    /// kernel one and not a simulation of it.
    ///
    /// It is produced with a bare `fork` rather than `Command`, because
    /// `execve` resets the dumpable flag: only a process that sets it *after*
    /// its last exec is non-dumpable, which is precisely the shape `aa-proxy`
    /// has. The child touches nothing but async-signal-safe calls, so forking
    /// from libtest's threaded harness is sound; it is killed and reaped on
    /// drop rather than exiting on its own.
    #[cfg(target_os = "linux")]
    struct NonDumpableChild {
        pid: u32,
    }

    #[cfg(target_os = "linux")]
    impl NonDumpableChild {
        fn spawn() -> Self {
            // Safety: the child path calls only `prctl`, `pause` and `_exit`,
            // all async-signal-safe; it never returns into test code.
            let pid = unsafe { libc::fork() };
            assert!(pid >= 0, "fork failed: {}", std::io::Error::last_os_error());
            if pid == 0 {
                unsafe {
                    libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
                    loop {
                        libc::pause();
                    }
                }
            }
            let child = Self { pid: pid as u32 };
            child.wait_until_hidden();
            child
        }

        /// `fork` returns in the parent before the child has run `prctl`, so the
        /// parent must not read until the flag is actually set.
        fn wait_until_hidden(&self) {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
            while std::time::Instant::now() < deadline {
                match std::fs::read_link(format!("/proc/{}/exe", self.pid)) {
                    Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => return,
                    _ => std::thread::sleep(std::time::Duration::from_millis(10)),
                }
            }
            panic!("pid {} never became non-dumpable", self.pid);
        }
    }

    #[cfg(target_os = "linux")]
    impl Drop for NonDumpableChild {
        fn drop(&mut self) {
            // Safety: both calls take the PID by value; the child is ours to reap.
            unsafe {
                libc::kill(self.pid as libc::pid_t, libc::SIGKILL);
                libc::waitpid(self.pid as libc::pid_t, std::ptr::null_mut(), 0);
            }
        }
    }
}
