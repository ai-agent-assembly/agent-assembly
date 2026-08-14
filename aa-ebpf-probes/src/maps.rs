//! BPF map definitions for file I/O kprobes.

use aa_ebpf_common::file::{FdPathKey, FileIoEventRaw, MAX_ENTRIES, MAX_PATH_LEN, MAX_PATH_PATTERNS};
use aa_ebpf_common::syscall::MAX_SYSCALL_ALLOWLIST;
use aya_ebpf::macros::map;
use aya_ebpf::maps::{HashMap, PerfEventArray};

/// Perf event array for sending file I/O events to userspace.
#[map]
pub static EVENTS: PerfEventArray<FileIoEventRaw> = PerfEventArray::new(0);

/// PID filter: only monitor processes whose PID is a key in this map.
/// Value is unused (u8 placeholder).
#[map]
pub static PID_FILTER: HashMap<u32, u8> = HashMap::with_max_entries(MAX_ENTRIES, 0);

/// Cache of (pid, fd) → file path, populated by the openat kretprobe.
/// Used by read/write kprobes to resolve fd to a path.
#[map]
pub static FD_PATH_MAP: HashMap<FdPathKey, [u8; MAX_PATH_LEN]> =
    HashMap::with_max_entries(MAX_ENTRIES, 0);

/// Temporary map to pass the filename from the openat kprobe entry
/// to the openat kretprobe (keyed by pid_tgid).
#[map]
pub static OPENAT_TMP: HashMap<u64, [u8; MAX_PATH_LEN]> =
    HashMap::with_max_entries(MAX_ENTRIES, 0);

/// Temporary map to pass the entry timestamp from the openat kprobe
/// entry to the openat kretprobe (keyed by pid_tgid). Used to compute
/// end-to-end syscall duration for the emitted `FileIoEventRaw`.
#[map]
pub static OPENAT_ENTRY_TS: HashMap<u64, u64> = HashMap::with_max_entries(MAX_ENTRIES, 0);

/// Temporary map to pass the resolved path from the read kprobe entry
/// to the read kretprobe (keyed by pid_tgid). The fd is only available
/// at entry, so the path is looked up via `FD_PATH_MAP` there and
/// stashed here for the kretprobe to read.
#[map]
pub static READ_TMP: HashMap<u64, [u8; MAX_PATH_LEN]> = HashMap::with_max_entries(MAX_ENTRIES, 0);

/// Temporary map to pass the entry timestamp from the read kprobe entry
/// to the read kretprobe (keyed by pid_tgid).
#[map]
pub static READ_ENTRY_TS: HashMap<u64, u64> = HashMap::with_max_entries(MAX_ENTRIES, 0);

/// Temporary map to pass the resolved path from the write kprobe entry
/// to the write kretprobe (keyed by pid_tgid). Same fd-context reason
/// as `READ_TMP`.
#[map]
pub static WRITE_TMP: HashMap<u64, [u8; MAX_PATH_LEN]> = HashMap::with_max_entries(MAX_ENTRIES, 0);

/// Temporary map to pass the entry timestamp from the write kprobe
/// entry to the write kretprobe (keyed by pid_tgid).
#[map]
pub static WRITE_ENTRY_TS: HashMap<u64, u64> = HashMap::with_max_entries(MAX_ENTRIES, 0);

/// Temporary map to pass the pathname (read from the syscall argument)
/// from the unlink kprobe entry to the unlink kretprobe (keyed by
/// `pid_tgid`). Unlinkat's path comes from `arg1`, not `FD_PATH_MAP`,
/// so it must be stashed at entry for the kretprobe to emit.
#[map]
pub static UNLINK_TMP: HashMap<u64, [u8; MAX_PATH_LEN]> =
    HashMap::with_max_entries(MAX_ENTRIES, 0);

/// Temporary map to pass the entry timestamp from the unlink kprobe
/// entry to the unlink kretprobe (keyed by pid_tgid).
#[map]
pub static UNLINK_ENTRY_TS: HashMap<u64, u64> = HashMap::with_max_entries(MAX_ENTRIES, 0);

/// Temporary map to pass the source pathname (read from `renameat2`'s
/// `arg1` = `oldpath`) from the rename kprobe entry to the rename
/// kretprobe (keyed by `pid_tgid`). Same arg-source reason as
/// `UNLINK_TMP`.
#[map]
pub static RENAME_TMP: HashMap<u64, [u8; MAX_PATH_LEN]> =
    HashMap::with_max_entries(MAX_ENTRIES, 0);

/// Temporary map to pass the entry timestamp from the rename kprobe
/// entry to the rename kretprobe (keyed by pid_tgid).
#[map]
pub static RENAME_ENTRY_TS: HashMap<u64, u64> = HashMap::with_max_entries(MAX_ENTRIES, 0);

/// Path blocklist: paths whose access should be flagged as sensitive.
///
/// **Match contract (AAASM-3921a/b — corrected).** The key is the **exact,
/// NUL-padded full path** as captured from the syscall argument, and the kprobe
/// does an **exact `HashMap::get` equality** match — NOT a hash of a prefix and
/// NOT a directory-prefix match. Earlier docs claimed "hash of the path prefix"
/// / prefix matching; the implementation never did either, so directory deny
/// rules (e.g. `/etc/`) silently never fired and non-canonical paths
/// (`/etc//shadow`, `/etc/../etc/shadow`, symlinks) evaded the in-kernel check.
///
/// Because this layer is **OBSERVE-ONLY** (it sets an alert flag; it does not
/// deny), prefix and canonicalization matching are reconciled in userspace:
/// [`SensitivePathDetector`](../../aa_ebpf/alert/struct.SensitivePathDetector.html)
/// canonicalizes each event path and does boundary-aware prefix matching, and
/// the final `is_sensitive` verdict is the OR of the kernel exact-match flag
/// and the userspace canonical-prefix match.
///
/// **Deferred (needs Linux):** moving canonicalization / prefix matching into
/// the kernel requires a `d_path` / dentry walk, which cannot be written or
/// verifier-validated without a Linux kernel target — tracked under AAASM-3921.
#[map]
pub static PATH_BLOCKLIST: HashMap<[u8; MAX_PATH_LEN], u8> =
    HashMap::with_max_entries(MAX_PATH_PATTERNS, 0);

/// Path allowlist: paths whose events should be suppressed.
///
/// If a path matches this map the kprobe skips event emission entirely. Same
/// **exact, NUL-padded full-path equality** contract as [`PATH_BLOCKLIST`]
/// (see its docs for the prefix/canonicalization reconciliation and the
/// deferred in-kernel `d_path` work). Value is `1` (allow / suppress).
#[map]
pub static PATH_ALLOWLIST: HashMap<[u8; MAX_PATH_LEN], u8> =
    HashMap::with_max_entries(MAX_PATH_PATTERNS, 0);

/// Syscall allowlist for the seccomp-style enforcement probe (AAASM-3631).
/// Key is the syscall number; a present key means the syscall is permitted
/// for monitored PIDs. The `syscall_guard` tracepoint default-denies (kills)
/// any monitored PID issuing a syscall NOT in this map. Populated by the
/// privileged loader daemon from the policy AST lowering (AAASM-3635).
#[map]
pub static SYSCALL_ALLOWLIST: HashMap<u32, u8> = HashMap::with_max_entries(MAX_SYSCALL_ALLOWLIST, 0);
