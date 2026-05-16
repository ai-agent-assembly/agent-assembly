//! BPF map definitions for file I/O kprobes.

use aa_ebpf_common::file::{FdPathKey, FileIoEventRaw, MAX_ENTRIES, MAX_PATH_LEN, MAX_PATH_PATTERNS};
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

/// Path pattern blocklist: paths that should trigger an alert.
/// Key is a hash of the path prefix, value is 1 (deny).
#[map]
pub static PATH_BLOCKLIST: HashMap<[u8; MAX_PATH_LEN], u8> =
    HashMap::with_max_entries(MAX_PATH_PATTERNS, 0);

/// Path pattern allowlist: paths whose events should be suppressed.
/// If a path matches this map, the kprobe skips event emission entirely.
/// Key is the path (null-padded), value is 1 (allow / suppress).
#[map]
pub static PATH_ALLOWLIST: HashMap<[u8; MAX_PATH_LEN], u8> =
    HashMap::with_max_entries(MAX_PATH_PATTERNS, 0);
