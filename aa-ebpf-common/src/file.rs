//! Shared types for file I/O kprobe events (AAASM-38).
//!
//! Emitted by `openat`, `read`, `write`, `unlink`, and `rename` kprobes in
//! `aa-ebpf-probes` and consumed by the userspace loader in `aa-ebpf`.

/// Maximum byte length of a file path stored in a BPF event or map entry.
pub const MAX_PATH_LEN: usize = 256;

/// Maximum number of events buffered in the perf event array.
pub const MAX_ENTRIES: u32 = 1024;

/// Maximum number of path patterns in the blocklist/allowlist BPF map.
pub const MAX_PATH_PATTERNS: u32 = 256;

/// Identifies which file-related syscall was intercepted.
///
/// Uses `#[repr(u32)]` for BPF compatibility (BPF maps require 4-byte alignment).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum SyscallType {
    /// `sys_openat` — open or create a file.
    Openat = 0,
    /// `sys_read` — read from a file descriptor.
    Read = 1,
    /// `sys_write` — write to a file descriptor.
    Write = 2,
    /// `sys_unlink` — delete a file.
    Unlink = 3,
    /// `sys_rename` — rename or move a file.
    Rename = 4,
}

/// A file I/O event emitted by a kprobe, in BPF-compatible layout.
///
/// This struct is written by BPF programs into a `PerfEventArray` and read
/// by the userspace loader. Both sides must agree on this exact layout.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct FileIoEventRaw {
    /// Process ID of the intercepted syscall.
    pub pid: u32,
    /// Thread ID of the intercepted syscall.
    pub tid: u32,
    /// Kernel timestamp in nanoseconds (from `bpf_ktime_get_ns`).
    pub timestamp_ns: u64,
    /// Which syscall was intercepted.
    pub syscall: SyscallType,
    /// Syscall-specific flags (e.g., `O_RDONLY` for `openat`).
    pub flags: u32,
    /// Syscall return code.
    pub return_code: i64,
    /// End-to-end syscall duration in nanoseconds (exit_ts − enter_ts).
    ///
    /// Populated by kretprobes that pair with an entry kprobe via a
    /// per-tid timestamp map. `0` when the syscall has only an entry
    /// hook (currently: read / write / unlink / rename — tracked under
    /// the AAASM-1425 follow-up for the remaining syscalls).
    pub duration_ns: u64,
    /// File path as a null-terminated byte array.
    pub path: [u8; MAX_PATH_LEN],
}

unsafe impl Send for FileIoEventRaw {}
unsafe impl Sync for FileIoEventRaw {}

/// Key for the fd-to-path BPF hash map: (pid, fd).
#[derive(Clone, Copy)]
#[repr(C)]
pub struct FdPathKey {
    /// Process ID that opened the file.
    pub pid: u32,
    /// File descriptor number returned by `openat`.
    pub fd: u64,
}
