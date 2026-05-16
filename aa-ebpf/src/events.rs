//! Event types emitted by eBPF probes.
//!
//! Re-exports shared event types from [`aa_ebpf_common`] and defines
//! userspace-only event types for file I/O kprobes.

pub use aa_ebpf_common::exec::{
    AlertLevel, ExecEvent, ProcessExitEvent, ProcessNode, ProcessSpawnEvent, ShellInjectionAlert, MAX_ARGV_ENTRIES,
    MAX_ARGV_LEN, MAX_EXECUTABLE_LEN,
};

use crate::error::EbpfError;
use crate::syscall::SyscallKind;
use aa_ebpf_common::file::{FileIoEventRaw, SyscallType};

/// A file I/O event captured by a kprobe.
///
/// Each event represents a single syscall interception with the metadata
/// needed to evaluate governance policies (PID lineage, file path, flags).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileIoEvent {
    /// Process ID of the intercepted syscall.
    pub pid: u32,
    /// Thread ID of the intercepted syscall.
    pub tid: u32,
    /// Kernel timestamp in nanoseconds (from `bpf_ktime_get_ns`).
    pub timestamp_ns: u64,
    /// Which syscall was intercepted.
    pub syscall: SyscallKind,
    /// File path associated with the syscall.
    pub path: String,
    /// Syscall-specific flags (e.g., `O_RDONLY` for `openat`).
    pub flags: u32,
    /// Syscall return code (`0` for success on entry probes).
    pub return_code: i64,
    /// Whether this event matched a blocklisted path (flags bit 0).
    pub is_sensitive: bool,
    /// End-to-end syscall duration in nanoseconds (`exit_ts − enter_ts`).
    ///
    /// `0` when the syscall has only an entry hook today (read /
    /// write / unlink / rename — tracked under the AAASM-1425 follow-up).
    /// Populated for `openat` via the entry-timestamp map.
    pub duration_ns: u64,
}

impl FileIoEvent {
    /// Parse a [`FileIoEventRaw`] received from the BPF perf event array
    /// into a userspace-friendly [`FileIoEvent`].
    pub fn from_raw(raw: &FileIoEventRaw) -> Result<Self, EbpfError> {
        let syscall = match raw.syscall {
            SyscallType::Openat => SyscallKind::Openat,
            SyscallType::Read => SyscallKind::Read,
            SyscallType::Write => SyscallKind::Write,
            SyscallType::Unlink => SyscallKind::Unlink,
            SyscallType::Rename => SyscallKind::Rename,
        };

        // Extract the null-terminated path from the fixed-size buffer.
        let nul_pos = raw.path.iter().position(|&b| b == 0).unwrap_or(raw.path.len());
        let path = core::str::from_utf8(&raw.path[..nul_pos])
            .map_err(|e| EbpfError::EventParse(format!("invalid UTF-8 in path: {e}")))?
            .to_string();

        Ok(Self {
            pid: raw.pid,
            tid: raw.tid,
            timestamp_ns: raw.timestamp_ns,
            syscall,
            path,
            flags: raw.flags,
            return_code: raw.return_code,
            is_sensitive: raw.flags & 1 != 0,
            duration_ns: raw.duration_ns,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aa_ebpf_common::file::MAX_PATH_LEN;

    fn make_raw(path: &str, syscall: SyscallType, flags: u32) -> FileIoEventRaw {
        let mut path_buf = [0u8; MAX_PATH_LEN];
        let bytes = path.as_bytes();
        path_buf[..bytes.len()].copy_from_slice(bytes);
        FileIoEventRaw {
            pid: 42,
            tid: 43,
            timestamp_ns: 1_000_000,
            syscall,
            flags,
            return_code: 3,
            duration_ns: 0,
            path: path_buf,
        }
    }

    #[test]
    fn file_io_event_construction() {
        let event = FileIoEvent {
            pid: 1234,
            tid: 1234,
            timestamp_ns: 999_999,
            syscall: SyscallKind::Openat,
            path: "/etc/shadow".into(),
            flags: 0,
            return_code: 0,
            is_sensitive: false,
            duration_ns: 0,
        };
        assert_eq!(event.pid, 1234);
        assert_eq!(event.syscall, SyscallKind::Openat);
        assert_eq!(event.path, "/etc/shadow");
    }

    #[test]
    fn from_raw_carries_duration_ns_through() {
        let mut raw = make_raw("/tmp/timed.txt", SyscallType::Openat, 0);
        raw.duration_ns = 123_456;
        let event = FileIoEvent::from_raw(&raw).expect("parse");
        assert_eq!(event.duration_ns, 123_456);
    }

    #[test]
    fn from_raw_parses_openat() {
        let raw = make_raw("/tmp/test.txt", SyscallType::Openat, 0);
        let event = FileIoEvent::from_raw(&raw).unwrap();
        assert_eq!(event.pid, 42);
        assert_eq!(event.tid, 43);
        assert_eq!(event.timestamp_ns, 1_000_000);
        assert_eq!(event.syscall, SyscallKind::Openat);
        assert_eq!(event.path, "/tmp/test.txt");
        assert_eq!(event.return_code, 3);
        assert!(!event.is_sensitive);
    }

    #[test]
    fn from_raw_parses_all_syscall_types() {
        let cases = [
            (SyscallType::Openat, SyscallKind::Openat),
            (SyscallType::Read, SyscallKind::Read),
            (SyscallType::Write, SyscallKind::Write),
            (SyscallType::Unlink, SyscallKind::Unlink),
            (SyscallType::Rename, SyscallKind::Rename),
        ];
        for (raw_kind, expected_kind) in cases {
            let raw = make_raw("/x", raw_kind, 0);
            let event = FileIoEvent::from_raw(&raw).unwrap();
            assert_eq!(event.syscall, expected_kind);
        }
    }

    #[test]
    fn from_raw_sensitive_flag() {
        let raw = make_raw("/etc/shadow", SyscallType::Openat, 1);
        let event = FileIoEvent::from_raw(&raw).unwrap();
        assert!(event.is_sensitive);
    }

    #[test]
    fn from_raw_no_sensitive_flag() {
        let raw = make_raw("/tmp/ok", SyscallType::Read, 0);
        let event = FileIoEvent::from_raw(&raw).unwrap();
        assert!(!event.is_sensitive);
    }

    #[test]
    fn from_raw_truncates_at_null() {
        let raw = make_raw("/a", SyscallType::Write, 0);
        let event = FileIoEvent::from_raw(&raw).unwrap();
        assert_eq!(event.path, "/a");
    }

    #[test]
    fn from_raw_empty_path() {
        let raw = make_raw("", SyscallType::Unlink, 0);
        let event = FileIoEvent::from_raw(&raw).unwrap();
        assert_eq!(event.path, "");
    }
}
