//! Bridge between eBPF kernel events and the runtime pipeline.
//!
//! Maps raw eBPF event types from `aa_ebpf` into `AuditEvent` proto messages
//! and enriches them for the broadcast channel.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aa_ebpf::events::{ExecEvent, FileIoEvent, ProcessExitEvent};
use aa_ebpf::syscall::SyscallKind;
use aa_proto::assembly::audit::v1::audit_event::Detail;
use aa_proto::assembly::audit::v1::{AuditEvent, FileOpDetail, ProcessExecDetail};
use aa_proto::assembly::common::v1::ActionType;

use crate::pipeline::{EnrichedEvent, EventSource};

/// Convert a file I/O eBPF event into an [`AuditEvent`] proto message.
///
/// Maps `SyscallKind` to the proto `operation` string and populates
/// a `FileOpDetail` with the path and detection source set to `"ebpf"`.
pub fn file_io_to_audit(event: &FileIoEvent) -> AuditEvent {
    let operation = match event.syscall {
        SyscallKind::Openat => "create",
        SyscallKind::Read => "read",
        SyscallKind::Write => "write",
        SyscallKind::Unlink => "delete",
        SyscallKind::Rename => "rename",
    }
    .to_string();

    AuditEvent {
        action_type: ActionType::FileOperation.into(),
        detail: Some(Detail::FileOp(FileOpDetail {
            operation,
            path: event.path.clone(),
            bytes: 0,
            source: "ebpf".to_string(),
            // eBPF events are point-in-time syscall traces, not durations.
            // Real measurement pending AAASM-1425.
            latency_ms: 0,
        })),
        ..AuditEvent::default()
    }
}

/// Extract a null-terminated UTF-8 string from a fixed-size byte buffer.
fn str_from_buf(buf: &[u8]) -> String {
    let nul = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..nul]).into_owned()
}

/// Convert an exec tracepoint event into an [`AuditEvent`] proto message.
///
/// Extracts the executable path from `filename` and the argument string from
/// `args` (both fixed-size null-terminated byte buffers). Populates a
/// `ProcessExecDetail` with `succeeded = true` (exec itself succeeded).
pub fn exec_event_to_audit(event: &ExecEvent) -> AuditEvent {
    let command = str_from_buf(&event.filename);
    let args_str = str_from_buf(&event.args);
    let args: Vec<String> = if args_str.is_empty() {
        Vec::new()
    } else {
        args_str.split(' ').map(String::from).collect()
    };

    AuditEvent {
        action_type: ActionType::ProcessExec.into(),
        detail: Some(Detail::Process(ProcessExecDetail {
            command,
            args,
            exit_code: 0,
            duration_ms: 0,
            succeeded: true,
        })),
        ..AuditEvent::default()
    }
}

/// Convert a process-exit event into an [`AuditEvent`] proto message.
///
/// Sets `succeeded` based on whether the exit code is zero and populates
/// a `ProcessExecDetail` with the exit code. Command and args are empty
/// because the exit event only carries the PID and exit code.
pub fn exit_event_to_audit(event: &ProcessExitEvent) -> AuditEvent {
    AuditEvent {
        action_type: ActionType::ProcessExec.into(),
        detail: Some(Detail::Process(ProcessExecDetail {
            command: String::new(),
            args: Vec::new(),
            exit_code: event.exit_code,
            duration_ms: 0,
            succeeded: event.exit_code == 0,
        })),
        ..AuditEvent::default()
    }
}

/// Wrap an [`AuditEvent`] into an [`EnrichedEvent`] with eBPF-specific metadata.
///
/// Uses the shared sequence counter for unified ordering with SDK events
/// and sets `connection_id = 0` (eBPF events have no IPC connection).
pub fn enrich_ebpf(event: AuditEvent, agent_id: &str, seq: &Arc<AtomicU64>) -> EnrichedEvent {
    let received_at_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_millis() as i64;
    let sequence_number = seq.fetch_add(1, Ordering::Relaxed);
    EnrichedEvent {
        inner: event,
        received_at_ms,
        source: EventSource::EBpf,
        agent_id: agent_id.to_string(),
        connection_id: 0,
        sequence_number,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enrich_ebpf_sets_source_and_connection_id() {
        let audit = AuditEvent::default();
        let seq = Arc::new(AtomicU64::new(0));
        let enriched = enrich_ebpf(audit, "test-agent", &seq);

        assert_eq!(enriched.source, EventSource::EBpf);
        assert_eq!(enriched.connection_id, 0);
        assert_eq!(enriched.agent_id, "test-agent");
        assert!(enriched.received_at_ms > 0);
    }

    #[test]
    fn enrich_ebpf_increments_sequence() {
        let seq = Arc::new(AtomicU64::new(0));
        let e1 = enrich_ebpf(AuditEvent::default(), "a", &seq);
        let e2 = enrich_ebpf(AuditEvent::default(), "a", &seq);

        assert_eq!(e1.sequence_number, 0);
        assert_eq!(e2.sequence_number, 1);
    }

    fn make_file_io(syscall: SyscallKind, path: &str) -> FileIoEvent {
        FileIoEvent {
            pid: 100,
            tid: 101,
            timestamp_ns: 5_000_000,
            syscall,
            path: path.to_string(),
            flags: 0,
            return_code: 0,
            is_sensitive: false,
            duration_ns: 0,
        }
    }

    fn make_exec_event(filename: &str, args: &str) -> ExecEvent {
        let mut fname_buf = [0u8; 256];
        let fb = filename.as_bytes();
        fname_buf[..fb.len()].copy_from_slice(fb);
        let mut args_buf = [0u8; 512];
        let ab = args.as_bytes();
        args_buf[..ab.len()].copy_from_slice(ab);
        ExecEvent {
            timestamp_ns: 1_000_000,
            pid: 42,
            ppid: 1,
            uid: 1000,
            _pad: 0,
            filename: fname_buf,
            args: args_buf,
        }
    }

    #[test]
    fn exec_event_to_audit_extracts_command_and_args() {
        let event = make_exec_event("/usr/bin/curl", "-s https://example.com");
        let audit = exec_event_to_audit(&event);

        assert_eq!(audit.action_type, i32::from(ActionType::ProcessExec));
        let detail = audit.detail.expect("detail should be set");
        match detail {
            Detail::Process(ref p) => {
                assert_eq!(p.command, "/usr/bin/curl");
                assert_eq!(p.args, vec!["-s", "https://example.com"]);
                assert!(p.succeeded);
                assert_eq!(p.exit_code, 0);
            }
            _ => panic!("expected Process detail, got {detail:?}"),
        }
    }

    #[test]
    fn exec_event_to_audit_handles_empty_args() {
        let event = make_exec_event("/bin/true", "");
        let audit = exec_event_to_audit(&event);

        let detail = audit.detail.expect("detail should be set");
        match detail {
            Detail::Process(ref p) => {
                assert_eq!(p.command, "/bin/true");
                assert!(p.args.is_empty());
            }
            _ => panic!("expected Process detail"),
        }
    }

    #[test]
    fn file_io_to_audit_maps_all_syscall_kinds() {
        let cases = [
            (SyscallKind::Openat, "create"),
            (SyscallKind::Read, "read"),
            (SyscallKind::Write, "write"),
            (SyscallKind::Unlink, "delete"),
            (SyscallKind::Rename, "rename"),
        ];
        for (kind, expected_op) in cases {
            let event = make_file_io(kind, "/tmp/test.txt");
            let audit = file_io_to_audit(&event);

            assert_eq!(audit.action_type, i32::from(ActionType::FileOperation));
            let detail = audit.detail.expect("detail should be set");
            match detail {
                Detail::FileOp(ref fop) => {
                    assert_eq!(fop.operation, expected_op, "syscall {kind:?}");
                    assert_eq!(fop.path, "/tmp/test.txt");
                    assert_eq!(fop.source, "ebpf");
                }
                _ => panic!("expected FileOp detail, got {detail:?}"),
            }
        }
    }

    #[test]
    fn exit_event_to_audit_success_exit() {
        let event = ProcessExitEvent {
            timestamp_ns: 2_000_000,
            pid: 42,
            exit_code: 0,
        };
        let audit = exit_event_to_audit(&event);

        assert_eq!(audit.action_type, i32::from(ActionType::ProcessExec));
        let detail = audit.detail.expect("detail should be set");
        match detail {
            Detail::Process(ref p) => {
                assert!(p.succeeded);
                assert_eq!(p.exit_code, 0);
                assert!(p.command.is_empty());
            }
            _ => panic!("expected Process detail"),
        }
    }

    #[test]
    fn exit_event_to_audit_nonzero_exit() {
        let event = ProcessExitEvent {
            timestamp_ns: 3_000_000,
            pid: 42,
            exit_code: 137,
        };
        let audit = exit_event_to_audit(&event);

        let detail = audit.detail.expect("detail should be set");
        match detail {
            Detail::Process(ref p) => {
                assert!(!p.succeeded);
                assert_eq!(p.exit_code, 137);
            }
            _ => panic!("expected Process detail"),
        }
    }
}
