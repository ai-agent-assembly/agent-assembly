//! eBPF-based kernel-level monitoring hooks for Agent Assembly — Layer 3.
//!
//! This crate is the **userspace** half of the aa-ebpf subsystem.  It loads
//! the compiled eBPF programs (from `aa-ebpf-probes`), attaches the probes
//! to the kernel, and reads structured events from the shared BPF ring buffer.
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────┐
//! │  aa-ebpf (userspace)                         │
//! │                                              │
//! │  EbpfLoader ──► UprobeManager  (AAASM-37)   │
//! │             ──► KprobeManager  (AAASM-38)   │
//! │             ──► TracepointManager (AAASM-39) │
//! │                                              │
//! │  RingBufReader ◄── BPF ring buffer           │
//! └─────────────────────────────────────────────┘
//!          │ kernel boundary │
//! ┌─────────────────────────────────────────────┐
//! │  aa-ebpf-probes (bpfel-unknown-none)         │
//! │                                              │
//! │  ssl_write_uprobe / ssl_read_uretprobe       │
//! │  openat_kprobe / write_kprobe / unlink_kprobe│
//! │  sched_process_exec (tracepoint)             │
//! └─────────────────────────────────────────────┘
//! ```
//!
//! ## Shared types
//!
//! Event structs shared between kernel-space and userspace live in
//! [`aa_ebpf_common`].  They are `#[repr(C)]` and `no_std` so they compile
//! for both targets without modification.
//!
//! ## Platform support
//!
//! eBPF is Linux-only. On macOS, this crate compiles but most aya-dependent
//! modules (`uprobe`, `kprobe`, `ringbuf`) are gated with
//! `#[cfg(target_os = "linux")]`.  The `tracepoint` module is cross-platform
//! (aya-dependent code is gated internally; non-Linux stubs are provided).
//! Cross-platform modules (`events`, `lineage`, `alert`, `error`, `loader`,
//! `maps`, `syscall`) are available on all platforms.

// Cross-platform modules (no aya dependency).
pub mod agent_discover;
pub mod alert;
pub mod error;
pub mod events;
pub mod kprobes;
pub mod lineage;
pub mod loader;
pub mod maps;
pub mod shell_detect;
pub mod syscall;

// aya-dependent modules — Linux only (except kprobe which has a non-Linux stub).
pub mod kprobe;
#[cfg(target_os = "linux")]
pub mod ringbuf;
// tracepoint is cross-platform: aya-dependent code is gated internally,
// and non-Linux stubs provide a consistent API surface.
pub mod tracepoint;
#[cfg(target_os = "linux")]
pub mod uprobe;

pub use alert::SensitivePathDetector;
pub use error::EbpfError;
pub use events::FileIoEvent;
pub use lineage::ProcessLineageTracker;
pub use loader::{EbpfLoader, ExecLoader, FileIoLoader};
pub use maps::{PathPattern, PathVerdict, MAX_PATH_LEN, MAX_PATH_PATTERNS};
#[cfg(target_os = "linux")]
pub use ringbuf::EbpfEvent;
pub use shell_detect::ShellDetector;
pub use syscall::SyscallKind;

/// Compiled BPF bytecode for the file I/O probe program.
///
/// Embedded from `aa-ebpf-probes/src/main.rs` at build time via `aya-build`.
/// Contains kprobes for openat, read, write, unlink, and rename syscalls.
/// Pass this slice to [`aya::Ebpf::load`] to obtain a handle to all programs
/// in the probe crate.
///
/// Only meaningful on Linux — on other platforms this constant is absent.
#[cfg(target_os = "linux")]
pub static AA_FILE_IO_BPF: &[u8] = aya::include_bytes_aligned!(concat!(
    env!("OUT_DIR"),
    "/aa-ebpf-probes/bpfel-unknown-none/release/aa-file-io"
));

/// Compiled BPF bytecode for the exec tracepoint programs (AAASM-39).
///
/// Embedded from `aa-ebpf-probes/src/exec_probes.rs` at build time.
/// Contains two programs: `handle_sched_process_exec`, `handle_sched_process_exit`.
/// Pass this slice to [`aya::Ebpf::load`] to obtain a handle.
///
/// Only meaningful on Linux — on other platforms this constant is absent.
#[cfg(target_os = "linux")]
pub static AA_EXEC_BPF: &[u8] = aya::include_bytes_aligned!(concat!(
    env!("OUT_DIR"),
    "/aa-ebpf-probes/bpfel-unknown-none/release/aa-exec-probes"
));

/// Compiled BPF bytecode for the TLS uprobe programs (AAASM-37).
///
/// Embedded from `aa-ebpf-probes/src/ssl_probes.rs` at build time.
/// Contains three programs: `ssl_write`, `ssl_read_entry`, `ssl_read_exit`.
/// Pass this slice to [`aya::Ebpf::load`] to obtain a handle.
///
/// Only meaningful on Linux — on other platforms this constant is absent.
#[cfg(target_os = "linux")]
pub static AA_TLS_BPF: &[u8] = aya::include_bytes_aligned!(concat!(
    env!("OUT_DIR"),
    "/aa-ebpf-probes/bpfel-unknown-none/release/aa-tls-probes"
));
