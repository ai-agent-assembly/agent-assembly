//! Shared no_std event types for the aa-ebpf kernel/userspace boundary.
//!
//! This crate is compiled twice:
//! - For the **host** target by `aa-ebpf` (userspace consumer).
//! - For the **bpf** target by `aa-ebpf-programs` (kernel-space producer).
//!
//! All types are `#[repr(C)]` and `Copy` so they can be safely transferred
//! through the BPF ring buffer without serialisation overhead.
//!
//! ## Modules
//!
//! | Module | Event type | Task |
//! |--------|-----------|------|
//! | [`tls`] | [`tls::TlsCaptureEvent`] | AAASM-37 — OpenSSL uprobe |
//! | [`file`] | [`file::FileIoEventRaw`] | AAASM-38 — file I/O kprobes |
//! | [`exec`] | [`exec::ProcessSpawnEvent`] | AAASM-39 — exec tracepoints |
//! | [`syscall`] | allowlist map constants | AAASM-3631 — syscall guard |
//! | [`abi`] | [`abi::native_syscall_nr`] | AAASM-3872 — compat-ABI guard |

// `no_std` for the bpf target and host builds; the unit-test harness for the
// pure-logic helpers (e.g. `abi`, `exec::flatten_argv_bounded`) needs `std`.
#![cfg_attr(not(test), no_std)]

pub mod abi;
pub mod exec;
pub mod file;
pub mod syscall;
pub mod tls;
