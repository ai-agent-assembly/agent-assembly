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

#![no_std]

pub mod exec;
pub mod file;
pub mod syscall;
pub mod tls;
