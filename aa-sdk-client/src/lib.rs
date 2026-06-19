//! Shared SDK runtime-client for Agent Assembly.
//!
//! `aa-sdk-client` is the single, FFI-agnostic implementation of the agent-side
//! SDK runtime client: the Unix-domain-socket transport, the IPC wire codec, the
//! `AssemblyClient` lifecycle, and event capture/shipping to `aa-runtime`. The
//! per-language FFI shims (`aa-ffi-python`, `aa-ffi-node`, `aa-ffi-go`) are thin
//! wrappers over this crate, so the transport/codec/lifecycle logic lives in
//! exactly one place and cannot drift between languages.
//!
//! # Trust model
//!
//! The SDK is **untrusted** and is **not** a security boundary. Authoritative
//! credential scanning, redaction, and normalization happen at the mandatory
//! runtime chokepoint (`aa-runtime`, AAASM-2568), which re-scans every event
//! unconditionally. Any credential preflight this crate performs (behind the
//! `preflight` feature) is **advisory, best-effort only**: it never sets a
//! `clean` / `already_scanned` marker on the wire, and nothing it asserts can
//! shorten the runtime's work.
//!
//! # Layout
//!
//! This crate is built up across the AAASM-2570 subtask series:
//!
//! - socket config + IPC wire codec — AAASM-2624
//! - UDS transport / background IPC thread — AAASM-2625
//! - `AssemblyClient` lifecycle, event shipping, advisory preflight — AAASM-2626

pub mod client;
pub mod codec;
pub mod config;
pub mod error;
pub mod gateway;
pub mod identity;
pub mod ipc;
pub mod keypair;
#[cfg(feature = "preflight")]
pub mod preflight;

pub use client::AssemblyClient;
pub use config::AssemblyConfig;
pub use error::SdkClientError;
pub use identity::agent_id_to_did_key;
pub use keypair::AgentKeypair;
#[cfg(feature = "preflight")]
pub use preflight::Preflight;
