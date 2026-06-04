//! Tokio async runtime wrapper and agent lifecycle management.
//!
//! This crate wraps `tokio` to provide a consistent async execution environment
//! for Agent Assembly components. It handles runtime initialization, shutdown
//! coordination, and lifecycle hooks.

pub mod approval;
pub mod approval_sink;
pub mod audit_publisher;
pub mod config;
pub mod correlation;
#[cfg(target_os = "linux")]
pub mod ebpf_bridge;
pub mod gateway_client;
pub mod health;
pub mod invalidation_client;
pub mod ipc;
pub mod l1_cache;
pub mod layer;
pub mod lifecycle;
pub mod pipeline;
pub mod policy;
pub mod runtime;

pub use runtime::run;
