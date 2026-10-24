//! Capability-lease state record (AAASM-6259, J81 Option A).
//!
//! Only the durable record format, its library API and the operator CLI's
//! storage live here. Nothing in this module is read by the runtime yet, so no
//! runtime behaviour is changed by it and none should be inferred from it.

#[cfg(unix)]
pub mod state;
