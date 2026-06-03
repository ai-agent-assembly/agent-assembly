//! In-memory `aa-storage` driver.
//!
//! `DashMap`- and `parking_lot`-backed implementations of the six storage
//! traits, for unit/integration tests and local development without a real
//! database. State is ephemeral — it lives only for the life of the process.

mod audit_sink;
mod credential_store;

pub use audit_sink::MemoryAuditSink;
pub use credential_store::MemoryCredentialStore;
