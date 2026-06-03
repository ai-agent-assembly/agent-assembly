//! In-memory `aa-storage` driver.
//!
//! `DashMap`- and `parking_lot`-backed implementations of the six storage
//! traits, for unit/integration tests and local development without a real
//! database. State is ephemeral — it lives only for the life of the process.
//!
//! Each store is a self-contained backend. Selecting them by name and building
//! them from an `agent-assembly.toml` `[storage]` section is the job of the
//! `aa-storage` driver registry (AAASM-2361) and the boot wiring, not this crate.

mod audit_sink;
mod credential_store;
mod lifecycle_store;
mod policy_store;
mod rate_limit_counter;
mod session_store;

pub use audit_sink::MemoryAuditSink;
pub use credential_store::MemoryCredentialStore;
pub use lifecycle_store::MemoryLifecycleStore;
pub use policy_store::MemoryPolicyStore;
pub use rate_limit_counter::MemoryRateLimitCounter;
pub use session_store::MemorySessionStore;
