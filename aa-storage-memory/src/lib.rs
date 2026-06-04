//! In-memory `aa-storage` driver.
//!
//! `DashMap`- and `parking_lot`-backed implementations of the six storage
//! traits, for unit/integration tests and local development without a real
//! database. State is ephemeral — it lives only for the life of the process.
//!
//! # Driver registration
//!
//! Call [`register`] from boot code to announce all six backends to an
//! [`aa_storage::Registry`] under [`DRIVER_NAME`] (`"memory"`), so an
//! `agent-assembly.toml` `[storage]` section can select them by name. The
//! per-kind [`factory`] types build a store from its `[storage.memory]`
//! subsection (which the memory driver ignores — it needs no connection
//! settings).

pub mod factory;

mod audit_sink;
mod credential_store;
mod lifecycle_store;
mod policy_store;
mod rate_limit_counter;
mod registration;
mod session_store;

pub use audit_sink::MemoryAuditSink;
pub use credential_store::MemoryCredentialStore;
pub use lifecycle_store::MemoryLifecycleStore;
pub use policy_store::MemoryPolicyStore;
pub use rate_limit_counter::MemoryRateLimitCounter;
pub use registration::{register, DRIVER_NAME};
pub use session_store::MemorySessionStore;
