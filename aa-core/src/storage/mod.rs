//! Storage trait abstraction for the Agent Assembly persistence layer.
//!
//! This module defines the narrow storage traits that every persistence backend
//! implements. It is a **pure interface** — no concrete backend dependency
//! (no `sqlx`, no `redis`, no `tonic`); it uses only `async-trait`, `thiserror`,
//! and the concrete domain types from `aa-core`.
//!
//! The OSS Postgres/Redis/memory drivers and the Enterprise gateway driver all
//! implement the same contract, so swapping the persistence backend never
//! changes any caller code.
//!
//! Callers import the traits and the domain types they reference from one path:
//!
//! ```
//! use aa_core::storage::{AgentId, AuditSink, PolicyDocument, PolicyStore};
//! ```
//!
//! The [`aa-storage`](https://docs.rs/aa-storage) crate re-exports this module
//! verbatim, so `aa_storage::*` and `aa_core::storage::*` are interchangeable.

mod audit_sink;
mod credential_store;
mod error;
mod lifecycle_store;
mod policy_store;
mod rate_limit_counter;
mod session_store;

pub use audit_sink::AuditSink;
pub use credential_store::CredentialStore;
pub use error::{Result, StorageError};
pub use lifecycle_store::LifecycleStore;
pub use policy_store::PolicyStore;
pub use rate_limit_counter::RateLimitCounter;
pub use session_store::{SessionRecord, SessionStore};

// Re-export the concrete domain types the traits reference so call sites import
// the storage contract and its types from a single path.
pub use crate::audit::AuditEntry;
pub use crate::identity::{AgentId, SessionId};
pub use crate::policy::PolicyDocument;
