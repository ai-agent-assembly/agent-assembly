//! Storage trait abstraction for the Agent Assembly persistence layer.
//!
//! This crate is a **pure interface**: it defines the narrow storage traits that
//! every persistence backend implements, and it carries no concrete backend
//! dependency (no `sqlx`, no `redis`, no `tonic`). Its only dependencies are
//! `async-trait`, `thiserror`, and the shared domain types re-exported from
//! `aa-core`.
//!
//! The OSS Postgres/Redis/memory drivers and the Enterprise gateway driver all
//! implement the same contract, so swapping the persistence backend never
//! changes any caller code.

#![warn(missing_docs)]

mod audit_sink;
mod credential_store;
mod error;
mod policy_store;
mod rate_limit_counter;
mod session_store;

pub use audit_sink::AuditSink;
pub use credential_store::CredentialStore;
pub use error::{Result, StorageError};
pub use policy_store::PolicyStore;
pub use rate_limit_counter::RateLimitCounter;
pub use session_store::{SessionRecord, SessionStore};

// Re-export the shared `aa-core` domain types the traits reference so call sites
// import the storage contract and its types from a single path (`aa_storage::*`).
pub use aa_core::{AgentId, AuditEntry, PolicyDocument, SessionId};
