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
//!
//! # Tenant isolation guardrail (AAASM-3919)
//!
//! These traits carry **no `org_id`/tenant argument**: every method funnels to
//! the reserved `SYSTEM_ORG` in the Postgres driver (the org-less trait impls in
//! `aa-storage-postgres` delegate to `SYSTEM_ORG`). The RLS-enforcing,
//! tenant-safe path is the concrete `*_for_tenant` inherent methods on the
//! `Pg*` types — `get_policy_for_tenant`, `insert_audit_log_for_tenant`,
//! `get_secret_for_tenant`, etc. — not this trait surface. Any **multi-tenant
//! Postgres** deployment MUST call those concrete tenant methods (or thread
//! `org_id` through these traits) before relying on the `0006`/`0007` RLS
//! migrations; the trait path alone co-mingles every tenant under `SYSTEM_ORG`.
//! Single-tenant/self-hosted use is unaffected.

mod audit_sink;
pub mod conformance;
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
