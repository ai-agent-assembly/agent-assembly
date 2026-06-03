//! Storage trait abstraction for the Agent Assembly persistence layer.
//!
//! This crate is a thin **facade** over [`aa_core::storage`]: it re-exports the
//! storage trait contract verbatim. The traits themselves live in `aa-core` so
//! they can also be reached at `aa_core::storage::*` — the two import paths are
//! interchangeable. Backend driver crates may depend on this crate to express
//! "I implement the storage contract" without coupling to the rest of `aa-core`'s
//! API surface, and existing `aa_storage::*` paths keep working.
//!
//! The crate is a pure interface — no concrete backend dependency (no `sqlx`,
//! `redis`, or `tonic`).
//!
//! # Traits
//!
//! - [`PolicyStore`] — fetch and invalidate an agent's effective policy
//! - [`AuditSink`] — append-only emission of audit entries
//! - [`SessionStore`] — persist, load, and delete per-execution session records
//! - [`CredentialStore`] — store and retrieve named secret material
//! - [`RateLimitCounter`] — read-modify-write counters for rate limiting
//! - [`LifecycleStore`] — agent register / heartbeat / deregister bookkeeping
//!
//! # Single import path
//!
//! ```
//! use aa_storage::{AgentId, AuditSink, PolicyDocument, PolicyStore};
//! ```

#![warn(missing_docs)]

pub use aa_core::storage::*;

pub mod builtin;
pub mod factory;

mod config;
mod driver_name;
mod error;
mod registry;

pub use config::StorageConfig;
pub use driver_name::DriverName;
pub use error::ConfigError;
pub use registry::Registry;
