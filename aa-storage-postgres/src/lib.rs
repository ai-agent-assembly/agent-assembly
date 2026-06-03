//! PostgreSQL storage driver for the Agent Assembly persistence layer.
//!
//! `aa-storage-postgres` is the **L3 primary** OSS driver: an operator points
//! `[storage.postgres]` at their own Postgres instance and Agent Assembly uses
//! it as the durable backing store. The crate ships the sqlx migrations for the
//! four MVP tables (`orgs`, `agents`, `policies`, `audit_logs`) and implements
//! the [`aa_core::storage`] trait contract against them.
//!
//! The trait implementations (`PgPolicyStore`, `PgAuditSink`, `PgCredentialStore`,
//! `PgLifecycleStore`) land alongside the connection-pool wrapper; this module
//! re-exports the public surface a caller needs to wire the driver up.

pub mod config;

pub use config::PostgresPoolConfig;
