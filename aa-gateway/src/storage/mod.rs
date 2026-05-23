//! Storage backend abstraction for the gateway control plane.
//!
//! This module owns the [`StorageBackend`] trait — the single point of
//! contact between the gateway's business logic and any persistent data
//! store. The trait is intentionally driver-agnostic: importing a database
//! driver (`sqlx`, `rusqlite`, `redis`, …) anywhere outside the `storage`
//! module is prohibited (Epic 18, Story S-A acceptance criterion).
//!
//! Concrete implementations land in subsequent Epic-18 stories:
//!
//! - SQLite backend — Epic 18 S-B
//! - PostgreSQL backend (with TimescaleDB hypertables) — Epic 18 S-C / S-D
//! - Migration runner — Epic 18 S-E
//! - Retention engine — Epic 18 S-F
//! - Redis cache — Epic 18 S-G
//! - Wire-up into the gateway, replacing in-memory stores — Epic 18 S-I
//!
//! ## Value-type ownership
//!
//! The storage layer defines its own value types ([`AuditEvent`],
//! [`AgentRecord`], [`PolicyVersion`], …) rather than reusing the gateway's
//! richer runtime structs. Keeping the two sides separate prevents the
//! storage schema from drifting whenever a runtime type grows new fields.

pub mod agent;
pub mod audit;
pub mod audit_bridge;
pub mod backend;
pub mod boot;
pub mod cache;
pub mod error;
pub mod health;
pub mod metric;
pub mod migrations;
pub mod policy;
pub mod postgres;
pub mod postgres_config;
pub mod retention;
pub mod retention_boot;
pub mod retention_config;
pub mod retention_engine;
pub mod sqlite;
pub mod timescale;

pub use agent::{AgentFilter, AgentRecord, TeamId};
pub use audit::{AuditEvent, AuditFilter};
pub use audit_bridge::audit_entry_to_storage_event;
pub use backend::StorageBackend;
pub use boot::{open_postgres_backend, open_sqlite_backend};
pub use cache::{PolicyCache, PolicyCacheLike, RedisConfig};
pub use error::{StorageError, StorageResult};
pub use health::{HealthStatus, RowCounts, StorageHealth};
pub use metric::{Metric, MetricPoint, MetricQuery};
pub use policy::{PolicyDocument, PolicyMeta, PolicyVersion};
pub use postgres::PostgresBackend;
pub use postgres_config::PostgresConfig;
pub use retention::{ColdAction, RetentionPolicy, RetentionStats};
pub use retention_boot::spawn_retention_engine;
pub use retention_config::{RetentionConfig, RetentionConfigError};
pub use retention_engine::RetentionEngine;
pub use sqlite::{SqliteBackend, SqliteConfig};
pub use timescale::TimescaleStats;
