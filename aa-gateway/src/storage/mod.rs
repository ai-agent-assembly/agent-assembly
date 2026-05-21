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
pub mod backend;
pub mod error;
pub mod health;
pub mod metric;
pub mod policy;
pub mod postgres;
pub mod postgres_config;
pub mod retention;

pub use agent::{AgentFilter, AgentRecord, TeamId};
pub use audit::{AuditEvent, AuditFilter};
pub use backend::StorageBackend;
pub use error::{StorageError, StorageResult};
pub use health::{HealthStatus, RowCounts, StorageHealth};
pub use metric::{Metric, MetricPoint, MetricQuery};
pub use policy::{PolicyDocument, PolicyMeta, PolicyVersion};
pub use postgres::PostgresBackend;
pub use postgres_config::PostgresConfig;
pub use retention::{ColdAction, RetentionPolicy, RetentionStats};
