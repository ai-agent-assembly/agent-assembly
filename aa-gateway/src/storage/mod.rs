//! Storage backend abstraction for the gateway control plane.
//!
//! Submodules are added incrementally under
//! [AAASM-1694](https://lightning-dust-mite.atlassian.net/browse/AAASM-1694).

pub mod agent;
pub mod audit;
pub mod error;
pub mod health;
pub mod metric;
pub mod policy;

pub use agent::{AgentFilter, AgentRecord, TeamId};
pub use audit::{AuditEvent, AuditFilter};
pub use error::{StorageError, StorageResult};
pub use health::{HealthStatus, RowCounts, StorageHealth};
pub use metric::{Metric, MetricPoint, MetricQuery};
pub use policy::{PolicyDocument, PolicyMeta, PolicyVersion};
