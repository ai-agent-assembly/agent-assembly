//! Storage backend abstraction for the gateway control plane.
//!
//! Submodules are added incrementally under
//! [AAASM-1694](https://lightning-dust-mite.atlassian.net/browse/AAASM-1694).

pub mod agent;
pub mod error;
pub mod health;

pub use agent::{AgentFilter, AgentRecord, TeamId};
pub use error::{StorageError, StorageResult};
pub use health::{HealthStatus, RowCounts, StorageHealth};
