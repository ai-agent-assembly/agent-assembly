//! Team-level approval routing, escalation, and routing configuration.

pub mod escalation;
mod persistence;
pub mod repo;
pub mod router;
pub mod routing_config;
pub mod sqlite_repo;

pub use repo::{
    global_default, ApprovalRoutingRepo, RepoError, DEFAULT_ESCALATION_ROLE, DEFAULT_ESCALATION_TIMEOUT_SECS,
};
pub use routing_config::{default_routing_config_path, RoutingConfigStore, TeamRoutingConfig};
pub use sqlite_repo::SqliteApprovalRoutingRepo;
