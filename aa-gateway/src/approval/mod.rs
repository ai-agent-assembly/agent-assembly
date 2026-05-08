//! Team-level approval routing, escalation, and routing configuration.

pub mod escalation;
pub mod router;
pub mod routing_config;

pub use routing_config::{RoutingConfigStore, TeamRoutingConfig, default_routing_config_path};
