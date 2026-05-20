//! HTTP presentation layer for Agent Assembly.
//!
//! This crate exposes the gateway's capabilities over HTTP using `axum`.
//! OpenAPI documentation is generated at build time from route annotations
//! via `utoipa`. CI validates that `openapi/v1.yaml` stays in sync with
//! the generated spec — a drift failure blocks merge.

pub mod alerts;
pub mod auth;
pub mod config;
pub mod destinations;
pub mod error;
pub mod events;
pub mod middleware;
pub mod models;
pub mod openapi;
pub mod pagination;
pub mod replay;
pub mod routes;
pub mod server;
pub mod shutdown;
pub mod state;
pub mod trace_store;
pub mod ws;

/// Re-export of the ops registry, which moved to `aa_gateway::ops` in
/// AAASM-1422 so the policy service can ingest operations from
/// `CheckActionRequest` without a reverse crate dependency.
pub use aa_gateway::ops;
pub use config::ApiConfig;
pub use error::ProblemDetail;
pub use events::EventBroadcast;
pub use models::{EventType, GovernanceEvent};
pub use openapi::ApiDoc;
pub use replay::ReplayBuffer;
pub use server::{build_app, run_server};
pub use state::AppState;
pub use trace_store::{InMemoryTraceStore, TraceStore};
