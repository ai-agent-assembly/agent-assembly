//! HTTP routes served by `aa-gateway`.
//!
//! In remote mode, the gateway exposes a small set of process-liveness
//! and admin endpoints over Axum. The full agent-control surface lives
//! in the sibling `aa-api` crate; this module only owns routes that
//! must be reachable even when `aa-api` is not mounted (today: `/healthz`,
//! `/api/v1/health`, and `/api/v1/admin/status`).

pub mod admin_status;
pub mod api_health;
pub mod healthz;
