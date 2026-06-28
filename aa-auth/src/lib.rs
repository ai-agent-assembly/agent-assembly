//! Shared HTTP authentication and authorization framework for Agent Assembly.
//!
//! This leaf crate holds the transport-agnostic auth primitives that the API
//! presentation layer (`aa-api`) — and, in a follow-up, the gateway — build on:
//! API-key and JWT credential validation, scope levels, per-key rate limiting,
//! and the deny-by-default authentication gate. It depends only on `axum`,
//! `http`, `serde`, and the credential primitives, never on `aa-core`,
//! `aa-gateway`, `aa-runtime`, or `aa-api`, so it stays a true leaf.

pub mod config;
pub mod rate_limit;

mod error;
pub use error::ProblemDetail;
