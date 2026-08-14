//! RFC 7807 Problem Details error responses.
//!
//! AAASM-3899: the [`ProblemDetail`] type now lives in the `aa-auth` leaf crate
//! (alongside the auth framework that renders it). It is re-exported here so
//! every existing `crate::error::ProblemDetail` path — including the
//! `openapi.rs` schema registration — keeps resolving unchanged.

pub use aa_auth::ProblemDetail;
