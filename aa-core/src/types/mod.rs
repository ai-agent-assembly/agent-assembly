//! Stable, wire-shaped types shared by every storage driver (AAASM-2355).
//!
//! These are the input/output types of the `aa-storage` traits. They live in
//! `aa-core` so that the OSS Postgres driver and the Enterprise gRPC driver
//! round-trip the *same* wire shape and never drift apart. Every type derives
//! `serde` (under the `serde` feature) and `schemars::JsonSchema` (under the
//! `schemars` feature) so the JSON contract is both serializable and
//! schema-describable.
//!
//! The module is namespaced (`aa_core::types::*`) rather than re-exported at the
//! crate root because [`AgentId`] here is the human-routable `<tenant>/<agent>`
//! identifier, distinct from the opaque 16-byte [`crate::identity::AgentId`].

mod agent_id;

pub use agent_id::{AgentId, AgentIdParseError};
