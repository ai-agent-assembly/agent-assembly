//! The sensitive-data decision event and its normalized finding rows
//! (ADR 0032 §8, AAASM-5355).
//!
//! Types only — nothing here writes, stores or serves anything.

mod schema;

pub use schema::{SchemaVersion, SENSITIVE_DATA_SCHEMA_VERSION};
