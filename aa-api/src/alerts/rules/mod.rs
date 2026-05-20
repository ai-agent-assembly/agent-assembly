//! Alert-rule CRUD primitives (AAASM-1386).
//!
//! The `/api/v1/alerts/rules` endpoints let operators author detection
//! rules without editing YAML. This module owns the rule domain types,
//! the in-memory store, the destination registry stub, and the minimum
//! viable rule evaluator.

pub mod destinations;
pub mod store;
pub mod types;
