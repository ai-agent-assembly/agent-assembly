//! Sealed execution receipts (AAASM-6166, ADR 0035 amendment, parent Epic
//! AAASM-6159) — a versioned, local, content-digest-sealed record of one
//! `aasm run` launch's policy, spec, backend and achieved capability
//! evidence.
//!
//! This module is built up over several commits. This top-level comment is
//! completed once the schema, validation and verification pieces exist —
//! see a later commit for the finished module documentation, including the
//! load-bearing "what a holding seal does and does not establish" section.
//!
//! # This commit
//!
//! [`text`] and [`canonical`] — the two primitives everything else in this
//! module is built from: [`text::ReceiptText`] (redaction by construction)
//! and [`canonical::Digest`]/[`canonical::canonical_json`] (the canonical
//! serialization a digest is taken over).
pub mod canonical;
pub mod host;
pub mod project;
pub mod schema;
pub mod text;
pub mod validate;

pub use canonical::{CanonicalError, Digest, CANONICAL_FORM};
pub use project::{body_for_run, ReceiptContext, TerminationInput};
pub use schema::{ReceiptBody, ReceiptEnvelope, ReceiptSeal, ReceiptSealKind, RECEIPT_SCHEMA};
pub use text::{FieldName, ReceiptText};
pub use validate::ReceiptDefect;
