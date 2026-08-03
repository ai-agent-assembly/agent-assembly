//! The durable sensitive-data projection (ADR 0032 §8, AAASM-5357).
//!
//! # Why this exists next to the audit bridge rather than inside it
//!
//! [`audit_entry_to_storage_event`](crate::storage::audit_entry_to_storage_event)
//! is lossy in fourteen distinct ways — it keeps no finding, no lineage beyond
//! `team_id`, no hash-chain metadata, persists the **raw** payload rather than
//! the redacted one, sets `action` and `decision` from the same source, and
//! hardcodes `dry_run: false`, `shadow_decision: None`, `matched_rule_id:
//! None`. ADR 0032 §8 forbids repairing it field by field (forbidden design
//! #15) and requires the replacement be written *beside* it. Nothing in this
//! module reads, writes or alters `audit_events`, `audit_bridge.rs`, or the
//! JSONL hash chain.
//!
//! # Tiering — the one rule that shapes every type here
//!
//! ADR 0032 §9 permits byte offsets and lengths **only** in the tamper-evident
//! audit tier: a length plus a category can identify a value in a small
//! domain. This projection is the other tier — it feeds dashboards, analytics
//! and metric labels — so it may carry category, severity, confidence,
//! outcome, method, recognizer and **field paths**, and no offset or length.
//!
//! That is enforced in two independent ways, because a `pub(crate)` accessor in
//! Rust means nothing once a row is published as JSON:
//!
//! 1. the write path accepts only
//!    [`SensitiveDataFindingRecord`](aa_core::types::sensitive_data::SensitiveDataFindingRecord),
//!    which is span-free by construction — it is built *from* a
//!    `CanonicalFinding` and discards the
//!    [`ByteSpan`](aa_security::canonical::ByteSpan); and
//! 2. neither [`SensitiveDataEventRow`] nor [`SensitiveDataFindingRow`] has a
//!    field to put one in, and `tests/sensitive_data_projection_test.rs`
//!    asserts the exact serialized key set and the exact SQL column set of
//!    both from *outside* this module's privacy.
//!
//! # Counting
//!
//! Event counts and finding counts are different measures and are never
//! collapsed (ADR 0032 §8, forbidden design #11). The event row carries
//! [`blocked_event_count`](SensitiveDataEventRow::blocked_event_count) and
//! [`blocked_finding_count`](SensitiveDataEventRow::blocked_finding_count) as
//! separate columns, and
//! [`CategoryFindingAggregate`](store::CategoryFindingAggregate) reports both
//! `event_count` and `finding_count` per category so a reader cannot pick one
//! and call it the other.
//!
//! # Prevention
//!
//! There is no `prevented` column. Redaction *forwards* the scrubbed bytes, so
//! a redacted action is a transformed transmission; the only proof of
//! non-transmission is explicit evidence. The row stores the three components
//! of that evidence — `enforcement_point`, `transmission_evidence`,
//! `enforcement_mode` — and
//! [`counts_as_prevented_transmission`](SensitiveDataEventRow::counts_as_prevented_transmission)
//! derives the metric from them, so no stored field can imply a block that did
//! not happen.
//!
//! # Tenancy
//!
//! `org_id` and `tenant_id` are `NOT NULL` columns on **both** tables and every
//! query takes a non-optional [`TenantScope`]. A findings query is therefore
//! scoped without joining the events table, and there is no way to spell an
//! unscoped read: the isolation is in the type, not in a convention the next
//! caller has to remember.
//!
//! # Retention tiering — deferred, with the reason
//!
//! Not implemented here. [`RetentionEngine`](crate::storage::RetentionEngine)
//! drives tiering from [`RetentionPolicy`](crate::storage::RetentionPolicy),
//! whose warm/cold windows are expressed per *backend*, not per table, and
//! whose SQLite path already downgrades `Archive` to a drop. Wiring a
//! second-class table into it would either apply the audit tier's retention to
//! a projection with different legal characteristics, or require a per-table
//! policy shape that is its own change. Until that is decided the projection
//! has **no** retention tier, so nothing is silently dropped — the failure mode
//! of deferring is unbounded growth, which is visible, rather than data
//! disappearing, which is not.

mod postgres;
mod rows;
mod sqlite;
mod store;

pub use rows::{CategoryTally, ProjectionError, SensitiveDataEventRow, SensitiveDataFindingRow, TenantScope};
pub use store::{
    CategoryFindingAggregate, SensitiveDataEventFilter, SensitiveDataProjection, SensitiveDataProjectionConfig,
    SensitiveDataProjectionWriter, WriteOutcome,
};
