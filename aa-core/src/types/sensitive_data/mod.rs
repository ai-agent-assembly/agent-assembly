//! The sensitive-data decision event and its normalized finding rows
//! (ADR 0032 §8, AAASM-5355).
//!
//! # What these records exist to answer
//!
//! *"How many findings of each class did agent X attempt to send to tool Y, how
//! many were blocked versus redacted, how many were uncertain?"* — a question
//! the system cannot answer today, for four separate reasons:
//! `audit_entry_to_storage_event` drops every credential finding, the hash chain
//! and all lineage except `team_id`; destination is not a dimension of the audit
//! event at all; "blocked" and "redacted" are indistinguishable from the event
//! type; and findings are binary, with no notion of uncertainty.
//!
//! These types are the lossless shape that bridge should have had. They are
//! **types only** — nothing here writes, stores or serves anything. ADR 0032 §8
//! requires the new projection to be written *beside* the existing bridge
//! rather than the bridge extended field by field (forbidden design #15), and
//! that writer is AAASM-5357's work.
//!
//! # Tiering — what may appear where
//!
//! ADR 0032 §9 splits the world in two, and that split is the main thing this
//! module encodes:
//!
//! | Tier | May carry |
//! |---|---|
//! | tamper-evident audit | byte offsets and lengths (`aa_security::canonical::ByteSpan`) |
//! | everything else — metrics, traces, API responses, dashboards | category, severity, confidence, outcome, method, recognizer, **field paths** |
//!
//! [`SensitiveDataFindingRecord`] is in the second tier and is **span-free by
//! construction**: it is built *from* a `CanonicalFinding` and discards the
//! span. [`SensitiveDataMetricLabels`] narrows further, to the six
//! bounded-cardinality labels §9 permits. AAASM-5352 recorded that obligation
//! against this ticket, noting that it would be incoherent to keep `end()`
//! `pub(crate)` in Rust and then publish the offset in JSON to anything that
//! asks.
//!
//! # Why the caller-supplied strings are screened
//!
//! Every other field is an enum, an integer, or a `&'static str` from
//! `aa-security`'s compiled-in catalogue — none of which can hold bytes the
//! scanner read. The strings a caller supplies are the whole remaining surface
//! through which a raw sensitive value could reach a record, so they are
//! screened rather than trusted: see [`FieldPath`], [`Endpoint`] and
//! [`FieldRejection`]. There is no constructor that takes an unscreened string.
//! [`FieldRejection`]'s documentation states plainly what that does and does
//! not prove.
//!
//! # Counting rules that are not negotiable
//!
//! **Event counts and finding counts are different measures** (ADR 0032 §8,
//! forbidden design #11). One event carries many findings; an action with three
//! findings that is blocked contributes `1` to a blocked *event* count and `3`
//! to a blocked *finding* count. [`FindingCounts`] holds only finding tallies,
//! and the event exposes the two through separately named accessors so they
//! cannot be confused at a call site.
//!
//! **"Prevented" requires evidence.** There is deliberately no `prevented:
//! bool`. [`ExecutionEvidence`] records what was observed about the bytes, and
//! [`SensitiveDataDecisionEvent::counts_as_prevented_transmission`] derives the
//! metric under §8's four conditions. Redaction *forwards* the scrubbed bytes,
//! so a redacted action is a transformed transmission and never a prevented
//! one — the mistake the `CredentialLeakBlocked` event name already made once.
//!
//! # Where the verdict lives
//!
//! ADR 0018's `RuntimeVerdict` is frozen by ADR 0032 D-2 and is **not** mirrored
//! as an enum here. See [`RuntimeVerdictLabel`] for why the event carries a
//! closed label newtype instead, and for the seam AAASM-5356 fills with the
//! additive `sensitive_data_disposition` field.

mod category_label;
mod counts;
mod event;
mod evidence;
mod finding_record;
mod guard;
mod projection;
mod schema;
mod verdict;
mod vocab;

pub use category_label::CategoryLabel;
pub use counts::{CategoryCount, CountsError, FindingCounts};
pub use event::{
    AgentLineage, CorrelationIds, Endpoint, EndpointKind, FindingClassification, InspectedAction, InspectionLatency,
    OperationKind, PolicyAttribution, PolicyReasonCode, RequestDirection, SensitiveDataDecisionEvent,
    SensitiveDataDecisionEventBuilder, Tenancy, TrustZone,
};
pub use evidence::{EnforcementPoint, ExecutionEvidence, InspectionFailurePath, TransmissionEvidence};
pub use finding_record::{AggregateKey, DetectionProvenance, SensitiveDataFindingRecord};
pub use guard::{AuditLabel, FieldPath, FieldRejection, MAX_FIELD_PATH_BYTES, MAX_LABEL_BYTES};
pub use projection::SensitiveDataMetricLabels;
pub use schema::{SchemaVersion, SENSITIVE_DATA_SCHEMA_VERSION};
pub use verdict::RuntimeVerdictLabel;
