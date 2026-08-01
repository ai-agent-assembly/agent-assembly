//! The sensitive-data decision event and its normalized finding rows
//! (ADR 0032 §8, AAASM-5355).
//!
//! Types only — nothing here writes, stores or serves anything.

mod evidence;
mod guard;
mod schema;
mod verdict;

pub use evidence::{EnforcementPoint, ExecutionEvidence, InspectionFailurePath, TransmissionEvidence};
pub use guard::{AuditLabel, FieldPath, FieldRejection, MAX_FIELD_PATH_BYTES, MAX_LABEL_BYTES};
pub use schema::{SchemaVersion, SENSITIVE_DATA_SCHEMA_VERSION};
pub use verdict::RuntimeVerdictLabel;
