//! The sensitive-data decision event and its normalized finding rows
//! (ADR 0032 §8, AAASM-5355).
//!
//! Types only — nothing here writes, stores or serves anything.

mod category_label;
mod counts;
mod event;
mod evidence;
mod finding_record;
mod guard;
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
pub use schema::{SchemaVersion, SENSITIVE_DATA_SCHEMA_VERSION};
pub use verdict::RuntimeVerdictLabel;
