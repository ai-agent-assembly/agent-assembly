//! The persisted shapes of the sensitive-data projection.
//!
//! Gateway-owned value types, per the storage layer's standing rule that the
//! schema does not move whenever a runtime type grows a field. They are
//! projected *from* `aa-core`'s
//! [`SensitiveDataDecisionEvent`] and [`SensitiveDataFindingRecord`]; nothing
//! constructs them from anything else, which is what makes the span-freedom
//! argument in the module doc hold end to end.

use aa_core::policy::EnforcementMode;
use aa_core::time::Timestamp;
use aa_core::types::sensitive_data::{
    EnforcementPoint, RuntimeVerdictLabel, SensitiveDataDecisionEvent, SensitiveDataFindingRecord,
    TransmissionEvidence, SENSITIVE_DATA_SCHEMA_VERSION,
};

use crate::storage::error::StorageError;

/// Why a decision event could not be projected into storable rows.
///
/// Every variant is a state that would produce a row a reader could not trust.
/// Refusing the write is the point: a projection that accepts an event whose
/// finding rows disagree with its own tallies is exactly the "prevention
/// dashboard reporting more blocked findings than there were findings" that
/// `aa-core`'s [`CountsError`](aa_core::types::sensitive_data::CountsError)
/// exists to prevent, arriving one layer down.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ProjectionError {
    /// `org_id` or `tenant_id` was blank.
    ///
    /// A blank tenant is not a narrower scope, it is a scope that matches
    /// whatever the next writer also leaves blank — so it is refused at
    /// construction rather than stored and filtered around later.
    #[error("tenancy field `{0}` must not be empty")]
    EmptyTenancy(&'static str),
    /// A finding row named a different event than the one being written.
    #[error("finding {ordinal} belongs to event `{finding_event_id}`, not `{event_id}`")]
    FindingEventIdMismatch {
        /// Position of the offending record in the supplied slice.
        ordinal: usize,
        /// The event the projection is writing.
        event_id: String,
        /// The event the record claims to belong to.
        finding_event_id: String,
    },
    /// The number of finding rows disagreed with the event's own total.
    ///
    /// The load-bearing check against collapsing event and finding counts: an
    /// event that says it carried one finding while three rows are handed over
    /// is one of the two numbers being written into the other's column.
    #[error("event `{event_id}` declares {declared} findings but {supplied} rows were supplied")]
    FindingCountMismatch {
        /// The event being written.
        event_id: String,
        /// `finding_counts.total` as the producer computed it.
        declared: u32,
        /// How many rows were actually handed over.
        supplied: usize,
    },
    /// The event's own tallies were internally inconsistent.
    ///
    /// `FindingCounts` only enforces this in
    /// [`tally`](aa_core::types::sensitive_data::FindingCounts::tally);
    /// deserializing one runs no invariant at all, so an event that reached the
    /// gateway over the wire can carry `blocked: 99` against `total: 1`. The
    /// read-path checks `aa-core` provides for exactly this are run here,
    /// before the row is durable rather than after.
    #[error("event `{event_id}` carries inconsistent finding tallies: {detail}")]
    InconsistentCounts {
        /// The event being written.
        event_id: String,
        /// Which invariant failed.
        detail: &'static str,
    },
    /// A JSON-encoded column could not be built.
    #[error("failed to encode column `{column}`: {source_message}")]
    Encode {
        /// The column that failed to encode.
        column: &'static str,
        /// The serializer's message.
        source_message: String,
    },
    /// The store rejected an otherwise well-formed write.
    ///
    /// Carries the message rather than the [`StorageError`] so this type stays
    /// `Clone` and `PartialEq` — a test asserting *which* projection error
    /// occurred should not have to reconstruct a driver error to do it.
    #[error("projection write failed: {0}")]
    Storage(String),
}

impl From<ProjectionError> for StorageError {
    fn from(err: ProjectionError) -> Self {
        StorageError::QueryFailed(err.to_string())
    }
}

/// The organisation and tenant every projection read and write is scoped to.
///
/// Exists as a distinct type so that "scoped by tenant" is a signature, not a
/// convention. [`SensitiveDataEventFilter`](super::SensitiveDataEventFilter)
/// takes one by value and offers no way to omit it, so there is no spelling of
/// an unscoped query to review for.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TenantScope {
    org_id: String,
    tenant_id: String,
}

impl TenantScope {
    /// Name an organisation and tenant.
    ///
    /// # Errors
    ///
    /// [`ProjectionError::EmptyTenancy`] if either identifier is empty or
    /// whitespace-only.
    pub fn new(org_id: impl Into<String>, tenant_id: impl Into<String>) -> Result<Self, ProjectionError> {
        let org_id = org_id.into();
        let tenant_id = tenant_id.into();
        if org_id.trim().is_empty() {
            return Err(ProjectionError::EmptyTenancy("org_id"));
        }
        if tenant_id.trim().is_empty() {
            return Err(ProjectionError::EmptyTenancy("tenant_id"));
        }
        Ok(Self { org_id, tenant_id })
    }

    /// The owning organisation.
    pub fn org_id(&self) -> &str {
        &self.org_id
    }

    /// The owning tenant within that organisation.
    pub fn tenant_id(&self) -> &str {
        &self.tenant_id
    }
}

/// How many findings of one category an event carried.
///
/// Denormalized onto the event row so the common dashboard query — "what
/// classes of data did this action carry?" — needs no join. The normalized
/// findings table remains the source of truth for grouping *across* events.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CategoryTally {
    /// The category, as the writing build spelled it.
    pub category: String,
    /// How many findings of it this event carried.
    pub count: u32,
}

/// One inspected action, as it is persisted.
///
/// # What is not here
///
/// No byte offset, no length, no raw or redacted payload, and no `prevented`
/// flag. The first two are the audit tier's alone (ADR 0032 §9); the payload is
/// the mistake the existing audit bridge already makes and is not repeated;
/// the last is derived from evidence by
/// [`counts_as_prevented_transmission`](Self::counts_as_prevented_transmission)
/// so it cannot disagree with the evidence it is drawn from.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SensitiveDataEventRow {
    /// Major of the schema the row was written against. A reader of a
    /// different major must refuse the row.
    pub schema_version_major: u16,
    /// Minor of that schema. Additive only; never a reason to refuse a row.
    pub schema_version_minor: u16,
    /// The event's identity, and the projection's idempotency key.
    pub event_id: String,
    /// When the action was inspected, in nanoseconds since the Unix epoch.
    pub occurred_at_ns: u64,
    /// When the projection wrote the row.
    ///
    /// Distinct from `occurred_at_ns` so a late arrival is visible as such
    /// rather than being silently backdated — see the late-arrival rule on
    /// [`SensitiveDataProjection::append_sensitive_data_decision`](super::SensitiveDataProjection::append_sensitive_data_decision).
    pub ingested_at_ns: u64,
    /// Owning organisation.
    pub org_id: String,
    /// Owning tenant.
    pub tenant_id: String,
    /// Owning team, when the action is attributable to one.
    pub team_id: Option<String>,
    /// The agent that performed the action.
    pub acting_agent_id: String,
    /// The agent at the root of the delegation chain.
    pub root_agent_id: String,
    /// The agent that delegated to the actor, if any.
    pub parent_agent_id: Option<String>,
    /// Delegation hops from the root.
    pub delegation_depth: u32,
    /// The agent session the action belongs to.
    pub session_id: Option<String>,
    /// Distributed-trace id.
    pub trace_id: Option<String>,
    /// Id of the individual request.
    pub request_id: Option<String>,
    /// Caller-chosen correlation id.
    pub correlation_id: Option<String>,
    /// What kind of operation it was.
    pub operation: String,
    /// What kind of thing the destination is.
    pub destination_kind: String,
    /// The destination's name. Unbounded cardinality — a drill-down dimension,
    /// never a metric label.
    pub destination_id: String,
    /// How far outside the boundary the destination sits.
    pub trust_zone: String,
    /// Which way the payload was travelling.
    pub direction: String,
    /// Identifier of the policy document in force.
    pub policy_document_id: Option<String>,
    /// Version of that document.
    pub policy_version: Option<u64>,
    /// Ids of the rules that matched. The audit bridge hardcodes this to
    /// `None`; here it is what the engine actually reported.
    pub matched_rule_ids: Vec<String>,
    /// Names of the fields that were inspected — the drill-down granularity
    /// ADR 0032 §9 grants in place of offsets.
    pub inspected_field_paths: Vec<String>,
    /// The enforcement outcome, as ADR 0018's frozen verdict.
    pub verdict: String,
    /// Where the decision was applied. Prevention condition 1.
    pub enforcement_point: String,
    /// What was observed about the forwarded bytes. Prevention condition 3.
    pub transmission_evidence: String,
    /// Whether enforcement was applied or merely computed. Prevention
    /// condition 4, and the honest replacement for the audit bridge's
    /// hardcoded `dry_run: false`.
    pub enforcement_mode: String,
    /// How the detection pass itself terminated. Never a synonym for "nothing
    /// found".
    pub inspection_failure_path: String,
    /// Severity representing the action's findings, absent when there were none.
    pub severity: Option<String>,
    /// Confidence band representing the action's findings.
    pub confidence: Option<String>,
    /// Detection technique representing the action's findings.
    pub method: Option<String>,
    /// Triage state representing the action's findings.
    pub status: Option<String>,
    /// Always `1`. Stored so that `SUM(event_count)` is spellable next to
    /// `SUM(finding_count)` and the two cannot be silently interchanged.
    pub event_count: u32,
    /// `1` when the action itself was refused, `0` otherwise. An **event**
    /// count, and never the same number as `blocked_finding_count`.
    pub blocked_event_count: u32,
    /// How many findings the action carried in total.
    pub finding_count: u32,
    /// How many **findings** were refused. ADR 0032 §8's worked example: three
    /// findings in one blocked action gives `blocked_event_count = 1` and
    /// `blocked_finding_count = 3`.
    pub blocked_finding_count: u32,
    /// How many **findings** were rewritten and then forwarded. A transformed
    /// finding is not a prevented one.
    pub transformed_finding_count: u32,
    /// Per-category finding tallies, denormalized for the join-free dashboard
    /// query.
    pub finding_count_by_category: Vec<CategoryTally>,
    /// Machine-aggregatable reasons for the decision.
    pub reason_codes: Vec<String>,
}

impl SensitiveDataEventRow {
    /// Project a decision event into its storable row.
    ///
    /// `findings` is taken only to validate it against the event's own tallies
    /// — the rows themselves are produced by
    /// [`SensitiveDataFindingRow::project`]. Validating here rather than at the
    /// SQL layer means an inconsistent event never reaches a transaction.
    ///
    /// # Errors
    ///
    /// [`ProjectionError::EmptyTenancy`], [`ProjectionError::FindingCountMismatch`]
    /// and [`ProjectionError::InconsistentCounts`], per their documentation.
    pub fn project(
        event: &SensitiveDataDecisionEvent,
        findings: &[SensitiveDataFindingRecord],
        ingested_at: Timestamp,
    ) -> Result<Self, ProjectionError> {
        let event_id = event.event_id.as_str().to_string();
        let scope = TenantScope::new(event.tenancy.org_id.as_str(), event.tenancy.tenant_id.as_str())?;

        if findings.len() != event.total_finding_count() as usize {
            return Err(ProjectionError::FindingCountMismatch {
                event_id,
                declared: event.total_finding_count(),
                supplied: findings.len(),
            });
        }
        if !event.finding_counts.breakdown_is_complete() {
            return Err(ProjectionError::InconsistentCounts {
                event_id,
                detail: "per-category breakdown does not sum to the total finding count",
            });
        }
        if !event.finding_counts.disposition_counts_are_consistent() {
            return Err(ProjectionError::InconsistentCounts {
                event_id,
                detail: "transformed + blocked finding counts exceed the total finding count",
            });
        }

        let classification = event.classification.as_ref();
        Ok(Self {
            schema_version_major: event.schema_version.major,
            schema_version_minor: event.schema_version.minor,
            event_id,
            occurred_at_ns: event.occurred_at.as_nanos(),
            ingested_at_ns: ingested_at.as_nanos(),
            org_id: scope.org_id().to_string(),
            tenant_id: scope.tenant_id().to_string(),
            team_id: event.tenancy.team_id.as_ref().map(|l| l.as_str().to_string()),
            acting_agent_id: event.lineage.acting_agent.as_str().to_string(),
            root_agent_id: event.lineage.root_agent.as_str().to_string(),
            parent_agent_id: event.lineage.parent_agent.as_ref().map(|a| a.as_str().to_string()),
            delegation_depth: event.lineage.delegation_depth,
            session_id: event.correlation.session_id.as_ref().map(|l| l.as_str().to_string()),
            trace_id: event.correlation.trace_id.as_ref().map(|l| l.as_str().to_string()),
            request_id: event.correlation.request_id.as_ref().map(|l| l.as_str().to_string()),
            correlation_id: event
                .correlation
                .correlation_id
                .as_ref()
                .map(|l| l.as_str().to_string()),
            operation: event.action.operation.as_str().to_string(),
            destination_kind: event.action.destination.kind.as_str().to_string(),
            destination_id: event.action.destination.identifier().to_string(),
            trust_zone: event.action.trust_zone.as_str().to_string(),
            direction: event.action.direction.as_str().to_string(),
            policy_document_id: event.policy.document_id.as_ref().map(|l| l.as_str().to_string()),
            policy_version: event.policy.version,
            matched_rule_ids: event
                .policy
                .matched_rule_ids
                .iter()
                .map(|l| l.as_str().to_string())
                .collect(),
            inspected_field_paths: event.inspected_fields.iter().map(|p| p.as_str().to_string()).collect(),
            verdict: event.verdict.as_str().to_string(),
            enforcement_point: event.execution.enforcement_point.as_str().to_string(),
            transmission_evidence: event.execution.transmission.as_str().to_string(),
            enforcement_mode: event.execution.mode.as_wire().to_string(),
            inspection_failure_path: event.inspection_failure_path.as_str().to_string(),
            severity: classification.map(|c| c.severity.as_str().to_string()),
            confidence: classification.map(|c| c.confidence.as_str().to_string()),
            method: classification.map(|c| c.method.as_str().to_string()),
            status: classification.map(|c| c.status.as_str().to_string()),
            event_count: event.event_count(),
            blocked_event_count: event.blocked_event_count(),
            finding_count: event.total_finding_count(),
            blocked_finding_count: event.blocked_finding_count(),
            transformed_finding_count: event.transformed_finding_count(),
            finding_count_by_category: event
                .finding_counts
                .by_category
                .iter()
                .map(|entry| CategoryTally {
                    category: entry.category.as_str().to_string(),
                    count: entry.count,
                })
                .collect(),
            reason_codes: event.reason_codes.iter().map(|c| c.as_str().to_string()).collect(),
        })
    }

    /// Whether this row may be counted as prevented transmission.
    ///
    /// Recomputed from the three stored evidence columns plus the verdict —
    /// ADR 0032 §8's four conditions — rather than read from a column, so a
    /// stored row can never claim a block that the evidence does not support.
    /// A `scrub` verdict satisfies condition 2 but redaction *forwards* the
    /// scrubbed bytes, so it reaches `true` only when the evidence separately
    /// records that the payload did not leave.
    ///
    /// Each clause is compared against the `aa-core` vocabulary rather than a
    /// literal, so a renamed variant is a compile-time change here instead of a
    /// silently-never-true predicate. `narrow` is excluded because it scopes
    /// the action without transforming the payload — asking
    /// [`RuntimeVerdictLabel::is_deny_or_transforming`] rather than listing
    /// verdicts is what keeps that decision in one place.
    pub fn counts_as_prevented_transmission(&self) -> bool {
        self.enforcement_point == EnforcementPoint::PreTransmission.as_str()
            && self.transmission_evidence == TransmissionEvidence::NotForwarded.as_str()
            && self.enforcement_mode == EnforcementMode::Enforce.as_wire()
            && RuntimeVerdictLabel::from_wire(&self.verdict).is_some_and(|v| v.is_deny_or_transforming())
    }
}

/// One normalized finding, as it is persisted beneath its event.
///
/// # Span-free by construction, twice over
///
/// It is projected only from [`SensitiveDataFindingRecord`], which discards the
/// [`ByteSpan`](aa_security::canonical::ByteSpan) when it is built from a
/// `CanonicalFinding`, and it has no field that could hold one if a caller had
/// it. The struct is deliberately *not* `#[non_exhaustive]`: an added field is
/// meant to be a visible, reviewable diff here, and the integration test pins
/// the exact key set so adding one fails the suite rather than silently
/// publishing an offset.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SensitiveDataFindingRow {
    /// Major of the schema the row was written against.
    pub schema_version_major: u16,
    /// Minor of that schema.
    pub schema_version_minor: u16,
    /// The event this finding belongs to.
    pub event_id: String,
    /// Position within its event, and the other half of the row's primary key.
    ///
    /// Not the [`AggregateKey`](aa_core::types::sensitive_data::AggregateKey):
    /// two findings of the same category at the same path share an aggregate
    /// key, so keying on it would deduplicate them and quietly lower the
    /// finding count. The ordinal is stable across a replay of the same event,
    /// which is what idempotency actually needs.
    pub finding_ordinal: u32,
    /// Owning organisation. Replicated from the event so a findings query is
    /// tenant-scoped without a join.
    pub org_id: String,
    /// Owning tenant. Replicated for the same reason.
    pub tenant_id: String,
    /// When the parent action was inspected. Replicated so a time-windowed
    /// finding aggregate needs no join either.
    pub occurred_at_ns: u64,
    /// What was found, in provider-neutral terms.
    pub category: String,
    /// How damaging its exposure would be.
    pub severity: String,
    /// How much the recognizer trusts the finding. Never an authorisation input.
    pub confidence: String,
    /// The technique that produced it.
    pub method: String,
    /// Its triage state. Nothing in this vocabulary means "clean".
    pub status: String,
    /// Which recognizer claims to have produced it.
    pub recognizer: String,
    /// The version of that recognizer. Descriptive, not a trust signal.
    pub recognizer_version: String,
    /// The name of the inspected field.
    pub field_path: String,
    /// The `[REDACTED:…]` label this finding redacts to, as the writing build
    /// emitted it.
    pub redaction_label: String,
    /// `category|field_path|method|recognizer`, stored so grouping does not
    /// have to reassemble it in SQL.
    pub aggregate_key: String,
}

impl SensitiveDataFindingRow {
    /// Project one finding record into its storable child row.
    ///
    /// The scope and `occurred_at` come from the parent event rather than the
    /// record, because the record carries neither and inventing them per-row
    /// would let a child disagree with its parent about which tenant it belongs
    /// to.
    ///
    /// # Errors
    ///
    /// [`ProjectionError::FindingEventIdMismatch`] when the record names an
    /// event other than `event_id`.
    pub fn project(
        record: &SensitiveDataFindingRecord,
        event_id: &str,
        scope: &TenantScope,
        occurred_at: Timestamp,
        ordinal: u32,
    ) -> Result<Self, ProjectionError> {
        if record.event_id.as_str() != event_id {
            return Err(ProjectionError::FindingEventIdMismatch {
                ordinal: ordinal as usize,
                event_id: event_id.to_string(),
                finding_event_id: record.event_id.as_str().to_string(),
            });
        }

        Ok(Self {
            schema_version_major: record.schema_version.major,
            schema_version_minor: record.schema_version.minor,
            event_id: event_id.to_string(),
            finding_ordinal: ordinal,
            org_id: scope.org_id().to_string(),
            tenant_id: scope.tenant_id().to_string(),
            occurred_at_ns: occurred_at.as_nanos(),
            category: record.category.as_str().to_string(),
            severity: record.severity.as_str().to_string(),
            confidence: record.confidence.as_str().to_string(),
            method: record.method.as_str().to_string(),
            status: record.status.as_str().to_string(),
            recognizer: record.provenance.recognizer.as_str().to_string(),
            recognizer_version: record.provenance.version.as_str().to_string(),
            field_path: record.field_path.as_str().to_string(),
            redaction_label: record.redaction_label.as_str().to_string(),
            aggregate_key: record.aggregate_key().as_str().to_string(),
        })
    }

    /// Whether this build can interpret the row.
    ///
    /// Majors must agree; a newer minor only adds fields and is readable.
    pub fn is_readable(&self) -> bool {
        self.schema_version_major == SENSITIVE_DATA_SCHEMA_VERSION.major
    }
}
