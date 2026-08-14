//! The per-action sensitive-data decision event.

use alloc::string::String;
use alloc::vec::Vec;

use aa_security::canonical::{ConfidenceBand, DetectionMethod, FindingStatus, Severity};

use crate::time::Timestamp;
use crate::types::AgentId;

use super::counts::FindingCounts;
use super::evidence::{ExecutionEvidence, InspectionFailurePath};
use super::guard::{screen, AuditLabel, FieldPath, FieldRejection, MAX_LABEL_BYTES};
use super::schema::{SchemaVersion, SENSITIVE_DATA_SCHEMA_VERSION};
use super::verdict::RuntimeVerdictLabel;
// `vocab` is referenced only from `cfg_attr(feature = "serde" / "schemars")`
// attributes on the fields below, so the import must carry the same condition
// or it is an `unused_imports` error whenever neither feature is on
// (AAASM-5682).
#[cfg(any(feature = "serde", feature = "schemars"))]
use super::vocab;
use super::DetectionProvenance;

/// Which organisation, tenant and team the action belongs to.
///
/// Carried on every event because every aggregate over these records has to be
/// scoped by it. An aggregation that loses the tenant is not a smaller answer,
/// it is one tenant's data shown to another.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
pub struct Tenancy {
    /// Owning organisation.
    pub org_id: AuditLabel,
    /// Owning tenant within the organisation.
    pub tenant_id: AuditLabel,
    /// Owning team, when the action is attributable to one.
    pub team_id: Option<AuditLabel>,
}

/// Who acted, and on whose behalf.
///
/// The existing audit bridge keeps `team_id` and drops all of this, which is
/// why "which agent, acting for which root agent, sent this?" is unanswerable
/// today.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
pub struct AgentLineage {
    /// The agent that performed the action.
    pub acting_agent: AgentId,
    /// The agent at the root of the delegation chain. Equal to `acting_agent`
    /// when nothing was delegated.
    pub root_agent: AgentId,
    /// The agent that delegated to the actor, if any.
    pub parent_agent: Option<AgentId>,
    /// How many delegation hops from the root. Zero when the actor is the root.
    pub delegation_depth: u32,
}

/// The identifiers that stitch this event to the rest of the trace.
///
/// All optional: a producer that has no trace context records none rather than
/// inventing one.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
pub struct CorrelationIds {
    /// The agent session the action belongs to.
    pub session_id: Option<AuditLabel>,
    /// Distributed-trace id.
    pub trace_id: Option<AuditLabel>,
    /// Id of the individual request.
    pub request_id: Option<AuditLabel>,
    /// Caller-chosen correlation id.
    pub correlation_id: Option<AuditLabel>,
}

/// What kind of thing an [`Endpoint`] names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[non_exhaustive]
pub enum EndpointKind {
    /// A tool exposed to the agent.
    Tool,
    /// An MCP server.
    McpServer,
    /// Another agent, over A2A.
    AgentPeer,
    /// A network host reached over HTTP(S).
    HttpHost,
    /// A path on the local filesystem.
    FilePath,
    /// A model provider endpoint.
    Model,
}

impl EndpointKind {
    /// The stable spelling used in events.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Tool => "tool",
            Self::McpServer => "mcp_server",
            Self::AgentPeer => "agent_peer",
            Self::HttpHost => "http_host",
            Self::FilePath => "file_path",
            Self::Model => "model",
        }
    }
}

/// Where an action came from, or was going.
///
/// # Screened, and not a metric label
///
/// The `identifier` is derived from the inspected request, so it is screened
/// with the credential scanner exactly as a [`FieldPath`] is. The concrete
/// case this closes is a destination written as
/// `postgresql://user:password@db.internal/app`: the scanner flags it and the
/// caller has to record the destination without the password.
///
/// It is also **unbounded cardinality** and must never become a metric label —
/// ADR 0032 §9 restricts labels to a bounded set, and validation requirement 4
/// names `destination` explicitly. Use
/// [`SensitiveDataMetricLabels`](super::SensitiveDataMetricLabels).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
pub struct Endpoint {
    /// What kind of endpoint this is.
    pub kind: EndpointKind,
    /// Its name: a tool name, an MCP server id, a host, a path.
    identifier: String,
}

impl Endpoint {
    /// Name an endpoint, screening the identifier.
    ///
    /// # Errors
    ///
    /// [`FieldRejection::CarriesSensitiveValue`] when the scanner recognises
    /// something in the identifier, plus the usual shape rejections.
    pub fn new(kind: EndpointKind, identifier: impl Into<String>) -> Result<Self, FieldRejection> {
        let identifier = identifier.into();
        screen(&identifier, MAX_LABEL_BYTES)?;
        Ok(Self { kind, identifier })
    }

    /// The endpoint's name.
    pub fn identifier(&self) -> &str {
        &self.identifier
    }
}

/// The kind of operation that was inspected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[non_exhaustive]
pub enum OperationKind {
    /// A tool invocation.
    ToolCall,
    /// A call to an MCP server.
    McpCall,
    /// An agent-to-agent message.
    AgentToAgent,
    /// Outbound network traffic.
    NetworkEgress,
    /// A write to the filesystem.
    FileWrite,
    /// A prompt or completion sent to a model.
    ModelCompletion,
}

impl OperationKind {
    /// The stable spelling used in events.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::ToolCall => "tool_call",
            Self::McpCall => "mcp_call",
            Self::AgentToAgent => "agent_to_agent",
            Self::NetworkEgress => "network_egress",
            Self::FileWrite => "file_write",
            Self::ModelCompletion => "model_completion",
        }
    }
}

/// How far outside the trust boundary the destination sits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[non_exhaustive]
pub enum TrustZone {
    /// Inside the organisation's own boundary.
    Internal,
    /// A known third party under contract.
    PartnerBoundary,
    /// The open internet.
    Public,
    /// Not classified. Never treated as `Internal` by default — an unclassified
    /// destination is the one most worth looking at.
    Unknown,
}

impl TrustZone {
    /// The stable spelling used in events.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Internal => "internal",
            Self::PartnerBoundary => "partner_boundary",
            Self::Public => "public",
            Self::Unknown => "unknown",
        }
    }
}

/// Which way the inspected payload was travelling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[non_exhaustive]
pub enum RequestDirection {
    /// Leaving the boundary. The direction sensitive-data egress policy is about.
    Outbound,
    /// Arriving from outside.
    Inbound,
    /// Between components inside the boundary.
    Internal,
}

impl RequestDirection {
    /// The stable spelling used in events.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Outbound => "outbound",
            Self::Inbound => "inbound",
            Self::Internal => "internal",
        }
    }
}

/// The action that was inspected, and where it was going.
///
/// Destination is the dimension the existing audit event does not have at all,
/// which is why "what did agent X try to send to tool Y" cannot be answered
/// today.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
pub struct InspectedAction {
    /// What kind of operation it was.
    pub operation: OperationKind,
    /// Where it originated, when that is meaningfully distinct from the actor.
    pub source: Option<Endpoint>,
    /// Where it was intended to go.
    pub destination: Endpoint,
    /// How far outside the boundary the destination sits.
    pub trust_zone: TrustZone,
    /// Which way the payload was travelling.
    pub direction: RequestDirection,
}

/// Which policy decided, and which of its rules matched.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
pub struct PolicyAttribution {
    /// Identifier of the policy document in force.
    pub document_id: Option<AuditLabel>,
    /// Version of that document.
    pub version: Option<u64>,
    /// Ids of the rules that matched. Empty when nothing matched.
    pub matched_rule_ids: Vec<AuditLabel>,
}

/// A machine-aggregatable reason for the decision.
///
/// A closed vocabulary rather than free text, because the point of a reason
/// code is to be counted. A prose reason cannot be grouped, and an operator
/// asking "why are we blocking so much traffic to this tool?" gets a list of
/// sentences instead of an answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[non_exhaustive]
pub enum PolicyReasonCode {
    /// Sensitive data was detected in the payload.
    SensitiveDataDetected,
    /// A rule in the active policy document matched.
    PolicyRuleMatched,
    /// The destination is not permitted to receive this class of data.
    DestinationNotPermitted,
    /// The action needs a human decision before it can proceed.
    ApprovalRequired,
    /// Detection could not be performed. Never a synonym for "nothing found"
    /// (ADR 0032 §5).
    DetectionUnavailable,
    /// The decision was computed but not applied, because the agent is in
    /// observe mode.
    ShadowEvaluationOnly,
}

impl PolicyReasonCode {
    /// The stable spelling used in events and metric labels.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::SensitiveDataDetected => "sensitive_data_detected",
            Self::PolicyRuleMatched => "policy_rule_matched",
            Self::DestinationNotPermitted => "destination_not_permitted",
            Self::ApprovalRequired => "approval_required",
            Self::DetectionUnavailable => "detection_unavailable",
            Self::ShadowEvaluationOnly => "shadow_evaluation_only",
        }
    }
}

/// How long inspection took.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
pub struct InspectionLatency {
    /// Time spent inside a detection provider, in microseconds.
    ///
    /// `None` for every v1 event: ADR 0032 D-1 puts out-of-process providers
    /// out of scope, so there is no provider to attribute time to. The field
    /// exists so the deferred work does not need a schema change to report it.
    pub provider_us: Option<u64>,
    /// Total time spent inspecting, in microseconds.
    pub total_us: u64,
}

/// The summary classification of an action's findings.
///
/// # Why there is no `summarise` constructor
///
/// The obvious helper would fold a set of findings into "highest severity,
/// lowest confidence". It is deliberately not provided, because
/// [`ConfidenceBand`] does not derive `PartialOrd` and that is a decision, not
/// an oversight: `aa-security` documents that `confidence >= threshold` must
/// not compile, since confidence is evidence about a detection and never an
/// authorisation input. Supplying a ranking here would hand back exactly the
/// comparison that was withheld, one crate over.
///
/// So the aggregation policy belongs to the writer — AAASM-5357 — which can
/// choose it with the reader's needs in view and without minting a general
/// ordering.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
pub struct FindingClassification {
    /// Severity representing the action's findings.
    #[cfg_attr(feature = "serde", serde(with = "vocab::severity"))]
    #[cfg_attr(feature = "schemars", schemars(schema_with = "vocab::severity::schema"))]
    pub severity: Severity,
    /// Confidence band representing the action's findings.
    #[cfg_attr(feature = "serde", serde(with = "vocab::confidence"))]
    #[cfg_attr(feature = "schemars", schemars(schema_with = "vocab::confidence::schema"))]
    pub confidence: ConfidenceBand,
    /// The detection technique representing the action's findings.
    #[cfg_attr(feature = "serde", serde(with = "vocab::method"))]
    #[cfg_attr(feature = "schemars", schemars(schema_with = "vocab::method::schema"))]
    pub method: DetectionMethod,
    /// The triage state representing the action's findings.
    #[cfg_attr(feature = "serde", serde(with = "vocab::status"))]
    #[cfg_attr(feature = "schemars", schemars(schema_with = "vocab::status::schema"))]
    pub status: FindingStatus,
}

/// One inspected action, and everything decided about it (ADR 0032 §8).
///
/// Written **alongside** the existing `audit_entry_to_storage_event` bridge,
/// never by extending it — forbidden design #15. That bridge loses 14 fields
/// including every credential finding, the hash chain and all lineage except
/// `team_id`, and sets `action` and `decision` from the same source; it is
/// superseded by attrition.
///
/// # Extending this without breaking it
///
/// `#[non_exhaustive]`, so downstream crates construct it through
/// [`builder`](Self::builder) and a new field is additive for every caller.
/// That is the seam AAASM-5356 uses for its optional
/// `sensitive_data_disposition` (ADR 0032 D-2), together with the
/// minor-version rule in [`SchemaVersion`]. For the same reason no type in this
/// module uses `serde(deny_unknown_fields)`: a strict reader would reject a
/// newer writer's event outright and turn an additive change into a breaking
/// one.
///
/// # Counting
///
/// Event counts and finding counts are separate and are reached through
/// separately named accessors —
/// [`blocked_event_count`](Self::blocked_event_count) versus
/// [`blocked_finding_count`](Self::blocked_finding_count) — so the two cannot
/// be confused at a call site.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[non_exhaustive]
pub struct SensitiveDataDecisionEvent {
    /// Schema this event was written against.
    pub schema_version: SchemaVersion,
    /// Unique id for this event.
    pub event_id: AuditLabel,
    /// When the action was inspected.
    pub occurred_at: Timestamp,
    /// Owning organisation, tenant and team.
    pub tenancy: Tenancy,
    /// Who acted, and on whose behalf.
    pub lineage: AgentLineage,
    /// Trace and correlation identifiers.
    pub correlation: CorrelationIds,
    /// The action and its destination.
    pub action: InspectedAction,
    /// Names of the fields that were inspected. **Names only** — ADR 0032 §9
    /// makes the field path the drill-down granularity in place of offsets.
    pub inspected_fields: Vec<FieldPath>,
    /// Which policy decided, and which rules matched.
    pub policy: PolicyAttribution,
    /// Finding-level tallies. Contains no event counts.
    pub finding_counts: FindingCounts,
    /// Summary classification of the findings, absent when there were none.
    pub classification: Option<FindingClassification>,
    /// Which recognizers contributed, and at which versions.
    pub detection: Vec<DetectionProvenance>,
    /// The enforcement outcome, as ADR 0018's frozen verdict.
    pub verdict: RuntimeVerdictLabel,
    /// What was observed about execution and transmission.
    pub execution: ExecutionEvidence,
    /// How the detection pass itself terminated.
    pub inspection_failure_path: InspectionFailurePath,
    /// How long inspection took.
    pub latency: InspectionLatency,
    /// Machine-aggregatable reasons for the decision.
    pub reason_codes: Vec<PolicyReasonCode>,
}

impl SensitiveDataDecisionEvent {
    /// Start building an event from the parts that are always required.
    ///
    /// Required arguments rather than required setters: forgetting one is then
    /// a compile error instead of a runtime error on a record that is already
    /// being written.
    pub fn builder(
        event_id: AuditLabel,
        occurred_at: Timestamp,
        tenancy: Tenancy,
        lineage: AgentLineage,
        action: InspectedAction,
        verdict: RuntimeVerdictLabel,
        execution: ExecutionEvidence,
    ) -> SensitiveDataDecisionEventBuilder {
        SensitiveDataDecisionEventBuilder {
            event: Self {
                schema_version: SENSITIVE_DATA_SCHEMA_VERSION,
                event_id,
                occurred_at,
                tenancy,
                lineage,
                correlation: CorrelationIds::default(),
                action,
                inspected_fields: Vec::new(),
                policy: PolicyAttribution::default(),
                finding_counts: FindingCounts::default(),
                classification: None,
                detection: Vec::new(),
                verdict,
                execution,
                inspection_failure_path: InspectionFailurePath::Completed,
                latency: InspectionLatency::default(),
                reason_codes: Vec::new(),
            },
        }
    }

    /// Always `1`. One event describes one inspected action.
    ///
    /// Trivial, and it exists anyway: it gives a call site somewhere to say
    /// "event" out loud next to [`total_finding_count`](Self::total_finding_count),
    /// which is the distinction ADR 0032 forbidden design #11 is about.
    pub const fn event_count(&self) -> u32 {
        1
    }

    /// `1` if this action was blocked outright, `0` otherwise.
    ///
    /// An **event** count. The action is blocked when the verdict is `deny`; a
    /// scrubbed action was permitted, with its payload rewritten.
    pub fn blocked_event_count(&self) -> u32 {
        u32::from(self.verdict == RuntimeVerdictLabel::DENY)
    }

    /// How many findings this action carried in total.
    pub const fn total_finding_count(&self) -> u32 {
        self.finding_counts.total
    }

    /// How many **findings** were blocked.
    ///
    /// ADR 0032 §8's worked example: an action with three findings that is
    /// blocked gives `blocked_event_count() == 1` and
    /// `blocked_finding_count() == 3`.
    pub const fn blocked_finding_count(&self) -> u32 {
        self.finding_counts.blocked
    }

    /// How many **findings** were rewritten and then forwarded.
    pub const fn transformed_finding_count(&self) -> u32 {
        self.finding_counts.transformed
    }

    /// Whether this event may be counted as prevented transmission.
    ///
    /// The only place ADR 0032 §8's four conditions are conjoined:
    ///
    /// 1. the enforcement point was pre-transmission;
    /// 2. the verdict was a deny or a transforming disposition;
    /// 3. explicit evidence records the payload did not reach its destination;
    /// 4. the action was not in observe mode.
    ///
    /// Conditions 1, 3 and 4 come from [`ExecutionEvidence`]; 2 from the
    /// verdict. Everything else is *detected*, not prevented — and a redaction,
    /// which forwards the scrubbed bytes, is a transformed transmission.
    ///
    /// Derived rather than stored, so it cannot disagree with the evidence it
    /// is drawn from.
    pub fn counts_as_prevented_transmission(&self) -> bool {
        self.execution.establishes_non_transmission() && self.verdict.is_deny_or_transforming()
    }
}

/// Builds a [`SensitiveDataDecisionEvent`].
///
/// Exists because the event is `#[non_exhaustive]` — downstream crates cannot
/// write a struct literal, and that is what lets AAASM-5356 add a field without
/// breaking them.
#[derive(Debug, Clone)]
pub struct SensitiveDataDecisionEventBuilder {
    event: SensitiveDataDecisionEvent,
}

impl SensitiveDataDecisionEventBuilder {
    /// Attach trace and correlation identifiers.
    #[must_use]
    pub fn correlation(mut self, correlation: CorrelationIds) -> Self {
        self.event.correlation = correlation;
        self
    }

    /// Record the names of the inspected fields.
    #[must_use]
    pub fn inspected_fields(mut self, fields: Vec<FieldPath>) -> Self {
        self.event.inspected_fields = fields;
        self
    }

    /// Attribute the decision to a policy document and its matched rules.
    #[must_use]
    pub fn policy(mut self, policy: PolicyAttribution) -> Self {
        self.event.policy = policy;
        self
    }

    /// Attach the finding tallies.
    #[must_use]
    pub fn finding_counts(mut self, counts: FindingCounts) -> Self {
        self.event.finding_counts = counts;
        self
    }

    /// Attach the summary classification of the findings.
    #[must_use]
    pub fn classification(mut self, classification: FindingClassification) -> Self {
        self.event.classification = Some(classification);
        self
    }

    /// Record which recognizers contributed.
    #[must_use]
    pub fn detection(mut self, detection: Vec<DetectionProvenance>) -> Self {
        self.event.detection = detection;
        self
    }

    /// Record how the detection pass terminated.
    #[must_use]
    pub fn inspection_failure_path(mut self, path: InspectionFailurePath) -> Self {
        self.event.inspection_failure_path = path;
        self
    }

    /// Record inspection latency.
    #[must_use]
    pub fn latency(mut self, latency: InspectionLatency) -> Self {
        self.event.latency = latency;
        self
    }

    /// Record the machine-aggregatable reasons for the decision.
    #[must_use]
    pub fn reason_codes(mut self, codes: Vec<PolicyReasonCode>) -> Self {
        self.event.reason_codes = codes;
        self
    }

    /// Finish the event.
    #[must_use]
    pub fn build(self) -> SensitiveDataDecisionEvent {
        self.event
    }
}

#[cfg(test)]
pub(super) mod fixtures {
    use aa_security::canonical::{
        ByteSpan, CanonicalCategory, CanonicalFinding, CategoryBase, ConfidenceBand, DetectionMethod, FindingStatus,
        Provenance, Recognizer, Severity,
    };

    use super::*;
    use crate::policy::EnforcementMode;
    use crate::types::sensitive_data::evidence::{EnforcementPoint, TransmissionEvidence};
    use crate::types::sensitive_data::SensitiveDataFindingRecord;

    /// A finding record built from synthetic inputs — no real credential is
    /// ever constructed anywhere in this module's tests.
    pub(in crate::types::sensitive_data) fn finding(
        category: CanonicalCategory,
        path: &str,
    ) -> SensitiveDataFindingRecord {
        let finding = CanonicalFinding::new(
            category,
            Severity::Critical,
            ConfidenceBand::High,
            ByteSpan::new(4, 44),
            DetectionMethod::Deterministic,
            Provenance::new(Recognizer::BuiltinScanner, "0.0.0-test"),
            FindingStatus::Confirmed,
        )
        .expect("well-formed span");
        SensitiveDataFindingRecord::from_finding(
            AuditLabel::new("01HZX9V8ABCDEFGHJKMNPQRSTV").unwrap(),
            &finding,
            FieldPath::parse(path).unwrap(),
        )
        .unwrap()
    }

    pub(in crate::types::sensitive_data) fn tenancy() -> Tenancy {
        Tenancy {
            org_id: AuditLabel::new("acme").unwrap(),
            tenant_id: AuditLabel::new("acme-prod").unwrap(),
            team_id: Some(AuditLabel::new("billing").unwrap()),
        }
    }

    pub(in crate::types::sensitive_data) fn lineage() -> AgentLineage {
        AgentLineage {
            acting_agent: AgentId::parse("acme/billing-bot").unwrap(),
            root_agent: AgentId::parse("acme/orchestrator").unwrap(),
            parent_agent: Some(AgentId::parse("acme/orchestrator").unwrap()),
            delegation_depth: 1,
        }
    }

    pub(in crate::types::sensitive_data) fn action() -> InspectedAction {
        InspectedAction {
            operation: OperationKind::ToolCall,
            source: None,
            destination: Endpoint::new(EndpointKind::HttpHost, "api.example.com").unwrap(),
            trust_zone: TrustZone::Public,
            direction: RequestDirection::Outbound,
        }
    }

    /// The ADR 0032 §8 worked example: three findings in one blocked action,
    /// refused before transmission while enforcing.
    pub(in crate::types::sensitive_data) fn blocked_action_with_three_findings() -> SensitiveDataDecisionEvent {
        let email = CanonicalCategory::unqualified(CategoryBase::EmailAddress);
        let token = CanonicalCategory::with_scheme(CategoryBase::AccessToken, "github", "personal_access");
        let records = [
            finding(email, "body.customer.email"),
            finding(email, "body.contact.email"),
            finding(token, "headers.authorization"),
        ];
        let counts = FindingCounts::tally(&records, 0, 3).unwrap();

        SensitiveDataDecisionEvent::builder(
            AuditLabel::new("01HZX9V8ABCDEFGHJKMNPQRSTV").unwrap(),
            Timestamp::from_nanos(1_700_000_000_000_000_000),
            tenancy(),
            lineage(),
            action(),
            RuntimeVerdictLabel::DENY,
            ExecutionEvidence::new(
                EnforcementPoint::PreTransmission,
                TransmissionEvidence::NotForwarded,
                EnforcementMode::Enforce,
            ),
        )
        .finding_counts(counts)
        .classification(FindingClassification {
            severity: Severity::Critical,
            confidence: ConfidenceBand::High,
            method: DetectionMethod::Deterministic,
            status: FindingStatus::Confirmed,
        })
        .detection(alloc::vec![DetectionProvenance::new(
            Recognizer::BuiltinScanner,
            "0.0.0-test"
        )
        .unwrap()])
        .inspected_fields(alloc::vec![
            FieldPath::parse("body.customer.email").unwrap(),
            FieldPath::parse("body.contact.email").unwrap(),
            FieldPath::parse("headers.authorization").unwrap(),
        ])
        .reason_codes(alloc::vec![PolicyReasonCode::SensitiveDataDetected])
        .latency(InspectionLatency {
            provider_us: None,
            total_us: 6,
        })
        .build()
    }
}

#[cfg(test)]
mod tests {
    use aa_security::canonical::{CanonicalCategory, CategoryBase};

    use super::fixtures::*;
    use super::*;
    use crate::policy::EnforcementMode;
    use crate::types::sensitive_data::evidence::{EnforcementPoint, TransmissionEvidence};
    use crate::types::sensitive_data::CategoryLabel;

    /// **ADR 0032 §8's worked example, and validation requirement 5.**
    ///
    /// Three findings in one blocked action gives `blocked_event_count = 1` and
    /// `blocked_finding_count = 3`. Collapsing the two is forbidden design #11,
    /// and this is the assertion that notices.
    #[test]
    fn three_findings_in_one_blocked_action_give_one_event_and_three_findings() {
        let event = blocked_action_with_three_findings();

        assert_eq!(event.event_count(), 1);
        assert_eq!(event.blocked_event_count(), 1);
        assert_eq!(event.total_finding_count(), 3);
        assert_eq!(event.blocked_finding_count(), 3);
        assert_ne!(
            event.blocked_event_count(),
            event.blocked_finding_count(),
            "the two counts must not be interchangeable, which is the whole point"
        );
    }

    /// The per-category breakdown survives onto the event, so "how many
    /// findings of each class went to tool Y" is answerable.
    #[test]
    fn the_event_carries_the_per_category_breakdown() {
        let event = blocked_action_with_three_findings();
        let email = CategoryLabel::from(CanonicalCategory::unqualified(CategoryBase::EmailAddress));
        let token = CategoryLabel::from(CanonicalCategory::with_scheme(
            CategoryBase::AccessToken,
            "github",
            "personal_access",
        ));
        assert_eq!(event.finding_counts.of_category(&email), 2);
        assert_eq!(event.finding_counts.of_category(&token), 1);
    }

    /// A blocked, pre-transmission, enforced action with refusal evidence is the
    /// one case that counts as prevented.
    #[test]
    fn a_blocked_pre_transmission_action_counts_as_prevented() {
        assert!(blocked_action_with_three_findings().counts_as_prevented_transmission());
    }

    /// **ADR 0032 validation requirement 6**: absence of execution evidence
    /// prevents an event counting as prevented, however restrictive the verdict.
    #[test]
    fn without_execution_evidence_a_deny_does_not_count_as_prevented() {
        let mut event = blocked_action_with_three_findings();
        event.execution = ExecutionEvidence::unrecorded(EnforcementMode::Enforce);

        assert_eq!(event.verdict, RuntimeVerdictLabel::DENY, "still a deny");
        assert!(
            !event.counts_as_prevented_transmission(),
            "a deny with no evidence is a decision, not a demonstrated prevention"
        );
    }

    /// A redaction forwards the scrubbed bytes. It is a transformed
    /// transmission, and calling it prevention is the mistake the
    /// `CredentialLeakBlocked` event name already made once.
    #[test]
    fn a_successful_redaction_does_not_count_as_prevented() {
        let mut event = blocked_action_with_three_findings();
        event.verdict = RuntimeVerdictLabel::SCRUB;
        event.execution = ExecutionEvidence::new(
            EnforcementPoint::PreTransmission,
            TransmissionEvidence::ForwardedClean,
            EnforcementMode::Enforce,
        );

        assert!(
            event.verdict.is_deny_or_transforming(),
            "scrub does satisfy the verdict condition on its own"
        );
        assert!(
            !event.counts_as_prevented_transmission(),
            "but the bytes went, so nothing was prevented"
        );
    }

    /// An observe-mode action computes a decision and applies nothing.
    #[test]
    fn an_observe_mode_action_does_not_count_as_prevented() {
        let mut event = blocked_action_with_three_findings();
        event.execution = ExecutionEvidence::new(
            EnforcementPoint::PreTransmission,
            TransmissionEvidence::NotForwarded,
            EnforcementMode::Observe,
        );
        assert!(!event.counts_as_prevented_transmission());
    }

    /// A `scrub` verdict is not a blocked event, even though it is restrictive.
    #[test]
    fn only_a_deny_is_a_blocked_event() {
        let mut event = blocked_action_with_three_findings();
        for verdict in [
            RuntimeVerdictLabel::ALLOW,
            RuntimeVerdictLabel::NARROW,
            RuntimeVerdictLabel::SCRUB,
            RuntimeVerdictLabel::PENDING,
        ] {
            event.verdict = verdict;
            assert_eq!(event.blocked_event_count(), 0, "{verdict} counted as a blocked event");
        }
        event.verdict = RuntimeVerdictLabel::DENY;
        assert_eq!(event.blocked_event_count(), 1);
    }

    /// A destination carrying an embedded password is refused, so it cannot
    /// become a permanent field of an audit record.
    #[test]
    fn a_destination_with_an_embedded_credential_is_refused() {
        assert_eq!(
            Endpoint::new(
                EndpointKind::HttpHost,
                "postgresql://user:password@db.internal:5432/app"
            ),
            Err(FieldRejection::CarriesSensitiveValue)
        );
        assert!(Endpoint::new(EndpointKind::HttpHost, "db.internal:5432").is_ok());
    }
}

#[cfg(all(test, feature = "serde"))]
mod serde_tests {
    use super::fixtures::*;
    use super::*;

    #[test]
    fn an_event_round_trips() {
        let event = blocked_action_with_three_findings();
        let json = serde_json::to_string(&event).unwrap();
        let restored: SensitiveDataDecisionEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(restored, event);
        assert_eq!(restored.blocked_event_count(), 1);
        assert_eq!(restored.blocked_finding_count(), 3);
    }

    /// **No `deny_unknown_fields`.** A `1.1` writer that adds
    /// `sensitive_data_disposition` must not break a `1.0` reader — that is
    /// ADR 0032 D-2's "absent must mean exactly what absence means today", and
    /// it only holds if the reader tolerates the field it has never heard of.
    ///
    /// Simulated with the actual field name AAASM-5356 will add, so this test
    /// is the guarantee that ticket depends on rather than a generic one.
    #[test]
    fn an_event_from_a_newer_minor_still_deserializes() {
        let mut json = serde_json::to_value(blocked_action_with_three_findings()).unwrap();
        let object = json.as_object_mut().unwrap();
        object.insert(
            "sensitive_data_disposition".into(),
            serde_json::Value::String("redact".into()),
        );
        object.insert("schema_version".into(), serde_json::json!({ "major": 1, "minor": 1 }));

        let restored: SensitiveDataDecisionEvent =
            serde_json::from_value(json).expect("a 1.0 reader must tolerate a 1.1 writer's added field");
        assert!(restored.schema_version.is_readable_by(SENSITIVE_DATA_SCHEMA_VERSION));
        assert_eq!(restored.blocked_finding_count(), 3);
    }

    /// The event carries no raw value and no offset anywhere in its tree,
    /// including inside the nested finding-level structures.
    #[test]
    fn a_serialized_event_carries_no_span_offset_or_length() {
        let json = serde_json::to_value(blocked_action_with_three_findings()).unwrap();

        fn walk(value: &serde_json::Value, forbidden: &[&str]) {
            match value {
                serde_json::Value::Object(map) => {
                    for (key, child) in map {
                        assert!(
                            !forbidden.contains(&key.as_str()),
                            "the event leaked `{key}`, which ADR 0032 §9 confines to the audit tier"
                        );
                        walk(child, forbidden);
                    }
                }
                serde_json::Value::Array(items) => items.iter().for_each(|item| walk(item, forbidden)),
                _ => {}
            }
        }

        walk(&json, &["span", "start", "end", "offset", "length", "len"]);
    }

    /// The verdict is on the wire as ADR 0018's label, not as a competing
    /// outcome enum of this module's own.
    #[test]
    fn the_event_carries_the_frozen_verdict_label() {
        let json = serde_json::to_value(blocked_action_with_three_findings()).unwrap();
        assert_eq!(json["verdict"], "deny");
    }
}
