//! The producer for the durable sensitive-data projection (AAASM-5440).
//!
//! AAASM-5357 delivered the projection's value types, write contract and two
//! backends; AAASM-5354 put both gateway scan seams behind the canonical
//! detection port and surfaced
//! [`EvaluationResult::canonical_findings`](super::EvaluationResult::canonical_findings).
//! Nothing joined the two. This module is that join: it turns one evaluation
//! into one [`SensitiveDataDecisionEvent`] plus its
//! [`SensitiveDataFindingRecord`] rows, and owns the task that persists them.
//!
//! # Why a channel, and not a call
//!
//! [`PolicyEngine::evaluate`](super::PolicyEngine::evaluate) is **synchronous**
//! and sits on the pre-action enforcement path — it is what an agent waits on
//! before its tool call runs. The projection's write contract is `async` and
//! talks to a database. Awaiting it here would put database latency inside every
//! governed action, and blocking on it would stall a runtime worker.
//!
//! So the seam is a bounded channel, exactly as the audit path already does with
//! `PolicyService::audit_tx`: the engine performs a non-blocking `try_send` and
//! returns, and [`SensitiveDataProjectionDrain`] does the write.
//!
//! # What happens when persistence fails (ADR 0032 §8; AAASM-5440 AC4)
//!
//! **Fail open on the decision, and never silently.** A projection row is a
//! reporting artefact; refusing an agent's action because a dashboard's table is
//! unavailable would convert an analytics outage into an enforcement outage. The
//! decision is already computed and returned by the time anything is written,
//! and no failure below can reach it — [`project_decision`] takes
//! `&EvaluationResult` and nothing in the pipeline reads what this module
//! produces.
//!
//! Silence is the other half, and it is the half that matters: a projection that
//! quietly loses rows is a governance surface asserting a completeness it does
//! not have. Every loss is counted on a counter that names its own failure mode,
//! and logged:
//!
//! | Counter | The loss it names |
//! |---|---|
//! | [`SensitiveDataProjectionSink::refused`] | the decision could not be *projected* — no attributable tenancy, an unmappable operation, a field the guard refused. Nothing was ever offered to the store. |
//! | [`SensitiveDataProjectionSink::dropped`] | the decision was projected but the channel was full or closed, so the store never saw it. |
//! | [`SensitiveDataProjectionDrain::failures`] | the store saw it and refused or failed the write. |
//!
//! Three counters rather than one because they are three different statements
//! about the data, and a reader asking "is this table complete?" is answered
//! wrongly by a single number that cannot tell "we never built the row" from "we
//! built it and the database rejected it".
//!
//! # Lifecycle ownership
//!
//! [`SensitiveDataProjectionService`] exists so no task is spawned without an
//! owner. It holds the sink, the spawned drain's [`JoinHandle`] and a
//! [`CancellationToken`], and [`shutdown`](SensitiveDataProjectionService::shutdown)
//! is the only way to end the drain deterministically: the engine holds a
//! *clone* of the sink inside an `Arc<PolicyEngine>` that outlives the serve
//! call, so "drop the last sender" is not a shutdown the composition root can
//! actually perform. The token is. Cancellation closes the channel and drains
//! what is already queued before returning, so a shutdown does not silently
//! discard rows that were accepted.
//!
//! # Tiering
//!
//! The only shape this module writes is [`SensitiveDataFindingRecord`], which is
//! span-free by construction — it is built *from* a
//! [`CanonicalFinding`](aa_security::canonical::CanonicalFinding) and discards
//! the [`ByteSpan`](aa_security::canonical::ByteSpan). Nothing here reads
//! `span()`, and the scanned payload — redacted or otherwise — is never carried
//! into an event. ADR 0032 §9 confines offsets, lengths and payloads to the
//! tamper-evident audit tier.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use aa_core::policy::EnforcementMode;
use aa_core::time::Timestamp;
use aa_core::types::sensitive_data::{
    AgentLineage, AuditLabel, CorrelationIds, DetectionProvenance, Endpoint, EndpointKind, EnforcementPoint,
    ExecutionEvidence, FieldPath, FieldRejection, FindingCounts, InspectedAction, OperationKind, PolicyAttribution,
    PolicyReasonCode, RequestDirection, RuntimeVerdictLabel, SensitiveDataDecisionEvent, SensitiveDataFindingRecord,
    Tenancy, TransmissionEvidence, TrustZone,
};
use aa_core::types::AgentId as WireAgentId;

use crate::storage::sensitive_data::{SensitiveDataProjection, SensitiveDataProjectionWriter, WriteOutcome};

use super::EvaluationResult;

/// How many projected decisions may await persistence before the sink starts
/// dropping.
///
/// Matches the audit channel's 4096 so a deployment that can absorb the audit
/// path's burst can absorb this one, and so the two tiers degrade at
/// comparable load rather than one masking the other's backlog.
pub const DEFAULT_PROJECTION_CAPACITY: usize = 4096;

/// One inspected action's projection: the event, and the finding rows its
/// tallies were computed from.
///
/// The two travel together because [`SensitiveDataProjectionWriter::write`]
/// refuses a pair whose counts disagree — carrying them separately would make
/// that check depend on a call site remembering to keep them in step.
#[derive(Debug, Clone)]
pub struct SensitiveDataDecision {
    /// The action-level event. Exactly one per inspected action.
    pub event: SensitiveDataDecisionEvent,
    /// The finding rows. Many per event — one action with three findings is one
    /// event and three rows (ADR 0032 §8).
    pub findings: Vec<SensitiveDataFindingRecord>,
}

/// Why an evaluation could not be turned into a projection at all.
///
/// Every variant is a *refusal to record something untrue*, not an error in the
/// usual sense. Each one is counted by
/// [`SensitiveDataProjectionSink::refused`] so the resulting gap in the
/// projection is visible rather than inferred from a row that is missing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProjectionRefusal {
    /// The acting agent has no authoritative `org_id`.
    ///
    /// Every read of this projection is tenant-scoped, so a row that cannot name
    /// its tenant is a row no scoped query can return. Writing it under a
    /// fabricated tenant would be worse than not writing it: it would appear in
    /// some other tenant's answer.
    UnattributableTenancy,
    /// The action has no honest [`OperationKind`].
    ///
    /// ADR 0032's vocabulary has no member for a process exec or an inter-team
    /// message, and `OperationKind` is `#[non_exhaustive]` in `aa-core`, so this
    /// crate cannot add one. Recording a `ProcessExec` as a `tool_call` would
    /// make the operation column assert something false about every such row,
    /// which is the defect class this Epic exists to remove — so the row is
    /// refused and counted instead.
    UnmappableOperation,
    /// A guarded string was refused: the shape check, or — for the destination
    /// identifier and the field path — the credential scan. ADR 0032's worked
    /// example is a destination written as a database URI with the password in
    /// it.
    FieldRefused(FieldRejection),
    /// The agent identifier could not be rendered in the `<tenant>/<agent>` form
    /// the projection stores, because the org id itself contains a `/`.
    UnrenderableAgentId,
    /// The finding tallies could not be computed — `transformed + blocked`
    /// exceeded the number of findings.
    InconsistentCounts,
}

impl core::fmt::Display for ProjectionRefusal {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnattributableTenancy => f.write_str("the acting agent has no authoritative org_id"),
            Self::UnmappableOperation => f.write_str("the action has no ADR 0032 operation kind"),
            Self::FieldRefused(rejection) => write!(f, "a projected field was refused: {rejection}"),
            Self::UnrenderableAgentId => f.write_str("the agent id could not be rendered as <tenant>/<agent>"),
            Self::InconsistentCounts => f.write_str("the finding tallies are inconsistent"),
        }
    }
}

impl From<FieldRejection> for ProjectionRefusal {
    fn from(rejection: FieldRejection) -> Self {
        Self::FieldRefused(rejection)
    }
}

/// The engine's non-blocking handle onto the projection.
///
/// Cloneable so one channel can be shared by several engines. Note that
/// `PolicyEngine`'s simulation engines deliberately do **not** receive a clone:
/// a dry run applies no enforcement and writes no audit entry, so it writes no
/// governance row either.
#[derive(Debug, Clone)]
pub struct SensitiveDataProjectionSink {
    tx: mpsc::Sender<SensitiveDataDecision>,
    dropped: Arc<AtomicU64>,
    refused: Arc<AtomicU64>,
}

impl SensitiveDataProjectionSink {
    /// Build a sink and the receiving half a [`SensitiveDataProjectionDrain`]
    /// consumes.
    ///
    /// `capacity` bounds how many projected decisions may await persistence.
    /// Bounded rather than unbounded on purpose: an unbounded queue converts a
    /// slow database into unbounded memory growth in the gateway, which is an
    /// availability failure in the enforcement process caused by a reporting
    /// tier. A full channel drops, counts and logs instead.
    pub fn channel(capacity: usize) -> (Self, mpsc::Receiver<SensitiveDataDecision>) {
        let (tx, rx) = mpsc::channel(capacity);
        (
            Self {
                tx,
                dropped: Arc::new(AtomicU64::new(0)),
                refused: Arc::new(AtomicU64::new(0)),
            },
            rx,
        )
    }

    /// Decisions that were projected but never reached the store because the
    /// channel was full or its consumer had gone.
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    /// Evaluations that could not be projected at all. See
    /// [`ProjectionRefusal`].
    pub fn refused(&self) -> u64 {
        self.refused.load(Ordering::Relaxed)
    }

    /// Offer one projected decision, without blocking.
    pub(super) fn record(&self, decision: SensitiveDataDecision) {
        let event_id = decision.event.event_id.as_str().to_string();
        if let Err(err) = self.tx.try_send(decision) {
            self.dropped.fetch_add(1, Ordering::Relaxed);
            match err {
                mpsc::error::TrySendError::Full(_) => {
                    tracing::warn!(
                        event_id,
                        "sensitive-data projection queue full — decision dropped, the projection is incomplete"
                    );
                }
                mpsc::error::TrySendError::Closed(_) => {
                    tracing::error!(
                        event_id,
                        "sensitive-data projection channel closed — the drain task is gone and every \
                         further decision will be lost"
                    );
                }
            }
        }
    }

    /// Record that an evaluation could not be projected.
    pub(super) fn refuse(&self, refusal: ProjectionRefusal) {
        self.refused.fetch_add(1, Ordering::Relaxed);
        tracing::warn!(
            reason = %refusal,
            "sensitive-data decision not projected — the projection is incomplete for this action"
        );
    }
}

/// Drains projected decisions into the projection's store.
///
/// Runs outside the enforcement path, so a slow or failing database costs
/// latency and rows, never a decision.
pub struct SensitiveDataProjectionDrain<S> {
    rx: mpsc::Receiver<SensitiveDataDecision>,
    writer: SensitiveDataProjectionWriter<S>,
    written: Arc<AtomicU64>,
    failures: Arc<AtomicU64>,
}

impl<S: SensitiveDataProjection> SensitiveDataProjectionDrain<S> {
    /// Pair a receiver with the writer that persists what comes out of it.
    pub fn new(rx: mpsc::Receiver<SensitiveDataDecision>, writer: SensitiveDataProjectionWriter<S>) -> Self {
        Self {
            rx,
            writer,
            written: Arc::new(AtomicU64::new(0)),
            failures: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Decisions the store accepted.
    ///
    /// Handed out as a shared counter rather than read from `&self` because
    /// [`run`](Self::run) consumes the drain — an observer has to take the
    /// handle before the task starts.
    pub fn written(&self) -> Arc<AtomicU64> {
        Arc::clone(&self.written)
    }

    /// Writes the store refused or failed.
    pub fn failures(&self) -> Arc<AtomicU64> {
        Arc::clone(&self.failures)
    }

    /// Persist every decision until `shutdown` is cancelled or every sender is
    /// gone.
    ///
    /// Two termination conditions, both deterministic and both needed:
    ///
    /// * `rx.recv()` yields `None` once the last [`SensitiveDataProjectionSink`]
    ///   clone is dropped — the natural end when the engine that held one is
    ///   itself dropped;
    /// * `shutdown` fires when the composition root stops the gateway while the
    ///   engine — and therefore a live sender — is still alive.
    ///
    /// On cancellation the receiver is closed and then drained, so decisions
    /// already accepted into the queue are still written. Ending on the token
    /// alone would discard them, which is the same silent loss the counters
    /// exist to prevent, arriving at shutdown instead of at runtime.
    ///
    /// `ingested_at` is stamped per decision rather than at projection time
    /// because it records when the row became durable, which is what makes a
    /// late arrival distinguishable from an on-time one (see the writer's
    /// late-arrival rule).
    pub async fn run(mut self, shutdown: CancellationToken) {
        loop {
            tokio::select! {
                maybe = self.rx.recv() => match maybe {
                    Some(decision) => self.persist(decision).await,
                    None => break,
                },
                () = shutdown.cancelled() => {
                    self.rx.close();
                    while let Some(decision) = self.rx.recv().await {
                        self.persist(decision).await;
                    }
                    break;
                }
            }
        }
    }

    async fn persist(&self, decision: SensitiveDataDecision) {
        let ingested_at = Timestamp::from(std::time::SystemTime::now());
        match self
            .writer
            .write(&decision.event, &decision.findings, ingested_at)
            .await
        {
            // `Disabled` is a write that did not happen, so it must not
            // increment a counter a reader uses to judge the tier's
            // completeness. The composition root only ever builds an enabled
            // writer, but a counter that would over-report under a
            // configuration nobody has yet chosen is a wrong number waiting for
            // one.
            Ok(WriteOutcome::Written) => {
                self.written.fetch_add(1, Ordering::Relaxed);
            }
            Ok(WriteOutcome::Disabled) => {}
            Err(err) => {
                self.failures.fetch_add(1, Ordering::Relaxed);
                // The event id, not the event: a failed write must not spill the
                // record's contents into a log line.
                tracing::error!(
                    event_id = decision.event.event_id.as_str(),
                    error = %err,
                    "sensitive-data projection write failed — the enforcement decision stands, the row is lost"
                );
            }
        }
    }
}

/// What a completed drain did, reported once at shutdown.
///
/// Returned rather than logged-and-forgotten so a composition root — or a test —
/// can assert on the completeness of the tier it just stopped writing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProjectionShutdown {
    /// Decisions the store accepted.
    pub written: u64,
    /// Decisions the store refused or failed to write.
    pub write_failures: u64,
    /// Decisions never offered to the store: the channel was full or closed.
    pub dropped: u64,
    /// Evaluations that could not be projected at all.
    pub refused: u64,
    /// `true` when the drain task ended by panicking rather than by returning.
    ///
    /// Its own field because a panicked drain and a clean one with zero writes
    /// are indistinguishable from the counters alone, and the first is a bug
    /// while the second is an idle gateway.
    pub drain_panicked: bool,
}

/// Owns the projection's spawned drain for the lifetime of a gateway process.
///
/// The composition root builds one of these, attaches
/// [`sink`](Self::sink) to the [`PolicyEngine`](super::PolicyEngine), keeps the
/// service alive for as long as it serves, and calls
/// [`shutdown`](Self::shutdown) afterwards. Every spawned task in this feature
/// is owned by one of these — there is no `tokio::spawn` in this module outside
/// [`spawn`](Self::spawn).
pub struct SensitiveDataProjectionService {
    sink: SensitiveDataProjectionSink,
    shutdown: CancellationToken,
    handle: JoinHandle<()>,
    written: Arc<AtomicU64>,
    failures: Arc<AtomicU64>,
}

impl SensitiveDataProjectionService {
    /// Build the channel, spawn the drain over `writer`, and keep the handle.
    ///
    /// `capacity` bounds the queue — see
    /// [`SensitiveDataProjectionSink::channel`] for why it is bounded at all.
    pub fn spawn<S: SensitiveDataProjection>(writer: SensitiveDataProjectionWriter<S>, capacity: usize) -> Self {
        let (sink, rx) = SensitiveDataProjectionSink::channel(capacity);
        let drain = SensitiveDataProjectionDrain::new(rx, writer);
        let written = drain.written();
        let failures = drain.failures();
        let shutdown = CancellationToken::new();
        let handle = tokio::spawn(drain.run(shutdown.clone()));
        Self {
            sink,
            shutdown,
            handle,
            written,
            failures,
        }
    }

    /// The handle to attach to the engine.
    pub fn sink(&self) -> &SensitiveDataProjectionSink {
        &self.sink
    }

    /// Rows the store has accepted so far.
    pub fn written(&self) -> u64 {
        self.written.load(Ordering::Relaxed)
    }

    /// Writes the store has refused or failed so far.
    pub fn write_failures(&self) -> u64 {
        self.failures.load(Ordering::Relaxed)
    }

    /// Stop the drain, wait for it to finish what it has already accepted, and
    /// report what the tier managed to record.
    ///
    /// Awaits the [`JoinHandle`] rather than dropping it so a drain that ended
    /// by panicking is reported instead of vanishing: a detached task's panic
    /// is visible only in a log line nobody is asserting on.
    pub async fn shutdown(self) -> ProjectionShutdown {
        self.shutdown.cancel();
        let drain_panicked = match self.handle.await {
            Ok(()) => false,
            Err(err) => {
                tracing::error!(error = %err, "sensitive-data projection drain did not exit cleanly");
                true
            }
        };
        ProjectionShutdown {
            written: self.written.load(Ordering::Relaxed),
            write_failures: self.failures.load(Ordering::Relaxed),
            dropped: self.sink.dropped(),
            refused: self.sink.refused(),
            drain_panicked,
        }
    }
}

/// Turn one evaluation into the projection's shape.
///
/// Every value below is derived from what the gateway actually knows. Where it
/// does not know something the field is left absent rather than filled with a
/// plausible default, because this projection is read as a governance
/// measurement:
///
/// * **`tenant_id` is the org id.** The gateway's authoritative tenancy is
///   `(org, team)`; it has no third, finer *tenant* concept. Folding the team
///   into `tenant_id` instead would make the same agent's rows move between
///   tenant scopes the moment a team is assigned, silently splitting a reader's
///   history. The team is stored in its own column.
/// * **No `classification`.** `aa-core` documents that the aggregation policy
///   belongs to the writer, precisely because `aa-security` withholds
///   `PartialOrd` on `ConfidenceBand` on purpose. Minting the ordering here to
///   summarise "highest severity, lowest confidence" would hand back the
///   comparison that was deliberately withheld one crate over. Every finding row
///   carries its own severity, confidence, method and status, so a reader gets
///   the distribution rather than a summary derived from an invented ranking.
/// * **`TransmissionEvidence::NotRecorded`.** The gateway decides; it does not
///   observe the bytes. Claiming `NotForwarded` here would let a denied action
///   count as prevented transmission on this layer's say-so.
/// * **`EnforcementPoint::PreTransmission`** is asserted, because it is true:
///   this is the synchronous pre-action path.
/// * **`InspectionLatency` is left at zero.** The engine does not time Stage 6
///   today; a fabricated duration would be worse than an absent one.
///
/// # Errors
///
/// [`ProjectionRefusal`] when the evaluation cannot be described truthfully.
pub(super) fn project_decision(
    ctx: &aa_core::AgentContext,
    action: &aa_core::GovernanceAction,
    lineage: &crate::registry::Lineage,
    mode: EnforcementMode,
    result: &EvaluationResult,
    occurred_at: Timestamp,
    event_id: &str,
) -> Result<SensitiveDataDecision, ProjectionRefusal> {
    let org = lineage
        .org_id
        .as_deref()
        .map(str::trim)
        .filter(|org| !org.is_empty())
        .ok_or(ProjectionRefusal::UnattributableTenancy)?;
    if org.contains('/') {
        return Err(ProjectionRefusal::UnrenderableAgentId);
    }

    let event_id = AuditLabel::new(event_id)?;
    let inspected = inspected_action(action)?;
    let field_path = FieldPath::parse(inspected.scanned_field)?;

    let findings = result
        .canonical_findings
        .iter()
        .map(|finding| SensitiveDataFindingRecord::from_finding(event_id.clone(), finding, field_path.clone()))
        .collect::<Result<Vec<_>, _>>()?;

    let verdict = verdict_label(result);
    let total = u32::try_from(findings.len()).unwrap_or(u32::MAX);
    // A finding is blocked or transformed, never both: a denied action forwarded
    // nothing to rewrite, and a redacted one was forwarded. Anything else — an
    // `alert_only` policy, an approval hold — transformed and blocked nothing,
    // and says so with two zeroes rather than by picking the friendlier of them.
    let (transformed, blocked) = match (&result.decision, result.redacted_payload.is_some()) {
        (aa_core::PolicyResult::Deny { .. }, _) => (0, total),
        (_, true) => (total, 0),
        _ => (0, 0),
    };
    let counts =
        FindingCounts::tally(&findings, transformed, blocked).map_err(|_| ProjectionRefusal::InconsistentCounts)?;

    let mut detection: Vec<DetectionProvenance> = Vec::new();
    for finding in &result.canonical_findings {
        let provenance = DetectionProvenance::try_from(finding.provenance())?;
        if !detection.contains(&provenance) {
            detection.push(provenance);
        }
    }

    let event = SensitiveDataDecisionEvent::builder(
        event_id,
        occurred_at,
        tenancy(org, lineage.team_id.as_deref())?,
        agent_lineage(ctx, lineage, org)?,
        inspected.action,
        verdict,
        ExecutionEvidence::new(
            EnforcementPoint::PreTransmission,
            TransmissionEvidence::NotRecorded,
            mode,
        ),
    )
    .correlation(CorrelationIds {
        session_id: Some(AuditLabel::new(hex::encode(ctx.session_id.as_bytes()))?),
        ..CorrelationIds::default()
    })
    .inspected_fields(vec![field_path])
    .policy(PolicyAttribution {
        document_id: result.policy_doc_id.as_deref().map(AuditLabel::new).transpose()?,
        version: None,
        matched_rule_ids: Vec::new(),
    })
    .finding_counts(counts)
    .detection(detection)
    .reason_codes(vec![PolicyReasonCode::SensitiveDataDetected])
    .build();

    Ok(SensitiveDataDecision { event, findings })
}

fn tenancy(org: &str, team: Option<&str>) -> Result<Tenancy, ProjectionRefusal> {
    let org_id = AuditLabel::new(org)?;
    Ok(Tenancy {
        org_id: org_id.clone(),
        tenant_id: org_id,
        team_id: team
            .map(str::trim)
            .filter(|team| !team.is_empty())
            .map(AuditLabel::new)
            .transpose()?,
    })
}

fn agent_lineage(
    ctx: &aa_core::AgentContext,
    lineage: &crate::registry::Lineage,
    org: &str,
) -> Result<AgentLineage, ProjectionRefusal> {
    let render = |bytes: &[u8; 16]| -> Result<WireAgentId, ProjectionRefusal> {
        WireAgentId::parse(format!("{org}/{}", hex::encode(bytes))).map_err(|_| ProjectionRefusal::UnrenderableAgentId)
    };

    let acting = render(ctx.agent_id.as_bytes())?;
    let root = match lineage
        .root_agent_id
        .or_else(|| ctx.root_agent_id.map(|id| *id.as_bytes()))
    {
        Some(bytes) => render(&bytes)?,
        None => acting.clone(),
    };
    let parent = match lineage
        .parent_agent_id
        .or_else(|| ctx.parent_agent_id.map(|id| *id.as_bytes()))
    {
        Some(bytes) => Some(render(&bytes)?),
        None => None,
    };

    Ok(AgentLineage {
        acting_agent: acting,
        root_agent: root,
        parent_agent: parent,
        delegation_depth: lineage.depth.unwrap_or(ctx.depth),
    })
}

/// The inspected action, plus the name of the field Stage 6 actually scanned.
struct InspectedActionParts {
    action: InspectedAction,
    scanned_field: &'static str,
}

/// Describe the action in ADR 0032's vocabulary.
///
/// `scanned_field` names the field `action_scan_text` actually read, so
/// `inspected_fields` is what was inspected rather than a plausible-looking
/// constant.
///
/// The destination identifier is deliberately narrower than the action's own
/// string: a `NetworkRequest`'s URL is reduced to its host, dropping the userinfo
/// and the query string. Those are the two parts of a URL that carry
/// credentials, and `EndpointKind::HttpHost` means the host in any case — so the
/// narrowing removes a leak channel and makes the column mean what it says.
fn inspected_action(action: &aa_core::GovernanceAction) -> Result<InspectedActionParts, ProjectionRefusal> {
    let (operation, kind, identifier, scanned_field, direction) = match action {
        aa_core::GovernanceAction::ToolCall { name, .. } => (
            OperationKind::ToolCall,
            EndpointKind::Tool,
            name.as_str(),
            "args",
            RequestDirection::Outbound,
        ),
        // Inbound: a tool result is data arriving from outside, inspected before
        // it is handed back to the agent.
        aa_core::GovernanceAction::ToolResult { tool_name, .. } => (
            OperationKind::ToolCall,
            EndpointKind::Tool,
            tool_name.as_str(),
            "result",
            RequestDirection::Inbound,
        ),
        aa_core::GovernanceAction::FileAccess { path, .. } => (
            OperationKind::FileWrite,
            EndpointKind::FilePath,
            path.as_str(),
            "path",
            RequestDirection::Outbound,
        ),
        aa_core::GovernanceAction::NetworkRequest { url, .. } => (
            OperationKind::NetworkEgress,
            EndpointKind::HttpHost,
            url_host(url),
            "url",
            RequestDirection::Outbound,
        ),
        aa_core::GovernanceAction::ProcessExec { .. } | aa_core::GovernanceAction::SendMessage { .. } => {
            return Err(ProjectionRefusal::UnmappableOperation)
        }
    };

    Ok(InspectedActionParts {
        action: InspectedAction {
            operation,
            source: None,
            destination: Endpoint::new(kind, identifier)?,
            // Unknown, not Internal. The gateway classifies destinations for
            // allow-listing, not for trust; asserting `Internal` on that basis
            // would make an unclassified destination read as a vetted one.
            trust_zone: TrustZone::Unknown,
            direction,
        },
        scanned_field,
    })
}

/// The host of a URL, without scheme, userinfo, port, path or query.
///
/// Hand-rolled rather than pulling in a URL parser for one field: everything
/// after the first `/`, `?` or `#` is discarded and everything up to the last
/// `@` before it is dropped, so a malformed input degrades to a shorter string
/// and never to a longer one. The result is screened by [`Endpoint::new`]
/// regardless.
fn url_host(url: &str) -> &str {
    let after_scheme = url.split_once("://").map_or(url, |(_, rest)| rest);
    let authority = after_scheme.split(['/', '?', '#']).next().unwrap_or(after_scheme);
    let host_port = authority.rsplit_once('@').map_or(authority, |(_, host)| host);
    host_port.rsplit_once(':').map_or(host_port, |(host, _)| host)
}

/// The verdict, in ADR 0018's frozen vocabulary.
///
/// Ordered most-restrictive first so a redacted *and* narrowed action reports
/// the disposition that actually rewrote its payload rather than the one that
/// merely scoped it.
fn verdict_label(result: &EvaluationResult) -> RuntimeVerdictLabel {
    match &result.decision {
        aa_core::PolicyResult::Deny { .. } => RuntimeVerdictLabel::DENY,
        aa_core::PolicyResult::RequiresApproval { .. } => RuntimeVerdictLabel::PENDING,
        aa_core::PolicyResult::Allow if result.redacted_payload.is_some() => RuntimeVerdictLabel::SCRUB,
        aa_core::PolicyResult::Allow if result.narrowed => RuntimeVerdictLabel::NARROW,
        aa_core::PolicyResult::Allow => RuntimeVerdictLabel::ALLOW,
    }
}
