//! An in-memory reference backend.
//!
//! # This backend isolates nothing
//!
//! It applies no mechanism, starts no process and confines nothing. It exists so
//! that negotiation and refusal can be tested against a backend whose reported
//! capabilities are set by the test rather than by the host — which is the only
//! way to prove that an observe-only capability is refused for a prevention
//! requirement, since no real host offers both halves of that comparison on
//! demand.
//!
//! It is behind the non-default `mock-backend` feature so that a release build
//! of a consumer cannot select it. Its own [`evidence`] never contains an
//! [`EvidenceKind::Decision`] record, so even if it is selected it cannot
//! produce a prevention claim — the capability report says what it *could* do,
//! and the evidence says what it *did*, which is nothing.
//!
//! [`evidence`]: MockBackend::evidence
//! [`EvidenceKind::Decision`]: crate::evidence::EvidenceKind::Decision

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use aa_core::attestation::ClaimTerm;

use crate::backend::{
    ExecutionHandle, ExitDisposition, IsolationBackend, PreparedExecution, SpawnError, TerminationRequest,
};
use crate::capability::{
    BackendAvailability, BackendCapabilities, CapabilityDomain, CapabilityReport, DecisionTiming, DescendantCoverage,
    Mediation, PlatformBoundary, Synchrony,
};
use crate::evidence::{EnforcementEvidence, EvidenceKind, EvidenceRecord};
use crate::plan::{negotiate, BackendIdentity, EnforcementPlan, Lowering, PlanRefusal, Provenance};
use crate::spec::ExecutionSpec;

/// A backend whose capabilities are whatever the caller says they are.
#[derive(Debug)]
pub struct MockBackend {
    identity: BackendIdentity,
    capabilities: BackendCapabilities,
    /// Plans handed to [`MockBackend::prepare`], keyed by token, so
    /// [`MockBackend::evidence`] can answer from the plan a handle came from.
    /// This is the state a real backend would hold its OS resources in — see
    /// [`PreparedExecution`] for why the handle is a token rather than an
    /// object.
    launched: Mutex<HashMap<String, EnforcementPlan>>,
    next_token: AtomicU64,
}

impl MockBackend {
    /// A backend with explicitly supplied capabilities.
    pub fn new(identity: BackendIdentity, capabilities: BackendCapabilities) -> Self {
        Self {
            identity,
            capabilities,
            launched: Mutex::new(HashMap::new()),
            next_token: AtomicU64::new(0),
        }
    }

    /// The identity every convenience constructor uses.
    fn mock_identity() -> BackendIdentity {
        BackendIdentity {
            id: "mock".to_string(),
            version: "0".to_string(),
            provenance: Provenance {
                source: "aa-isolation::mock (in-memory reference backend)".to_string(),
                license: "Apache-2.0".to_string(),
                modified: false,
            },
        }
    }

    /// A backend that reports synchronous pre-effect enforcement, with
    /// process-tree coverage, for exactly the listed domains and nothing else.
    pub fn preventing(domains: &[CapabilityDomain]) -> Self {
        let reports = domains
            .iter()
            .map(|domain| {
                CapabilityReport::new(*domain, Mediation::Enforce, DecisionTiming::Pre, Synchrony::Sync)
                    .with_descendants(DescendantCoverage::ProcessTree)
            })
            .collect();
        Self::new(
            Self::mock_identity(),
            BackendCapabilities::new(
                BackendAvailability::Available,
                PlatformBoundary::SharedHostKernel,
                reports,
            )
            .expect("caller-supplied domains are unique"),
        )
    }

    /// A backend identical to [`MockBackend::preventing`] except that its
    /// mediation is [`Mediation::Observe`].
    ///
    /// Every other axis — timing, synchrony, support, descendant coverage — is
    /// held at the same value on purpose. It makes the pair a controlled
    /// comparison: when a prevention requirement is met by one and refused by
    /// the other, mediation is the only variable that moved, so the refusal
    /// cannot be attributed to some other weakened field.
    pub fn observing(domains: &[CapabilityDomain]) -> Self {
        let reports = domains
            .iter()
            .map(|domain| {
                CapabilityReport::new(*domain, Mediation::Observe, DecisionTiming::Pre, Synchrony::Sync)
                    .with_descendants(DescendantCoverage::ProcessTree)
            })
            .collect();
        Self::new(
            Self::mock_identity(),
            BackendCapabilities::new(
                BackendAvailability::Available,
                PlatformBoundary::SharedHostKernel,
                reports,
            )
            .expect("caller-supplied domains are unique"),
        )
    }

    /// A backend that reports no mechanism for any domain.
    pub fn inert() -> Self {
        let reports = CapabilityDomain::ALL
            .iter()
            .map(|domain| CapabilityReport::unsupported(*domain, "mock backend applies no mechanism"))
            .collect();
        Self::new(
            Self::mock_identity(),
            BackendCapabilities::new(
                BackendAvailability::Available,
                PlatformBoundary::SharedHostKernel,
                reports,
            )
            .expect("CapabilityDomain::ALL is unique"),
        )
    }

    /// A backend that cannot be selected on this host.
    pub fn unavailable(reason: impl Into<String>) -> Self {
        Self::new(
            Self::mock_identity(),
            BackendCapabilities::new(
                BackendAvailability::Unavailable { reason: reason.into() },
                PlatformBoundary::SharedHostKernel,
                Vec::new(),
            )
            .expect("empty report list is unique"),
        )
    }

    fn issue_token(&self) -> String {
        format!("mock-{}", self.next_token.fetch_add(1, Ordering::Relaxed))
    }
}

impl IsolationBackend for MockBackend {
    fn identity(&self) -> BackendIdentity {
        self.identity.clone()
    }

    fn capabilities(&self) -> BackendCapabilities {
        self.capabilities.clone()
    }

    fn plan(&self, spec: &ExecutionSpec) -> Result<EnforcementPlan, PlanRefusal> {
        negotiate(
            spec,
            &self.identity,
            &self.capabilities,
            // The lowering is the mock's honest description of its mechanism.
            // It states that nothing was applied rather than emitting a
            // plausible-looking step, because a lowering that reads like real
            // work is exactly what would make a test pass for the wrong reason.
            &|requirement, _outcome| {
                Lowering::new([format!(
                    "mock: no mechanism applied for domain `{}`",
                    requirement.domain()
                )])
            },
        )
    }

    fn prepare(&self, plan: EnforcementPlan) -> Result<PreparedExecution, SpawnError> {
        if plan.backend().id != self.identity.id {
            return Err(SpawnError::BackendMismatch {
                expected: self.identity.id.clone(),
                found: plan.backend().id.clone(),
            });
        }
        let token = self.issue_token();
        self.launched
            .lock()
            .expect("mock backend state poisoned")
            .insert(token.clone(), plan.clone());
        Ok(PreparedExecution::new(plan, token))
    }

    fn spawn(&self, prepared: PreparedExecution) -> Result<ExecutionHandle, SpawnError> {
        if prepared.plan().backend().id != self.identity.id {
            return Err(SpawnError::BackendMismatch {
                expected: self.identity.id.clone(),
                found: prepared.plan().backend().id.clone(),
            });
        }
        Ok(ExecutionHandle::new(
            self.identity.clone(),
            prepared.token(),
            prepared.plan().posture(),
        ))
    }

    /// The disposition of a run that never started.
    ///
    /// [`ExitDisposition::NoCode`] rather than `Code(0)`, and the difference is
    /// the whole reason the two states exist. This backend starts no process, so
    /// there is no exit code to report; answering `0` would let a test assert
    /// "the confined program succeeded" against a backend that ran nothing, which
    /// is the shape of false pass this crate is built to make impossible.
    fn wait_for_exit(&self, handle: &ExecutionHandle) -> Result<ExitDisposition, SpawnError> {
        let launched = self.launched.lock().expect("mock backend state poisoned");
        if !launched.contains_key(handle.token()) {
            return Err(SpawnError::Supervision {
                detail: format!("no prepared execution recorded for handle `{}`", handle.token()),
            });
        }
        Ok(ExitDisposition::NoCode {
            detail: "the mock backend applies no mechanism and starts no process, so nothing ran and no \
                     exit code exists"
                .to_string(),
        })
    }

    /// Always an error, on every handle.
    ///
    /// `Ok` on this trait means the request reached the execution. Nothing is
    /// executing, so nothing can be reached, and returning `Ok` would let a
    /// caller record a delivered termination that never happened.
    fn terminate(&self, handle: &ExecutionHandle, _request: TerminationRequest) -> Result<(), SpawnError> {
        Err(SpawnError::Supervision {
            detail: format!(
                "the mock backend started no process for handle `{}`, so no termination request can be \
                 delivered",
                handle.token()
            ),
        })
    }

    /// Evidence for a run that did not happen.
    ///
    /// Derived from the plan, so every record is
    /// [`EvidenceKind::Configured`]. One extra record states plainly that no
    /// mechanism was applied. Nothing here is a
    /// [`EvidenceKind::Decision`], so
    /// [`EnforcementEvidence::supports_prevention_claim`] is false for every
    /// domain even when [`MockBackend::preventing`] reported that it could
    /// prevent them.
    fn evidence(&self, handle: &ExecutionHandle) -> EnforcementEvidence {
        let launched = self.launched.lock().expect("mock backend state poisoned");
        let Some(plan) = launched.get(handle.token()) else {
            return EnforcementEvidence::new(self.identity.clone(), handle.posture()).with_record(
                EvidenceRecord::about_run(
                    EvidenceKind::Configured,
                    ClaimTerm::Unmeasured,
                    "no prepared execution recorded for this handle",
                ),
            );
        };
        EnforcementEvidence::from_plan(plan).with_record(EvidenceRecord::about_run(
            EvidenceKind::Configured,
            ClaimTerm::Unmeasured,
            "mock backend applied no mechanism; nothing about this run was measured",
        ))
    }
}
