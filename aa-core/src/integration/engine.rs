//! Executing a plan, repairing what drifted, and taking it all back out.
//!
//! # This is the service's half of ADR 0030 Decision 2
//!
//! Row 2 of the responsibility matrix gives plan *authoring* to the adapter; row
//! 3 gives plan *execution*, receipt durability, transactionality and idempotence
//! to the service, and row 10 gives it drift and repair. This module is that
//! half, expressed against a [`StepExecutor`] so the mutation mechanics stay
//! swappable — the Claude Code specifics are AAASM-5281's, the transport is
//! AAASM-5279's, and neither belongs here.
//!
//! # Four operations, one invariant
//!
//! [`apply`](IntegrationEngine::apply), [`repair`](IntegrationEngine::repair),
//! [`remove`](IntegrationEngine::remove) and
//! [`recover`](IntegrationEngine::recover) all hold the same invariant: **never
//! write over something you cannot account for.** Concretely —
//!
//! * apply refuses a plan that does not validate, and rolls itself back if a
//!   required step fails, so a failed install leaves no half-integration;
//! * repair refuses to run at all when any AASM-affecting drift finding is not
//!   repairable, and touches only the steps drift named;
//! * remove restores from the receipt's prior-state record, and reports a
//!   residual instead of writing a value it cannot substantiate;
//! * recover acts on the journal's deterministic rule and escalates rather than
//!   guessing.
//!
//! # Idempotence is checked twice, deliberately
//!
//! Once inside the executor — a step whose target already holds exactly what the
//! step would write reports [`mutated: false`](StepOutcome::mutated) and does not
//! open the file — and once in [`apply`](IntegrationEngine::apply), which skips
//! rewriting an unchanged receipt so that reapplying does not even churn the
//! store's upgrade history. Either check alone would leave "nothing changed"
//! observably false somewhere.

use std::collections::BTreeMap;
use std::path::Path;

use super::drift::{ArtifactObservation, DriftInputs, DriftKind, DriftReport, ObservedStep};
use super::fingerprint::{self, FingerprintError};
use super::journal::{recovery_action, JournalOperation, OperationJournal, RecoveryAction, StepProgress};
use super::plan::IntegrationPlan;
use super::receipt::{IntegrationReceipt, PriorSettingsState, StepReceipt};
use super::state::ProtectionLevel;
use super::status::VerificationResult;
use super::step::{
    ArtifactOperation, IntegrationStep, SettingsMerge, SettingsScope, StepAction, StepRequirement, TrustMaterialKind,
};
use super::store::{ReceiptStore, StoreError};
use super::version::{ComponentVersions, ToolVersion, VersionCompatibility};
use crate::dev_tool::DevToolKind;

/// What applying one step left behind.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct StepOutcome {
    /// Fingerprint of the AASM-owned part of what was written.
    pub fingerprint: Option<String>,
    /// Fingerprint of the whole target document, when the step wrote into a
    /// document that also holds content AASM does not own.
    pub document_fingerprint: Option<String>,
    /// What the target held for the claimed keys before the step ran.
    pub prior_state: Option<PriorSettingsState>,
    /// Whether anything on the host actually changed.
    ///
    /// `false` on a reapply whose target already holds exactly what the step
    /// would write — the mechanical half of the idempotence guarantee.
    pub mutated: bool,
}

/// Why a step could not be applied, reversed or observed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ExecutionError {
    /// This executor has no mechanism for that action.
    ///
    /// An honest refusal rather than a silent success: a no-op that reports
    /// success would produce a receipt claiming a mutation that never happened.
    #[error("this executor cannot perform a {kind} step")]
    Unsupported {
        /// [`StepAction::kind`] of the action it cannot perform.
        kind: &'static str,
    },
    /// The step needs rendered content the caller did not supply.
    #[error("no rendered content was supplied for step {step_id:?}")]
    ContentMissing {
        /// The step that needed it.
        step_id: String,
    },
    /// The rendered content does not hash to what the plan says it should.
    ///
    /// Fail-closed on a plan/content mismatch: the plan is what the user
    /// reviewed, and writing different bytes than the ones described would make
    /// the dry run a lie.
    #[error("the content supplied for step {step_id:?} does not match the digest the plan describes")]
    ContentMismatch {
        /// The step whose content did not match.
        step_id: String,
    },
    /// The filesystem refused.
    #[error("{artifact}: {detail}")]
    Io {
        /// What was being touched.
        artifact: String,
        /// What went wrong.
        detail: String,
    },
    /// A document could not be parsed or projected.
    #[error("{artifact}: {source}")]
    Fingerprint {
        /// What was being read.
        artifact: String,
        /// Why.
        #[source]
        source: FingerprintError,
    },
}

/// Performs the mutations a plan describes.
///
/// Split from the engine so the transactional, receipt-owning half is written
/// and tested once while the per-mechanism mechanics stay per-tool.
pub trait StepExecutor {
    /// Perform `step`'s mutation, or report why it cannot.
    fn apply(&mut self, step: &IntegrationStep) -> Result<StepOutcome, ExecutionError>;

    /// Undo what `step` recorded. Must be idempotent: recovery may call it for a
    /// step that was already reversed, and a second call has to succeed.
    fn reverse(&mut self, step: &StepReceipt) -> Result<(), ExecutionError>;

    /// Look at what the host currently holds for `step`.
    fn observe(&self, step: &StepReceipt) -> ArtifactObservation;
}

/// Everything an apply needs that the plan does not carry.
#[derive(Debug, Clone)]
pub struct ApplyContext {
    /// Identifier for the receipt this apply will write.
    pub receipt_id: String,
    /// The core, adapter and schema versions doing the work.
    pub versions: ComponentVersions,
    /// The tool version detected at apply time, when one was.
    pub tool_version: Option<ToolVersion>,
    /// Now, as seconds since the Unix epoch.
    pub now_unix_secs: u64,
}

/// What an apply did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplyOutcome {
    /// The receipt that is now stored.
    pub receipt: IntegrationReceipt,
    /// Whether anything on the host changed. `false` means the integration was
    /// already exactly as the plan describes.
    pub mutated: bool,
    /// Optional steps that could not be applied, with the reason. Required steps
    /// never appear here — a failed required step aborts and rolls back.
    pub skipped: Vec<(String, String)>,
}

/// What a repair did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepairOutcome {
    /// The steps that were rewritten.
    pub repaired_steps: Vec<String>,
    /// The updated receipt.
    pub receipt: IntegrationReceipt,
    /// Drift that was found and deliberately left alone, because it is not
    /// AASM's to fix.
    pub preserved_user_changes: Vec<String>,
}

/// What a removal did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemovalOutcome {
    /// The steps that were reversed.
    pub reversed_steps: Vec<String>,
    /// What could not be undone, in words the user can act on. Non-empty means
    /// the receipt was **kept**, so status still reports what is left.
    pub residual: Vec<String>,
    /// Whether the receipt was deleted.
    pub receipt_deleted: bool,
}

/// Why an engine operation could not complete.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum EngineError {
    /// The plan does not validate, so it is not executable.
    #[error("the plan is not internally consistent: {0}")]
    InvalidPlan(#[from] super::plan::PlanError),
    /// A required step failed. The apply rolled itself back.
    #[error("required step {step_id:?} failed and the apply was rolled back: {source}")]
    RequiredStepFailed {
        /// The step that failed.
        step_id: String,
        /// Why.
        #[source]
        source: ExecutionError,
    },
    /// Reversing a step failed.
    #[error("step {step_id:?} could not be reversed: {source}")]
    ReversalFailed {
        /// The step that could not be reversed.
        step_id: String,
        /// Why.
        #[source]
        source: ExecutionError,
    },
    /// There is no receipt to operate on.
    #[error("no receipt records an integration for this tool at {scope} scope")]
    NoReceipt {
        /// The scope that was looked at.
        scope: SettingsScope,
    },
    /// Repair was asked to fix drift it cannot fix.
    #[error("repair cannot proceed: {detail}")]
    Unrepairable {
        /// What blocks it.
        detail: String,
    },
    /// An interrupted operation needs a human.
    #[error("an interrupted operation could not be recovered automatically: {reason}")]
    RecoveryEscalated {
        /// What to tell the user.
        reason: String,
    },
    /// Reading or writing the store failed.
    #[error(transparent)]
    Store(#[from] StoreError),
}

/// Applies, repairs, removes and recovers integrations against a store.
#[derive(Debug)]
pub struct IntegrationEngine<E: StepExecutor> {
    executor: E,
    store: ReceiptStore,
}

impl<E: StepExecutor> IntegrationEngine<E> {
    /// Build an engine over `executor` and `store`.
    pub fn new(executor: E, store: ReceiptStore) -> Self {
        Self { executor, store }
    }

    /// The store this engine reads and writes.
    pub fn store(&self) -> &ReceiptStore {
        &self.store
    }

    /// The executor, for callers that need to inspect what it recorded.
    pub fn executor(&self) -> &E {
        &self.executor
    }

    /// Validate `plan` and render it, without touching anything.
    ///
    /// The stability of the rendering is
    /// [`IntegrationPlan::render_dry_run`]'s contract; what this adds is the
    /// guarantee that producing it cannot mutate, because it takes `&self` and
    /// never reaches the executor.
    pub fn dry_run(&self, plan: &IntegrationPlan) -> Result<String, EngineError> {
        plan.validate()?;
        Ok(plan.render_dry_run())
    }

    /// Execute `plan`, writing a receipt.
    ///
    /// Ordering is the journal's: the journal is written before the first
    /// mutation and deleted after the receipt, so a crash at any point leaves a
    /// state [`recover`](Self::recover) can resolve without guessing.
    ///
    /// A failed **required** step aborts and reverses everything already
    /// applied — a partially applied required plan is not a weaker integration,
    /// it is an unknown one. A failed **optional** step is recorded in
    /// [`ApplyOutcome::skipped`] and the apply continues, because an optional
    /// step's absence is exactly what
    /// [`StepRequirement::Optional`] means.
    pub fn apply(&mut self, plan: &IntegrationPlan, context: &ApplyContext) -> Result<ApplyOutcome, EngineError> {
        plan.validate()?;

        let existing = self.store.load_receipt(&plan.tool, plan.settings_scope).ok().flatten();

        let mut journal = OperationJournal::starting(
            JournalOperation::Apply,
            &plan.plan_id,
            plan.tool.clone(),
            plan.settings_scope,
            context.now_unix_secs,
            plan.steps.iter().map(|s| s.id.clone()),
        );
        self.store.save_journal(&journal)?;

        let mut step_receipts: Vec<StepReceipt> = Vec::with_capacity(plan.steps.len());
        let mut skipped: Vec<(String, String)> = Vec::new();
        let mut mutated = false;

        for step in &plan.steps {
            match self.executor.apply(step) {
                Ok(outcome) => {
                    mutated |= outcome.mutated;

                    let mut receipt = StepReceipt::applied(step, outcome.fingerprint);
                    if let Some(doc) = outcome.document_fingerprint {
                        receipt = receipt.with_document_fingerprint(doc);
                    }
                    if let Some(prior) = outcome.prior_state {
                        receipt = receipt.with_prior_state(prior);
                    }

                    // Journalled with its reversal information *before* the next
                    // step runs: a crash from here on has to be undoable from
                    // the journal alone, because no receipt exists yet.
                    journal.record_applied(receipt.clone());
                    self.store.save_journal(&journal)?;
                    step_receipts.push(receipt);
                }
                Err(source) => {
                    journal.mark(
                        &step.id,
                        StepProgress::Failed {
                            reason: source.to_string(),
                        },
                    );
                    self.store.save_journal(&journal)?;

                    if step.requirement == StepRequirement::Required {
                        self.reverse_all(&mut journal, &step_receipts)?;
                        self.store.delete_journal(&plan.tool, plan.settings_scope)?;
                        return Err(EngineError::RequiredStepFailed {
                            step_id: step.id.clone(),
                            source,
                        });
                    }
                    skipped.push((step.id.clone(), source.to_string()));
                    step_receipts.push(StepReceipt::not_applied(step));
                }
            }
        }

        // Reusing the prior receipt's id when the plan is the same is what stops
        // a no-op reapply from registering as an upgrade in the store's history.
        let receipt_id = match &existing {
            Some(prior) if prior.plan_id == plan.plan_id => prior.receipt_id.clone(),
            _ => context.receipt_id.clone(),
        };

        let mut receipt = IntegrationReceipt {
            schema_version: super::version::LIFECYCLE_SCHEMA_VERSION,
            receipt_id,
            plan_id: plan.plan_id.clone(),
            tool: plan.tool.clone(),
            profile: plan.profile,
            settings_scope: plan.settings_scope,
            applied_at_unix_secs: context.now_unix_secs,
            versions: context.versions.clone(),
            tool_version: context.tool_version.clone(),
            steps: step_receipts,
            planned_level: plan.planned_level,
            achieved_level: ProtectionLevel::PartiallyIntegrated,
            achieved_evidence: Vec::new(),
            verified_at_unix_secs: None,
        };
        receipt.achieved_level = configuration_level(&receipt, plan.planned_level);

        // A reapply that changed nothing keeps the receipt it already had,
        // including its `applied_at` and its verification evidence: rewriting
        // them would make an operation that mutated nothing look like a fresh
        // install and would discard a verification that is still valid.
        if !mutated {
            if let Some(prior) = &existing {
                if prior.plan_id == plan.plan_id && receipts_agree(prior, &receipt) {
                    self.store.delete_journal(&plan.tool, plan.settings_scope)?;
                    return Ok(ApplyOutcome {
                        receipt: prior.clone(),
                        mutated: false,
                        skipped,
                    });
                }
            }
        }

        self.store.save_receipt(&receipt)?;
        self.store.delete_journal(&plan.tool, plan.settings_scope)?;

        Ok(ApplyOutcome {
            receipt,
            mutated,
            skipped,
        })
    }

    /// Observe every applied step and classify what diverged.
    pub fn detect_drift(
        &self,
        tool: &DevToolKind,
        scope: SettingsScope,
        compatibility: &VersionCompatibility,
        current_endpoint: Option<&str>,
    ) -> DriftReport {
        let (receipt, unreadable) = match self.store.load_receipt(tool, scope) {
            Ok(receipt) => (receipt, None),
            Err(err) => {
                let reason = err.as_untrustworthy_receipt_reason().unwrap_or_else(|| err.to_string());
                (None, Some(reason))
            }
        };

        let observed: Vec<ObservedStep> = receipt
            .as_ref()
            .map(|r| {
                r.steps
                    .iter()
                    .filter(|s| s.applied)
                    .map(|s| ObservedStep {
                        step_id: s.step_id.clone(),
                        artifact: artifact_label(s),
                        observation: self.executor.observe(s),
                    })
                    .collect()
            })
            .unwrap_or_default();

        DriftInputs {
            receipt: receipt.as_ref(),
            receipt_unreadable: unreadable,
            observed: &observed,
            compatibility,
            current_endpoint,
        }
        .classify()
    }

    /// Rewrite the AASM-owned state `report` found to have drifted, and nothing
    /// else.
    ///
    /// Refuses outright when any AASM-affecting finding is not repairable: a
    /// repair that fixed the settings while the receipt was corrupt, or while
    /// half the artifacts were unreadable, would report success for a state it
    /// never established.
    pub fn repair(
        &mut self,
        plan: &IntegrationPlan,
        report: &DriftReport,
        now_unix_secs: u64,
    ) -> Result<RepairOutcome, EngineError> {
        if !report.is_fully_repairable() {
            let blocking: Vec<&str> = report
                .findings
                .iter()
                .filter(|f| f.kind.affects_aasm_state() && !f.kind.is_repairable())
                .map(|f| f.kind.as_str())
                .collect();
            return Err(EngineError::Unrepairable {
                detail: format!("these conditions need attention first: {}", blocking.join(", ")),
            });
        }

        let mut receipt = self
            .store
            .load_receipt(&plan.tool, plan.settings_scope)?
            .ok_or(EngineError::NoReceipt {
                scope: plan.settings_scope,
            })?;

        let target_ids = report.repairable_step_ids();
        let mut repaired = Vec::new();

        for step in plan.steps.iter().filter(|s| target_ids.contains(&s.id)) {
            let outcome = self
                .executor
                .apply(step)
                .map_err(|source| EngineError::RequiredStepFailed {
                    step_id: step.id.clone(),
                    source,
                })?;

            // The prior state captured at *install* time is what removal must
            // restore, so a repair records the new fingerprints and leaves the
            // original prior-state snapshot alone. Overwriting it would make
            // removal restore the tampered values rather than the user's own.
            if let Some(existing) = receipt.steps.iter_mut().find(|s| s.step_id == step.id) {
                existing.applied = true;
                existing.fingerprint = outcome.fingerprint;
                existing.document_fingerprint = outcome.document_fingerprint;
            }
            repaired.push(step.id.clone());
        }

        receipt.applied_at_unix_secs = now_unix_secs;
        receipt.achieved_level = configuration_level(&receipt, plan.planned_level);
        // A repair re-established configuration; it did not re-exercise traffic.
        // Dropping the old evidence is what stops a repaired integration from
        // inheriting a `GatewayProtected` claim nothing has re-substantiated.
        receipt.achieved_evidence.clear();
        receipt.verified_at_unix_secs = None;
        self.store.save_receipt(&receipt)?;

        Ok(RepairOutcome {
            repaired_steps: repaired,
            receipt,
            preserved_user_changes: report
                .findings
                .iter()
                .filter(|f| f.kind == DriftKind::UserManagedUnrelatedChange)
                .map(|f| f.artifact.clone())
                .collect(),
        })
    }

    /// Record a verification pass against the stored receipt.
    ///
    /// Split from [`apply`](Self::apply) because verification is a *later*
    /// observation: the receipt records the level it can currently justify and
    /// the evidence for it, which is what lets a status read tell "verified once,
    /// long ago" from "verified now".
    pub fn record_verification(
        &mut self,
        tool: &DevToolKind,
        scope: SettingsScope,
        result: &VerificationResult,
        freshness_window_secs: u64,
    ) -> Result<IntegrationReceipt, EngineError> {
        let mut receipt = self
            .store
            .load_receipt(tool, scope)?
            .ok_or(EngineError::NoReceipt { scope })?;

        let justified = result.highest_justified_level(result.verified_at_unix_secs, freshness_window_secs);
        receipt.achieved_level = justified
            .min(receipt.planned_level)
            .min(receipt.profile.max_reportable_level());
        receipt.achieved_evidence.clone_from(&result.evidence);
        receipt.verified_at_unix_secs = Some(result.verified_at_unix_secs);
        self.store.save_receipt(&receipt)?;
        Ok(receipt)
    }

    /// Reverse everything the receipt records as applied and delete the receipt.
    ///
    /// Steps whose restoration the receipt cannot prove are reported in
    /// [`RemovalOutcome::residual`], and their presence keeps the receipt on
    /// disk: a user whose settings could not be fully restored must still be
    /// able to see what Agent Assembly left behind.
    pub fn remove(&mut self, tool: &DevToolKind, scope: SettingsScope) -> Result<RemovalOutcome, EngineError> {
        let receipt = self
            .store
            .load_receipt(tool, scope)?
            .ok_or(EngineError::NoReceipt { scope })?;

        let applied: Vec<StepReceipt> = receipt.steps.iter().filter(|s| s.applied).cloned().collect();
        let mut journal = OperationJournal::starting(
            JournalOperation::Remove,
            &receipt.plan_id,
            tool.clone(),
            scope,
            receipt.applied_at_unix_secs,
            applied.iter().map(|s| s.step_id.clone()),
        );
        self.store.save_journal(&journal)?;

        let mut residual: Vec<String> = receipt
            .unrestorable_steps()
            .iter()
            .map(|s| unrestorable_reason(s))
            .collect();

        let reversed = self.reverse_all(&mut journal, &applied)?;

        let receipt_deleted = residual.is_empty();
        if receipt_deleted {
            self.store.delete_receipt(tool, scope)?;
        } else {
            residual.push(
                "the integration receipt was kept so you can see what remains; remove it by hand once you are done"
                    .to_string(),
            );
        }
        self.store.delete_journal(tool, scope)?;

        Ok(RemovalOutcome {
            reversed_steps: reversed,
            residual,
            receipt_deleted,
        })
    }

    /// Resolve an interrupted apply or remove.
    ///
    /// Safe to call at every start and safe to call twice — the journal's rule
    /// is a pure function of two facts, and every reversal it asks for is
    /// idempotent.
    pub fn recover(&mut self, tool: &DevToolKind, scope: SettingsScope) -> Result<RecoveryAction, EngineError> {
        let journal = self.store.load_journal(tool, scope)?;
        let action = recovery_action(journal.as_ref(), self.store.receipt_exists(tool, scope));

        match &action {
            RecoveryAction::Nothing => {}
            RecoveryAction::ClearStaleJournal => {
                self.store.delete_journal(tool, scope)?;
            }
            RecoveryAction::Escalate { reason } => {
                return Err(EngineError::RecoveryEscalated { reason: reason.clone() })
            }
            RecoveryAction::RollBackInterruptedApply { step_ids } => {
                // No receipt exists — that is what makes this an interrupted
                // apply — so the journal's own per-step outcomes are the only
                // reversal information there is.
                let mut journal = journal.expect("a rollback action implies a journal");
                let steps: Vec<StepReceipt> = journal
                    .applied_outcomes()
                    .into_iter()
                    .filter(|s| step_ids.contains(&s.step_id))
                    .collect();
                self.reverse_all(&mut journal, &steps)?;
                self.store.delete_journal(tool, scope)?;
            }
            RecoveryAction::ResumeInterruptedRemove { step_ids } => {
                // A removal still has its receipt, which is the durable home for
                // the prior state each reversal restores.
                let receipt = self
                    .store
                    .load_receipt(tool, scope)?
                    .ok_or(EngineError::NoReceipt { scope })?;
                let steps: Vec<StepReceipt> = receipt
                    .steps
                    .iter()
                    .filter(|s| s.applied && step_ids.contains(&s.step_id))
                    .cloned()
                    .collect();

                let mut journal = journal.expect("a resume action implies a journal");
                self.reverse_all(&mut journal, &steps)?;
                self.store.delete_receipt(tool, scope)?;
                self.store.delete_journal(tool, scope)?;
            }
        }

        Ok(action)
    }

    /// Reverse `steps` in reverse application order, journalling each one.
    fn reverse_all(
        &mut self,
        journal: &mut OperationJournal,
        steps: &[StepReceipt],
    ) -> Result<Vec<String>, EngineError> {
        let mut reversed = Vec::new();
        for step in steps.iter().rev() {
            match self.executor.reverse(step) {
                Ok(()) => {
                    journal.mark(&step.step_id, StepProgress::Reversed);
                    reversed.push(step.step_id.clone());
                }
                Err(source) => {
                    journal.mark(
                        &step.step_id,
                        StepProgress::Failed {
                            reason: source.to_string(),
                        },
                    );
                    self.store.save_journal(journal)?;
                    return Err(EngineError::ReversalFailed {
                        step_id: step.step_id.clone(),
                        source,
                    });
                }
            }
            self.store.save_journal(journal)?;
        }
        Ok(reversed)
    }
}

/// The highest level configuration alone can justify, capped by the plan.
///
/// Never above [`Integrated`](ProtectionLevel::Integrated): reaching
/// `GatewayProtected` needs traffic that was exercised and adjudicated, which an
/// apply does not do.
fn configuration_level(receipt: &IntegrationReceipt, planned: ProtectionLevel) -> ProtectionLevel {
    let required = receipt.required_steps();
    let level = if required > 0 && receipt.verified_required_steps() >= required {
        ProtectionLevel::Integrated
    } else {
        ProtectionLevel::PartiallyIntegrated
    };
    level.min(planned).min(receipt.profile.max_reportable_level())
}

/// Whether a freshly computed receipt describes the same host state as a stored
/// one, ignoring the fields that move on every run.
fn receipts_agree(stored: &IntegrationReceipt, fresh: &IntegrationReceipt) -> bool {
    stored.steps.len() == fresh.steps.len()
        && stored
            .steps
            .iter()
            .zip(&fresh.steps)
            .all(|(a, b)| a.step_id == b.step_id && a.applied == b.applied && a.fingerprint == b.fingerprint)
}

fn unrestorable_reason(step: &StepReceipt) -> String {
    match &step.prior_state {
        Some(prior) if !prior.withheld_keys.is_empty() => format!(
            "{}: the previous value of {} was not stored because it looked like a credential, \
             so it could not be restored",
            artifact_label(step),
            prior.withheld_keys.join(", ")
        ),
        _ => format!("{}: this step recorded no way to undo it", artifact_label(step)),
    }
}

fn artifact_label(step: &StepReceipt) -> String {
    match step.action.affected_paths().first() {
        Some(path) => path.display().to_string(),
        None => format!("{} ({})", step.step_id, step.action.kind()),
    }
}

/// A [`StepExecutor`] for the plan steps that are pure filesystem writes.
///
/// # What it does and does not cover
///
/// Managed settings, trust material and owned artifacts — every step whose
/// mutation is "put these bytes at this path" — are handled here, once, with the
/// prior-state capture and idempotence check that receipts and drift depend on.
/// Launch-environment injection, proxy variables, MCP lists, IDE registration
/// and runtime connection are **not**: each needs mechanism the filesystem
/// cannot supply, and each belongs to the adapter that knows its tool
/// (AAASM-5281). Those report [`ExecutionError::Unsupported`] rather than
/// succeeding quietly, so a receipt can never claim a mutation nothing performed.
///
/// # Why content is injected rather than read from the plan
///
/// A [`StepAction`] carries the *digest* of what will be written, not the bytes:
/// the adapter renders the content and the service writes it (ADR 0030 matrix
/// rows 2 and 3). This executor therefore takes the rendered content by step id
/// and checks it against the digest the plan showed the user before writing
/// anything.
#[derive(Debug, Default)]
pub struct FilesystemExecutor {
    rendered: BTreeMap<String, String>,
}

impl FilesystemExecutor {
    /// An executor with no content, for plans that only remove things.
    pub fn new() -> Self {
        Self::default()
    }

    /// Supply the content a step will write.
    #[must_use]
    pub fn with_content(mut self, step_id: impl Into<String>, content: impl Into<String>) -> Self {
        self.rendered.insert(step_id.into(), content.into());
        self
    }

    fn content_for(&self, step_id: &str, expected_sha256: &str) -> Result<&str, ExecutionError> {
        let content = self
            .rendered
            .get(step_id)
            .map(String::as_str)
            .ok_or_else(|| ExecutionError::ContentMissing {
                step_id: step_id.to_string(),
            })?;

        // Accept a digest over either the raw rendering or its canonical form:
        // an adapter hashes what it produced, and the C3 constraint means the
        // canonical form is what actually survives the write.
        let matches = fingerprint::sha256_hex(content) == expected_sha256
            || fingerprint::canonicalize(content).is_ok_and(|c| fingerprint::sha256_hex(&c) == expected_sha256);
        if !matches {
            return Err(ExecutionError::ContentMismatch {
                step_id: step_id.to_string(),
            });
        }
        Ok(content)
    }

    fn apply_settings(
        &self,
        step_id: &str,
        path: &Path,
        managed_keys: &[String],
        content: &str,
        merge: SettingsMerge,
    ) -> Result<StepOutcome, ExecutionError> {
        let label = path.display().to_string();
        let current = read_document(path)?;

        let fp = |source| ExecutionError::Fingerprint {
            artifact: label.clone(),
            source,
        };

        let prior_values = fingerprint::managed_projection(&current, managed_keys).map_err(fp)?;
        let (safe_values, withheld_keys) = fingerprint::screen_managed_values(&prior_values).map_err(fp)?;
        let prior_state = PriorSettingsState {
            managed_values_json: safe_values,
            absent_keys: fingerprint::absent_managed_keys(&current, managed_keys).map_err(fp)?,
            withheld_keys,
            document_fingerprint: fingerprint::document_fingerprint(&current).map_err(fp)?,
        };

        let next = match merge {
            SettingsMerge::MergeManagedKeys => {
                fingerprint::merge_managed_keys(&current, content, managed_keys).map_err(fp)?
            }
            SettingsMerge::Replace => fingerprint::canonicalize(content).map_err(fp)?,
        };

        let unchanged = fingerprint::canonicalize(&current).map_err(fp)? == next && path.exists();
        if !unchanged {
            write_preserving_mode(path, &next, step_id)?;
        }

        Ok(StepOutcome {
            fingerprint: Some(fingerprint::managed_fingerprint(&next, managed_keys).map_err(fp)?),
            document_fingerprint: Some(fingerprint::document_fingerprint(&next).map_err(fp)?),
            prior_state: Some(prior_state),
            mutated: !unchanged,
        })
    }

    fn write_blob(&self, step_id: &str, path: &Path, content: &str) -> Result<StepOutcome, ExecutionError> {
        let unchanged = std::fs::read_to_string(path).is_ok_and(|existing| existing == content);
        if !unchanged {
            write_preserving_mode(path, content, step_id)?;
        }
        Ok(StepOutcome {
            fingerprint: Some(fingerprint::fingerprint_raw(content)),
            document_fingerprint: None,
            prior_state: None,
            mutated: !unchanged,
        })
    }
}

impl StepExecutor for FilesystemExecutor {
    fn apply(&mut self, step: &IntegrationStep) -> Result<StepOutcome, ExecutionError> {
        match &step.action {
            StepAction::WriteManagedSettings {
                path,
                managed_keys,
                content_sha256,
                merge,
                ..
            } => {
                let content = self.content_for(&step.id, content_sha256)?.to_string();
                self.apply_settings(&step.id, path, managed_keys, &content, *merge)
            }
            StepAction::MaterialiseTrustMaterial {
                kind,
                path,
                content_sha256,
            } => {
                if *kind == TrustMaterialKind::ProxyCaTrustStoreAnchor {
                    // A trust-store anchor is a privileged host change, not a
                    // file write, and ADR 0030 §6.6 requires it to be its own
                    // individually consented mechanism. Refusing here is what
                    // stops it being smuggled in as an ordinary artifact.
                    return Err(ExecutionError::Unsupported {
                        kind: "trust-store-anchor",
                    });
                }
                let content = self.content_for(&step.id, content_sha256)?.to_string();
                self.write_blob(&step.id, path, &content)
            }
            StepAction::ManageArtifact { operation, path } => match operation {
                ArtifactOperation::Remove => {
                    let existed = path.exists();
                    remove_file(path)?;
                    Ok(StepOutcome {
                        mutated: existed,
                        ..StepOutcome::default()
                    })
                }
                ArtifactOperation::Create | ArtifactOperation::Update => {
                    let content =
                        self.rendered
                            .get(&step.id)
                            .cloned()
                            .ok_or_else(|| ExecutionError::ContentMissing {
                                step_id: step.id.clone(),
                            })?;
                    self.write_blob(&step.id, path, &content)
                }
            },
            StepAction::RunProtectionTest { .. } => {
                // A probe mutates nothing and produces no fingerprint. Its
                // result is evidence, adjudicated by the core, and it reaches
                // the receipt through `record_verification`, never through here.
                Ok(StepOutcome::default())
            }
            other => Err(ExecutionError::Unsupported { kind: other.kind() }),
        }
    }

    fn reverse(&mut self, step: &StepReceipt) -> Result<(), ExecutionError> {
        if let (Some(prior), StepAction::WriteManagedSettings { path, .. }) = (&step.prior_state, &step.action) {
            let label = path.display().to_string();
            let fp = |source| ExecutionError::Fingerprint {
                artifact: label.clone(),
                source,
            };

            if !path.exists() {
                // Already gone. Removal has to be safe to run twice.
                return Ok(());
            }
            let current = read_document(path)?;
            let restored = fingerprint::restore_managed_keys(&current, &prior.managed_values_json, &prior.absent_keys)
                .map_err(fp)?;

            // A document left holding nothing but what AASM added is a file AASM
            // created; leaving an empty `{}` behind would be an artifact the
            // user never had.
            if restored == "{}" && prior.document_fingerprint == fingerprint::fingerprint_raw("{}") {
                return remove_file(path);
            }
            write_preserving_mode(path, &restored, &step.step_id)?;
            // Deliberately not withheld keys: they were never stored, so there
            // is nothing to write back, and `unrestorable_steps` has already
            // told the user.
            return Ok(());
        }

        match &step.reversal {
            Some(StepAction::ManageArtifact {
                operation: ArtifactOperation::Remove,
                path,
            }) => remove_file(path),
            Some(other) => Err(ExecutionError::Unsupported { kind: other.kind() }),
            None => match &step.action {
                // A step that mutated nothing needs no reversal.
                StepAction::RunProtectionTest { .. } => Ok(()),
                other => Err(ExecutionError::Unsupported { kind: other.kind() }),
            },
        }
    }

    fn observe(&self, step: &StepReceipt) -> ArtifactObservation {
        match &step.action {
            StepAction::WriteManagedSettings { path, managed_keys, .. } => {
                if !path.exists() {
                    return ArtifactObservation::Missing;
                }
                let raw = match std::fs::read_to_string(path) {
                    Ok(raw) => raw,
                    Err(e) => return ArtifactObservation::Unreadable { reason: e.to_string() },
                };
                match (
                    fingerprint::managed_fingerprint(&raw, managed_keys),
                    fingerprint::document_fingerprint(&raw),
                ) {
                    (Ok(managed_fingerprint), Ok(document)) => ArtifactObservation::Present {
                        managed_fingerprint,
                        document_fingerprint: Some(document),
                    },
                    (Err(e), _) | (_, Err(e)) => ArtifactObservation::Unreadable { reason: e.to_string() },
                }
            }
            StepAction::MaterialiseTrustMaterial { path, .. } | StepAction::ManageArtifact { path, .. } => {
                match std::fs::read_to_string(path) {
                    Ok(raw) => ArtifactObservation::Present {
                        managed_fingerprint: fingerprint::fingerprint_raw(&raw),
                        document_fingerprint: None,
                    },
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => ArtifactObservation::Missing,
                    Err(e) => ArtifactObservation::Unreadable { reason: e.to_string() },
                }
            }
            other => ArtifactObservation::Unreadable {
                reason: format!("a {} step has no filesystem state to inspect", other.kind()),
            },
        }
    }
}

/// Read a JSON document, treating an absent file as an empty object.
///
/// An absent settings file and an empty one mean the same thing to a merge, and
/// collapsing them here is what makes the first install and every reinstall take
/// the same code path.
fn read_document(path: &Path) -> Result<String, ExecutionError> {
    match std::fs::read_to_string(path) {
        Ok(raw) if raw.trim().is_empty() => Ok("{}".to_string()),
        Ok(raw) => Ok(raw),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok("{}".to_string()),
        Err(e) => Err(ExecutionError::Io {
            artifact: path.display().to_string(),
            detail: e.to_string(),
        }),
    }
}

/// Write `body` to `path` atomically, keeping whatever mode the file already had.
///
/// The tool's own settings file belongs to the user, so its permissions are
/// theirs to choose; AASM's own state is the thing this codebase pins to `0600`
/// (see [`ReceiptStore`](super::ReceiptStore)). Writing through a temporary file
/// and renaming keeps a crash mid-write from truncating a file the user needs.
fn write_preserving_mode(path: &Path, body: &str, step_id: &str) -> Result<(), ExecutionError> {
    let io = |detail: String| ExecutionError::Io {
        artifact: format!("{} (step {step_id})", path.display()),
        detail,
    };

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| io(e.to_string()))?;
    }

    #[cfg(unix)]
    let existing_mode = {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(path).ok().map(|m| m.permissions().mode())
    };

    let tmp = path.with_extension("aasm-tmp");
    std::fs::write(&tmp, body).map_err(|e| io(e.to_string()))?;

    #[cfg(unix)]
    if let Some(mode) = existing_mode {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(mode)).map_err(|e| io(e.to_string()))?;
    }

    std::fs::rename(&tmp, path).map_err(|e| io(e.to_string()))
}

fn remove_file(path: &Path) -> Result<(), ExecutionError> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(ExecutionError::Io {
            artifact: path.display().to_string(),
            detail: e.to_string(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::integration::plan::{IntegrationRequest, ProtectionProfile};
    use crate::integration::state::{EvidenceKind, ExerciseOutcome, ProtectionEvidence};
    use crate::integration::status::{VerificationOutcome, VerificationResult};
    use crate::integration::version::{core_version, SupportedToolVersions, LIFECYCLE_SCHEMA_VERSION};
    use crate::integration::IntegrationCapability;
    use crate::GovernanceLevel;
    use std::path::PathBuf;

    /// Fabricated to match `aa_security`'s `sk-ant-` literal pattern. Never a
    /// credential; the `AAASM5278SYNTHETIC` marker is what the negative test
    /// searches the persisted receipt for.
    const SYNTHETIC_SECRET: &str =
        "sk-ant-api03-AAASM5278SYNTHETICDONOTUSEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    const MANAGED_CONTENT: &str = r#"{"permissions":{"allow":["Bash"],"deny":[]},"permissionMode":"default"}"#;

    struct Fixture {
        _dir: tempfile::TempDir,
        settings: PathBuf,
        ca: PathBuf,
        store: ReceiptStore,
    }

    fn fixture() -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        Fixture {
            settings: dir.path().join("tool").join("settings.json"),
            ca: dir.path().join("aasm").join("ca.pem"),
            store: ReceiptStore::at(dir.path().join("state")),
            _dir: dir,
        }
    }

    fn managed_keys() -> Vec<String> {
        vec!["permissions".to_string(), "permissionMode".to_string()]
    }

    fn settings_step(path: &Path) -> IntegrationStep {
        IntegrationStep::new(
            "settings",
            StepAction::WriteManagedSettings {
                scope: SettingsScope::User,
                path: path.to_path_buf(),
                managed_keys: managed_keys(),
                content_sha256: fingerprint::sha256_hex(MANAGED_CONTENT),
                merge: SettingsMerge::MergeManagedKeys,
            },
            "write the managed settings block",
        )
    }

    fn ca_step(path: &Path, pem: &str) -> IntegrationStep {
        IntegrationStep::new(
            "ca",
            StepAction::MaterialiseTrustMaterial {
                kind: TrustMaterialKind::ProxyCaCertificatePem,
                path: path.to_path_buf(),
                content_sha256: fingerprint::sha256_hex(pem),
            },
            "write the AASM proxy CA where the tool can read it",
        )
        .with_reversal(StepAction::ManageArtifact {
            operation: ArtifactOperation::Remove,
            path: path.to_path_buf(),
        })
    }

    fn plan(f: &Fixture) -> IntegrationPlan {
        let request = IntegrationRequest::new(
            DevToolKind::ClaudeCode,
            ProtectionProfile::Recommended,
            SettingsScope::User,
        );
        IntegrationPlan::new(
            "plan-1",
            &request,
            ProtectionLevel::Integrated,
            GovernanceLevel::L2Enforce,
        )
        .with_step(settings_step(&f.settings))
        .with_step(ca_step(
            &f.ca,
            "-----BEGIN CERTIFICATE-----\nAASM\n-----END CERTIFICATE-----\n",
        ))
    }

    fn executor(_f: &Fixture) -> FilesystemExecutor {
        FilesystemExecutor::new()
            .with_content("settings", MANAGED_CONTENT)
            .with_content("ca", "-----BEGIN CERTIFICATE-----\nAASM\n-----END CERTIFICATE-----\n")
    }

    fn engine(f: &Fixture) -> IntegrationEngine<FilesystemExecutor> {
        IntegrationEngine::new(executor(f), f.store.clone())
    }

    fn context(now: u64) -> ApplyContext {
        ApplyContext {
            receipt_id: format!("receipt-{now}"),
            versions: ComponentVersions {
                core: core_version(),
                adapter: ToolVersion::new(0, 1, 0),
                lifecycle_schema: LIFECYCLE_SCHEMA_VERSION,
            },
            tool_version: Some(ToolVersion::new(2, 1, 220)),
            now_unix_secs: now,
        }
    }

    fn compatible() -> VersionCompatibility {
        VersionCompatibility::Compatible {
            detected: ToolVersion::new(2, 1, 220),
        }
    }

    fn read_settings(f: &Fixture) -> serde_json::Value {
        serde_json::from_str(&std::fs::read_to_string(&f.settings).unwrap()).unwrap()
    }

    fn write_settings(f: &Fixture, raw: &str) {
        std::fs::create_dir_all(f.settings.parent().unwrap()).unwrap();
        std::fs::write(&f.settings, raw).unwrap();
    }

    #[test]
    fn a_dry_run_renders_the_plan_and_mutates_nothing() {
        let f = fixture();
        let e = engine(&f);
        let rendered = e.dry_run(&plan(&f)).unwrap();

        assert!(
            rendered.starts_with("integration plan plan-1 for ClaudeCode"),
            "{rendered}"
        );
        assert!(rendered.contains("settings scope: user"), "{rendered}");
        assert!(!f.settings.exists(), "a dry run must not create the target file");
        assert!(!f.ca.exists());
        assert!(!f.store.root().exists(), "a dry run must not create the receipt store");
    }

    #[test]
    fn a_plan_that_does_not_validate_is_never_executed() {
        let f = fixture();
        let mut e = engine(&f);
        // Two steps sharing an id: a receipt could not attribute them.
        let broken = plan(&f).with_step(settings_step(&f.settings));
        assert!(matches!(
            e.apply(&broken, &context(1)),
            Err(EngineError::InvalidPlan(_))
        ));
        assert!(!f.settings.exists());
    }

    #[test]
    fn apply_writes_a_receipt_and_preserves_unmanaged_keys() {
        let f = fixture();
        write_settings(&f, r#"{"theme":"dark","permissionMode":"acceptEdits"}"#);

        let mut e = engine(&f);
        let outcome = e.apply(&plan(&f), &context(1_000)).unwrap();

        assert!(outcome.mutated);
        assert!(outcome.skipped.is_empty());
        assert_eq!(outcome.receipt.achieved_level, ProtectionLevel::Integrated);
        assert_eq!(
            read_settings(&f)["theme"],
            "dark",
            "an unmanaged key must survive apply"
        );
        assert_eq!(read_settings(&f)["permissionMode"], "default");
        assert!(f.ca.exists());

        let stored = f
            .store
            .load_receipt(&DevToolKind::ClaudeCode, SettingsScope::User)
            .unwrap()
            .unwrap();
        assert_eq!(stored, outcome.receipt);
        assert_eq!(stored.verified_required_steps(), stored.required_steps());
        assert!(
            f.store
                .load_journal(&DevToolKind::ClaudeCode, SettingsScope::User)
                .unwrap()
                .is_none(),
            "a completed apply leaves no journal"
        );

        // The prior value of the key AASM displaced is what removal restores.
        let prior = stored.steps[0].prior_state.as_ref().unwrap();
        assert!(prior.managed_values_json.contains("acceptEdits"));
        assert_eq!(prior.absent_keys, vec!["permissions".to_string()]);
    }

    #[test]
    fn reapplying_the_same_plan_mutates_nothing() {
        let f = fixture();
        write_settings(&f, r#"{"theme":"dark"}"#);

        let mut e = engine(&f);
        let first = e.apply(&plan(&f), &context(1_000)).unwrap();
        let before = std::fs::read_to_string(&f.settings).unwrap();
        let receipt_before =
            std::fs::read_to_string(f.store.receipt_path(&DevToolKind::ClaudeCode, SettingsScope::User)).unwrap();

        let second = e.apply(&plan(&f), &context(9_999)).unwrap();

        assert!(!second.mutated, "a reapply must report that it changed nothing");
        assert_eq!(second.receipt, first.receipt, "including its applied-at timestamp");
        assert_eq!(std::fs::read_to_string(&f.settings).unwrap(), before);
        assert_eq!(
            std::fs::read_to_string(f.store.receipt_path(&DevToolKind::ClaudeCode, SettingsScope::User)).unwrap(),
            receipt_before,
            "the stored receipt must be byte-identical after a no-op reapply"
        );
    }

    #[test]
    fn a_clean_install_reports_no_drift() {
        let f = fixture();
        write_settings(&f, r#"{"theme":"dark"}"#);
        let mut e = engine(&f);
        e.apply(&plan(&f), &context(1_000)).unwrap();

        let report = e.detect_drift(&DevToolKind::ClaudeCode, SettingsScope::User, &compatible(), None);
        assert!(report.is_clean(), "{report:?}");
    }

    #[test]
    fn reformatting_the_settings_file_is_not_drift() {
        // The C3 constraint's honest consequence: the adapter reserialises, so
        // comparison is over semantics. A user who pretty-printed their file has
        // not drifted.
        let f = fixture();
        write_settings(&f, r#"{"theme":"dark"}"#);
        let mut e = engine(&f);
        e.apply(&plan(&f), &context(1_000)).unwrap();

        let value: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&f.settings).unwrap()).unwrap();
        std::fs::write(&f.settings, serde_json::to_string_pretty(&value).unwrap()).unwrap();

        let report = e.detect_drift(&DevToolKind::ClaudeCode, SettingsScope::User, &compatible(), None);
        assert!(report.is_clean(), "{report:?}");
    }

    #[test]
    fn repair_rewrites_aasm_state_and_leaves_a_later_user_key_alone() {
        let f = fixture();
        write_settings(&f, r#"{"theme":"dark"}"#);
        let mut e = engine(&f);
        e.apply(&plan(&f), &context(1_000)).unwrap();

        // The user tampers with an AASM-managed key *and* adds one of their own
        // after installation.
        let mut doc = read_settings(&f);
        doc["permissionMode"] = serde_json::json!("bypassPermissions");
        doc["editorFontSize"] = serde_json::json!(18);
        std::fs::write(&f.settings, doc.to_string()).unwrap();

        let report = e.detect_drift(&DevToolKind::ClaudeCode, SettingsScope::User, &compatible(), None);
        assert!(report.contains(DriftKind::AasmManagedValueChanged));
        assert!(report.is_fully_repairable());

        let outcome = e.repair(&plan(&f), &report, 2_000).unwrap();
        assert_eq!(outcome.repaired_steps, vec!["settings".to_string()]);

        let after = read_settings(&f);
        assert_eq!(
            after["permissionMode"], "default",
            "the AASM-managed key must be restored"
        );
        assert_eq!(
            after["editorFontSize"], 18,
            "a user key added after installation must survive repair"
        );
        assert_eq!(
            after["theme"], "dark",
            "a user key present before installation must survive repair"
        );
        assert!(f.ca.exists(), "repair must not touch steps drift did not name");
    }

    #[test]
    fn repair_does_not_run_when_only_an_unrelated_user_key_changed() {
        let f = fixture();
        write_settings(&f, r#"{"theme":"dark"}"#);
        let mut e = engine(&f);
        e.apply(&plan(&f), &context(1_000)).unwrap();

        let mut doc = read_settings(&f);
        doc["theme"] = serde_json::json!("light");
        std::fs::write(&f.settings, doc.to_string()).unwrap();

        let report = e.detect_drift(&DevToolKind::ClaudeCode, SettingsScope::User, &compatible(), None);
        assert!(report.contains(DriftKind::UserManagedUnrelatedChange));
        assert!(report.aasm_state_is_intact());

        let outcome = e.repair(&plan(&f), &report, 2_000).unwrap();
        assert!(
            outcome.repaired_steps.is_empty(),
            "repair must have nothing to do about a key AASM does not own"
        );
        assert_eq!(outcome.preserved_user_changes, vec![f.settings.display().to_string()]);
        assert_eq!(read_settings(&f)["theme"], "light", "the user's own change stands");
    }

    #[test]
    fn a_corrupt_receipt_blocks_repair_instead_of_silently_reinstalling() {
        let f = fixture();
        write_settings(&f, r#"{"theme":"dark"}"#);
        let mut e = engine(&f);
        e.apply(&plan(&f), &context(1_000)).unwrap();

        // Hand-edit the stored receipt without recomputing its integrity hash.
        let path = f.store.receipt_path(&DevToolKind::ClaudeCode, SettingsScope::User);
        let raw = std::fs::read_to_string(&path).unwrap();
        let tampered = raw.replace("\"plan_id\": \"plan-1\"", "\"plan_id\": \"plan-forged\"");
        assert_ne!(tampered, raw, "the fixture must actually have been modified");
        std::fs::write(&path, tampered).unwrap();

        let report = e.detect_drift(&DevToolKind::ClaudeCode, SettingsScope::User, &compatible(), None);
        assert!(report.contains(DriftKind::ReceiptCorrupt), "{report:?}");
        assert!(!report.is_fully_repairable());

        let err = e
            .repair(&plan(&f), &report, 2_000)
            .expect_err("repair must refuse to write against a receipt it cannot trust");
        assert!(matches!(err, EngineError::Unrepairable { .. }), "{err:?}");
    }

    #[test]
    fn a_missing_aasm_artifact_is_repaired() {
        let f = fixture();
        let mut e = engine(&f);
        e.apply(&plan(&f), &context(1_000)).unwrap();
        std::fs::remove_file(&f.ca).unwrap();

        let report = e.detect_drift(&DevToolKind::ClaudeCode, SettingsScope::User, &compatible(), None);
        assert!(report.contains(DriftKind::AasmArtifactMissing));

        e.repair(&plan(&f), &report, 2_000).unwrap();
        assert!(f.ca.exists());
        assert!(e
            .detect_drift(&DevToolKind::ClaudeCode, SettingsScope::User, &compatible(), None)
            .is_clean());
    }

    #[test]
    fn a_repair_drops_the_verification_it_did_not_re_run() {
        let f = fixture();
        let mut e = engine(&f);
        e.apply(&plan(&f), &context(1_000)).unwrap();
        e.record_verification(
            &DevToolKind::ClaudeCode,
            SettingsScope::User,
            &VerificationResult {
                verified_at_unix_secs: 1_000,
                outcome: VerificationOutcome::Passed,
                evidence: vec![ProtectionEvidence::new(
                    IntegrationCapability::ModelPathInterception,
                    EvidenceKind::Exercised {
                        outcome: ExerciseOutcome::Redacted,
                    },
                    1_000,
                    "probe adjudicated by the core",
                )],
            },
            3_600,
        )
        .unwrap();

        std::fs::remove_file(&f.ca).unwrap();
        let report = e.detect_drift(&DevToolKind::ClaudeCode, SettingsScope::User, &compatible(), None);
        let outcome = e.repair(&plan(&f), &report, 2_000).unwrap();

        assert!(
            outcome.receipt.achieved_evidence.is_empty(),
            "a repair re-established configuration; it did not re-exercise traffic"
        );
        assert_eq!(outcome.receipt.verified_at_unix_secs, None);
        assert!(outcome.receipt.achieved_level <= ProtectionLevel::Integrated);
    }

    #[test]
    fn verification_records_the_level_and_the_evidence_that_justified_it() {
        let f = fixture();
        let mut e = engine(&f);
        let request = IntegrationRequest::new(
            DevToolKind::ClaudeCode,
            ProtectionProfile::Recommended,
            SettingsScope::User,
        );
        let probing = IntegrationPlan::new(
            "plan-probe",
            &request,
            ProtectionLevel::GatewayProtected,
            GovernanceLevel::L2Enforce,
        )
        .with_step(settings_step(&f.settings))
        .with_step(
            IntegrationStep::new(
                "probe",
                StepAction::RunProtectionTest {
                    probe: crate::integration::ProbeDescriptor {
                        id: "synthetic-secret".to_string(),
                        mechanism: IntegrationCapability::ModelPathInterception,
                        description: "send a synthetic secret down the model path".to_string(),
                    },
                },
                "verify the model path is actually intercepted",
            )
            .optional(),
        );

        let applied = e.apply(&probing, &context(1_000)).unwrap();
        assert_eq!(
            applied.receipt.achieved_level,
            ProtectionLevel::Integrated,
            "an apply configures; it does not exercise traffic, so it cannot claim GatewayProtected"
        );

        let verified = e
            .record_verification(
                &DevToolKind::ClaudeCode,
                SettingsScope::User,
                &VerificationResult {
                    verified_at_unix_secs: 1_100,
                    outcome: VerificationOutcome::Passed,
                    evidence: vec![ProtectionEvidence::new(
                        IntegrationCapability::ModelPathInterception,
                        EvidenceKind::Exercised {
                            outcome: ExerciseOutcome::Redacted,
                        },
                        1_100,
                        "the synthetic secret was redacted before egress",
                    )],
                },
                3_600,
            )
            .unwrap();

        assert_eq!(verified.achieved_level, ProtectionLevel::GatewayProtected);
        assert_eq!(verified.verified_at_unix_secs, Some(1_100));
        assert_eq!(
            verified.validate(),
            Ok(()),
            "the claim must be one its evidence can carry"
        );
    }

    #[test]
    fn remove_restores_prior_state_and_keeps_later_user_changes() {
        let f = fixture();
        write_settings(&f, r#"{"theme":"dark","permissionMode":"acceptEdits"}"#);
        let mut e = engine(&f);
        e.apply(&plan(&f), &context(1_000)).unwrap();

        // The user changes something of their own after installation.
        let mut doc = read_settings(&f);
        doc["theme"] = serde_json::json!("light");
        std::fs::write(&f.settings, doc.to_string()).unwrap();

        let outcome = e.remove(&DevToolKind::ClaudeCode, SettingsScope::User).unwrap();
        assert!(outcome.residual.is_empty(), "{:?}", outcome.residual);
        assert!(outcome.receipt_deleted);
        assert_eq!(outcome.reversed_steps, vec!["ca".to_string(), "settings".to_string()]);

        let after = read_settings(&f);
        assert_eq!(
            after["permissionMode"], "acceptEdits",
            "the displaced value is restored"
        );
        assert!(after.get("permissions").is_none(), "a key AASM added is deleted");
        assert_eq!(after["theme"], "light", "a post-install user change survives removal");
        assert!(!f.ca.exists(), "an artifact AASM created is deleted");
        assert!(!f.store.receipt_exists(&DevToolKind::ClaudeCode, SettingsScope::User));
    }

    #[test]
    fn remove_deletes_a_settings_file_it_created_outright() {
        let f = fixture();
        let mut e = engine(&f);
        e.apply(&plan(&f), &context(1_000)).unwrap();
        assert!(f.settings.exists());

        e.remove(&DevToolKind::ClaudeCode, SettingsScope::User).unwrap();
        assert!(
            !f.settings.exists(),
            "a file that held nothing but AASM's keys is AASM's to remove"
        );
    }

    #[test]
    fn remove_is_idempotent_and_refuses_without_a_receipt() {
        let f = fixture();
        let mut e = engine(&f);
        e.apply(&plan(&f), &context(1_000)).unwrap();
        e.remove(&DevToolKind::ClaudeCode, SettingsScope::User).unwrap();

        assert!(matches!(
            e.remove(&DevToolKind::ClaudeCode, SettingsScope::User),
            Err(EngineError::NoReceipt { .. })
        ));
    }

    #[test]
    fn a_withheld_prior_value_becomes_a_residual_and_keeps_the_receipt() {
        let f = fixture();
        // The user keeps a credential inside a key AASM manages.
        write_settings(
            &f,
            &format!(r#"{{"theme":"dark","permissionMode":"{SYNTHETIC_SECRET}"}}"#),
        );
        let mut e = engine(&f);
        e.apply(&plan(&f), &context(1_000)).unwrap();

        let outcome = e.remove(&DevToolKind::ClaudeCode, SettingsScope::User).unwrap();
        assert!(
            !outcome.receipt_deleted,
            "the user must still be able to see what remains"
        );
        assert!(
            outcome.residual.iter().any(|r| r.contains("permissionMode")),
            "{:?}",
            outcome.residual
        );
        assert!(f.store.receipt_exists(&DevToolKind::ClaudeCode, SettingsScope::User));
    }

    #[test]
    fn no_raw_secret_from_the_settings_file_can_reach_the_receipt() {
        let f = fixture();
        write_settings(
            &f,
            &format!(r#"{{"apiKey":"{SYNTHETIC_SECRET}","permissionMode":"{SYNTHETIC_SECRET}","theme":"dark"}}"#),
        );
        let mut e = engine(&f);
        e.apply(&plan(&f), &context(1_000)).unwrap();

        let persisted =
            std::fs::read_to_string(f.store.receipt_path(&DevToolKind::ClaudeCode, SettingsScope::User)).unwrap();

        // The whole secret, and any recognisable fragment of it.
        assert!(
            !persisted.contains(SYNTHETIC_SECRET),
            "the receipt holds the raw secret"
        );
        assert!(
            !persisted.contains("AAASM5278SYNTHETIC"),
            "the receipt holds a fragment of the secret"
        );
        assert!(!persisted.contains("sk-ant-"), "the receipt holds a credential prefix");

        // And the file itself still has both, so the test is about the receipt
        // rather than about the secret having been destroyed.
        let on_disk = std::fs::read_to_string(&f.settings).unwrap();
        assert!(on_disk.contains(SYNTHETIC_SECRET));

        // The unmanaged key was never even read into a projection; the managed
        // one was read, screened and withheld.
        let receipt = f
            .store
            .load_receipt(&DevToolKind::ClaudeCode, SettingsScope::User)
            .unwrap()
            .unwrap();
        let prior = receipt.steps[0].prior_state.as_ref().unwrap();
        assert_eq!(prior.withheld_keys, vec!["permissionMode".to_string()]);
        assert!(!prior.is_fully_restorable());
    }

    /// Drive an apply and stop it after `after_steps` mutations, leaving exactly
    /// the on-disk state a crash at that point would: a journal, the mutations
    /// that got that far, and no receipt.
    fn interrupt_apply_after(f: &Fixture, after_steps: usize) -> OperationJournal {
        let p = plan(f);
        let mut executor = executor(f);
        let mut journal = OperationJournal::starting(
            JournalOperation::Apply,
            &p.plan_id,
            DevToolKind::ClaudeCode,
            SettingsScope::User,
            1_000,
            p.steps.iter().map(|s| s.id.clone()),
        );
        f.store.save_journal(&journal).unwrap();

        for step in p.steps.iter().take(after_steps) {
            let outcome = executor.apply(step).unwrap();
            let mut receipt = StepReceipt::applied(step, outcome.fingerprint);
            if let Some(doc) = outcome.document_fingerprint {
                receipt = receipt.with_document_fingerprint(doc);
            }
            if let Some(prior) = outcome.prior_state {
                receipt = receipt.with_prior_state(prior);
            }
            journal.record_applied(receipt);
            f.store.save_journal(&journal).unwrap();
        }
        journal
    }

    #[test]
    fn an_interrupted_apply_rolls_back_to_where_the_developer_started() {
        let f = fixture();
        write_settings(&f, r#"{"theme":"dark","permissionMode":"acceptEdits"}"#);
        let untouched = std::fs::read_to_string(&f.settings).unwrap();

        // Crash after the settings write, before the CA step and before any
        // receipt exists.
        interrupt_apply_after(&f, 1);
        assert_ne!(
            std::fs::read_to_string(&f.settings).unwrap(),
            untouched,
            "the fixture must actually have mutated the host"
        );
        assert!(!f.store.receipt_exists(&DevToolKind::ClaudeCode, SettingsScope::User));

        let mut e = engine(&f);
        let action = e.recover(&DevToolKind::ClaudeCode, SettingsScope::User).unwrap();
        assert!(
            matches!(action, RecoveryAction::RollBackInterruptedApply { .. }),
            "{action:?}"
        );

        let after = read_settings(&f);
        assert_eq!(
            after["permissionMode"], "acceptEdits",
            "the displaced value is put back"
        );
        assert!(after.get("permissions").is_none(), "the key the apply added is removed");
        assert_eq!(after["theme"], "dark");
        assert!(!f.ca.exists(), "a step that never ran left nothing to remove");
        assert!(
            f.store
                .load_journal(&DevToolKind::ClaudeCode, SettingsScope::User)
                .unwrap()
                .is_none(),
            "recovery clears the journal it resolved"
        );

        // Running recovery again is a no-op, not a second rollback.
        assert_eq!(
            e.recover(&DevToolKind::ClaudeCode, SettingsScope::User).unwrap(),
            RecoveryAction::Nothing
        );
    }

    #[test]
    fn a_crash_after_the_receipt_was_written_only_clears_the_journal() {
        let f = fixture();
        write_settings(&f, r#"{"theme":"dark"}"#);
        let mut e = engine(&f);
        let applied = e.apply(&plan(&f), &context(1_000)).unwrap();

        // The receipt landed; the journal deletion did not.
        let mut journal = OperationJournal::starting(
            JournalOperation::Apply,
            "plan-1",
            DevToolKind::ClaudeCode,
            SettingsScope::User,
            1_000,
            applied.receipt.steps.iter().map(|s| s.step_id.clone()),
        );
        for step in &applied.receipt.steps {
            journal.record_applied(step.clone());
        }
        f.store.save_journal(&journal).unwrap();

        let settings_before = std::fs::read_to_string(&f.settings).unwrap();
        assert_eq!(
            e.recover(&DevToolKind::ClaudeCode, SettingsScope::User).unwrap(),
            RecoveryAction::ClearStaleJournal
        );
        assert_eq!(
            std::fs::read_to_string(&f.settings).unwrap(),
            settings_before,
            "a completed apply must not be undone by recovery"
        );
        assert!(f.store.receipt_exists(&DevToolKind::ClaudeCode, SettingsScope::User));
    }

    #[test]
    fn an_interrupted_remove_finishes_and_is_safe_to_run_twice() {
        let f = fixture();
        write_settings(&f, r#"{"theme":"dark","permissionMode":"acceptEdits"}"#);
        let mut e = engine(&f);
        e.apply(&plan(&f), &context(1_000)).unwrap();

        // A removal that got as far as the CA and then died.
        let mut journal = OperationJournal::starting(
            JournalOperation::Remove,
            "plan-1",
            DevToolKind::ClaudeCode,
            SettingsScope::User,
            1_000,
            ["settings".to_string(), "ca".to_string()],
        );
        journal.mark("ca", StepProgress::Reversed);
        std::fs::remove_file(&f.ca).unwrap();
        f.store.save_journal(&journal).unwrap();

        let action = e.recover(&DevToolKind::ClaudeCode, SettingsScope::User).unwrap();
        assert!(
            matches!(action, RecoveryAction::ResumeInterruptedRemove { .. }),
            "{action:?}"
        );
        assert_eq!(
            read_settings(&f)["permissionMode"],
            "acceptEdits",
            "resuming finishes the restore rather than reverting it"
        );
        assert!(!f.store.receipt_exists(&DevToolKind::ClaudeCode, SettingsScope::User));

        // Running recovery again must be a no-op, not an error.
        assert_eq!(
            e.recover(&DevToolKind::ClaudeCode, SettingsScope::User).unwrap(),
            RecoveryAction::Nothing
        );
    }

    #[test]
    fn recovery_escalates_a_journal_from_a_newer_core() {
        let f = fixture();
        let mut e = engine(&f);
        let mut journal = OperationJournal::starting(
            JournalOperation::Apply,
            "plan-1",
            DevToolKind::ClaudeCode,
            SettingsScope::User,
            1_000,
            ["settings".to_string()],
        );
        journal.schema_version = LIFECYCLE_SCHEMA_VERSION + 1;
        journal.mark("settings", StepProgress::Applied);
        f.store.save_journal(&journal).unwrap();

        assert!(matches!(
            e.recover(&DevToolKind::ClaudeCode, SettingsScope::User),
            Err(EngineError::RecoveryEscalated { .. })
        ));
        assert!(
            f.store
                .load_journal(&DevToolKind::ClaudeCode, SettingsScope::User)
                .unwrap()
                .is_some(),
            "an escalated journal is kept for the human it is escalated to"
        );
    }

    #[test]
    fn a_failed_required_step_rolls_the_whole_apply_back() {
        let f = fixture();
        write_settings(&f, r#"{"theme":"dark"}"#);
        let before = std::fs::read_to_string(&f.settings).unwrap();

        // The CA step's content is not supplied, so it fails; it is required.
        let executor = FilesystemExecutor::new().with_content("settings", MANAGED_CONTENT);
        let mut e = IntegrationEngine::new(executor, f.store.clone());

        let err = e
            .apply(&plan(&f), &context(1_000))
            .expect_err("a required step that cannot run must abort the apply");
        assert!(matches!(err, EngineError::RequiredStepFailed { .. }), "{err:?}");

        assert!(
            !f.store.receipt_exists(&DevToolKind::ClaudeCode, SettingsScope::User),
            "a failed apply must not leave a receipt claiming an integration"
        );
        assert_eq!(
            std::fs::read_to_string(&f.settings).unwrap(),
            before,
            "the rollback must return the settings file to what the developer had"
        );
        assert!(f
            .store
            .load_journal(&DevToolKind::ClaudeCode, SettingsScope::User)
            .unwrap()
            .is_none());
    }

    #[test]
    fn a_failed_optional_step_is_recorded_rather_than_fatal() {
        let f = fixture();
        let mut optional_ca = plan(&f);
        optional_ca.steps[1] = optional_ca.steps[1].clone().optional();

        let executor = FilesystemExecutor::new().with_content("settings", MANAGED_CONTENT);
        let mut e = IntegrationEngine::new(executor, f.store.clone());
        let outcome = e.apply(&optional_ca, &context(1_000)).unwrap();

        assert_eq!(outcome.skipped.len(), 1);
        assert_eq!(outcome.skipped[0].0, "ca");
        assert_eq!(
            outcome.receipt.achieved_level,
            ProtectionLevel::Integrated,
            "an optional step's absence does not make the integration partial"
        );
        assert!(!outcome.receipt.steps[1].applied);
    }

    #[test]
    fn content_that_does_not_match_the_reviewed_plan_is_refused() {
        let f = fixture();
        let executor = FilesystemExecutor::new()
            .with_content("settings", r#"{"permissionMode":"bypassPermissions"}"#)
            .with_content("ca", "-----BEGIN CERTIFICATE-----\nAASM\n-----END CERTIFICATE-----\n");
        let mut e = IntegrationEngine::new(executor, f.store.clone());

        let err = e
            .apply(&plan(&f), &context(1_000))
            .expect_err("the digest must be checked");
        assert!(
            matches!(
                err,
                EngineError::RequiredStepFailed {
                    source: ExecutionError::ContentMismatch { .. },
                    ..
                }
            ),
            "{err:?}"
        );
        assert!(!f.settings.exists());
    }

    #[test]
    fn a_trust_store_anchor_is_refused_rather_than_written_as_a_file() {
        let f = fixture();
        let anchor = IntegrationStep::new(
            "anchor",
            StepAction::MaterialiseTrustMaterial {
                kind: TrustMaterialKind::ProxyCaTrustStoreAnchor,
                path: f.ca.clone(),
                content_sha256: fingerprint::sha256_hex("pem"),
            },
            "install the AASM CA into the system trust store",
        );
        let mut executor = FilesystemExecutor::new().with_content("anchor", "pem");
        assert!(matches!(
            executor.apply(&anchor),
            Err(ExecutionError::Unsupported {
                kind: "trust-store-anchor"
            })
        ));
    }

    #[test]
    fn a_mechanism_this_executor_lacks_is_refused_rather_than_silently_succeeding() {
        let mut executor = FilesystemExecutor::new();
        let env = IntegrationStep::new(
            "env",
            StepAction::InjectLaunchEnvironment {
                scope: SettingsScope::User,
                variable: "NODE_EXTRA_CA_CERTS".to_string(),
                value: crate::integration::EnvValue::Literal("/tmp/ca.pem".to_string()),
            },
            "make the tool's Node runtime trust the AASM proxy CA",
        );
        assert!(matches!(
            executor.apply(&env),
            Err(ExecutionError::Unsupported {
                kind: "inject-launch-environment"
            })
        ));
    }

    #[test]
    fn upgrading_the_plan_supersedes_the_previous_receipt() {
        let f = fixture();
        let mut e = engine(&f);
        e.apply(&plan(&f), &context(1_000)).unwrap();

        let mut upgraded = plan(&f);
        upgraded.plan_id = "plan-2".to_string();
        let outcome = e.apply(&upgraded, &context(2_000)).unwrap();
        assert_eq!(outcome.receipt.plan_id, "plan-2");
        assert_eq!(outcome.receipt.receipt_id, "receipt-2000");

        let envelope = f
            .store
            .load_envelope(&DevToolKind::ClaudeCode, SettingsScope::User)
            .unwrap()
            .unwrap();
        assert_eq!(envelope.superseded.len(), 1);
        assert_eq!(envelope.superseded[0].receipt_id, "receipt-1000");
    }

    #[test]
    fn a_tool_upgrade_out_of_range_is_reported_and_not_repaired_away() {
        let f = fixture();
        let mut e = engine(&f);
        e.apply(&plan(&f), &context(1_000)).unwrap();

        let incompatible = SupportedToolVersions::between(ToolVersion::new(2, 0, 0), ToolVersion::new(3, 0, 0))
            .classify(Some(&ToolVersion::new(3, 4, 0)));
        let report = e.detect_drift(&DevToolKind::ClaudeCode, SettingsScope::User, &incompatible, None);
        assert!(report.contains(DriftKind::ToolVersionIncompatible));

        let err = e
            .repair(&plan(&f), &report, 2_000)
            .expect_err("repair cannot fix a version");
        assert!(matches!(err, EngineError::Unrepairable { .. }), "{err:?}");
    }

    #[test]
    fn a_reversal_that_fails_is_reported_rather_than_silently_completing() {
        let f = fixture();
        let mut e = engine(&f);
        e.apply(&plan(&f), &context(1_000)).unwrap();

        // Drop the reversal information the CA step carried, leaving the engine
        // with no way to undo it.
        let mut receipt = f
            .store
            .load_receipt(&DevToolKind::ClaudeCode, SettingsScope::User)
            .unwrap()
            .unwrap();
        receipt.steps[1].reversal = None;
        f.store.save_receipt(&receipt).unwrap();

        let err = e
            .remove(&DevToolKind::ClaudeCode, SettingsScope::User)
            .expect_err("an unreversible step must not be reported as removed");
        assert!(matches!(err, EngineError::ReversalFailed { .. }), "{err:?}");
        assert!(
            f.store.receipt_exists(&DevToolKind::ClaudeCode, SettingsScope::User),
            "the receipt survives a failed removal so the user can still see what is installed"
        );
        assert!(
            f.store
                .load_journal(&DevToolKind::ClaudeCode, SettingsScope::User)
                .unwrap()
                .is_some(),
            "the journal survives so recovery can resume the removal"
        );
    }
}
