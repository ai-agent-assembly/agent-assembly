//! The Developer Integration Service — [`IntegrationLifecycle`] over
//! AAASM-5278's [`IntegrationEngine`] (ADR 0030 §1.1 layer L-B, AAASM-5280).
//!
//! # What this is, and what it is not
//!
//! [`super::lifecycle::IntegrationLifecycle`] is the port the DI-API server
//! calls; AAASM-5279 shipped it as a trait with no implementation, because the
//! only correct implementation needed AAASM-5278's engine. This module is that
//! implementation, and it is the *only* place the two halves meet:
//!
//! * **Adapters author** — [`DevToolIntegration`] detects the tool, declares
//!   capabilities, authors an [`IntegrationPlan`], derives an
//!   [`IntegrationStatus`], runs the protection test and authors a
//!   [`RemovalPlan`].
//! * **The engine executes** — [`IntegrationEngine`] applies steps, writes the
//!   journal and the receipt, classifies drift, repairs AASM-owned state and
//!   reverses a removal.
//!
//! Nothing here knows what a Claude Code settings file looks like, or what any
//! other tool's configuration is. Every per-tool fact arrives through the
//! adapter trait; every mutation goes through the engine's executor. That is
//! what keeps ADR 0030's matrix rows 2 and 3 honest — *adapters author, the
//! service executes* — and it is why the CLI in AAASM-5280 can be a pure client
//! with no tool knowledge of its own.
//!
//! # Two bindings this module fixes, because the port left them open
//!
//! 1. **`remove(tool, None)` authors; `remove(tool, Some(plan_id))` executes.**
//!    The verb space is closed (§5.6.1), so there is no "removal plan" verb to
//!    add and no second surface to invent (forbidden design 11). The optional
//!    plan id already in the port carries the distinction, exactly the way
//!    `Plan`/`Apply` carry it for installation: a caller that has not seen the
//!    reversal steps cannot have consented to them.
//! 2. **A plan is only executable while the service remembers authoring it.**
//!    Plans are held in memory, not on disk, and a restart forgets them. A
//!    client must re-plan, which is the correct outcome: the plan a user
//!    approved described the host as it was, and the host may have moved.
//!
//! # Where the bytes come from
//!
//! An [`aa_core::integration::IntegrationStep`] carries the *digest* of what will be written, never
//! the content (§5.5). The adapter renders the content and the service writes
//! it, so applying a plan needs a rendering that hashes to what the user
//! reviewed. [`StepContentSource`] is that seam, and
//! [`FilesystemExecutor`] fails closed when the digest does not match — a
//! rendering that drifted from the reviewed plan is refused rather than written.

use std::collections::BTreeMap;
use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::Mutex;

use aa_core::dev_tool::{DevToolKind, GovernanceLevel};
use aa_core::integration::policy_posture::PolicyPosture;
use aa_core::integration::{
    now_unix_secs, ApplyContext, DevToolIntegration, DriftKind, DriftReport, EngineError, FilesystemExecutor,
    IntegrationCapability, IntegrationEngine, IntegrationPlan, IntegrationReceipt, IntegrationRequest,
    IntegrationStatus, ProtectionLevel, ProtectionState, ReceiptStore, RemovalPlan, SettingsScope, StepExecutor,
    VerificationOutcome, VerificationResult, VersionCompatibility, DEFAULT_FRESHNESS_WINDOW_SECS,
};

use super::apply_outcome::ApplyMutation;
use super::lifecycle::{
    AppliedIntegration, ApprovalInput, ApprovalRelayReceipt, IntegrationLifecycle, LifecycleError, LifecycleTarget,
    RepairReport, ScopedSecurityEvent, ToolDescriptor,
};
use super::projection::tool_id;

/// Renders the bytes a plan's steps will write.
///
/// Separate from [`DevToolIntegration`] because authoring a plan and producing
/// the content it describes are different moments: a plan may be reviewed for
/// minutes before it is applied, and the content must be re-derived at apply
/// time so that a policy or profile change between the two is caught by the
/// digest check rather than silently written.
#[async_trait]
pub trait StepContentSource: Send + Sync {
    /// The content for each of `plan`'s steps that writes any, keyed by step id.
    ///
    /// Steps this source has no content for are simply absent; the executor
    /// then reports [`aa_core::integration::ExecutionError::ContentMissing`]
    /// rather than writing an empty file.
    async fn render(&self, plan: &IntegrationPlan) -> Result<BTreeMap<String, String>, String>;
}

/// A content source that renders nothing.
///
/// Correct for a removal-only or observation-only deployment, and the default
/// for a registration that supplies no source: an executor with no content
/// refuses the write instead of inventing one.
pub struct NoContent;

#[async_trait]
impl StepContentSource for NoContent {
    async fn render(&self, _plan: &IntegrationPlan) -> Result<BTreeMap<String, String>, String> {
        Ok(BTreeMap::new())
    }
}

/// Builds the executor that performs one tool's mutations.
///
/// [`FilesystemExecutor`] handles every step whose mutation is "put these bytes
/// at this path" and refuses the rest, because launch-environment injection,
/// proxy variables and MCP lists need mechanism the filesystem cannot supply.
/// A tool whose plan contains one of those has to bring the executor for it —
/// so *which* executor runs is a property of the registration, not a constant
/// of the service (AAASM-5281).
///
/// The service still owns transactionality, the journal, the receipt and
/// rollback; only the per-mechanism mechanics move.
pub trait StepExecutorFactory: Send + Sync {
    /// An executor holding `rendered`, keyed by step id.
    fn executor(&self, rendered: BTreeMap<String, String>) -> Box<dyn StepExecutor + Send>;
}

/// The default factory: a plain [`FilesystemExecutor`].
pub struct FilesystemSteps;

impl StepExecutorFactory for FilesystemSteps {
    fn executor(&self, rendered: BTreeMap<String, String>) -> Box<dyn StepExecutor + Send> {
        let mut executor = FilesystemExecutor::new();
        for (step_id, content) in rendered {
            executor = executor.with_content(step_id, content);
        }
        Box::new(executor)
    }
}

/// One tool's adapter, the source of the bytes its plans describe, and the
/// executor that performs them.
pub struct RegisteredIntegration {
    /// The tool this registration answers for.
    pub tool: DevToolKind,
    /// The adapter that authors for it.
    pub integration: Arc<dyn DevToolIntegration>,
    /// Where the rendered content for its plan steps comes from.
    pub content: Arc<dyn StepContentSource>,
    /// What performs its plan steps.
    pub executor: Arc<dyn StepExecutorFactory>,
}

impl RegisteredIntegration {
    /// Register `integration` for `tool` with no content source and the
    /// filesystem executor.
    pub fn new(tool: DevToolKind, integration: Arc<dyn DevToolIntegration>) -> Self {
        Self {
            tool,
            integration,
            content: Arc::new(NoContent),
            executor: Arc::new(FilesystemSteps),
        }
    }

    /// Supply the rendering its plan steps need to be applicable.
    #[must_use]
    pub fn with_content(mut self, content: Arc<dyn StepContentSource>) -> Self {
        self.content = content;
        self
    }

    /// Supply the executor its plan steps need to be performable.
    #[must_use]
    pub fn with_executor(mut self, executor: Arc<dyn StepExecutorFactory>) -> Self {
        self.executor = executor;
        self
    }
}

/// A plan the service authored, with the consent the request carried.
///
/// The consent lives on [`IntegrationRequest`], not on [`IntegrationPlan`], so
/// applying a cached plan needs both halves: the steps the user reviewed *and*
/// whether they agreed to the privileged ones among them (§6.6).
#[derive(Clone)]
struct AuthoredPlan {
    plan: IntegrationPlan,
    allow_privileged_host_steps: bool,
}

/// The lifecycle service the DI-API server calls.
pub struct EngineLifecycle {
    integrations: Vec<RegisteredIntegration>,
    store: ReceiptStore,
    /// Plans authored but not yet applied, keyed by plan id. See the module
    /// docs: deliberately not durable.
    plans: Mutex<BTreeMap<String, AuthoredPlan>>,
    freshness_window_secs: u64,
}

impl EngineLifecycle {
    /// Build the service over `integrations`, storing receipts in `store`.
    pub fn new(integrations: Vec<RegisteredIntegration>, store: ReceiptStore) -> Self {
        Self {
            integrations,
            store,
            plans: Mutex::new(BTreeMap::new()),
            freshness_window_secs: DEFAULT_FRESHNESS_WINDOW_SECS,
        }
    }

    /// Use a non-default verification freshness window.
    #[must_use]
    pub fn with_freshness_window(mut self, secs: u64) -> Self {
        self.freshness_window_secs = secs;
        self
    }

    fn registered(&self, tool: &DevToolKind) -> Result<&RegisteredIntegration, LifecycleError> {
        self.integrations
            .iter()
            .find(|r| &r.tool == tool)
            .ok_or_else(|| LifecycleError::UnknownTool { tool_id: tool_id(tool) })
    }

    /// The receipt for `tool`, or the reason there is nothing to act on.
    ///
    /// A receipt that cannot be *read* is an error, never an absent one: a
    /// corrupt receipt must not be reported as "not installed", because that
    /// reading would invite an install on top of state nobody can account for.
    fn receipt(&self, tool: &DevToolKind, scope: SettingsScope) -> Result<IntegrationReceipt, LifecycleError> {
        match self.store.load_receipt(tool, scope) {
            Ok(Some(receipt)) => Ok(receipt),
            Ok(None) => Err(LifecycleError::Refused {
                detail: format!(
                    "no integration receipt records {} at {scope} scope; run an install first",
                    tool_id(tool)
                ),
            }),
            Err(e) => Err(LifecycleError::Failed {
                detail: format!("the integration receipt could not be read: {e}"),
            }),
        }
    }

    /// The scope a stored receipt used, so a status/verify/repair/remove reads
    /// the surface that was actually written rather than the one the caller's
    /// working directory would suggest.
    fn installed_scope(&self, tool: &DevToolKind) -> Option<SettingsScope> {
        [SettingsScope::User, SettingsScope::Project, SettingsScope::Managed]
            .into_iter()
            .find(|scope| self.store.receipt_exists(tool, *scope))
    }

    fn scope_or_default(&self, tool: &DevToolKind) -> SettingsScope {
        self.installed_scope(tool).unwrap_or(SettingsScope::User)
    }

    /// An engine whose executor holds the content `plan` describes.
    async fn engine_for(
        &self,
        registered: &RegisteredIntegration,
        plan: &IntegrationPlan,
    ) -> Result<IntegrationEngine<Box<dyn StepExecutor + Send>>, LifecycleError> {
        let rendered = registered
            .content
            .render(plan)
            .await
            .map_err(|detail| LifecycleError::Failed { detail })?;
        Ok(IntegrationEngine::new(
            registered.executor.executor(rendered),
            self.store.clone(),
        ))
    }

    /// An engine with no content, for the operations that only read or reverse.
    ///
    /// Still the tool's own executor: observing a launch-environment variable
    /// and reversing one are both mechanisms the filesystem executor does not
    /// have, so a shared observing engine would report every such artifact as
    /// unreadable and refuse to remove it.
    fn observing_engine(&self, registered: &RegisteredIntegration) -> IntegrationEngine<Box<dyn StepExecutor + Send>> {
        IntegrationEngine::new(registered.executor.executor(BTreeMap::new()), self.store.clone())
    }

    /// Re-author the plan a stored receipt was applied from.
    ///
    /// Repair needs the plan's steps to rewrite them, and a receipt records
    /// what was applied rather than how to reproduce it. Re-authoring from the
    /// receipt's own profile and scope is what keeps a repair a *repair*: it
    /// restores the integration the user chose, not the one today's defaults
    /// would produce.
    ///
    /// The project a project-scoped install went into is part of "the integration
    /// the user chose", and `repair` carries no request from the caller — so it
    /// comes from the receipt's own record of the file it wrote, never from this
    /// process's working directory (AAASM-5913). A receipt that cannot name its
    /// project produces a request with none, and the adapter refuses; that is the
    /// intended outcome, because there is nothing here that could honestly stand
    /// in for it.
    async fn plan_from_receipt(
        &self,
        registered: &RegisteredIntegration,
        receipt: &IntegrationReceipt,
    ) -> Result<IntegrationPlan, LifecycleError> {
        let mut request = IntegrationRequest::new(receipt.tool.clone(), receipt.profile, receipt.settings_scope)
            .requesting_level(receipt.planned_level);
        request.project_root = receipt.project_root().map(std::path::Path::to_path_buf);
        registered
            .integration
            .plan_integration(&request)
            .await
            .map_err(|e| LifecycleError::Failed {
                detail: format!("the integration plan could not be re-authored: {e}"),
            })
    }

    fn drift(
        &self,
        registered: &RegisteredIntegration,
        scope: SettingsScope,
        compatibility: &VersionCompatibility,
    ) -> DriftReport {
        self.observing_engine(registered)
            .detect_drift(&registered.tool, scope, compatibility, None)
    }

    /// Fold a drift report into a derived status.
    ///
    /// The adapter derives the ladder rung from the receipt; the engine
    /// classifies what the host currently holds. Drift is the engine's answer
    /// and it always wins, because a rung derived from a receipt whose
    /// artifacts no longer match is precisely the over-claim ADR 0030 forbidden
    /// design 4 exists to prevent.
    fn apply_drift(status: &mut IntegrationStatus, report: &DriftReport) {
        let mismatched = report.mismatched_artifacts();
        if mismatched.is_empty() {
            return;
        }
        status.state = ProtectionState::Drifted {
            last_held: status.state.achieved_level(),
            mismatched,
        };
    }

    fn descriptor(&self, registered: &RegisteredIntegration) -> ToolDescriptor {
        let info = registered.integration.detect();
        let support = registered.integration.version_support();
        let detected_version = info
            .as_ref()
            .and_then(|i| i.version.as_deref())
            .and_then(|v| v.parse().ok());
        ToolDescriptor {
            tool: registered.tool.clone(),
            display_name: display_name(&registered.tool),
            detected: info.is_some(),
            compatibility: support.supported_tool_versions.classify(detected_version.as_ref()),
            detected_version,
            capabilities: registered.integration.capabilities(),
            // A ceiling for a tool that is not on this host is not a claim
            // worth making, so an undetected tool reports the bottom of the
            // scale rather than what it *would* reach if installed.
            adapter_ceiling: info
                .as_ref()
                .map(|i| i.governance_level)
                .unwrap_or(GovernanceLevel::L0Discover),
        }
    }
}

/// A name to show a user, derived from the tool id so the two never disagree.
fn display_name(tool: &DevToolKind) -> String {
    match tool {
        DevToolKind::ClaudeCode => "Claude Code".to_string(),
        DevToolKind::Codex => "Codex".to_string(),
        DevToolKind::GitHubCopilot => "GitHub Copilot".to_string(),
        DevToolKind::WindsurfCascade => "Windsurf Cascade".to_string(),
        DevToolKind::Custom(name) => name.clone(),
    }
}

/// The mechanism a drift finding is *about*.
///
/// [`RepairReport::unrepairable`] is keyed by capability because that is what a
/// user acts on ("your managed settings drifted"), while a
/// [`aa_core::integration::DriftFinding`] is keyed by the artifact that
/// diverged. This is the one mapping between them, kept here so the wording a
/// user sees comes from one place.
fn finding_mechanism(kind: DriftKind) -> IntegrationCapability {
    match kind {
        DriftKind::ToolVersionIncompatible => IntegrationCapability::Discovery,
        DriftKind::RuntimeEndpointStale => IntegrationCapability::ModelGatewayBaseUrl,
        DriftKind::UserManagedUnrelatedChange
        | DriftKind::AasmManagedValueChanged
        | DriftKind::AasmArtifactMissing
        | DriftKind::ReceiptMissing
        | DriftKind::ReceiptCorrupt
        | DriftKind::Unobservable => IntegrationCapability::ManagedSettings,
        // `DriftKind` is `#[non_exhaustive]`: a kind added later has no
        // mechanism mapping yet, and attributing it to the wrong one would put
        // a misleading label on a repair report. Settings is the conservative
        // default — it is the mechanism every drift class so far belongs to.
        _ => IntegrationCapability::ManagedSettings,
    }
}

fn engine_error(e: EngineError) -> LifecycleError {
    match e {
        EngineError::NoReceipt { scope } => LifecycleError::Refused {
            detail: format!("no integration receipt exists at {scope} scope"),
        },
        EngineError::Unrepairable { detail } => LifecycleError::Refused { detail },
        EngineError::RecoveryEscalated { reason } => LifecycleError::Refused { detail: reason },
        other => LifecycleError::Failed {
            detail: other.to_string(),
        },
    }
}

/// Resolve the policy a governed launch on this host would run under.
///
/// The service is the single place this happens (ADR 0030 forbidden design 10):
/// adapters govern one tool each while the effective policy is a property of the
/// host, and a client that resolved it for itself would be reporting a claim it
/// manufactured. `status` and `verify` therefore both read this, and `aasm run`
/// reaches the same answer because it calls the same resolver.
///
/// A failure to resolve is reported as [`PolicyPosture::Unknown`], never as
/// `Unconfigured`: the latter is a governance finding about the operator's
/// setup, and an error reading the disk is not.
pub(crate) fn resolve_host_policy() -> PolicyPosture {
    // The mapping lives in `aa-policy` beside the resolution it describes, so
    // `status`, `verify` and the audit record `aasm run` emits cannot drift
    // into three descriptions of the same four states (AAASM-5349).
    aa_policy::resolve::resolve(None).posture()
}

#[async_trait]
impl IntegrationLifecycle for EngineLifecycle {
    async fn list_tools(&self) -> Result<Vec<ToolDescriptor>, LifecycleError> {
        Ok(self.integrations.iter().map(|r| self.descriptor(r)).collect())
    }

    async fn plan(&self, request: IntegrationRequest) -> Result<IntegrationPlan, LifecycleError> {
        let registered = self.registered(&request.tool)?;
        if registered.integration.detect().is_none() {
            return Err(LifecycleError::ToolNotInstalled {
                tool_id: tool_id(&request.tool),
            });
        }
        let plan = registered
            .integration
            .plan_integration(&request)
            .await
            .map_err(|e| LifecycleError::Failed {
                detail: format!("the integration plan could not be authored: {e}"),
            })?;
        // Validate here rather than at apply: a plan that cannot be executed is
        // not a dry run a user should be asked to approve.
        plan.validate().map_err(|e| LifecycleError::Failed {
            detail: format!("the adapter authored a plan that does not validate: {e}"),
        })?;
        self.plans.lock().await.insert(
            plan.plan_id.clone(),
            AuthoredPlan {
                plan: plan.clone(),
                allow_privileged_host_steps: request.allow_privileged_host_steps,
            },
        );
        Ok(plan)
    }

    async fn apply(&self, tool: &DevToolKind, plan_id: &str) -> Result<AppliedIntegration, LifecycleError> {
        let registered = self.registered(tool)?;
        let authored = self
            .plans
            .lock()
            .await
            .get(plan_id)
            .filter(|a| &a.plan.tool == tool)
            .cloned()
            .ok_or_else(|| LifecycleError::UnknownPlan {
                plan_id: plan_id.to_string(),
            })?;
        let plan = authored.plan;

        // §6.6: a privileged host step is never implied by a profile. The
        // request that authored the plan is the record of what was consented
        // to, so an unconsented privileged step is refused rather than skipped
        // — skipping would produce a receipt for a weaker integration than the
        // one asked for, with nothing saying so.
        if let Some(step) = plan.privileged_steps().next() {
            if !authored.allow_privileged_host_steps {
                return Err(LifecycleError::Refused {
                    detail: format!(
                        "step {:?} changes host state and was not consented to; \
                         re-plan with privileged host steps allowed to include it",
                        step.id
                    ),
                });
            }
        }

        let support = registered.integration.version_support();
        let context = ApplyContext {
            receipt_id: format!("receipt-{}", plan.plan_id),
            versions: support.component_versions(),
            tool_version: registered
                .integration
                .detect()
                .and_then(|i| i.version)
                .and_then(|v| v.parse().ok()),
            now_unix_secs: now_unix_secs(),
        };

        let mut engine = self.engine_for(registered, &plan).await?;
        // Resolve any interrupted operation before adding to it. Safe to call
        // twice, and it is what makes a repeated install idempotent rather than
        // additive after a crash.
        engine.recover(tool, plan.settings_scope).map_err(engine_error)?;
        let outcome = engine.apply(&plan, &context).map_err(engine_error)?;
        // The engine compares canonical forms, so this is an observation rather
        // than a prediction: `mutated` is false only when every step found the
        // target already exactly as the plan describes. Stated, never inferred
        // downstream — the receipt id is reused across a no-op reapply and the
        // timestamp is second-granularity, so neither can carry this
        // (AAASM-5674).
        let mutation = if outcome.mutated {
            ApplyMutation::Changed
        } else {
            ApplyMutation::Unchanged
        };
        Ok(AppliedIntegration {
            receipt: outcome.receipt,
            mutation,
        })
    }

    async fn status(&self, tool: &DevToolKind, _target: &LifecycleTarget) -> Result<IntegrationStatus, LifecycleError> {
        let registered = self.registered(tool)?;
        let scope = self.scope_or_default(tool);
        let receipt = self
            .store
            .load_receipt(tool, scope)
            .map_err(|e| LifecycleError::Failed {
                detail: format!("the integration receipt could not be read: {e}"),
            })?;

        let mut status = registered
            .integration
            .integration_status(receipt.as_ref())
            .await
            .map_err(|e| LifecycleError::Failed {
                detail: format!("the integration status could not be derived: {e}"),
            })?;

        if receipt.is_some() {
            let report = self.drift(registered, scope, &status.compatibility);
            Self::apply_drift(&mut status, &report);
        }
        // The adapter reported `Unknown` by construction — it governs one tool
        // and cannot speak for the host. Overwriting here is what makes the
        // service the single resolver rather than one of several.
        status.policy = resolve_host_policy();
        Ok(status)
    }

    async fn verify(
        &self,
        tool: &DevToolKind,
        _target: &LifecycleTarget,
    ) -> Result<VerificationResult, LifecycleError> {
        let registered = self.registered(tool)?;
        let scope = self.scope_or_default(tool);
        let receipt = self.receipt(tool, scope)?;

        let result = registered
            .integration
            .verify_integration(&receipt)
            .await
            .map_err(|e| LifecycleError::Failed {
                detail: format!("the protection test could not be run: {e}"),
            })?;

        // Record it even when it failed. A failed verification is the evidence
        // that lowers the reported level, and dropping it would leave status
        // reporting the level the last *successful* pass justified — the exact
        // "verified once, long ago" over-claim §4.2 rules out.
        self.observing_engine(registered)
            .record_verification(tool, scope, &result, self.freshness_window_secs)
            .map_err(engine_error)?;
        Ok(result)
    }

    async fn repair(
        &self,
        tool: &DevToolKind,
        target: &LifecycleTarget,
    ) -> Result<(RepairReport, IntegrationStatus), LifecycleError> {
        let registered = self.registered(tool)?;
        let scope = self.scope_or_default(tool);
        let receipt = self.receipt(tool, scope)?;
        let plan = self.plan_from_receipt(registered, &receipt).await?;

        let status_before = registered
            .integration
            .integration_status(Some(&receipt))
            .await
            .map_err(|e| LifecycleError::Failed {
                detail: format!("the integration status could not be derived: {e}"),
            })?;
        let report = self.drift(registered, scope, &status_before.compatibility);

        let mut engine = self.engine_for(registered, &plan).await?;
        let outcome = engine.repair(&plan, &report, now_unix_secs()).map_err(engine_error)?;

        let repaired = RepairReport {
            repaired: outcome.repaired_steps,
            // Findings the engine deliberately left alone are reported as
            // unrepairable-with-a-reason rather than omitted: "we did not touch
            // your own changes" is information the user needs, and silence
            // there reads as "there was nothing else".
            unrepairable: report
                .findings
                .iter()
                .filter(|f| !f.kind.is_repairable())
                .map(|f| (finding_mechanism(f.kind), f.detail.clone()))
                .collect(),
        };
        let status = self.status(tool, target).await?;
        Ok((repaired, status))
    }

    async fn remove(
        &self,
        tool: &DevToolKind,
        _target: &LifecycleTarget,
        plan_id: Option<&str>,
    ) -> Result<RemovalPlan, LifecycleError> {
        let registered = self.registered(tool)?;
        let scope = self.scope_or_default(tool);
        let receipt = self.receipt(tool, scope)?;

        let mut plan = registered
            .integration
            .plan_removal(&receipt)
            .await
            .map_err(|e| LifecycleError::Failed {
                detail: format!("the removal plan could not be authored: {e}"),
            })?;

        // No plan id: the caller is asking what removal *would* do. Authoring
        // is pure, so this returns without touching anything.
        let Some(requested) = plan_id else {
            return Ok(plan);
        };
        if requested != plan.plan_id {
            return Err(LifecycleError::UnknownPlan {
                plan_id: requested.to_string(),
            });
        }

        let mut engine = self.observing_engine(registered);
        engine.recover(tool, scope).map_err(engine_error)?;
        let outcome = engine.remove(tool, scope).map_err(engine_error)?;
        plan.residual.extend(outcome.residual);
        Ok(plan)
    }

    async fn scoped_events(
        &self,
        tool: &DevToolKind,
        _limit: u32,
        _since_unix_secs: u64,
    ) -> Result<Vec<ScopedSecurityEvent>, LifecycleError> {
        // The runtime's audit stream is not integration-scoped yet, and an
        // empty list is the honest answer for "no events are attributable to
        // this integration". Returning a plausible-looking projection built
        // from unattributed rows would be worse than returning nothing.
        self.registered(tool)?;
        Ok(Vec::new())
    }

    async fn relay_approval(
        &self,
        tool: &DevToolKind,
        _approval_id: &str,
        _input: ApprovalInput,
    ) -> Result<ApprovalRelayReceipt, LifecycleError> {
        self.registered(tool)?;
        // Relaying needs the runtime's approval queue, which this service does
        // not hold. Refusing is the only safe answer: an acknowledgement this
        // service invented would tell a client a human's input reached the
        // decision authority when it did not.
        Err(LifecycleError::Refused {
            detail: "approval relay is not available from this runtime build".to_string(),
        })
    }
}

/// Whether `result` established anything by exercising the protected path.
///
/// Exposed because it is the rule the CLI's exit code turns on: a verification
/// that only read configuration back has not shown that anything is protected,
/// however complete the configuration is (ADR 0030 forbidden design 4).
pub fn exercised_the_protected_path(result: &VerificationResult) -> bool {
    matches!(result.outcome, VerificationOutcome::Passed) && result.has_exercised_evidence()
}

/// The highest level `result` can justify, for callers that want to show the
/// gap between what was planned and what was proven.
pub fn justified_level(result: &VerificationResult, now_unix_secs: u64, window_secs: u64) -> ProtectionLevel {
    result.highest_justified_level(now_unix_secs, window_secs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::devint::fixture::{FixtureContent, FixtureIntegration, FixtureVerification};
    use aa_core::integration::ProtectionProfile;

    struct Harness {
        _dir: tempfile::TempDir,
        settings: std::path::PathBuf,
        store_root: std::path::PathBuf,
        service: EngineLifecycle,
    }

    fn harness(build: impl FnOnce(FixtureIntegration) -> FixtureIntegration) -> Harness {
        let dir = tempfile::tempdir().expect("tempdir");
        let settings = dir.path().join("settings.json");
        let store_root = dir.path().join("store");
        let fixture = build(FixtureIntegration::new(DevToolKind::ClaudeCode, &settings));
        let content = Arc::new(FixtureContent::new(fixture.rendered()));
        let service = EngineLifecycle::new(
            vec![RegisteredIntegration::new(DevToolKind::ClaudeCode, Arc::new(fixture)).with_content(content)],
            ReceiptStore::at(&store_root),
        );
        Harness {
            _dir: dir,
            settings,
            store_root,
            service,
        }
    }

    fn request() -> IntegrationRequest {
        IntegrationRequest::new(
            DevToolKind::ClaudeCode,
            ProtectionProfile::Recommended,
            SettingsScope::User,
        )
    }

    /// The plan verb's whole contract. Asserted against the filesystem rather
    /// than against the return value, because "it did not mutate" is a claim
    /// about the host, not about the struct.
    #[tokio::test]
    async fn planning_writes_no_file_no_receipt_and_no_store_directory() {
        let h = harness(|f| f);
        let plan = h.service.plan(request()).await.expect("plan");
        assert_eq!(plan.steps.len(), 1);
        assert!(!h.settings.exists(), "plan wrote the tool's settings");
        assert!(!h.store_root.exists(), "plan created the receipt store");
    }

    #[tokio::test]
    async fn applying_twice_is_idempotent_and_preserves_unrelated_user_keys() {
        let h = harness(|f| f);
        std::fs::write(&h.settings, r#"{"theme":"solarized"}"#).expect("seed");

        let plan = h.service.plan(request()).await.expect("plan");
        let first = h
            .service
            .apply(&DevToolKind::ClaudeCode, &plan.plan_id)
            .await
            .expect("apply");
        let after_first = std::fs::read_to_string(&h.settings).expect("read");
        assert!(after_first.contains("solarized"), "the user's own key was lost");
        assert!(after_first.contains("aasmManaged"));

        let plan = h.service.plan(request()).await.expect("re-plan");
        let second = h
            .service
            .apply(&DevToolKind::ClaudeCode, &plan.plan_id)
            .await
            .expect("re-apply");
        assert_eq!(
            std::fs::read_to_string(&h.settings).expect("read"),
            after_first,
            "a repeated install changed the settings"
        );
        assert_eq!(first.receipt.steps.len(), second.receipt.steps.len());
        // The fact the DI-API had no way to carry until AAASM-5674, asserted at
        // the layer that establishes it. A repeated install is a success and a
        // no-op, and the engine's canonical-form comparison is what knows the
        // difference — not the receipt id, which the reapply deliberately
        // reuses, and not the timestamp, which it deliberately keeps.
        assert_eq!(first.mutation, ApplyMutation::Changed);
        assert_eq!(second.mutation, ApplyMutation::Unchanged);
        assert_eq!(
            first.receipt.receipt_id, second.receipt.receipt_id,
            "the reused receipt id is exactly why the outcome cannot be derived from it"
        );
    }

    /// A plan that is not the one this service authored cannot be applied, so a
    /// client cannot execute steps nobody reviewed.
    #[tokio::test]
    async fn an_unknown_plan_id_is_refused() {
        let h = harness(|f| f);
        match h
            .service
            .apply(&DevToolKind::ClaudeCode, "plan-someone-else-made")
            .await
        {
            Err(LifecycleError::UnknownPlan { plan_id }) => assert_eq!(plan_id, "plan-someone-else-made"),
            other => panic!("expected UnknownPlan, got {other:?}"),
        }
    }

    /// §6.6: a host-state change is never implied. Without consent the apply is
    /// refused rather than silently reduced to the non-privileged steps.
    #[tokio::test]
    async fn a_privileged_step_without_consent_is_refused() {
        let h = harness(|f| f.requiring_privilege());
        let plan = h.service.plan(request()).await.expect("plan");
        match h.service.apply(&DevToolKind::ClaudeCode, &plan.plan_id).await {
            Err(LifecycleError::Refused { detail }) => assert!(detail.contains("host state"), "{detail}"),
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn an_undetected_tool_cannot_be_planned() {
        let h = harness(|f| f.undetected());
        match h.service.plan(request()).await {
            Err(LifecycleError::ToolNotInstalled { tool_id }) => assert_eq!(tool_id, "claude-code"),
            other => panic!("expected ToolNotInstalled, got {other:?}"),
        }
    }

    /// The anti-vacuous-pass rule at the service layer: settings that exist and
    /// read back correctly do not amount to a pass, and the level they justify
    /// stops below `GatewayProtected`.
    #[tokio::test]
    async fn read_back_alone_neither_passes_nor_reaches_gateway_protected() {
        let h = harness(|f| f.verifying(FixtureVerification::ReadBackOnly));
        let plan = h.service.plan(request()).await.expect("plan");
        h.service
            .apply(&DevToolKind::ClaudeCode, &plan.plan_id)
            .await
            .expect("apply");

        let result = h
            .service
            .verify(&DevToolKind::ClaudeCode, &LifecycleTarget::unspecified())
            .await
            .expect("verify");
        assert!(!exercised_the_protected_path(&result));
        assert!(
            justified_level(&result, result.verified_at_unix_secs, DEFAULT_FRESHNESS_WINDOW_SECS)
                < ProtectionLevel::GatewayProtected,
            "read-back evidence justified a traffic-level claim"
        );

        let status = h
            .service
            .status(&DevToolKind::ClaudeCode, &LifecycleTarget::unspecified())
            .await
            .expect("status");
        assert!(status.achieved_level() < ProtectionLevel::GatewayProtected);
    }

    #[tokio::test]
    async fn exercised_evidence_is_what_reaches_gateway_protected() {
        let h = harness(|f| f);
        let plan = h.service.plan(request()).await.expect("plan");
        h.service
            .apply(&DevToolKind::ClaudeCode, &plan.plan_id)
            .await
            .expect("apply");
        let result = h
            .service
            .verify(&DevToolKind::ClaudeCode, &LifecycleTarget::unspecified())
            .await
            .expect("verify");
        assert!(exercised_the_protected_path(&result));
    }

    /// A failed pass must still be recorded: otherwise status keeps reporting
    /// what the last *successful* pass justified.
    #[tokio::test]
    async fn a_failed_verification_lowers_the_reported_level() {
        let h = harness(|f| f.verifying(FixtureVerification::Leaked));
        let plan = h.service.plan(request()).await.expect("plan");
        h.service
            .apply(&DevToolKind::ClaudeCode, &plan.plan_id)
            .await
            .expect("apply");
        h.service
            .verify(&DevToolKind::ClaudeCode, &LifecycleTarget::unspecified())
            .await
            .expect("verify");
        let status = h
            .service
            .status(&DevToolKind::ClaudeCode, &LifecycleTarget::unspecified())
            .await
            .expect("status");
        assert!(status.achieved_level() < ProtectionLevel::GatewayProtected);
    }

    #[tokio::test]
    async fn verifying_without_an_installation_is_refused_rather_than_passing() {
        let h = harness(|f| f);
        match h
            .service
            .verify(&DevToolKind::ClaudeCode, &LifecycleTarget::unspecified())
            .await
        {
            Err(LifecycleError::Refused { detail }) => assert!(detail.contains("install"), "{detail}"),
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    /// The binding this module fixes: no plan id means *author only*.
    #[tokio::test]
    async fn removal_without_a_plan_id_authors_without_removing() {
        let h = harness(|f| f);
        let plan = h.service.plan(request()).await.expect("plan");
        h.service
            .apply(&DevToolKind::ClaudeCode, &plan.plan_id)
            .await
            .expect("apply");
        let before = std::fs::read_to_string(&h.settings).expect("read");

        let removal = h
            .service
            .remove(&DevToolKind::ClaudeCode, &LifecycleTarget::unspecified(), None)
            .await
            .expect("preview");
        assert!(!removal.steps.is_empty());
        assert_eq!(std::fs::read_to_string(&h.settings).expect("read"), before);
        assert!(
            h.service
                .status(&DevToolKind::ClaudeCode, &LifecycleTarget::unspecified())
                .await
                .expect("status")
                .phase
                == aa_core::integration::LifecyclePhase::Installed,
            "a preview removed the integration"
        );
    }

    #[tokio::test]
    async fn removal_with_the_plan_id_restores_the_users_own_settings() {
        let h = harness(|f| f);
        std::fs::write(&h.settings, r#"{"theme":"solarized"}"#).expect("seed");
        let plan = h.service.plan(request()).await.expect("plan");
        h.service
            .apply(&DevToolKind::ClaudeCode, &plan.plan_id)
            .await
            .expect("apply");

        let preview = h
            .service
            .remove(&DevToolKind::ClaudeCode, &LifecycleTarget::unspecified(), None)
            .await
            .expect("preview");
        h.service
            .remove(
                &DevToolKind::ClaudeCode,
                &LifecycleTarget::unspecified(),
                Some(&preview.plan_id),
            )
            .await
            .expect("remove");

        let restored = std::fs::read_to_string(&h.settings).expect("read");
        assert!(restored.contains("solarized"), "removal lost the user's own key");
        assert!(!restored.contains("aasmManaged"), "removal left AASM's keys behind");
    }

    #[tokio::test]
    async fn removal_with_a_plan_id_nobody_authored_is_refused() {
        let h = harness(|f| f);
        let plan = h.service.plan(request()).await.expect("plan");
        h.service
            .apply(&DevToolKind::ClaudeCode, &plan.plan_id)
            .await
            .expect("apply");
        match h
            .service
            .remove(
                &DevToolKind::ClaudeCode,
                &LifecycleTarget::unspecified(),
                Some("removal-nope"),
            )
            .await
        {
            Err(LifecycleError::UnknownPlan { plan_id }) => assert_eq!(plan_id, "removal-nope"),
            other => panic!("expected UnknownPlan, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn drift_in_an_aasm_owned_key_is_reported_and_repaired() {
        let h = harness(|f| f);
        let plan = h.service.plan(request()).await.expect("plan");
        h.service
            .apply(&DevToolKind::ClaudeCode, &plan.plan_id)
            .await
            .expect("apply");

        std::fs::write(&h.settings, r#"{"aasmManaged":false,"theme":"solarized"}"#).expect("tamper");
        let drifted = h
            .service
            .status(&DevToolKind::ClaudeCode, &LifecycleTarget::unspecified())
            .await
            .expect("status");
        assert!(
            matches!(drifted.state, ProtectionState::Drifted { .. }),
            "tampering with a managed key must report drift, got {:?}",
            drifted.state
        );

        let (report, _) = h
            .service
            .repair(&DevToolKind::ClaudeCode, &LifecycleTarget::unspecified())
            .await
            .expect("repair");
        assert_eq!(report.repaired, vec!["settings".to_string()]);
        let repaired = std::fs::read_to_string(&h.settings).expect("read");
        assert!(repaired.contains("solarized"), "repair discarded the user's own key");
        assert!(
            !matches!(
                h.service
                    .status(&DevToolKind::ClaudeCode, &LifecycleTarget::unspecified())
                    .await
                    .expect("status")
                    .state,
                ProtectionState::Drifted { .. }
            ),
            "repair did not clear the drift"
        );
    }

    #[tokio::test]
    async fn a_tool_no_adapter_knows_is_an_unknown_tool_not_a_crash() {
        let h = harness(|f| f);
        match h
            .service
            .status(&DevToolKind::Codex, &LifecycleTarget::unspecified())
            .await
        {
            Err(LifecycleError::UnknownTool { tool_id }) => assert_eq!(tool_id, "codex"),
            other => panic!("expected UnknownTool, got {other:?}"),
        }
    }

    /// Nothing this service returns can carry the rendered settings body, so a
    /// secret an adapter put in one cannot reach a client through any verb.
    #[tokio::test]
    async fn no_lifecycle_response_carries_the_rendered_settings_body() {
        let h = harness(|f| f.poisoned());
        let plan = h.service.plan(request()).await.expect("plan");
        let receipt = h
            .service
            .apply(&DevToolKind::ClaudeCode, &plan.plan_id)
            .await
            .expect("apply");
        let status = h
            .service
            .status(&DevToolKind::ClaudeCode, &LifecycleTarget::unspecified())
            .await
            .expect("status");
        let verification = h
            .service
            .verify(&DevToolKind::ClaudeCode, &LifecycleTarget::unspecified())
            .await
            .expect("verify");
        let removal = h
            .service
            .remove(&DevToolKind::ClaudeCode, &LifecycleTarget::unspecified(), None)
            .await
            .expect("preview");

        let sentinel = crate::devint::fixture::LEAK_SENTINEL;
        for (what, rendered) in [
            ("plan", format!("{plan:?}")),
            ("receipt", format!("{receipt:?}")),
            ("status", format!("{status:?}")),
            ("verification", format!("{verification:?}")),
            ("removal", format!("{removal:?}")),
        ] {
            assert!(!rendered.contains(sentinel), "{what} carried the settings body");
        }
    }
}
