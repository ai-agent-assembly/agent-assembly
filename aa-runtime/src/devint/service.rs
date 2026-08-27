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

    /// The scope to act on, and the receipt if one is stored there.
    ///
    /// Two questions the callers used to answer separately, joined because the
    /// second one validates the first: the scope a caller named is not a scope
    /// until the receipt found there is confirmed to be the installation they
    /// meant.
    ///
    /// A caller that named no scope gets [`Self::installed_scope`]'s answer —
    /// "there should be exactly one, use it". That was the whole of the old
    /// behaviour, and on a host with one installation it is still right.
    fn resolve_target(
        &self,
        tool: &DevToolKind,
        target: &LifecycleTarget,
    ) -> Result<(SettingsScope, Option<IntegrationReceipt>), LifecycleError> {
        let scope = self.target_scope(tool, target);
        let receipt = self
            .store
            .load_receipt(tool, scope)
            .map_err(|e| LifecycleError::Failed {
                detail: format!("the integration receipt could not be read: {e}"),
            })?;
        if let Some(receipt) = &receipt {
            Self::confirm_project(tool, receipt, target)?;
            Self::confirm_user_config_home(tool, receipt, target)?;
        }
        Ok((scope, receipt))
    }

    /// As [`Self::resolve_target`], for the verbs that have nothing to do
    /// without a receipt.
    fn require_target(
        &self,
        tool: &DevToolKind,
        target: &LifecycleTarget,
    ) -> Result<(SettingsScope, IntegrationReceipt), LifecycleError> {
        let scope = self.target_scope(tool, target);
        let receipt = self.receipt(tool, scope)?;
        Self::confirm_project(tool, &receipt, target)?;
        Self::confirm_user_config_home(tool, &receipt, target)?;
        Ok((scope, receipt))
    }

    fn target_scope(&self, tool: &DevToolKind, target: &LifecycleTarget) -> SettingsScope {
        target
            .settings_scope
            .or_else(|| self.installed_scope(tool))
            .unwrap_or(SettingsScope::User)
    }

    /// Refuse a project-scope receipt the request does not name (AAASM-5913).
    ///
    /// A project-scope receipt belongs to one project, and until now nothing in
    /// a `status`/`verify`/`repair`/`remove` request said which project the
    /// caller had in mind. There is exactly one project-scope receipt slot per
    /// tool on a host, so a caller standing in an unrelated repository was told
    /// that repository was protected — and `repair` and `remove`, which act on
    /// the paths the receipt records, would then have written to and deleted
    /// from the *other* project's files.
    ///
    /// So the request has to name the project, and the name has to match. The
    /// three ways it can fail are all refusals, deliberately:
    ///
    /// - **Nothing named.** A pre-DI-API-6 client, or one whose working
    ///   directory could not be read. Nothing here can honestly stand in for
    ///   it; this daemon's own directory least of all.
    /// - **A different project named.** The caller is somewhere else. Neither
    ///   answer — reporting the stored project, or reporting "not installed" —
    ///   is true of what they asked, so neither is given.
    /// - **The receipt cannot say.** A project-scope receipt with no applied
    ///   settings write records no project, so there is nothing to compare and
    ///   the comparison cannot be skipped.
    ///
    /// User and managed scope are unaffected: their destinations were never the
    /// caller's to name, so there is nothing to disagree about.
    ///
    /// None of the refusals name the other project's path. These details reach
    /// a client verbatim as `DENY_CODE_LIFECYCLE_ERROR`, and "which other
    /// repository this developer has on disk" is not something the caller asked
    /// about or is owed.
    fn confirm_project(
        tool: &DevToolKind,
        receipt: &IntegrationReceipt,
        target: &LifecycleTarget,
    ) -> Result<(), LifecycleError> {
        if receipt.settings_scope != SettingsScope::Project {
            return Ok(());
        }
        let Some(requested) = target.project_root.as_deref() else {
            return Err(LifecycleError::Refused {
                detail: format!(
                    "{} is installed at project scope, and this request does not say which project it is \
                     about; re-run from the project's directory with a client that speaks DI-API {}",
                    tool_id(tool),
                    crate::devint::negotiate::DI_API_PROJECT_ROOT_SINCE
                ),
            });
        };
        let Some(recorded) = receipt.project_root() else {
            return Err(LifecycleError::Refused {
                detail: format!(
                    "the stored project-scope receipt for {} does not record which project it wrote, so it \
                     cannot be shown to be this one; remove and re-install the integration",
                    tool_id(tool)
                ),
            });
        };
        if same_path(recorded, requested) {
            return Ok(());
        }
        Err(LifecycleError::Refused {
            detail: format!(
                "the project-scope integration for {} belongs to another project, not this one; run this \
                 command from the project it was installed into",
                tool_id(tool)
            ),
        })
    }

    /// Refuse a cached plan the caller cannot claim as this project's
    /// (AAASM-5913).
    ///
    /// [`Self::confirm_project`]'s question asked on the write path, where it is
    /// a different question with a different source of truth. There a stored
    /// receipt says which project the installation is in; here nothing is
    /// installed yet, and the *plan* says which project it was authored for.
    ///
    /// The plan cache is process-global and keyed only by the plan id, so an
    /// authored plan outlives the invocation that asked for it: a client can hold
    /// the id, the developer can move to another repository, and applying it from
    /// there would still write the project it was authored for. Agent Assembly's
    /// managed keys would land in a checked-in `.claude/settings.json` the caller
    /// never named, under a receipt claiming a project they are not in.
    ///
    /// A plan id now names its project, which is what makes a stale one
    /// diagnosable in a log — but a label nobody compares is decoration. This is
    /// the comparison, and it is made against the full canonical paths rather
    /// than the truncated digest in the id.
    ///
    /// As with [`Self::confirm_project`], no refusal names the other project's
    /// path: these details reach a client verbatim, and which other repository a
    /// developer has on disk is not what the caller asked about.
    fn confirm_plan_project(plan: &IntegrationPlan, target: &LifecycleTarget) -> Result<(), LifecycleError> {
        // A user- or managed-scope plan is about the host, not a project, so
        // there is nothing for the caller's directory to disagree with.
        let Some(authored_for) = plan.project_root.as_deref() else {
            return Ok(());
        };
        let Some(requested) = target.project_root.as_deref() else {
            return Err(LifecycleError::Refused {
                detail: format!(
                    "this plan was authored for a project, and this request does not say which project it \
                     is being applied from; re-run the install from that project's directory with a \
                     client that speaks DI-API {}",
                    crate::devint::negotiate::DI_API_PROJECT_ROOT_SINCE
                ),
            });
        };
        if same_path(authored_for, requested) {
            return Ok(());
        }
        Err(LifecycleError::Refused {
            detail: "this plan was authored for another project, not this one; re-run the install from \
                     the project you mean to change"
                .to_string(),
        })
    }

    /// Refuse a stored receipt the caller cannot claim as this configuration
    /// home's (AAASM-5957).
    ///
    /// Mirrors [`Self::confirm_project`] exactly, one scope over: same three
    /// refusal cases (nothing named, a different home named, the receipt
    /// cannot say), same reasoning for why User and Project/Managed scope
    /// otherwise have nothing to disagree about, same refusal to name the
    /// other home's path in the message a client receives.
    fn confirm_user_config_home(
        tool: &DevToolKind,
        receipt: &IntegrationReceipt,
        target: &LifecycleTarget,
    ) -> Result<(), LifecycleError> {
        if receipt.settings_scope != SettingsScope::User {
            return Ok(());
        }
        let Some(requested) = target.user_config_home.as_deref() else {
            return Err(LifecycleError::Refused {
                detail: format!(
                    "{} is installed at user scope, and this request does not say which configuration \
                     home it is about; retry with a client that speaks DI-API {}",
                    tool_id(tool),
                    crate::devint::negotiate::DI_API_USER_CONFIG_HOME_SINCE
                ),
            });
        };
        let Some(recorded) = receipt.user_config_home() else {
            return Err(LifecycleError::Refused {
                detail: format!(
                    "the stored user-scope receipt for {} does not record which configuration home it \
                     wrote, so it cannot be shown to be this one; remove and re-install the integration",
                    tool_id(tool)
                ),
            });
        };
        if same_path(recorded, requested) {
            return Ok(());
        }
        Err(LifecycleError::Refused {
            detail: format!(
                "the user-scope integration for {} belongs to another configuration home, not this one",
                tool_id(tool)
            ),
        })
    }

    /// Refuse a cached plan the caller cannot claim as this configuration
    /// home's (AAASM-5957).
    ///
    /// Mirrors [`Self::confirm_plan_project`] exactly, one scope over.
    fn confirm_plan_user_config_home(plan: &IntegrationPlan, target: &LifecycleTarget) -> Result<(), LifecycleError> {
        let Some(authored_for) = plan.user_config_home.as_deref() else {
            return Ok(());
        };
        let Some(requested) = target.user_config_home.as_deref() else {
            return Err(LifecycleError::Refused {
                detail: format!(
                    "this plan was authored for a configuration home, and this request does not say \
                     which one it is being applied from; retry with a client that speaks DI-API {}",
                    crate::devint::negotiate::DI_API_USER_CONFIG_HOME_SINCE
                ),
            });
        };
        if same_path(authored_for, requested) {
            return Ok(());
        }
        Err(LifecycleError::Refused {
            detail: "this plan was authored for another configuration home, not this one".to_string(),
        })
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
        request.user_config_home = receipt.user_config_home().map(std::path::Path::to_path_buf);
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

/// Whether two paths name the same directory.
///
/// Shared by [`Service::confirm_project`]/[`Service::confirm_plan_project`]
/// and [`Service::confirm_user_config_home`]/
/// [`Service::confirm_plan_user_config_home`] (AAASM-5957) — one comparison
/// rule for "is this the same root", regardless of which scope's root it is.
///
/// The caller's root arrives canonicalized, and a receipt written since
/// AAASM-5913 recorded a canonical one — but a receipt written *before* it
/// recorded whatever the daemon's working directory happened to be spelled as,
/// and on macOS `/tmp` and `/private/tmp` are the same directory under two
/// names. Comparing the raw strings would refuse a legitimately installed
/// project on the strength of a symlink, which reads to the developer as "your
/// install is broken".
///
/// Canonicalizing here rather than migrating the receipt keeps the receipt's
/// serialized form — and therefore every already-stored receipt's integrity
/// hash — untouched. A directory that no longer exists cannot be canonicalized;
/// the raw path is then all there is, and comparing it is still strictly better
/// than not comparing.
fn same_path(a: &std::path::Path, b: &std::path::Path) -> bool {
    let canonical = |p: &std::path::Path| p.canonicalize().unwrap_or_else(|_| p.to_path_buf());
    a == b || canonical(a) == canonical(b)
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

    async fn apply(
        &self,
        tool: &DevToolKind,
        plan_id: &str,
        target: &LifecycleTarget,
    ) -> Result<AppliedIntegration, LifecycleError> {
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
        // Which project, before what it may do in it: a plan belonging to
        // somewhere else is not a consent question, so it is settled first.
        Self::confirm_plan_project(&plan, target)?;
        Self::confirm_plan_user_config_home(&plan, target)?;

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

    async fn status(&self, tool: &DevToolKind, target: &LifecycleTarget) -> Result<IntegrationStatus, LifecycleError> {
        let registered = self.registered(tool)?;
        let (scope, receipt) = self.resolve_target(tool, target)?;

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

    async fn verify(&self, tool: &DevToolKind, target: &LifecycleTarget) -> Result<VerificationResult, LifecycleError> {
        let registered = self.registered(tool)?;
        let (scope, receipt) = self.require_target(tool, target)?;

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
        let (scope, receipt) = self.require_target(tool, target)?;
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
        target: &LifecycleTarget,
        plan_id: Option<&str>,
    ) -> Result<RemovalPlan, LifecycleError> {
        let registered = self.registered(tool)?;
        let (scope, receipt) = self.require_target(tool, target)?;

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

    impl Harness {
        /// The target every User-scope read/reverse verb in this suite means:
        /// this harness's own settings file's directory.
        ///
        /// Mandatory since AAASM-5957 — `confirm_user_config_home` refuses a
        /// User-scope receipt with no configuration home named, and every
        /// fixture in this suite installs at User scope by default. Real,
        /// not synthetic: it is exactly `receipt.user_config_home()` derives
        /// from the same settings path, so the comparison is genuine rather
        /// than trivially satisfied by both sides being absent.
        fn target(&self) -> LifecycleTarget {
            LifecycleTarget {
                settings_scope: None,
                project_root: None,
                user_config_home: Some(self.settings.parent().expect("settings has a parent").to_path_buf()),
            }
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
            .apply(&DevToolKind::ClaudeCode, &plan.plan_id, &h.target())
            .await
            .expect("apply");
        let after_first = std::fs::read_to_string(&h.settings).expect("read");
        assert!(after_first.contains("solarized"), "the user's own key was lost");
        assert!(after_first.contains("aasmManaged"));

        let plan = h.service.plan(request()).await.expect("re-plan");
        let second = h
            .service
            .apply(&DevToolKind::ClaudeCode, &plan.plan_id, &h.target())
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
            .apply(&DevToolKind::ClaudeCode, "plan-someone-else-made", &h.target())
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
        match h
            .service
            .apply(&DevToolKind::ClaudeCode, &plan.plan_id, &h.target())
            .await
        {
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
            .apply(&DevToolKind::ClaudeCode, &plan.plan_id, &h.target())
            .await
            .expect("apply");

        let result = h
            .service
            .verify(&DevToolKind::ClaudeCode, &h.target())
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
            .status(&DevToolKind::ClaudeCode, &h.target())
            .await
            .expect("status");
        assert!(status.achieved_level() < ProtectionLevel::GatewayProtected);
    }

    #[tokio::test]
    async fn exercised_evidence_is_what_reaches_gateway_protected() {
        let h = harness(|f| f);
        let plan = h.service.plan(request()).await.expect("plan");
        h.service
            .apply(&DevToolKind::ClaudeCode, &plan.plan_id, &h.target())
            .await
            .expect("apply");
        let result = h
            .service
            .verify(&DevToolKind::ClaudeCode, &h.target())
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
            .apply(&DevToolKind::ClaudeCode, &plan.plan_id, &h.target())
            .await
            .expect("apply");
        h.service
            .verify(&DevToolKind::ClaudeCode, &h.target())
            .await
            .expect("verify");
        let status = h
            .service
            .status(&DevToolKind::ClaudeCode, &h.target())
            .await
            .expect("status");
        assert!(status.achieved_level() < ProtectionLevel::GatewayProtected);
    }

    #[tokio::test]
    async fn verifying_without_an_installation_is_refused_rather_than_passing() {
        let h = harness(|f| f);
        match h.service.verify(&DevToolKind::ClaudeCode, &h.target()).await {
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
            .apply(&DevToolKind::ClaudeCode, &plan.plan_id, &h.target())
            .await
            .expect("apply");
        let before = std::fs::read_to_string(&h.settings).expect("read");

        let removal = h
            .service
            .remove(&DevToolKind::ClaudeCode, &h.target(), None)
            .await
            .expect("preview");
        assert!(!removal.steps.is_empty());
        assert_eq!(std::fs::read_to_string(&h.settings).expect("read"), before);
        assert!(
            h.service
                .status(&DevToolKind::ClaudeCode, &h.target())
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
            .apply(&DevToolKind::ClaudeCode, &plan.plan_id, &h.target())
            .await
            .expect("apply");

        let preview = h
            .service
            .remove(&DevToolKind::ClaudeCode, &h.target(), None)
            .await
            .expect("preview");
        h.service
            .remove(&DevToolKind::ClaudeCode, &h.target(), Some(&preview.plan_id))
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
            .apply(&DevToolKind::ClaudeCode, &plan.plan_id, &h.target())
            .await
            .expect("apply");
        match h
            .service
            .remove(&DevToolKind::ClaudeCode, &h.target(), Some("removal-nope"))
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
            .apply(&DevToolKind::ClaudeCode, &plan.plan_id, &h.target())
            .await
            .expect("apply");

        std::fs::write(&h.settings, r#"{"aasmManaged":false,"theme":"solarized"}"#).expect("tamper");
        let drifted = h
            .service
            .status(&DevToolKind::ClaudeCode, &h.target())
            .await
            .expect("status");
        assert!(
            matches!(drifted.state, ProtectionState::Drifted { .. }),
            "tampering with a managed key must report drift, got {:?}",
            drifted.state
        );

        let (report, _) = h
            .service
            .repair(&DevToolKind::ClaudeCode, &h.target())
            .await
            .expect("repair");
        assert_eq!(report.repaired, vec!["settings".to_string()]);
        let repaired = std::fs::read_to_string(&h.settings).expect("read");
        assert!(repaired.contains("solarized"), "repair discarded the user's own key");
        assert!(
            !matches!(
                h.service
                    .status(&DevToolKind::ClaudeCode, &h.target())
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
        match h.service.status(&DevToolKind::Codex, &h.target()).await {
            Err(LifecycleError::UnknownTool { tool_id }) => assert_eq!(tool_id, "codex"),
            other => panic!("expected UnknownTool, got {other:?}"),
        }
    }

    // ── AAASM-5913: which project a read-or-reverse verb is about ──────────

    /// A harness whose fixture writes where a project-scope install writes.
    ///
    /// The path matters: [`IntegrationReceipt::project_root`] derives the
    /// project from the settings file's grandparent, so a fixture writing
    /// `<dir>/settings.json` produces a receipt that records the *tempdir's
    /// parent* as its project. Writing `<project>/.claude/settings.json` is what
    /// a real project-scope install does, and the only shape these tests can
    /// honestly assert against.
    fn project_harness() -> (Harness, std::path::PathBuf) {
        let dir = tempfile::tempdir().expect("tempdir");
        let project = dir.path().join("project");
        let settings = project.join(".claude").join("settings.json");
        std::fs::create_dir_all(settings.parent().expect("parent")).expect("mkdir");
        let store_root = dir.path().join("store");
        let fixture = FixtureIntegration::new(DevToolKind::ClaudeCode, &settings);
        let content = Arc::new(FixtureContent::new(fixture.rendered()));
        let service = EngineLifecycle::new(
            vec![RegisteredIntegration::new(DevToolKind::ClaudeCode, Arc::new(fixture)).with_content(content)],
            ReceiptStore::at(&store_root),
        );
        (
            Harness {
                _dir: dir,
                settings,
                store_root,
                service,
            },
            project,
        )
    }

    /// Install at project scope, naming `project`, and return the harness.
    async fn installed_into_project() -> (Harness, std::path::PathBuf) {
        let (h, project) = project_harness();
        let request = IntegrationRequest::new(
            DevToolKind::ClaudeCode,
            ProtectionProfile::Recommended,
            SettingsScope::Project,
        )
        .with_project_root(&project);
        let plan = h.service.plan(request).await.expect("plan");
        let applied = h
            .service
            .apply(&DevToolKind::ClaudeCode, &plan.plan_id, &target_for(&project))
            .await
            .expect("apply");
        assert_eq!(
            applied.receipt.project_root(),
            Some(project.as_path()),
            "the receipt must record the project it wrote, or these tests assert nothing"
        );
        (h, project)
    }

    fn target_for(project: &std::path::Path) -> LifecycleTarget {
        LifecycleTarget {
            settings_scope: None,
            project_root: Some(project.to_path_buf()),
            user_config_home: None,
        }
    }

    /// The project the request names is the project that is reported on.
    #[tokio::test]
    async fn the_project_a_request_names_is_the_one_reported_on() {
        let (h, project) = installed_into_project().await;
        let status = h
            .service
            .status(&DevToolKind::ClaudeCode, &target_for(&project))
            .await
            .expect("status");
        assert_eq!(status.phase, aa_core::integration::LifecyclePhase::Installed);
    }

    /// AAASM-5913: a request that names no project cannot be answered from a
    /// project-scope receipt, because there is nothing to compare it to. The
    /// daemon's own working directory is not a substitute — it is the defect.
    #[tokio::test]
    async fn a_project_scope_installation_is_not_reported_to_a_request_that_names_no_project() {
        let (h, _project) = installed_into_project().await;
        match h.service.status(&DevToolKind::ClaudeCode, &h.target()).await {
            Err(LifecycleError::Refused { detail }) => {
                assert!(
                    detail.contains("does not say which project"),
                    "the refusal must say what is missing: {detail}"
                );
            }
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    /// The defect as a user met it: standing in an unrelated repository, being
    /// told it was protected. Every read-or-reverse verb refuses now, because
    /// `repair` and `remove` would have written to and deleted from the other
    /// project's files.
    #[tokio::test]
    async fn every_read_or_reverse_verb_refuses_a_project_that_is_not_the_installed_one() {
        let (h, project) = installed_into_project().await;
        let elsewhere = tempfile::tempdir().expect("tempdir");
        let other = target_for(elsewhere.path());
        let tool = DevToolKind::ClaudeCode;

        let refusals = [
            ("status", h.service.status(&tool, &other).await.err()),
            ("verify", h.service.verify(&tool, &other).await.err()),
            ("repair", h.service.repair(&tool, &other).await.err()),
            ("remove", h.service.remove(&tool, &other, None).await.err()),
        ];
        for (verb, error) in refusals {
            match error {
                Some(LifecycleError::Refused { detail }) => {
                    assert!(
                        detail.contains("another project"),
                        "{verb} must say the installation belongs elsewhere: {detail}"
                    );
                    assert!(
                        !detail.contains(&project.display().to_string()),
                        "{verb} disclosed the other project's path: {detail}"
                    );
                }
                other => panic!("{verb} must be refused, got {other:?}"),
            }
        }

        // And nothing was written to or removed from the installed project on
        // the way to those refusals.
        assert!(h.settings.exists(), "a refused verb touched the other project's files");
    }

    /// AAASM-5913, the write path: a plan authored for one project cannot be
    /// executed from another.
    ///
    /// The read verbs compare the caller's project against a *receipt*, which
    /// only exists once something is installed. An apply has no receipt yet, so
    /// the comparison is against the plan — and it has to happen, because the
    /// plan cache is process-global and keyed on the plan id alone. Any client
    /// on the host that holds an id can present it later, from anywhere, and
    /// before this check the service would have written the project the plan was
    /// authored for while the caller was standing somewhere else entirely.
    ///
    /// The refusal is asserted to *not* name the authoring project. A detail
    /// string reaches a client verbatim, and which other repository a developer
    /// has on disk is not what this caller asked about.
    #[tokio::test]
    async fn a_plan_authored_for_one_project_is_not_applyable_from_another() {
        let (h, project) = project_harness();
        let request = IntegrationRequest::new(
            DevToolKind::ClaudeCode,
            ProtectionProfile::Recommended,
            SettingsScope::Project,
        )
        .with_project_root(&project);
        let plan = h.service.plan(request).await.expect("plan");
        let elsewhere = tempfile::tempdir().expect("tempdir");

        match h
            .service
            .apply(&DevToolKind::ClaudeCode, &plan.plan_id, &target_for(elsewhere.path()))
            .await
        {
            Err(LifecycleError::Refused { detail }) => {
                assert!(
                    detail.contains("another project"),
                    "the refusal must say the plan belongs elsewhere: {detail}"
                );
                assert!(
                    !detail.contains(&project.display().to_string()),
                    "the refusal disclosed the authoring project's path: {detail}"
                );
            }
            other => panic!("expected a refusal, got {other:?}"),
        }
        assert!(
            !h.settings.exists(),
            "the refused apply wrote the authoring project's settings anyway"
        );
        assert!(
            !h.store_root.exists(),
            "the refused apply recorded a receipt for an install that did not happen"
        );

        // Refused, not consumed: the developer who authored it can still apply
        // it from the project it is about. A check that invalidated the plan
        // would turn one client's mistake into another client's failure.
        let applied = h
            .service
            .apply(&DevToolKind::ClaudeCode, &plan.plan_id, &target_for(&project))
            .await
            .expect("the authoring project may still apply its own plan");
        assert_eq!(applied.receipt.project_root(), Some(project.as_path()));
    }

    /// A caller that names no project cannot execute a plan that is about one.
    ///
    /// Distinct from the case above, and it is the one a pre-DI-API-6 client
    /// produces: not "the wrong project" but "no project at all". Answering it
    /// from the daemon's own directory is the defect, so the only sound answer is
    /// to refuse — and to say which version carries the field, since a client too
    /// old to send it cannot discover that from the wire.
    #[tokio::test]
    async fn a_project_scope_plan_is_not_applyable_by_a_request_that_names_no_project() {
        let (h, project) = project_harness();
        let request = IntegrationRequest::new(
            DevToolKind::ClaudeCode,
            ProtectionProfile::Recommended,
            SettingsScope::Project,
        )
        .with_project_root(&project);
        let plan = h.service.plan(request).await.expect("plan");

        match h
            .service
            .apply(&DevToolKind::ClaudeCode, &plan.plan_id, &h.target())
            .await
        {
            Err(LifecycleError::Refused { detail }) => {
                assert!(
                    detail.contains("does not say which project"),
                    "the refusal must say what is missing: {detail}"
                );
                assert!(
                    detail.contains(&crate::devint::negotiate::DI_API_PROJECT_ROOT_SINCE.to_string()),
                    "the refusal must name the version that carries the field: {detail}"
                );
            }
            other => panic!("expected a refusal, got {other:?}"),
        }
        assert!(!h.settings.exists(), "the refused apply wrote settings anyway");
    }

    /// A user-scope plan is about the host, not a project, so a caller's
    /// directory has nothing to disagree with — including a caller that names
    /// one. This is what keeps the check fail-open exactly where it should be:
    /// every pre-v6 client's plans are user or managed scope, so none of them
    /// starts being refused.
    #[tokio::test]
    async fn a_host_wide_plan_is_applyable_from_any_directory() {
        let h = harness(|f| f);
        let plan = h.service.plan(request()).await.expect("plan");
        let elsewhere = tempfile::tempdir().expect("tempdir");
        h.service
            .apply(&DevToolKind::ClaudeCode, &plan.plan_id, &target_for(elsewhere.path()))
            .await
            .expect("a host-wide plan is not about the caller's directory");
    }

    /// Two spellings of one directory are one project. A receipt written before
    /// this fix recorded whatever path the daemon's own directory was spelled
    /// as, and on macOS `/tmp` and `/private/tmp` are the same place.
    #[tokio::test]
    async fn a_second_spelling_of_the_same_project_is_the_same_project() {
        let (h, project) = installed_into_project().await;
        let link = h
            .settings
            .parent()
            .and_then(std::path::Path::parent)
            .and_then(std::path::Path::parent)
            .expect("tempdir root")
            .join("link-to-project");
        std::os::unix::fs::symlink(&project, &link).expect("symlink");
        let status = h
            .service
            .status(&DevToolKind::ClaudeCode, &target_for(&link))
            .await
            .expect("a symlink to the installed project is the installed project");
        assert_eq!(status.phase, aa_core::integration::LifecyclePhase::Installed);
    }

    /// User scope is unaffected: its destination was never the caller's to name,
    /// so there is nothing to disagree about and nothing new to supply.
    #[tokio::test]
    async fn a_user_scope_installation_still_needs_no_project_named() {
        let h = harness(|f| f);
        let plan = h.service.plan(request()).await.expect("plan");
        h.service
            .apply(&DevToolKind::ClaudeCode, &plan.plan_id, &h.target())
            .await
            .expect("apply");
        let status = h
            .service
            .status(&DevToolKind::ClaudeCode, &h.target())
            .await
            .expect("a user-scope installation answers an unspecified target");
        assert_eq!(status.phase, aa_core::integration::LifecyclePhase::Installed);
    }

    /// A target naming no configuration home cannot be answered from a
    /// User-scope receipt (AAASM-5957) — the daemon's own ambient
    /// `CLAUDE_CONFIG_DIR`/`HOME` is not a substitute; it is the defect this
    /// ticket fixes. Mirrors
    /// [`a_project_scope_installation_is_not_reported_to_a_request_that_names_no_project`]
    /// one scope over.
    #[tokio::test]
    async fn a_user_scope_installation_is_not_reported_to_a_request_that_names_no_config_home() {
        let h = harness(|f| f);
        let plan = h.service.plan(request()).await.expect("plan");
        h.service
            .apply(&DevToolKind::ClaudeCode, &plan.plan_id, &h.target())
            .await
            .expect("apply");
        match h
            .service
            .status(&DevToolKind::ClaudeCode, &LifecycleTarget::unspecified())
            .await
        {
            Err(LifecycleError::Refused { detail }) => {
                assert!(
                    detail.contains("does not say which configuration home"),
                    "the refusal must say what is missing: {detail}"
                );
            }
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    /// The defect as a user met it, one scope over from AAASM-5913's: a daemon
    /// launched (or whose environment was substituted) with a *different*
    /// `CLAUDE_CONFIG_DIR` must not have that leak into an unrelated caller's
    /// read of, or reversal against, this installation's own configuration
    /// home. Every read-or-reverse verb refuses, for the same reason
    /// `repair`/`remove` refuse a mismatched project: they would otherwise
    /// write to and delete from a configuration home the caller never named.
    #[tokio::test]
    async fn every_read_or_reverse_verb_refuses_a_config_home_that_is_not_the_installed_one() {
        let h = harness(|f| f);
        let plan = h.service.plan(request()).await.expect("plan");
        h.service
            .apply(&DevToolKind::ClaudeCode, &plan.plan_id, &h.target())
            .await
            .expect("apply");
        let elsewhere = tempfile::tempdir().expect("tempdir");
        let other = LifecycleTarget {
            settings_scope: None,
            project_root: None,
            user_config_home: Some(elsewhere.path().to_path_buf()),
        };
        let tool = DevToolKind::ClaudeCode;

        let refusals = [
            ("status", h.service.status(&tool, &other).await.err()),
            ("verify", h.service.verify(&tool, &other).await.err()),
            ("repair", h.service.repair(&tool, &other).await.err()),
            ("remove", h.service.remove(&tool, &other, None).await.err()),
        ];
        for (verb, error) in refusals {
            match error {
                Some(LifecycleError::Refused { detail }) => {
                    assert!(
                        detail.contains("another"),
                        "{verb} must say the installation belongs to a different configuration home: {detail}"
                    );
                }
                other => panic!("{verb} must be refused, got {other:?}"),
            }
        }

        // And nothing was written to or removed from the installed
        // configuration on the way to those refusals.
        assert!(
            h.settings.exists(),
            "a refused verb touched the installed configuration's files"
        );
    }

    /// AAASM-5957, the write path: a plan authored for one configuration home
    /// cannot be executed against another — mirroring
    /// [`a_plan_authored_for_one_project_is_not_applyable_from_another`] one
    /// scope over. The plan cache is process-global and keyed on the plan id
    /// alone, so any client on the host that holds an id could otherwise
    /// present it from a different `CLAUDE_CONFIG_DIR`/`HOME` and have it
    /// applied there instead.
    #[tokio::test]
    async fn a_plan_authored_for_one_config_home_is_not_applyable_against_another() {
        let h = harness(|f| f);
        let home = h.settings.parent().expect("settings has a parent").to_path_buf();
        let plan = h
            .service
            .plan(request().with_user_config_home(&home))
            .await
            .expect("plan");
        let elsewhere = tempfile::tempdir().expect("tempdir");
        let other = LifecycleTarget {
            settings_scope: None,
            project_root: None,
            user_config_home: Some(elsewhere.path().to_path_buf()),
        };

        match h.service.apply(&DevToolKind::ClaudeCode, &plan.plan_id, &other).await {
            Err(LifecycleError::Refused { detail }) => {
                assert!(
                    detail.contains("another configuration home"),
                    "the refusal must say the plan belongs to a different configuration home: {detail}"
                );
            }
            other => panic!("expected a refusal, got {other:?}"),
        }
        assert!(
            !h.settings.exists(),
            "the refused apply wrote the authoring home's settings anyway"
        );

        // Refused, not consumed: the caller who authored it can still apply
        // it against the configuration home it is about.
        let applied = h
            .service
            .apply(&DevToolKind::ClaudeCode, &plan.plan_id, &h.target())
            .await
            .expect("the authoring caller may still apply its own plan");
        assert_eq!(
            applied.receipt.user_config_home(),
            Some(h.settings.parent().expect("settings has a parent"))
        );
    }

    /// A project-scope installation is unaffected: its destination was never
    /// the configuration-home field's to name, so there is nothing to
    /// disagree about — the AAASM-5957 mirror of
    /// [`a_user_scope_installation_still_needs_no_project_named`].
    #[tokio::test]
    async fn a_project_scope_installation_still_needs_no_config_home_named() {
        let (h, project) = installed_into_project().await;
        let status = h
            .service
            .status(&DevToolKind::ClaudeCode, &target_for(&project))
            .await
            .expect("a project-scope installation answers a target naming no configuration home");
        assert_eq!(status.phase, aa_core::integration::LifecyclePhase::Installed);
    }

    /// Nothing this service returns can carry the rendered settings body, so a
    /// secret an adapter put in one cannot reach a client through any verb.
    #[tokio::test]
    async fn no_lifecycle_response_carries_the_rendered_settings_body() {
        let h = harness(|f| f.poisoned());
        let plan = h.service.plan(request()).await.expect("plan");
        let receipt = h
            .service
            .apply(&DevToolKind::ClaudeCode, &plan.plan_id, &h.target())
            .await
            .expect("apply");
        let status = h
            .service
            .status(&DevToolKind::ClaudeCode, &h.target())
            .await
            .expect("status");
        let verification = h
            .service
            .verify(&DevToolKind::ClaudeCode, &h.target())
            .await
            .expect("verify");
        let removal = h
            .service
            .remove(&DevToolKind::ClaudeCode, &h.target(), None)
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
