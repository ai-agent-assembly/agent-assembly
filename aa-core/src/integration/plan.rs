//! What the user asked for, and the reviewable plan an adapter authors in reply.
//!
//! An [`IntegrationPlan`] is a **dry run that has not happened yet**: it is
//! serializable, renderable, validated before anything is executed, and it names
//! every mechanism it *cannot* use along with the reason. That last part is what
//! moves "GitHub Copilot is a VS Code extension and cannot be launched" from a
//! run-time `LaunchFailed` to a plan-time statement the user can act on (ADR
//! 0030 §3.2).
//!
//! Nothing in this module can carry a [`PolicyDocument`](crate::PolicyDocument).
//! A plan names a profile by reference ([`PolicyProfileRef`]) — enough to display
//! and compare, not enough to read — which is ADR 0030 §5.5's minimisation
//! enforced by the shape of the type rather than by a redaction pass someone
//! might forget.

use std::fmt::Write as _;
use std::path::PathBuf;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use super::capability::IntegrationCapability;
use super::state::ProtectionLevel;
use super::step::{IntegrationStep, SettingsScope, StepAction};
use super::version::LIFECYCLE_SCHEMA_VERSION;
use crate::dev_tool::{DevToolKind, GovernanceLevel};
use crate::policy::EnforcementMode;

/// The named bundle of protection settings a user chose.
///
/// A profile is what the user *asked for*; a [`ProtectionLevel`] is what the
/// system can *prove*. They are separate types because a user can select
/// `Strict` on a machine where nothing is routed through the gateway, and the
/// honest answer there is `Integrated`, not "strict protection active".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum ProtectionProfile {
    /// The default: enforce, redact sensitive findings and proceed, approve
    /// where policy asks.
    Recommended,
    /// Enforce, with a narrower egress allowlist and approval required for
    /// destructive tool classes.
    Strict,
    /// Compute and audit every decision; apply none of them.
    ObserveOnly,
}

impl ProtectionProfile {
    /// The [`EnforcementMode`] this profile resolves to.
    ///
    /// [`EnforcementMode::Disabled`] is deliberately unreachable: it skips
    /// policy evaluation entirely and is valid only in hermetic test
    /// environments, so no user-facing profile may map to it.
    pub fn enforcement_mode(self) -> EnforcementMode {
        match self {
            Self::Recommended | Self::Strict => EnforcementMode::Enforce,
            Self::ObserveOnly => EnforcementMode::Observe,
        }
    }

    /// Whether decisions computed under this profile are actually applied.
    pub fn is_enforcing(self) -> bool {
        self.enforcement_mode() == EnforcementMode::Enforce
    }

    /// The highest protection level this profile may ever be reported at.
    ///
    /// `ObserveOnly` is capped at [`ProtectionLevel::Integrated`]: observing is
    /// not protecting, and displaying it as protection is the single most likely
    /// way for the product to lie about itself.
    pub fn max_reportable_level(self) -> ProtectionLevel {
        match self {
            Self::Recommended | Self::Strict => ProtectionLevel::HostEnforced,
            Self::ObserveOnly => ProtectionLevel::Integrated,
        }
    }
}

/// A policy profile named by reference rather than by content.
///
/// Enough to display, select and compare; never enough to read the policy. The
/// resolution from a name to a document happens inside the trusted layers (ADR
/// 0030 matrix row 6) and the document never leaves them.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct PolicyProfileRef {
    /// Stable identifier the control plane knows this profile by.
    pub id: String,
    /// Name to show a user.
    pub display_name: String,
    /// Digest of the resolved document, so two references can be compared for
    /// equality without either side holding the content.
    pub digest: String,
}

/// What the caller wants done.
///
/// Every field is something the caller may legitimately choose. There is no
/// field a caller could use to supply a policy document, a credential or a path
/// the service did not derive — an untrusted client can ask for an integration,
/// never dictate its content.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct IntegrationRequest {
    /// Which tool to integrate.
    pub tool: DevToolKind,
    /// Which profile the user chose.
    pub profile: ProtectionProfile,
    /// The level the caller is aiming for. The plan may be lower; it may never
    /// be silently higher.
    pub requested_level: ProtectionLevel,
    /// Which configuration surface to write. Explicit and mandatory — the
    /// destination is never inferred from the caller's working directory.
    pub settings_scope: SettingsScope,
    /// The project this request is about, as an absolute path.
    ///
    /// # Why the request has to carry it (AAASM-5913)
    ///
    /// [`settings_scope`](Self::settings_scope) says *which kind* of surface to
    /// write; at [`Project`](SettingsScope::Project) scope it does not say
    /// *whose*. A lifecycle service runs as a long-lived daemon shared by every
    /// client on the host, so the only working directory it can read is its own
    /// — the one it happened to be spawned in, which is some earlier caller's
    /// project or none at all. Resolving the project from there wrote Agent
    /// Assembly's managed keys into a *different* repository's checked-in
    /// `.claude/settings.json`, and re-pointed itself every time the daemon was
    /// restarted.
    ///
    /// So the caller states it, once, at invocation time. `None` at Project
    /// scope is an error the service reports — never a fallback to its own
    /// working directory (see [`PlanError::ProjectRootMissing`]).
    ///
    /// At User and Managed scope this is optional context, never a destination:
    /// it lets the plan disclose that a project configuration also exists near
    /// the caller and will be left alone. No step's path is ever derived from it
    /// at those scopes.
    pub project_root: Option<PathBuf>,
    /// Whether the caller has consented to steps that change host state. A plan
    /// containing privileged steps that were not consented to is a plan the
    /// service must not execute.
    pub allow_privileged_host_steps: bool,
    /// The policy profile the core resolved for this request, by reference.
    pub policy_profile: Option<PolicyProfileRef>,
}

impl IntegrationRequest {
    /// A request aiming at [`ProtectionLevel::GatewayProtected`], with no
    /// consent for privileged host steps.
    pub fn new(tool: DevToolKind, profile: ProtectionProfile, settings_scope: SettingsScope) -> Self {
        Self {
            tool,
            profile,
            requested_level: ProtectionLevel::GatewayProtected,
            settings_scope,
            project_root: None,
            allow_privileged_host_steps: false,
            policy_profile: None,
        }
    }

    /// Aim at a different level.
    #[must_use]
    pub fn requesting_level(mut self, level: ProtectionLevel) -> Self {
        self.requested_level = level;
        self
    }

    /// Name the project this request is about.
    ///
    /// Mandatory at [`SettingsScope::Project`]; see
    /// [`project_root`](Self::project_root).
    #[must_use]
    pub fn with_project_root(mut self, project_root: impl Into<PathBuf>) -> Self {
        self.project_root = Some(project_root.into());
        self
    }

    /// Record the user's consent to host-state changes.
    #[must_use]
    pub fn allowing_privileged_host_steps(mut self) -> Self {
        self.allow_privileged_host_steps = true;
        self
    }

    /// Attach the resolved policy profile reference.
    #[must_use]
    pub fn with_policy_profile(mut self, policy_profile: PolicyProfileRef) -> Self {
        self.policy_profile = Some(policy_profile);
        self
    }

    /// The highest level this request could honestly reach, clamped by the
    /// profile. Choosing `ObserveOnly` and asking for `GatewayProtected` yields
    /// `Integrated`, not the request.
    pub fn effective_target_level(&self) -> ProtectionLevel {
        self.requested_level.min(self.profile.max_reportable_level())
    }
}

/// A mechanism this tool cannot use, and why, stated at plan time.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct UnsupportedMechanism {
    /// The mechanism that is unavailable.
    pub capability: IntegrationCapability,
    /// The user-facing reason, taken from the adapter's capability declaration.
    pub reason: String,
}

/// Why a plan is not internally consistent.
///
/// These are contract violations by the adapter that authored the plan, not user
/// errors, and the service must refuse to execute a plan that produces one.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum PlanError {
    /// Two steps share an id, so a receipt could not key on them.
    #[error("duplicate step id {id:?}")]
    DuplicateStepId {
        /// The repeated identifier.
        id: String,
    },
    /// A step writes to a settings surface the plan did not declare — the exact
    /// class of bug where the file written depends on the caller's working
    /// directory.
    #[error("step {id:?} writes to the {found} settings scope but the plan declared {expected}")]
    SettingsScopeMismatch {
        /// The offending step.
        id: String,
        /// The scope the plan declared.
        expected: SettingsScope,
        /// The scope the step named.
        found: SettingsScope,
    },
    /// A project-scoped plan does not name the project it is about, so the only
    /// project root available to the executing service would be its own working
    /// directory — some other caller's repository (AAASM-5913).
    #[error(
        "this plan writes to the project settings scope but names no project root, and the \
         project a change lands in must never be inferred from the working directory of the \
         service executing it"
    )]
    ProjectRootMissing,
    /// A project-scoped settings write lands outside the project the plan names.
    #[error("step {id:?} writes {path} which is outside the project root {project_root} this plan names")]
    ProjectRootEscape {
        /// The offending step.
        id: String,
        /// Where it would write.
        path: PathBuf,
        /// The project the plan declared.
        project_root: PathBuf,
    },
    /// A privileged host step carries no consent prompt, or no way to undo it.
    #[error("privileged host step {id:?} is missing {missing}")]
    PrivilegedStepIncomplete {
        /// The offending step.
        id: String,
        /// What it lacks.
        missing: &'static str,
    },
    /// The plan claims it will reach a level the steps cannot substantiate.
    #[error("the plan claims {claimed} but {detail}")]
    UnsubstantiatedLevel {
        /// The level claimed.
        claimed: ProtectionLevel,
        /// What is missing.
        detail: String,
    },
    /// The plan claims a level above what the chosen profile may ever report.
    #[error("profile {profile:?} may never be reported above {cap}, but the plan claims {claimed}")]
    ProfileLevelCap {
        /// The chosen profile.
        profile: ProtectionProfile,
        /// The profile's ceiling.
        cap: ProtectionLevel,
        /// The level claimed.
        claimed: ProtectionLevel,
    },
}

/// The steps one adapter says are needed to take one tool to one level.
///
/// Authored by the adapter, executed by the service, and shown to the user
/// first.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct IntegrationPlan {
    /// The [`LIFECYCLE_SCHEMA_VERSION`] this plan was authored against.
    pub schema_version: u32,
    /// Stable identifier the subsequent apply refers to.
    pub plan_id: String,
    /// The tool this plan integrates.
    pub tool: DevToolKind,
    /// The profile the request named.
    pub profile: ProtectionProfile,
    /// The settings surface every settings-touching step must write to.
    pub settings_scope: SettingsScope,
    /// The project a [`Project`](SettingsScope::Project)-scoped plan writes into,
    /// carried from [`IntegrationRequest::project_root`] so the plan can be
    /// checked against it and so a reviewer can read which repository they are
    /// about to change (AAASM-5913).
    pub project_root: Option<PathBuf>,
    /// The resolved policy profile, by reference.
    pub policy_profile: Option<PolicyProfileRef>,
    /// The level this plan intends to reach if every step succeeds and verifies.
    pub planned_level: ProtectionLevel,
    /// The adapter's static build-time ceiling. A ceiling never implies a
    /// measurement; it is carried so a user can see the gap.
    pub adapter_ceiling: GovernanceLevel,
    /// The steps, in execution order.
    pub steps: Vec<IntegrationStep>,
    /// Mechanisms this tool cannot use, with reasons.
    pub unsupported: Vec<UnsupportedMechanism>,
    /// Anything else the user should read before approving.
    pub warnings: Vec<String>,
}

impl IntegrationPlan {
    /// An empty plan for `request`, claiming `planned_level`.
    pub fn new(
        plan_id: impl Into<String>,
        request: &IntegrationRequest,
        planned_level: ProtectionLevel,
        adapter_ceiling: GovernanceLevel,
    ) -> Self {
        Self {
            schema_version: LIFECYCLE_SCHEMA_VERSION,
            plan_id: plan_id.into(),
            tool: request.tool.clone(),
            profile: request.profile,
            settings_scope: request.settings_scope,
            project_root: request.project_root.clone(),
            policy_profile: request.policy_profile.clone(),
            planned_level,
            adapter_ceiling,
            steps: Vec::new(),
            unsupported: Vec::new(),
            warnings: Vec::new(),
        }
    }

    /// Append a step.
    #[must_use]
    pub fn with_step(mut self, step: IntegrationStep) -> Self {
        self.steps.push(step);
        self
    }

    /// Record a mechanism this tool cannot use, and why.
    #[must_use]
    pub fn declaring_unsupported(mut self, capability: IntegrationCapability, reason: impl Into<String>) -> Self {
        self.unsupported.push(UnsupportedMechanism {
            capability,
            reason: reason.into(),
        });
        self
    }

    /// Add a warning for the user to read before approving.
    #[must_use]
    pub fn warn(mut self, warning: impl Into<String>) -> Self {
        self.warnings.push(warning.into());
        self
    }

    /// Steps the integration depends on.
    pub fn required_steps(&self) -> impl Iterator<Item = &IntegrationStep> {
        self.steps.iter().filter(|s| s.is_required())
    }

    /// Steps that change host state.
    pub fn privileged_steps(&self) -> impl Iterator<Item = &IntegrationStep> {
        self.steps.iter().filter(|s| s.is_privileged())
    }

    /// Every filesystem artifact this plan touches, deduplicated in first-seen
    /// order.
    pub fn affected_artifacts(&self) -> Vec<PathBuf> {
        let mut seen = Vec::new();
        for path in self.steps.iter().flat_map(|s| s.action.affected_paths()) {
            if !seen.contains(&path) {
                seen.push(path);
            }
        }
        seen
    }

    /// Whether the plan contains a protection test whose probe exercises a
    /// mechanism that actually intercepts the model path.
    ///
    /// A probe pointed at a routing lever is not a protection test.
    pub fn has_interception_probe(&self) -> bool {
        self.steps.iter().any(|step| match &step.action {
            StepAction::RunProtectionTest { probe } => probe.mechanism.justifies_gateway_protection(),
            _ => false,
        })
    }

    /// Check the plan's internal consistency before anything is executed.
    ///
    /// The checks exist because each corresponds to a way the product could
    /// otherwise mislead a user:
    ///
    /// * duplicate ids ⇒ a receipt that cannot attribute a step;
    /// * a step writing outside the declared scope ⇒ a file written somewhere
    ///   the user did not choose;
    /// * a project-scoped plan that names no project, or a project-scoped write
    ///   landing outside the project it names ⇒ a checked-in file changed in a
    ///   repository the user never named (AAASM-5913);
    /// * a privileged step with no consent prompt or no reversal ⇒ a host change
    ///   that was neither agreed to nor undoable;
    /// * a claim of [`GatewayProtected`](ProtectionLevel::GatewayProtected) with
    ///   no interception probe ⇒ a traffic claim with no plan to observe
    ///   traffic;
    /// * `ObserveOnly` claiming more than `Integrated` ⇒ monitoring displayed as
    ///   protection.
    pub fn validate(&self) -> Result<(), PlanError> {
        if self.settings_scope == SettingsScope::Project && self.project_root.is_none() {
            return Err(PlanError::ProjectRootMissing);
        }

        let mut seen_ids: Vec<&str> = Vec::new();
        for step in &self.steps {
            if seen_ids.contains(&step.id.as_str()) {
                return Err(PlanError::DuplicateStepId { id: step.id.clone() });
            }
            seen_ids.push(&step.id);
            self.validate_step(step)?;
        }

        let cap = self.profile.max_reportable_level();
        if self.planned_level > cap {
            return Err(PlanError::ProfileLevelCap {
                profile: self.profile,
                cap,
                claimed: self.planned_level,
            });
        }

        if self.planned_level >= ProtectionLevel::GatewayProtected && !self.has_interception_probe() {
            return Err(PlanError::UnsubstantiatedLevel {
                claimed: self.planned_level,
                detail: "it contains no protection test that exercises model-path interception; \
                         routing a tool's traffic elsewhere is not evidence that anything inspected it"
                    .to_string(),
            });
        }

        Ok(())
    }

    /// Validate one step's scope and privilege consistency in isolation.
    fn validate_step(&self, step: &IntegrationStep) -> Result<(), PlanError> {
        if let Some(found) = step.action.settings_scope() {
            if found != self.settings_scope {
                return Err(PlanError::SettingsScopeMismatch {
                    id: step.id.clone(),
                    expected: self.settings_scope,
                    found,
                });
            }
        }

        // A project-scoped settings write has to land inside the project the plan
        // names. Checking the *path* and not merely the scope label is what makes
        // this catch AAASM-5913: the defective adapter authored a step correctly
        // labelled `project` whose path pointed at a different repository
        // entirely, so a scope-only check called that plan consistent.
        //
        // Only the settings surface is checked. Every other artifact a
        // project-scoped plan writes — the CA copy, the launch environment, the
        // MitM host list — lives under Agent Assembly's own state root by
        // design, and asserting those into the project would be wrong.
        if let (
            StepAction::WriteManagedSettings {
                scope: SettingsScope::Project,
                path,
                ..
            },
            Some(project_root),
        ) = (&step.action, self.project_root.as_ref())
        {
            if !path.starts_with(project_root) {
                return Err(PlanError::ProjectRootEscape {
                    id: step.id.clone(),
                    path: path.clone(),
                    project_root: project_root.clone(),
                });
            }
        }

        if let super::step::StepPrivilege::PrivilegedHost { consent_prompt } = &step.privilege {
            if consent_prompt.trim().is_empty() {
                return Err(PlanError::PrivilegedStepIncomplete {
                    id: step.id.clone(),
                    missing: "a consent prompt",
                });
            }
            if step.reversal.is_none() {
                return Err(PlanError::PrivilegedStepIncomplete {
                    id: step.id.clone(),
                    missing: "a reversal step",
                });
            }
        }

        Ok(())
    }

    /// Render the plan for user review.
    ///
    /// The shape is stable so the CLI, the dashboard and a golden test can all
    /// depend on it: a header block of `key: value` lines, then `steps:`,
    /// `unsupported:` and `warnings:` sections, each omitted when empty.
    pub fn render_dry_run(&self) -> String {
        let mut out = String::new();
        let _ = writeln!(out, "integration plan {} for {:?}", self.plan_id, self.tool);
        let _ = writeln!(out, "  schema: {}", self.schema_version);
        let _ = writeln!(
            out,
            "  profile: {:?} (enforcement: {:?})",
            self.profile,
            self.profile.enforcement_mode()
        );
        let _ = writeln!(out, "  settings scope: {}", self.settings_scope);
        // Named only when there is one, so the shape of a user- or
        // managed-scoped rendering is unchanged. When there is one, a reviewer
        // gets to read *which repository* is about to be changed before they
        // approve it (AAASM-5913).
        if let Some(project_root) = &self.project_root {
            let _ = writeln!(out, "  project root: {}", project_root.display());
        }
        let _ = writeln!(
            out,
            "  planned level: {} (adapter ceiling: {})",
            self.planned_level, self.adapter_ceiling
        );
        if let Some(profile) = &self.policy_profile {
            let _ = writeln!(out, "  policy profile: {} ({})", profile.display_name, profile.digest);
        }

        let _ = writeln!(out, "steps:");
        if self.steps.is_empty() {
            let _ = writeln!(out, "  (none)");
        }
        for (index, step) in self.steps.iter().enumerate() {
            let _ = writeln!(out, "  {}. {}", index + 1, step.render_dry_run());
            if let super::step::StepPrivilege::PrivilegedHost { consent_prompt } = &step.privilege {
                let _ = writeln!(out, "     consent: {consent_prompt}");
            }
        }

        if !self.unsupported.is_empty() {
            let _ = writeln!(out, "unsupported:");
            for mechanism in &self.unsupported {
                let _ = writeln!(out, "  - {:?}: {}", mechanism.capability, mechanism.reason);
            }
        }

        if !self.warnings.is_empty() {
            let _ = writeln!(out, "warnings:");
            for warning in &self.warnings {
                let _ = writeln!(out, "  - {warning}");
            }
        }

        out
    }
}

/// The steps that undo an integration.
///
/// Separate from [`IntegrationPlan`] because removal is not "apply in reverse":
/// it is derived from what a receipt says was actually applied, and it must be
/// able to admit that something cannot be undone automatically
/// ([`residual`](Self::residual)) rather than silently leaving it behind.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct RemovalPlan {
    /// The [`LIFECYCLE_SCHEMA_VERSION`] this plan was authored against.
    pub schema_version: u32,
    /// Stable identifier the subsequent removal refers to.
    pub plan_id: String,
    /// The tool being removed.
    pub tool: DevToolKind,
    /// The reversal steps, in execution order.
    pub steps: Vec<IntegrationStep>,
    /// Things this plan knowingly leaves behind, in words a user can act on.
    pub residual: Vec<String>,
    /// Anything else the user should read before approving.
    pub warnings: Vec<String>,
}

impl RemovalPlan {
    /// An empty removal plan for `tool`.
    pub fn new(plan_id: impl Into<String>, tool: DevToolKind) -> Self {
        Self {
            schema_version: LIFECYCLE_SCHEMA_VERSION,
            plan_id: plan_id.into(),
            tool,
            steps: Vec::new(),
            residual: Vec::new(),
            warnings: Vec::new(),
        }
    }

    /// Append a reversal step.
    #[must_use]
    pub fn with_step(mut self, step: IntegrationStep) -> Self {
        self.steps.push(step);
        self
    }

    /// Declare something this plan cannot undo.
    #[must_use]
    pub fn with_residual(mut self, residual: impl Into<String>) -> Self {
        self.residual.push(residual.into());
        self
    }

    /// Add a warning for the user to read before approving.
    #[must_use]
    pub fn warn(mut self, warning: impl Into<String>) -> Self {
        self.warnings.push(warning.into());
        self
    }

    /// Check that no two steps share an id.
    pub fn validate(&self) -> Result<(), PlanError> {
        let mut seen: Vec<&str> = Vec::new();
        for step in &self.steps {
            if seen.contains(&step.id.as_str()) {
                return Err(PlanError::DuplicateStepId { id: step.id.clone() });
            }
            seen.push(&step.id);
        }
        Ok(())
    }

    /// Render the removal plan for user review, in the same stable shape as
    /// [`IntegrationPlan::render_dry_run`].
    pub fn render_dry_run(&self) -> String {
        let mut out = String::new();
        let _ = writeln!(out, "removal plan {} for {:?}", self.plan_id, self.tool);
        let _ = writeln!(out, "  schema: {}", self.schema_version);
        let _ = writeln!(out, "steps:");
        if self.steps.is_empty() {
            let _ = writeln!(out, "  (none)");
        }
        for (index, step) in self.steps.iter().enumerate() {
            let _ = writeln!(out, "  {}. {}", index + 1, step.render_dry_run());
        }
        if !self.residual.is_empty() {
            let _ = writeln!(out, "left behind:");
            for residual in &self.residual {
                let _ = writeln!(out, "  - {residual}");
            }
        }
        if !self.warnings.is_empty() {
            let _ = writeln!(out, "warnings:");
            for warning in &self.warnings {
                let _ = writeln!(out, "  - {warning}");
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::integration::step::{ArtifactOperation, ProbeDescriptor, SettingsMerge, StepAction};

    fn request() -> IntegrationRequest {
        IntegrationRequest::new(
            DevToolKind::ClaudeCode,
            ProtectionProfile::Recommended,
            SettingsScope::User,
        )
    }

    fn settings_step(scope: SettingsScope) -> IntegrationStep {
        IntegrationStep::new(
            "settings",
            StepAction::WriteManagedSettings {
                scope,
                path: PathBuf::from("/home/dev/.claude/settings.json"),
                managed_keys: vec!["permissions".to_string()],
                content_sha256: "abc".to_string(),
                merge: SettingsMerge::MergeManagedKeys,
                format: crate::integration::step::DocumentFormat::Json,
            },
            "write the managed settings block",
        )
        .with_reversal(StepAction::ManageArtifact {
            operation: ArtifactOperation::Remove,
            path: PathBuf::from("/home/dev/.claude/settings.json"),
        })
    }

    fn probe_step(mechanism: IntegrationCapability) -> IntegrationStep {
        IntegrationStep::new(
            "probe",
            StepAction::RunProtectionTest {
                probe: ProbeDescriptor {
                    id: "synthetic-secret".to_string(),
                    mechanism,
                    description: "send a synthetic secret down the model path".to_string(),
                },
            },
            "exercise the model path",
        )
    }

    #[test]
    fn observe_only_is_capped_below_protection() {
        let observe = ProtectionProfile::ObserveOnly;
        assert_eq!(observe.enforcement_mode(), EnforcementMode::Observe);
        assert!(!observe.is_enforcing());
        assert_eq!(observe.max_reportable_level(), ProtectionLevel::Integrated);

        let req = IntegrationRequest::new(DevToolKind::ClaudeCode, observe, SettingsScope::User);
        assert_eq!(req.requested_level, ProtectionLevel::GatewayProtected);
        assert_eq!(req.effective_target_level(), ProtectionLevel::Integrated);

        let plan = IntegrationPlan::new(
            "p1",
            &req,
            ProtectionLevel::GatewayProtected,
            GovernanceLevel::L2Enforce,
        )
        .with_step(settings_step(SettingsScope::User))
        .with_step(probe_step(IntegrationCapability::ModelPathInterception));
        assert!(matches!(plan.validate(), Err(PlanError::ProfileLevelCap { .. })));
    }

    #[test]
    fn a_gateway_protected_claim_needs_an_interception_probe() {
        let req = request();

        // No probe at all.
        let no_probe = IntegrationPlan::new(
            "p1",
            &req,
            ProtectionLevel::GatewayProtected,
            GovernanceLevel::L2Enforce,
        )
        .with_step(settings_step(SettingsScope::User));
        assert!(matches!(
            no_probe.validate(),
            Err(PlanError::UnsubstantiatedLevel { .. })
        ));

        // A probe pointed at a routing lever is not a protection test.
        let routing_probe = IntegrationPlan::new(
            "p2",
            &req,
            ProtectionLevel::GatewayProtected,
            GovernanceLevel::L2Enforce,
        )
        .with_step(settings_step(SettingsScope::User))
        .with_step(probe_step(IntegrationCapability::ModelGatewayBaseUrl));
        assert!(!routing_probe.has_interception_probe());
        assert!(matches!(
            routing_probe.validate(),
            Err(PlanError::UnsubstantiatedLevel { .. })
        ));

        // Interception probe: accepted.
        let interception = IntegrationPlan::new(
            "p3",
            &req,
            ProtectionLevel::GatewayProtected,
            GovernanceLevel::L2Enforce,
        )
        .with_step(settings_step(SettingsScope::User))
        .with_step(probe_step(IntegrationCapability::ModelPathInterception));
        assert_eq!(interception.validate(), Ok(()));
    }

    #[test]
    fn a_step_may_not_write_outside_the_declared_scope() {
        let req = request(); // declares SettingsScope::User
        let plan = IntegrationPlan::new("p1", &req, ProtectionLevel::Integrated, GovernanceLevel::L2Enforce)
            .with_step(settings_step(SettingsScope::Project));
        match plan.validate() {
            Err(PlanError::SettingsScopeMismatch { expected, found, .. }) => {
                assert_eq!(expected, SettingsScope::User);
                assert_eq!(found, SettingsScope::Project);
            }
            other => panic!("expected SettingsScopeMismatch, got {other:?}"),
        }
    }

    /// AAASM-5913. A project-scoped plan that names no project is not a plan
    /// that "defaults sensibly" — it is a plan whose destination will be filled
    /// in by whatever working directory the executing service happens to have.
    #[test]
    fn a_project_scoped_plan_that_names_no_project_is_rejected() {
        let req = IntegrationRequest::new(
            DevToolKind::ClaudeCode,
            ProtectionProfile::Recommended,
            SettingsScope::Project,
        );
        assert_eq!(req.project_root, None, "the request under test must name no project");

        let plan = IntegrationPlan::new("p1", &req, ProtectionLevel::Integrated, GovernanceLevel::L2Enforce)
            .with_step(settings_step(SettingsScope::Project));
        assert_eq!(plan.validate(), Err(PlanError::ProjectRootMissing));

        // Control: the same plan, with the project named, validates — so the
        // rejection above is about the missing root and not about project scope
        // being unusable.
        let named = req.clone().with_project_root("/home/dev");
        let plan = IntegrationPlan::new("p1", &named, ProtectionLevel::Integrated, GovernanceLevel::L2Enforce)
            .with_step(settings_step(SettingsScope::Project));
        assert_eq!(plan.validate(), Ok(()));
    }

    /// AAASM-5913, the defect in one assertion: the step is labelled `project`,
    /// as the broken adapter labelled it, and writes into somebody else's
    /// repository. A scope-only check called that consistent.
    #[test]
    fn a_project_scoped_write_may_not_land_outside_the_project_the_plan_names() {
        let req = IntegrationRequest::new(
            DevToolKind::ClaudeCode,
            ProtectionProfile::Recommended,
            SettingsScope::Project,
        )
        // The caller's project…
        .with_project_root("/home/dev/project-b");

        // …and a step writing into the *daemon's* project.
        let plan = IntegrationPlan::new("p1", &req, ProtectionLevel::Integrated, GovernanceLevel::L2Enforce)
            .with_step(settings_step(SettingsScope::Project));
        match plan.validate() {
            Err(PlanError::ProjectRootEscape { path, project_root, .. }) => {
                assert_eq!(path, PathBuf::from("/home/dev/.claude/settings.json"));
                assert_eq!(project_root, PathBuf::from("/home/dev/project-b"));
            }
            other => panic!("expected ProjectRootEscape, got {other:?}"),
        }
    }

    /// The non-settings artifacts a project-scoped install writes live under
    /// Agent Assembly's own state root, and must not be dragged into the project
    /// by the check above.
    #[test]
    fn the_project_root_check_leaves_agent_assembly_owned_artifacts_alone() {
        let req = IntegrationRequest::new(
            DevToolKind::ClaudeCode,
            ProtectionProfile::Recommended,
            SettingsScope::Project,
        )
        .with_project_root("/home/dev/project-b");

        let ca = IntegrationStep::new(
            "proxy-ca",
            StepAction::ManageArtifact {
                operation: ArtifactOperation::Create,
                path: PathBuf::from("/home/dev/.aasm/integrations/claude-code/project/aasm-proxy-ca.pem"),
            },
            "materialise the proxy certificate authority",
        );
        let plan =
            IntegrationPlan::new("p1", &req, ProtectionLevel::Integrated, GovernanceLevel::L2Enforce).with_step(ca);
        assert_eq!(plan.validate(), Ok(()));
    }

    #[test]
    fn duplicate_step_ids_are_rejected() {
        let req = request();
        let plan = IntegrationPlan::new("p1", &req, ProtectionLevel::Integrated, GovernanceLevel::L2Enforce)
            .with_step(settings_step(SettingsScope::User))
            .with_step(settings_step(SettingsScope::User));
        assert!(matches!(plan.validate(), Err(PlanError::DuplicateStepId { .. })));
    }

    #[test]
    fn a_privileged_step_needs_consent_and_a_reversal() {
        let req = request();

        let no_reversal = IntegrationStep::new(
            "trust-store",
            StepAction::ManageArtifact {
                operation: ArtifactOperation::Create,
                path: PathBuf::from("/Library/Keychains/System.keychain"),
            },
            "install the AASM CA into the system trust store",
        )
        .privileged("Agent Assembly will modify your system trust store.");
        let plan = IntegrationPlan::new("p1", &req, ProtectionLevel::Integrated, GovernanceLevel::L2Enforce)
            .with_step(no_reversal.clone());
        assert!(matches!(
            plan.validate(),
            Err(PlanError::PrivilegedStepIncomplete {
                missing: "a reversal step",
                ..
            })
        ));

        let no_prompt = no_reversal
            .clone()
            .privileged("   ")
            .with_reversal(StepAction::ManageArtifact {
                operation: ArtifactOperation::Remove,
                path: PathBuf::from("/Library/Keychains/System.keychain"),
            });
        let plan = IntegrationPlan::new("p2", &req, ProtectionLevel::Integrated, GovernanceLevel::L2Enforce)
            .with_step(no_prompt);
        assert!(matches!(
            plan.validate(),
            Err(PlanError::PrivilegedStepIncomplete {
                missing: "a consent prompt",
                ..
            })
        ));
    }

    #[test]
    fn dry_run_has_a_stable_shape() {
        let req = request().with_policy_profile(PolicyProfileRef {
            id: "team-default".to_string(),
            display_name: "Team default".to_string(),
            digest: "sha256:abc".to_string(),
        });
        let plan = IntegrationPlan::new("plan-1", &req, ProtectionLevel::Integrated, GovernanceLevel::L2Enforce)
            .with_step(settings_step(SettingsScope::User))
            .declaring_unsupported(IntegrationCapability::ManagedLaunch, "no launch command")
            .warn("host enforcement is unavailable on this platform");

        let rendered = plan.render_dry_run();
        let expected = "\
integration plan plan-1 for ClaudeCode
  schema: 1
  profile: Recommended (enforcement: Enforce)
  settings scope: user
  planned level: Integrated (adapter ceiling: L2Enforce)
  policy profile: Team default (sha256:abc)
steps:
  1. [required] settings (write-managed-settings): write the managed settings block
unsupported:
  - ManagedLaunch: no launch command
warnings:
  - host enforcement is unavailable on this platform
";
        assert_eq!(rendered, expected);
    }

    #[test]
    fn a_removal_plan_admits_what_it_cannot_undo() {
        let plan = RemovalPlan::new("r1", DevToolKind::Codex)
            .with_residual("the proxy CA remains in the system trust store")
            .warn("restart the tool for the removal to take effect");
        assert_eq!(plan.validate(), Ok(()));
        let rendered = plan.render_dry_run();
        assert!(rendered.contains("steps:\n  (none)"), "{rendered}");
        assert!(rendered.contains("left behind:"), "{rendered}");
    }

    #[cfg(feature = "serde")]
    #[test]
    fn plans_round_trip_through_json() {
        let req = request();
        let plan = IntegrationPlan::new("p1", &req, ProtectionLevel::Integrated, GovernanceLevel::L2Enforce)
            .with_step(settings_step(SettingsScope::User));
        let json = serde_json::to_string(&plan).unwrap();
        let restored: IntegrationPlan = serde_json::from_str(&json).unwrap();
        assert_eq!(restored, plan);
    }
}
