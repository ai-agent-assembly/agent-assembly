//! Turning lifecycle values into what may leave the trust boundary
//! (ADR 0030 §5.5).
//!
//! # Minimisation is a shape, not a pass
//!
//! Every function here maps a rich internal type onto a wire type that
//! **cannot hold** the things that must not leave. That is deliberate and it is
//! the acceptance criterion: a redaction pass is something a future contributor
//! can forget to call, whereas a struct with no field for a secret cannot carry
//! one however carelessly it is populated.
//!
//! The sharp edge is [`step_view`]. `aa_core::integration::StepAction` legitimately
//! carries values the *service* needs — a rendered settings body's digest, an
//! injected environment variable's value, a proxy variable map, a model base
//! URL. An adapter is free to put a credential in any of those. `StepView` has
//! no field any of them could land in: it carries the step's identity, its kind,
//! the settings surface, the AASM-owned **key names**, the artifact **paths**
//! and the content **fingerprint**. A reviewer can see what will change and
//! compare digests; nobody can read a value out of it, including a compromised
//! client that asked nicely.
//!
//! | The service holds | The DI-API returns |
//! | --- | --- |
//! | `PolicyDocument` | `PolicyProfileRefView { id, display_name, digest }` |
//! | rendered settings content | `content_sha256` + `managed_keys` |
//! | `EnvValue::Literal("sk-…")` | the variable *name*, nothing else |
//! | `ConfigureProxy { variables }` | the variable *names*, nothing else |
//! | audit rows | counts, verdict kinds, timestamps, redaction labels |
//! | any storage or gateway credential | nothing — no field exists |
//!
//! # Tool ids
//!
//! `DevToolKind` has no stable string form of its own, so [`tool_id`] and
//! [`parse_tool_id`] define one here. They round-trip, and an unknown id
//! becomes `DevToolKind::Custom` rather than a guess at a built-in — the
//! lifecycle service is what decides whether a tool exists, and it answers
//! `UnknownTool` if it does not.

use aa_core::dev_tool::{DevToolKind, GovernanceLevel};
use aa_core::integration::{
    ArtifactOperation, CapabilityResolution, DevToolCapabilities, EvidenceKind, ExerciseOutcome, IntegrationCapability,
    IntegrationPlan, IntegrationReceipt, IntegrationStatus, IntegrationStep, LifecyclePhase, PolicyProfileRef,
    ProtectionEvidence, ProtectionLevel, ProtectionProfile, ProtectionState, RemovalPlan, SettingsScope, StepAction,
    StepPrivilege, StepReceipt, StepRequirement, VerificationOutcome, VerificationResult, VersionCompatibility,
};
use aa_proto::assembly::devint::v1 as wire;

use super::lifecycle::{RepairReport, ScopedSecurityEvent, ToolDescriptor};

/// The stable wire id for a tool.
pub fn tool_id(tool: &DevToolKind) -> String {
    match tool {
        DevToolKind::ClaudeCode => "claude-code".to_string(),
        DevToolKind::Codex => "codex".to_string(),
        DevToolKind::GitHubCopilot => "github-copilot".to_string(),
        DevToolKind::WindsurfCascade => "windsurf-cascade".to_string(),
        DevToolKind::Custom(name) => name.clone(),
    }
}

/// Parse a wire tool id.
///
/// An unrecognised id becomes [`DevToolKind::Custom`] rather than an error:
/// deciding whether a tool exists belongs to the lifecycle service, which
/// answers `UnknownTool` for one it does not know. Resolving it here would put
/// tool knowledge in two places.
pub fn parse_tool_id(id: &str) -> DevToolKind {
    match id {
        "claude-code" => DevToolKind::ClaudeCode,
        "codex" => DevToolKind::Codex,
        "github-copilot" => DevToolKind::GitHubCopilot,
        "windsurf-cascade" => DevToolKind::WindsurfCascade,
        other => DevToolKind::Custom(other.to_string()),
    }
}

/// Snake_case name for a protection level.
pub const fn level_name(level: ProtectionLevel) -> &'static str {
    match level {
        ProtectionLevel::NotInstalled => "not_installed",
        ProtectionLevel::DetectedNotIntegrated => "detected_not_integrated",
        ProtectionLevel::PartiallyIntegrated => "partially_integrated",
        ProtectionLevel::Integrated => "integrated",
        ProtectionLevel::GatewayProtected => "gateway_protected",
        ProtectionLevel::HostEnforced => "host_enforced",
    }
}

/// Snake_case name for a governance ceiling.
pub const fn ceiling_name(level: GovernanceLevel) -> &'static str {
    match level {
        GovernanceLevel::L0Discover => "l0_discover",
        GovernanceLevel::L1Observe => "l1_observe",
        GovernanceLevel::L2Enforce => "l2_enforce",
        GovernanceLevel::L3Native => "l3_native",
    }
}

/// Snake_case name for a settings surface.
pub const fn scope_name(scope: SettingsScope) -> &'static str {
    match scope {
        SettingsScope::User => "user",
        SettingsScope::Project => "project",
        SettingsScope::Managed => "managed",
    }
}

/// Parse a wire settings-scope token. `None` for anything unrecognised — a
/// destination must be named, never inferred.
pub fn parse_scope(name: &str) -> Option<SettingsScope> {
    match name {
        "user" => Some(SettingsScope::User),
        "project" => Some(SettingsScope::Project),
        "managed" => Some(SettingsScope::Managed),
        _ => None,
    }
}

/// Snake_case name for a protection profile.
pub const fn profile_name(profile: ProtectionProfile) -> &'static str {
    match profile {
        ProtectionProfile::Recommended => "recommended",
        ProtectionProfile::Strict => "strict",
        ProtectionProfile::ObserveOnly => "observe_only",
    }
}

/// Parse a wire profile token. `None` for anything unrecognised.
pub fn parse_profile(name: &str) -> Option<ProtectionProfile> {
    match name {
        "recommended" => Some(ProtectionProfile::Recommended),
        "strict" => Some(ProtectionProfile::Strict),
        "observe_only" => Some(ProtectionProfile::ObserveOnly),
        _ => None,
    }
}

/// Parse a wire protection-level token. `None` for anything unrecognised.
pub fn parse_level(name: &str) -> Option<ProtectionLevel> {
    [
        ProtectionLevel::NotInstalled,
        ProtectionLevel::DetectedNotIntegrated,
        ProtectionLevel::PartiallyIntegrated,
        ProtectionLevel::Integrated,
        ProtectionLevel::GatewayProtected,
        ProtectionLevel::HostEnforced,
    ]
    .into_iter()
    .find(|l| level_name(*l) == name)
}

/// Snake_case name for an integration mechanism.
pub const fn capability_name(capability: IntegrationCapability) -> &'static str {
    match capability {
        IntegrationCapability::Discovery => "discovery",
        IntegrationCapability::ManagedSettings => "managed_settings",
        IntegrationCapability::ManagedLaunch => "managed_launch",
        IntegrationCapability::ModelPathInterception => "model_path_interception",
        IntegrationCapability::ModelGatewayBaseUrl => "model_gateway_base_url",
        IntegrationCapability::HttpProxy => "http_proxy",
        IntegrationCapability::Hooks => "hooks",
        IntegrationCapability::McpDiscovery => "mcp_discovery",
        IntegrationCapability::McpGovernance => "mcp_governance",
        IntegrationCapability::ToolActionApproval => "tool_action_approval",
        IntegrationCapability::NativeIdeUi => "native_ide_ui",
        IntegrationCapability::HostEnforcement => "host_enforcement",
        // `IntegrationCapability` is `#[non_exhaustive]`: a mechanism this
        // build cannot name is reported as unknown rather than mislabelled as a
        // neighbour, which would attribute evidence to the wrong mechanism.
        _ => "unknown",
    }
}

/// Snake_case name for a lifecycle phase.
pub const fn phase_name(phase: LifecyclePhase) -> &'static str {
    match phase {
        LifecyclePhase::NotInstalled => "not_installed",
        LifecyclePhase::DetectedNotIntegrated => "detected_not_integrated",
        LifecyclePhase::Planned => "planned",
        LifecyclePhase::Installed => "installed",
        LifecyclePhase::PartiallyInstalled => "partially_installed",
        LifecyclePhase::RemovalPending => "removal_pending",
        // `LifecyclePhase` is `#[non_exhaustive]`: a phase this build does not
        // know resolves to "unknown", never to a phase it might not be.
        _ => "unknown",
    }
}

/// Snake_case name for a version-compatibility verdict.
///
/// `Unknown` keeps its own name rather than folding into `incompatible`: they
/// call for different remediation, and "we could not compare" must not read as
/// "we compared and it failed".
pub const fn compatibility_name(compatibility: &VersionCompatibility) -> &'static str {
    match compatibility {
        VersionCompatibility::Compatible { .. } => "compatible",
        VersionCompatibility::Unknown { .. } => "unknown",
        VersionCompatibility::Incompatible { .. } => "incompatible",
        // `#[non_exhaustive]`: a verdict this build cannot name resolves to
        // "unknown", the downward direction (ADR 0030 §4.2 rule 2).
        _ => "unknown",
    }
}

/// Project one capability declaration.
fn capability_view(caps: &DevToolCapabilities, capability: IntegrationCapability) -> wire::CapabilityView {
    let support = match caps.resolve(capability) {
        CapabilityResolution::Effective => "supported",
        CapabilityResolution::Unsupported => "unsupported",
        CapabilityResolution::Absent => "absent",
    };
    wire::CapabilityView {
        capability: capability_name(capability).to_string(),
        support: support.to_string(),
        // The adapter's own user-facing sentence, present only when it declared
        // one. Absent capabilities carry no reason, precisely because nobody
        // declared anything about them.
        reason: caps.unsupported_reason(capability).unwrap_or_default().to_string(),
    }
}

/// Project a tool descriptor.
pub fn tool_summary(descriptor: &ToolDescriptor) -> wire::ToolSummary {
    wire::ToolSummary {
        tool_id: tool_id(&descriptor.tool),
        display_name: descriptor.display_name.clone(),
        detected: descriptor.detected,
        detected_version: descriptor
            .detected_version
            .as_ref()
            .map(ToString::to_string)
            .unwrap_or_default(),
        compatibility: compatibility_name(&descriptor.compatibility).to_string(),
        capabilities: IntegrationCapability::ALL
            .into_iter()
            .map(|c| capability_view(&descriptor.capabilities, c))
            .collect(),
        adapter_ceiling: ceiling_name(descriptor.adapter_ceiling).to_string(),
    }
}

/// Project a policy profile reference. Already a reference in `aa-core`; kept
/// as an explicit mapping so the wire type never silently widens to the
/// document.
pub fn policy_profile_view(profile: &PolicyProfileRef) -> wire::PolicyProfileRefView {
    wire::PolicyProfileRefView {
        id: profile.id.clone(),
        display_name: profile.display_name.clone(),
        digest: profile.digest.clone(),
    }
}

/// The stable kind token for a step action.
const fn action_kind(action: &StepAction) -> &'static str {
    match action {
        StepAction::WriteManagedSettings { .. } => "write_managed_settings",
        StepAction::ApplyLegacyManagedSettings { .. } => "apply_legacy_managed_settings",
        StepAction::InstallHook { .. } => "install_hook",
        StepAction::RemoveHook { .. } => "remove_hook",
        StepAction::ConfigureModelGatewayBaseUrl { .. } => "configure_model_gateway_base_url",
        StepAction::ConfigureProxy { .. } => "configure_proxy",
        StepAction::MaterialiseTrustMaterial { .. } => "materialise_trust_material",
        StepAction::InjectLaunchEnvironment { .. } => "inject_launch_environment",
        StepAction::ConfigureMcpServers { .. } => "configure_mcp_servers",
        StepAction::RegisterIdeClient { .. } => "register_ide_client",
        StepAction::ConnectLocalRuntime { .. } => "connect_local_runtime",
        StepAction::RunProtectionTest { .. } => "run_protection_test",
        StepAction::ManageArtifact { .. } => "manage_artifact",
        // `StepAction` is `#[non_exhaustive]`: an action this build cannot name
        // is reported as unknown rather than mislabelled as a neighbour.
        _ => "unknown",
    }
}

/// The names, paths and fingerprint a step exposes — and nothing else.
///
/// This is the function that enforces §5.5. Read the match arms as an
/// allowlist: each one names which *identifiers* of that action escape. Values
/// (`EnvValue`, `variables`, `base_url`, rendered content) are never in the
/// output, so a secret an adapter put in one cannot reach a client.
struct StepFacts {
    settings_scope: String,
    managed_keys: Vec<String>,
    artifact_paths: Vec<String>,
    content_sha256: String,
}

fn step_facts(action: &StepAction) -> StepFacts {
    let mut facts = StepFacts {
        settings_scope: String::new(),
        managed_keys: Vec::new(),
        artifact_paths: Vec::new(),
        content_sha256: String::new(),
    };
    match action {
        StepAction::WriteManagedSettings {
            scope,
            path,
            managed_keys,
            content_sha256,
            ..
        } => {
            facts.settings_scope = scope_name(*scope).to_string();
            facts.artifact_paths.push(path.display().to_string());
            facts.managed_keys = managed_keys.clone();
            facts.content_sha256 = content_sha256.clone();
        }
        StepAction::ApplyLegacyManagedSettings { scope, content_sha256 } => {
            facts.settings_scope = scope_name(*scope).to_string();
            facts.content_sha256 = content_sha256.clone();
        }
        StepAction::InstallHook { name, scope, path } | StepAction::RemoveHook { name, scope, path } => {
            facts.settings_scope = scope_name(*scope).to_string();
            facts.managed_keys.push(name.clone());
            facts.artifact_paths.push(path.display().to_string());
        }
        StepAction::ConfigureModelGatewayBaseUrl { scope, variable, .. } => {
            // The variable *name* only. The URL is a value, and values do not
            // cross this boundary even when they look innocuous — a base URL
            // can carry a token in its userinfo or query.
            facts.settings_scope = scope_name(*scope).to_string();
            facts.managed_keys.push(variable.clone());
        }
        StepAction::ConfigureProxy { scope, variables } => {
            facts.settings_scope = scope_name(*scope).to_string();
            facts.managed_keys = variables.keys().cloned().collect();
        }
        StepAction::MaterialiseTrustMaterial {
            path, content_sha256, ..
        } => {
            facts.artifact_paths.push(path.display().to_string());
            facts.content_sha256 = content_sha256.clone();
        }
        StepAction::InjectLaunchEnvironment { scope, variable, .. } => {
            // Name only — `EnvValue::Literal` is exactly the field an adapter
            // could put a credential in.
            facts.settings_scope = scope_name(*scope).to_string();
            facts.managed_keys.push(variable.clone());
        }
        StepAction::ConfigureMcpServers { allowed, denied } => {
            // Server *names* are identifiers, and naming them is the whole
            // point of showing an MCP allow/deny list for review.
            facts.managed_keys = allowed.iter().chain(denied.iter()).cloned().collect();
        }
        StepAction::RegisterIdeClient { host, .. } => {
            facts.managed_keys.push(host.clone());
        }
        StepAction::ManageArtifact { path, .. } => {
            // A path Agent Assembly owns outright. Naming it is the point: a
            // user approving a step that creates a file should see which file.
            facts.artifact_paths.push(path.display().to_string());
        }
        StepAction::RunProtectionTest { probe } => {
            // The probe's identifier, so a reviewer can tell which probe is
            // being offered. The descriptor carries no value fields.
            facts.managed_keys.push(probe.id.clone());
        }
        // Unknown future actions expose nothing. Failing closed on a variant
        // this build cannot reason about is the only safe default: an unknown
        // action's fields are unknown, so none of them can be shown to be safe.
        _ => {}
    }
    facts
}

/// Project a plan step.
pub fn step_view(step: &IntegrationStep) -> wire::StepView {
    let facts = step_facts(&step.action);
    let (privilege, consent_prompt) = match &step.privilege {
        StepPrivilege::User => ("user".to_string(), String::new()),
        StepPrivilege::PrivilegedHost { consent_prompt } => ("privileged_host".to_string(), consent_prompt.clone()),
    };
    wire::StepView {
        id: step.id.clone(),
        summary: step.summary.clone(),
        action_kind: action_kind(&step.action).to_string(),
        requirement: match step.requirement {
            StepRequirement::Required => "required".to_string(),
            StepRequirement::Optional => "optional".to_string(),
        },
        privilege,
        consent_prompt,
        settings_scope: facts.settings_scope,
        managed_keys: facts.managed_keys,
        artifact_paths: facts.artifact_paths,
        content_sha256: facts.content_sha256,
        reversible: step.reversal.is_some(),
    }
}

/// Project an integration plan.
pub fn plan_view(plan: &IntegrationPlan) -> wire::PlanView {
    wire::PlanView {
        schema_version: plan.schema_version,
        plan_id: plan.plan_id.clone(),
        tool_id: tool_id(&plan.tool),
        profile: profile_name(plan.profile).to_string(),
        settings_scope: scope_name(plan.settings_scope).to_string(),
        policy_profile: plan.policy_profile.as_ref().map(policy_profile_view),
        planned_level: level_name(plan.planned_level).to_string(),
        adapter_ceiling: ceiling_name(plan.adapter_ceiling).to_string(),
        steps: plan.steps.iter().map(step_view).collect(),
        unsupported: plan
            .unsupported
            .iter()
            .map(|u| wire::UnsupportedMechanismView {
                capability: capability_name(u.capability).to_string(),
                reason: u.reason.clone(),
            })
            .collect(),
        warnings: plan.warnings.clone(),
    }
}

/// Project a removal plan.
pub fn removal_view(plan: &RemovalPlan) -> wire::RemovalView {
    wire::RemovalView {
        schema_version: plan.schema_version,
        plan_id: plan.plan_id.clone(),
        tool_id: tool_id(&plan.tool),
        steps: plan.steps.iter().map(step_view).collect(),
        residual: plan.residual.clone(),
        warnings: plan.warnings.clone(),
    }
}

fn step_outcome_view(receipt: &StepReceipt) -> wire::StepOutcomeView {
    wire::StepOutcomeView {
        step_id: receipt.step_id.clone(),
        outcome: if receipt.applied { "applied" } else { "skipped" }.to_string(),
        // A fingerprint, not the content it fingerprints.
        fingerprint: receipt.fingerprint.clone().unwrap_or_default(),
    }
}

/// Project an apply receipt.
///
/// The receipt holds each step's full `StepAction`; the view holds the step id,
/// whether it applied, and its fingerprint. Nothing else about the action is
/// reachable from a client.
pub fn apply_view(receipt: &IntegrationReceipt) -> wire::ApplyView {
    wire::ApplyView {
        plan_id: receipt.plan_id.clone(),
        receipt_id: receipt.receipt_id.clone(),
        applied_at_unix_secs: receipt.applied_at_unix_secs,
        steps: receipt.steps.iter().map(step_outcome_view).collect(),
        planned_level: level_name(receipt.planned_level).to_string(),
        achieved_level: level_name(receipt.achieved_level).to_string(),
    }
}

/// Project one piece of evidence, with the timestamp that makes it "verified at
/// T" rather than "true now".
pub fn evidence_view(evidence: &ProtectionEvidence) -> wire::EvidenceView {
    let (kind, outcome) = match &evidence.kind {
        EvidenceKind::ReadBack { matches_receipt } => (
            "read_back",
            if *matches_receipt { "matched" } else { "mismatched" }.to_string(),
        ),
        EvidenceKind::Exercised { outcome } => (
            "exercised",
            match outcome {
                ExerciseOutcome::Blocked => "blocked",
                ExerciseOutcome::Redacted => "redacted",
                ExerciseOutcome::ObservedOnly => "observed_only",
                ExerciseOutcome::Leaked => "leaked",
                // `#[non_exhaustive]`: an outcome this build cannot name is
                // reported as inconclusive, never as a protective one.
                _ => "inconclusive",
            }
            .to_string(),
        ),
        EvidenceKind::HostAttested { healthy } => (
            "host_attested",
            if *healthy { "healthy" } else { "unhealthy" }.to_string(),
        ),
        EvidenceKind::Absent { reason } => ("absent", reason.clone()),
        _ => ("unknown", String::new()),
    };
    wire::EvidenceView {
        mechanism: capability_name(evidence.mechanism).to_string(),
        kind: kind.to_string(),
        outcome,
        observed_at_unix_secs: evidence.observed_at_unix_secs,
        detail: evidence.detail.clone(),
    }
}

/// Project an integration status.
pub fn status_view(status: &IntegrationStatus) -> wire::StatusView {
    let (state, drift_mismatched, reason, remediation) = match &status.state {
        ProtectionState::Ladder(_) => ("ladder", Vec::new(), String::new(), String::new()),
        ProtectionState::Drifted { mismatched, .. } => ("drifted", mismatched.clone(), String::new(), String::new()),
        ProtectionState::Degraded { reason, .. } => ("degraded", Vec::new(), reason.clone(), String::new()),
        ProtectionState::Incompatible { reason, remediation } => {
            ("incompatible", Vec::new(), reason.clone(), remediation.clone())
        }
        _ => ("unknown", Vec::new(), String::new(), String::new()),
    };
    wire::StatusView {
        tool_id: tool_id(&status.tool),
        phase: phase_name(status.phase).to_string(),
        state: state.to_string(),
        achieved_level: level_name(status.achieved_level()).to_string(),
        planned_level: level_name(status.planned_level).to_string(),
        adapter_ceiling: ceiling_name(status.adapter_ceiling).to_string(),
        compatibility: compatibility_name(&status.compatibility).to_string(),
        evidence: status.evidence.iter().map(evidence_view).collect(),
        next_level: status.next_level.as_ref().map(|n| wire::NextLevelView {
            level: level_name(n.level).to_string(),
            blocked_because: n.blocked_because.clone(),
        }),
        observed_at_unix_secs: status.observed_at_unix_secs,
        drift_mismatched,
        state_reason: reason,
        state_remediation: remediation,
    }
}

/// Project a verification result.
pub fn verification_view(result: &VerificationResult) -> wire::VerificationView {
    let (outcome, missing, reason) = match &result.outcome {
        VerificationOutcome::Passed => ("passed", Vec::new(), String::new()),
        VerificationOutcome::PartiallyPassed { missing } => ("partially_passed", missing.clone(), String::new()),
        VerificationOutcome::Failed { reason } => ("failed", Vec::new(), reason.clone()),
        VerificationOutcome::Unverifiable { reason } => ("unverifiable", Vec::new(), reason.clone()),
        // An outcome this build cannot name resolves downward to
        // "unverifiable": "we do not know" must never read as "we looked and it
        // was fine" (ADR 0030 §4.2 rule 2).
        _ => ("unverifiable", Vec::new(), "unrecognised outcome".to_string()),
    };
    wire::VerificationView {
        verified_at_unix_secs: result.verified_at_unix_secs,
        outcome: outcome.to_string(),
        missing,
        reason,
        evidence: result.evidence.iter().map(evidence_view).collect(),
    }
}

/// Project a repair report together with the status it produced.
pub fn repair_view(tool: &DevToolKind, report: &RepairReport, status: &IntegrationStatus) -> wire::RepairView {
    wire::RepairView {
        tool_id: tool_id(tool),
        repaired: report.repaired.clone(),
        unrepairable: report
            .unrepairable
            .iter()
            .map(|(capability, reason)| wire::UnsupportedMechanismView {
                capability: capability_name(*capability).to_string(),
                reason: reason.clone(),
            })
            .collect(),
        status: Some(status_view(status)),
    }
}

/// Project a redacted security event.
pub fn scoped_event_view(event: &ScopedSecurityEvent) -> wire::ScopedEvent {
    wire::ScopedEvent {
        occurred_at_unix_secs: event.occurred_at_unix_secs,
        verdict_kind: event.verdict_kind.as_str().to_string(),
        mechanism: capability_name(event.mechanism).to_string(),
        count: event.count,
        redaction_labels: event.redaction_labels.clone(),
    }
}

/// Snake_case name for an artifact operation. Kept alongside the other name
/// tables so the server module never reaches into `aa-core`'s enums directly.
pub const fn artifact_operation_name(operation: ArtifactOperation) -> &'static str {
    match operation {
        ArtifactOperation::Create => "create",
        ArtifactOperation::Update => "update",
        ArtifactOperation::Remove => "remove",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aa_core::integration::{
        CapabilitySupport, EnvValue, IntegrationRequest, SettingsMerge, ToolVersion, TrustMaterialKind,
    };
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    /// The sentinel every value-bearing field of the fixture carries. If it
    /// appears anywhere in an encoded response, minimisation leaked.
    const SECRET: &str = "sk-live-THISMUSTNEVERLEAVE-0123456789";

    fn poisoned_steps() -> Vec<IntegrationStep> {
        let mut proxy_vars = BTreeMap::new();
        proxy_vars.insert(
            "HTTPS_PROXY".to_string(),
            format!("http://user:{SECRET}@127.0.0.1:8080"),
        );

        vec![
            IntegrationStep::new(
                "settings",
                StepAction::WriteManagedSettings {
                    scope: SettingsScope::User,
                    path: PathBuf::from("/home/dev/.claude/settings.json"),
                    managed_keys: vec!["aasm.gatewayUrl".to_string()],
                    content_sha256: "abc123".to_string(),
                    merge: SettingsMerge::MergeManagedKeys,
                },
                "Write the managed settings block",
            ),
            IntegrationStep::new(
                "env",
                StepAction::InjectLaunchEnvironment {
                    scope: SettingsScope::User,
                    variable: "ANTHROPIC_AUTH_TOKEN".to_string(),
                    value: EnvValue::Literal(SECRET.to_string()),
                },
                "Inject the launch environment",
            ),
            IntegrationStep::new(
                "proxy",
                StepAction::ConfigureProxy {
                    scope: SettingsScope::User,
                    variables: proxy_vars,
                },
                "Route traffic through the AASM proxy",
            ),
            IntegrationStep::new(
                "base-url",
                StepAction::ConfigureModelGatewayBaseUrl {
                    scope: SettingsScope::User,
                    variable: "ANTHROPIC_BASE_URL".to_string(),
                    base_url: format!("https://gw.local/?token={SECRET}"),
                },
                "Point the tool at the gateway",
            ),
            IntegrationStep::new(
                "ca",
                StepAction::MaterialiseTrustMaterial {
                    kind: TrustMaterialKind::ProxyCaTrustStoreAnchor,
                    path: PathBuf::from("/home/dev/.aa/ca/aasm-ca.pem"),
                    content_sha256: "deadbeef".to_string(),
                },
                "Install the AASM CA",
            )
            .privileged("AASM will add its certificate authority to the system trust store."),
        ]
    }

    fn poisoned_plan() -> IntegrationPlan {
        let request = IntegrationRequest::new(
            DevToolKind::ClaudeCode,
            ProtectionProfile::Recommended,
            SettingsScope::User,
        )
        .with_policy_profile(PolicyProfileRef {
            id: "team-default".to_string(),
            display_name: "Team default".to_string(),
            digest: "sha256:1234".to_string(),
        });
        let mut plan = IntegrationPlan::new(
            "plan-1",
            &request,
            ProtectionLevel::GatewayProtected,
            GovernanceLevel::L2Enforce,
        );
        plan.steps = poisoned_steps();
        plan
    }

    /// Encode a wire message and search its bytes. Searching the *encoded
    /// form* rather than a Debug rendering is deliberate: it is what actually
    /// crosses the socket.
    fn encoded_contains(message: &impl prost::Message, needle: &str) -> bool {
        let bytes = message.encode_to_vec();
        String::from_utf8_lossy(&bytes).contains(needle)
    }

    #[test]
    fn a_step_view_carries_no_step_value() {
        for step in poisoned_steps() {
            let view = step_view(&step);
            assert!(
                !encoded_contains(&view, SECRET),
                "step {} leaked a value into the wire",
                step.id
            );
        }
    }

    #[test]
    fn a_plan_view_carries_no_step_value() {
        let view = plan_view(&poisoned_plan());
        assert!(!encoded_contains(&view, SECRET), "plan leaked a value into the wire");
    }

    #[test]
    fn a_step_view_still_carries_what_a_reviewer_needs() {
        // Minimisation must not be achieved by returning nothing: a plan a
        // human cannot review is not a reviewable dry run.
        let view = step_view(&poisoned_steps()[0]);
        assert_eq!(view.action_kind, "write_managed_settings");
        assert_eq!(view.settings_scope, "user");
        assert_eq!(view.managed_keys, vec!["aasm.gatewayUrl"]);
        assert_eq!(view.artifact_paths, vec!["/home/dev/.claude/settings.json"]);
        assert_eq!(view.content_sha256, "abc123");
        assert_eq!(view.requirement, "required");
    }

    #[test]
    fn a_privileged_step_carries_its_consent_prompt() {
        let steps = poisoned_steps();
        let view = step_view(steps.last().unwrap());
        assert_eq!(view.privilege, "privileged_host");
        assert!(view.consent_prompt.contains("trust store"));
    }

    #[test]
    fn an_env_injection_exposes_the_name_and_not_the_value() {
        let steps = poisoned_steps();
        let view = step_view(&steps[1]);
        assert_eq!(view.managed_keys, vec!["ANTHROPIC_AUTH_TOKEN"]);
        assert!(!encoded_contains(&view, SECRET));
    }

    #[test]
    fn a_proxy_step_exposes_variable_names_and_not_their_values() {
        let steps = poisoned_steps();
        let view = step_view(&steps[2]);
        assert_eq!(view.managed_keys, vec!["HTTPS_PROXY"]);
        assert!(!encoded_contains(&view, SECRET));
    }

    #[test]
    fn a_base_url_is_a_value_and_does_not_cross() {
        // A base URL looks innocuous and can carry a token in its query or
        // userinfo, so the name crosses and the URL does not.
        let steps = poisoned_steps();
        let view = step_view(&steps[3]);
        assert_eq!(view.managed_keys, vec!["ANTHROPIC_BASE_URL"]);
        assert!(!encoded_contains(&view, SECRET));
        assert!(!encoded_contains(&view, "gw.local"));
    }

    #[test]
    fn a_policy_profile_crosses_as_a_reference_only() {
        let view = plan_view(&poisoned_plan());
        let profile = view.policy_profile.expect("profile reference");
        assert_eq!(profile.id, "team-default");
        assert_eq!(profile.digest, "sha256:1234");
        // There is no field on `PolicyProfileRefView` that could hold a
        // document; the assertion is that the projection did not invent one by
        // stuffing content into `display_name`.
        assert_eq!(profile.display_name, "Team default");
    }

    #[test]
    fn tool_ids_round_trip() {
        for tool in [
            DevToolKind::ClaudeCode,
            DevToolKind::Codex,
            DevToolKind::GitHubCopilot,
            DevToolKind::WindsurfCascade,
            DevToolKind::Custom("myeditor".to_string()),
        ] {
            assert_eq!(parse_tool_id(&tool_id(&tool)), tool);
        }
    }

    #[test]
    fn an_unrecognised_scope_or_profile_is_not_defaulted() {
        assert_eq!(parse_scope("Users"), None);
        assert_eq!(parse_scope(""), None);
        assert_eq!(parse_profile("STRICT"), None);
        assert_eq!(parse_level("gateway"), None);
        assert_eq!(
            parse_level("gateway_protected"),
            Some(ProtectionLevel::GatewayProtected)
        );
    }

    #[test]
    fn an_absent_capability_is_not_reported_as_supported() {
        let caps = DevToolCapabilities::new()
            .supported(IntegrationCapability::Discovery)
            .unsupported(IntegrationCapability::ManagedLaunch, "no launch command");
        let view = capability_view(&caps, IntegrationCapability::Hooks);
        assert_eq!(view.support, "absent");
        assert!(view.reason.is_empty());

        let unsupported = capability_view(&caps, IntegrationCapability::ManagedLaunch);
        assert_eq!(unsupported.support, "unsupported");
        assert_eq!(unsupported.reason, "no launch command");
    }

    #[test]
    fn a_requires_version_declaration_without_a_detected_version_is_absent() {
        let caps = DevToolCapabilities::new().declare(
            IntegrationCapability::Hooks,
            CapabilitySupport::RequiresVersion {
                min: ToolVersion::new(2, 0, 0),
                detected: None,
            },
        );
        assert_eq!(capability_view(&caps, IntegrationCapability::Hooks).support, "absent");
    }

    #[test]
    fn an_apply_view_carries_fingerprints_not_content() {
        let receipt = IntegrationReceipt {
            schema_version: 1,
            receipt_id: "r-1".to_string(),
            plan_id: "plan-1".to_string(),
            tool: DevToolKind::ClaudeCode,
            profile: ProtectionProfile::Recommended,
            settings_scope: SettingsScope::User,
            applied_at_unix_secs: 1_700_000_000,
            versions: aa_core::integration::VersionSupport {
                adapter_version: ToolVersion::new(1, 0, 0),
                lifecycle_schema_version: 1,
                supported_tool_versions: aa_core::integration::SupportedToolVersions::any(),
            }
            .component_versions(),
            tool_version: None,
            steps: poisoned_steps()
                .iter()
                .map(|s| StepReceipt::applied(s, Some("fp-1".to_string())))
                .collect(),
            planned_level: ProtectionLevel::GatewayProtected,
            achieved_level: ProtectionLevel::Integrated,
            achieved_evidence: Vec::new(),
            verified_at_unix_secs: None,
        };
        let view = apply_view(&receipt);
        assert_eq!(view.steps.len(), 5);
        assert!(view.steps.iter().all(|s| s.fingerprint == "fp-1"));
        assert!(
            !encoded_contains(&view, SECRET),
            "the receipt holds full StepActions; the view must not"
        );
    }

    #[test]
    fn a_scoped_event_carries_labels_and_not_content() {
        let event = ScopedSecurityEvent {
            occurred_at_unix_secs: 1_700_000_000,
            verdict_kind: super::super::lifecycle::VerdictKind::Redacted,
            mechanism: IntegrationCapability::ModelPathInterception,
            count: 3,
            redaction_labels: vec!["aws_access_key".to_string()],
        };
        let view = scoped_event_view(&event);
        assert_eq!(view.verdict_kind, "redacted");
        assert_eq!(view.count, 3);
        assert_eq!(view.redaction_labels, vec!["aws_access_key"]);
        assert!(!encoded_contains(&view, SECRET));
    }

    #[test]
    fn an_unverifiable_result_is_never_rendered_as_passed() {
        let result = VerificationResult::unverifiable(1_700_000_000, "no probe descriptor");
        let view = verification_view(&result);
        assert_eq!(view.outcome, "unverifiable");
        assert_eq!(view.reason, "no probe descriptor");
    }

    #[test]
    fn evidence_carries_its_timestamp() {
        let evidence = ProtectionEvidence::new(
            IntegrationCapability::ModelPathInterception,
            EvidenceKind::Exercised {
                outcome: ExerciseOutcome::Redacted,
            },
            1_700_000_123,
            "probe redacted at the proxy",
        );
        let view = evidence_view(&evidence);
        assert_eq!(view.observed_at_unix_secs, 1_700_000_123);
        assert_eq!(view.kind, "exercised");
        assert_eq!(view.outcome, "redacted");
    }
}
