//! Contract tests for the Developer Integration lifecycle (AAASM-5277).
//!
//! # Why they live in this crate
//!
//! Two things are under test at once. The obvious one is that the three tool
//! categories ADR 0030 §3.5 distinguishes — CLI, IDE-hosted and SaaS — can each
//! be expressed without declaring a capability they do not have. The less
//! obvious one is that they can be expressed **using only what
//! `aa-devtool-contract` re-exports**: these fixtures never name `aa_core`, so
//! if the audited re-export list were insufficient for a real adapter, this file
//! would not compile.
//!
//! The fixtures are deliberately shaped like the real tools:
//!
//! * [`CliTool`] is the Claude Code shape — launchable, MCP-governed, and the
//!   only one that can put an AASM component in its model path.
//! * [`IdeHostedTool`] is the Copilot shape — no launch command at all, so it
//!   implements no launch surface and says why at plan time.
//! * [`SaasTool`] is the hosted-agent shape — nothing local to configure, so it
//!   is capped at observation and implements none of the optional surfaces.
//!
//! Not one of them contains an `Ok(())` stub or an `unimplemented!()`.

use std::path::PathBuf;

use aa_devtool_contract::PolicyPosture;
use aa_devtool_contract::{
    capability_conformance, AdapterError, ArtifactOperation, DevToolCapabilities, DevToolInfo, DevToolIntegration,
    DevToolKind, DocumentFormat, EnvValue, EvidenceKind, ExerciseOutcome, GovernanceLevel, HookableTool,
    IntegrationCapability, IntegrationPlan, IntegrationReceipt, IntegrationRequest, IntegrationStatus, IntegrationStep,
    LaunchSpec, LaunchableTool, LifecyclePhase, McpGovernedTool, McpServerInfo, PlanError, ProbeDescriptor,
    ProtectionEvidence, ProtectionLevel, ProtectionProfile, ProtectionState, RemovalPlan, SettingsMerge, SettingsScope,
    StateDerivation, StepAction, SupportedToolVersions, ToolVersion, TrustMaterialKind, VerificationOutcome,
    VerificationResult, VersionCompatibility, VersionSupport, DEFAULT_FRESHNESS_WINDOW_SECS, LIFECYCLE_SCHEMA_VERSION,
};

const NOW: u64 = 1_700_000_000;

fn version_support(min: ToolVersion) -> VersionSupport {
    VersionSupport {
        adapter_version: ToolVersion::new(0, 1, 0),
        lifecycle_schema_version: LIFECYCLE_SCHEMA_VERSION,
        supported_tool_versions: SupportedToolVersions::at_least(min),
    }
}

fn info(kind: DevToolKind, version: &str, level: GovernanceLevel) -> DevToolInfo {
    DevToolInfo {
        kind,
        version: Some(version.to_string()),
        install_path: PathBuf::from("/usr/local/bin/tool"),
        governance_level: level,
        supports_mcp: false,
        supports_managed_settings: true,
    }
}

fn empty_status(tool: DevToolKind, phase: LifecyclePhase, state: ProtectionState) -> IntegrationStatus {
    IntegrationStatus {
        tool,
        phase,
        state,
        evidence: Vec::new(),
        planned_level: ProtectionLevel::DetectedNotIntegrated,
        adapter_ceiling: GovernanceLevel::L1Observe,
        compatibility: VersionCompatibility::Unknown {
            reason: "not probed in this fixture".to_string(),
        },
        next_level: None,
        observed_at_unix_secs: NOW,
        policy: PolicyPosture::Unknown {
            reason: "not resolved in this fixture".to_string(),
        },
    }
}

// ---------------------------------------------------------------------------
// CLI tool — the Claude Code shape.
// ---------------------------------------------------------------------------

struct CliTool;

impl CliTool {
    const CA_PATH: &'static str = "/home/dev/.aa/ca/aasm-ca.pem";
}

#[async_trait::async_trait]
impl DevToolIntegration for CliTool {
    fn capabilities(&self) -> DevToolCapabilities {
        DevToolCapabilities::new()
            .supported(IntegrationCapability::Discovery)
            .supported(IntegrationCapability::ManagedSettings)
            .supported(IntegrationCapability::ManagedLaunch)
            .supported(IntegrationCapability::ModelPathInterception)
            .supported(IntegrationCapability::ModelGatewayBaseUrl)
            .supported(IntegrationCapability::HttpProxy)
            .supported(IntegrationCapability::Hooks)
            .supported(IntegrationCapability::McpDiscovery)
            .supported(IntegrationCapability::McpGovernance)
            .supported(IntegrationCapability::ToolActionApproval)
            .unsupported(
                IntegrationCapability::NativeIdeUi,
                "this tool is a terminal CLI with no IDE surface",
            )
            .unsupported(
                IntegrationCapability::HostEnforcement,
                "host enforcement is unavailable on this platform",
            )
    }

    fn detect(&self) -> Option<DevToolInfo> {
        Some(info(DevToolKind::ClaudeCode, "2.1.220", GovernanceLevel::L2Enforce))
    }

    fn version_support(&self) -> VersionSupport {
        version_support(ToolVersion::new(2, 0, 0))
    }

    async fn plan_integration(&self, request: &IntegrationRequest) -> Result<IntegrationPlan, AdapterError> {
        let scope = request.settings_scope;
        let plan = IntegrationPlan::new(
            "cli-plan",
            request,
            request.effective_target_level(),
            GovernanceLevel::L2Enforce,
        )
        .with_step(
            IntegrationStep::new(
                "settings",
                StepAction::WriteManagedSettings {
                    scope,
                    path: PathBuf::from("/home/dev/.claude/settings.json"),
                    managed_keys: vec!["permissions".to_string()],
                    content_sha256: "sha-settings".to_string(),
                    merge: SettingsMerge::MergeManagedKeys,
                    format: DocumentFormat::Json,
                },
                "write the managed settings block",
            )
            .with_reversal(StepAction::ManageArtifact {
                operation: ArtifactOperation::Remove,
                path: PathBuf::from("/home/dev/.claude/settings.json"),
            }),
        )
        .with_step(
            IntegrationStep::new(
                "ca",
                StepAction::MaterialiseTrustMaterial {
                    kind: TrustMaterialKind::ProxyCaCertificatePem,
                    path: PathBuf::from(Self::CA_PATH),
                    content_sha256: "sha-ca".to_string(),
                },
                "write the AASM proxy CA where the tool's runtime can read it",
            )
            .with_reversal(StepAction::ManageArtifact {
                operation: ArtifactOperation::Remove,
                path: PathBuf::from(Self::CA_PATH),
            }),
        )
        .with_step(
            IntegrationStep::new(
                "node-ca",
                StepAction::InjectLaunchEnvironment {
                    scope,
                    variable: "NODE_EXTRA_CA_CERTS".to_string(),
                    value: EnvValue::ArtifactPath(PathBuf::from(Self::CA_PATH)),
                },
                "make the tool's Node runtime trust the AASM proxy CA",
            )
            .with_reversal(StepAction::InjectLaunchEnvironment {
                scope,
                variable: "NODE_EXTRA_CA_CERTS".to_string(),
                value: EnvValue::Literal(String::new()),
            }),
        )
        .with_step(IntegrationStep::new(
            "probe",
            StepAction::RunProtectionTest {
                probe: ProbeDescriptor {
                    id: "synthetic-secret".to_string(),
                    mechanism: IntegrationCapability::ModelPathInterception,
                    description: "send a synthetic secret down the model path".to_string(),
                },
            },
            "prove the model path is actually intercepted",
        ))
        .declaring_unsupported(
            IntegrationCapability::HostEnforcement,
            "host enforcement is unavailable on this platform",
        );

        Ok(plan)
    }

    async fn integration_status(
        &self,
        receipt: Option<&IntegrationReceipt>,
    ) -> Result<IntegrationStatus, AdapterError> {
        let compatibility = self
            .version_support()
            .supported_tool_versions
            .classify(Some(&ToolVersion::new(2, 1, 220)));
        let evidence = vec![
            ProtectionEvidence::new(
                IntegrationCapability::ManagedSettings,
                EvidenceKind::ReadBack { matches_receipt: true },
                NOW,
                "settings read back and matched the receipt",
            ),
            ProtectionEvidence::new(
                IntegrationCapability::ModelPathInterception,
                EvidenceKind::Exercised {
                    outcome: ExerciseOutcome::Redacted,
                },
                NOW,
                "the synthetic secret was redacted before egress",
            ),
        ];

        let state = StateDerivation {
            detected: true,
            receipt_present: receipt.is_some(),
            required_steps: receipt.map(IntegrationReceipt::required_steps).unwrap_or(0),
            required_steps_verified: receipt.map(IntegrationReceipt::verified_required_steps).unwrap_or(0),
            mismatched_artifacts: &[],
            compatibility: &compatibility,
            schema_newer_than_core: false,
            evidence: &evidence,
            planned_level: ProtectionLevel::GatewayProtected,
            now_unix_secs: NOW,
            freshness_window_secs: DEFAULT_FRESHNESS_WINDOW_SECS,
        }
        .derive();

        Ok(IntegrationStatus {
            tool: DevToolKind::ClaudeCode,
            phase: if receipt.is_some() {
                LifecyclePhase::Installed
            } else {
                LifecyclePhase::DetectedNotIntegrated
            },
            state,
            evidence,
            planned_level: ProtectionLevel::GatewayProtected,
            adapter_ceiling: GovernanceLevel::L2Enforce,
            compatibility,
            next_level: None,
            observed_at_unix_secs: NOW,
            policy: PolicyPosture::Unknown {
                reason: "not resolved in this fixture".to_string(),
            },
        })
    }

    async fn verify_integration(&self, _receipt: &IntegrationReceipt) -> Result<VerificationResult, AdapterError> {
        Ok(VerificationResult {
            verified_at_unix_secs: NOW,
            outcome: VerificationOutcome::Passed,
            evidence: vec![ProtectionEvidence::new(
                IntegrationCapability::ModelPathInterception,
                EvidenceKind::Exercised {
                    outcome: ExerciseOutcome::Redacted,
                },
                NOW,
                "the synthetic secret was redacted before egress",
            )],
        })
    }

    async fn plan_removal(&self, receipt: &IntegrationReceipt) -> Result<RemovalPlan, AdapterError> {
        let mut plan = RemovalPlan::new("cli-removal", receipt.tool.clone());
        for (index, action) in receipt.reversal_actions().into_iter().enumerate() {
            plan = plan.with_step(IntegrationStep::new(
                format!("reverse-{index}"),
                action,
                "undo a recorded step",
            ));
        }
        Ok(plan)
    }

    fn as_mcp_governed(&self) -> Option<&dyn McpGovernedTool> {
        Some(self)
    }

    fn as_launchable(&self) -> Option<&dyn LaunchableTool> {
        Some(self)
    }

    fn as_hookable(&self) -> Option<&dyn HookableTool> {
        Some(self)
    }
}

#[async_trait::async_trait]
impl McpGovernedTool for CliTool {
    async fn list_mcp_servers(&self) -> Result<Vec<McpServerInfo>, AdapterError> {
        Ok(vec![McpServerInfo {
            name: "filesystem".to_string(),
            command: "mcp-filesystem".to_string(),
            args: Vec::new(),
        }])
    }

    fn plan_mcp_governance(&self, allowed: &[String], denied: &[String]) -> Result<IntegrationStep, AdapterError> {
        Ok(IntegrationStep::new(
            "mcp",
            StepAction::ConfigureMcpServers {
                allowed: allowed.to_vec(),
                denied: denied.to_vec(),
            },
            "apply the MCP allow/deny list",
        ))
    }
}

impl LaunchableTool for CliTool {
    fn build_launch_command(&self, spec: &LaunchSpec) -> Result<std::process::Command, AdapterError> {
        let mut command = std::process::Command::new("claude");
        command.args(&spec.tool_args);
        command.env("AASM_AGENT_ID", &spec.agent_id);
        if let Some(proxy) = &spec.proxy_addr {
            command.env("HTTPS_PROXY", proxy);
        }
        for (name, value) in &spec.env {
            command.env(name, value);
        }
        Ok(command)
    }
}

impl HookableTool for CliTool {
    fn plan_hooks(&self, request: &IntegrationRequest) -> Result<Vec<IntegrationStep>, AdapterError> {
        Ok(vec![IntegrationStep::new(
            "pre-tool-hook",
            StepAction::InstallHook {
                name: "PreToolUse".to_string(),
                scope: request.settings_scope,
                path: PathBuf::from("/home/dev/.claude/hooks/aasm-pre-tool.sh"),
            },
            "install the pre-tool governance hook",
        )])
    }
}

// ---------------------------------------------------------------------------
// IDE-hosted tool — the Copilot shape. No launch command exists.
// ---------------------------------------------------------------------------

struct IdeHostedTool;

#[async_trait::async_trait]
impl DevToolIntegration for IdeHostedTool {
    fn capabilities(&self) -> DevToolCapabilities {
        // McpDiscovery / McpGovernance are not mentioned at all: this adapter has
        // not answered the question, which is absent — not a claim either way.
        DevToolCapabilities::new()
            .supported(IntegrationCapability::Discovery)
            .supported(IntegrationCapability::ManagedSettings)
            .supported(IntegrationCapability::NativeIdeUi)
            .supported(IntegrationCapability::ToolActionApproval)
            .unsupported(
                IntegrationCapability::ManagedLaunch,
                "GitHub Copilot is a VS Code extension and has no launch command",
            )
            .unsupported(
                IntegrationCapability::ModelPathInterception,
                "the IDE host owns the network stack; AASM cannot place itself in the model path",
            )
    }

    fn detect(&self) -> Option<DevToolInfo> {
        Some(info(DevToolKind::GitHubCopilot, "1.4.0", GovernanceLevel::L2Enforce))
    }

    fn version_support(&self) -> VersionSupport {
        version_support(ToolVersion::new(1, 0, 0))
    }

    async fn plan_integration(&self, request: &IntegrationRequest) -> Result<IntegrationPlan, AdapterError> {
        let caps = self.capabilities();
        let mut plan = IntegrationPlan::new(
            "ide-plan",
            request,
            // No interception mechanism, so the honest ceiling is Integrated
            // regardless of what was requested.
            request.effective_target_level().min(ProtectionLevel::Integrated),
            GovernanceLevel::L2Enforce,
        )
        .with_step(
            IntegrationStep::new(
                "settings",
                StepAction::WriteManagedSettings {
                    scope: request.settings_scope,
                    path: PathBuf::from("/home/dev/Library/Application Support/Code/User/settings.json"),
                    managed_keys: vec!["github.copilot.advanced".to_string()],
                    content_sha256: "sha-vscode".to_string(),
                    merge: SettingsMerge::MergeManagedKeys,
                    format: DocumentFormat::Json,
                },
                "merge the managed keys into the IDE host's user settings",
            )
            .with_reversal(StepAction::ManageArtifact {
                operation: ArtifactOperation::Update,
                path: PathBuf::from("/home/dev/Library/Application Support/Code/User/settings.json"),
            }),
        )
        .with_step(IntegrationStep::new(
            "register",
            StepAction::RegisterIdeClient {
                host: "vscode".to_string(),
                client_id: "agent-assembly.aasm".to_string(),
            },
            "register the AASM extension as the status and approval surface",
        ));

        for capability in [
            IntegrationCapability::ManagedLaunch,
            IntegrationCapability::ModelPathInterception,
        ] {
            if let Some(reason) = caps.unsupported_reason(capability) {
                plan = plan.declaring_unsupported(capability, reason);
            }
        }

        Ok(plan)
    }

    async fn integration_status(
        &self,
        _receipt: Option<&IntegrationReceipt>,
    ) -> Result<IntegrationStatus, AdapterError> {
        Ok(empty_status(
            DevToolKind::GitHubCopilot,
            LifecyclePhase::DetectedNotIntegrated,
            ProtectionState::Ladder(ProtectionLevel::DetectedNotIntegrated),
        ))
    }

    async fn verify_integration(&self, _receipt: &IntegrationReceipt) -> Result<VerificationResult, AdapterError> {
        Ok(VerificationResult {
            verified_at_unix_secs: NOW,
            outcome: VerificationOutcome::PartiallyPassed {
                missing: vec!["model-path interception is not available for an IDE-hosted tool".to_string()],
            },
            evidence: vec![ProtectionEvidence::new(
                IntegrationCapability::ManagedSettings,
                EvidenceKind::ReadBack { matches_receipt: true },
                NOW,
                "the managed keys read back unchanged",
            )],
        })
    }

    async fn plan_removal(&self, receipt: &IntegrationReceipt) -> Result<RemovalPlan, AdapterError> {
        Ok(RemovalPlan::new("ide-removal", receipt.tool.clone()))
    }
}

// ---------------------------------------------------------------------------
// SaaS tool — nothing local to configure, capped at observation.
// ---------------------------------------------------------------------------

struct SaasTool;

#[async_trait::async_trait]
impl DevToolIntegration for SaasTool {
    fn capabilities(&self) -> DevToolCapabilities {
        DevToolCapabilities::new()
            .unsupported(IntegrationCapability::Discovery, "no local install to detect")
            .unsupported(
                IntegrationCapability::ManagedSettings,
                "the agent runs in the vendor's tenant; there is no local settings surface",
            )
            .unsupported(
                IntegrationCapability::ManagedLaunch,
                "the agent is started by the vendor, not by this host",
            )
            .supported(IntegrationCapability::HostEnforcement)
    }

    fn detect(&self) -> Option<DevToolInfo> {
        None
    }

    fn version_support(&self) -> VersionSupport {
        version_support(ToolVersion::new(0, 0, 0))
    }

    async fn plan_integration(&self, request: &IntegrationRequest) -> Result<IntegrationPlan, AdapterError> {
        let caps = self.capabilities();
        let mut plan = IntegrationPlan::new(
            "saas-plan",
            request,
            // Nothing local to install, so nothing above "we can see it" is
            // claimable.
            ProtectionLevel::DetectedNotIntegrated,
            GovernanceLevel::L1Observe,
        )
        .with_step(IntegrationStep::new(
            "connect",
            StepAction::ConnectLocalRuntime { socket_path: None },
            "attach egress observation for this tenant's traffic",
        ))
        .warn("this tool is observed at the network edge only; nothing is configured on this host");

        for capability in [
            IntegrationCapability::Discovery,
            IntegrationCapability::ManagedSettings,
            IntegrationCapability::ManagedLaunch,
        ] {
            if let Some(reason) = caps.unsupported_reason(capability) {
                plan = plan.declaring_unsupported(capability, reason);
            }
        }

        Ok(plan)
    }

    async fn integration_status(
        &self,
        _receipt: Option<&IntegrationReceipt>,
    ) -> Result<IntegrationStatus, AdapterError> {
        Ok(empty_status(
            DevToolKind::Custom("saas-agent".to_string()),
            LifecyclePhase::NotInstalled,
            ProtectionState::Ladder(ProtectionLevel::NotInstalled),
        ))
    }

    async fn verify_integration(&self, _receipt: &IntegrationReceipt) -> Result<VerificationResult, AdapterError> {
        Ok(VerificationResult::unverifiable(
            NOW,
            "there is nothing on this host to read back",
        ))
    }

    async fn plan_removal(&self, receipt: &IntegrationReceipt) -> Result<RemovalPlan, AdapterError> {
        Ok(RemovalPlan::new("saas-removal", receipt.tool.clone()))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

fn request(tool: DevToolKind, profile: ProtectionProfile) -> IntegrationRequest {
    IntegrationRequest::new(tool, profile, SettingsScope::User)
}

#[test]
fn all_three_categories_are_expressible_without_a_single_no_op() {
    let integrations: Vec<Box<dyn DevToolIntegration>> =
        vec![Box::new(CliTool), Box::new(IdeHostedTool), Box::new(SaasTool)];
    for integration in &integrations {
        assert!(
            capability_conformance(integration.as_ref()).is_empty(),
            "every declaration must be backed by the surface that implements it"
        );
    }
}

#[test]
fn mcp_is_one_optional_capability_among_many() {
    // One of three tool categories has MCP at all. A design in which "plugin"
    // means "MCP server" would force the other two into stubs.
    assert!(CliTool.as_mcp_governed().is_some());
    assert!(IdeHostedTool.as_mcp_governed().is_none());
    assert!(SaasTool.as_mcp_governed().is_none());

    // And the two without it declare nothing rather than declaring a lie.
    assert!(!IdeHostedTool
        .capabilities()
        .is_effective(IntegrationCapability::McpGovernance));
    assert_eq!(
        IdeHostedTool
            .capabilities()
            .unsupported_reason(IntegrationCapability::McpGovernance),
        None,
        "an unanswered question must not be reported as an answered one"
    );
}

#[test]
fn a_tool_without_a_launch_command_says_so_instead_of_implementing_one() {
    assert!(IdeHostedTool.as_launchable().is_none());
    assert!(SaasTool.as_launchable().is_none());

    let caps = IdeHostedTool.capabilities();
    let reason = caps
        .unsupported_reason(IntegrationCapability::ManagedLaunch)
        .expect("the reason must be available at plan time");
    assert!(reason.contains("VS Code extension"), "{reason}");
}

#[tokio::test]
async fn the_cli_plan_wires_the_ca_the_spike_measured_and_probes_the_result() {
    let plan = CliTool
        .plan_integration(&request(DevToolKind::ClaudeCode, ProtectionProfile::Recommended))
        .await
        .expect("planning must succeed");

    assert_eq!(plan.validate(), Ok(()));
    assert_eq!(plan.planned_level, ProtectionLevel::GatewayProtected);
    assert!(plan.has_interception_probe());

    // The CA is materialised and the launch environment points at that exact
    // artifact — the combination AAASM-5276 found missing.
    let ca = PathBuf::from(CliTool::CA_PATH);
    assert!(plan.affected_artifacts().contains(&ca));
    let injects_ca = plan.steps.iter().any(|step| {
        matches!(
            &step.action,
            StepAction::InjectLaunchEnvironment { variable, value, .. }
                if variable == "NODE_EXTRA_CA_CERTS" && value == &EnvValue::ArtifactPath(ca.clone())
        )
    });
    assert!(injects_ca, "the plan must point the tool's runtime at the CA it wrote");

    // Every step that mutates something can be undone. The protection test is
    // the only step with no reversal, because it changes nothing.
    for step in plan.steps.iter().filter(|s| !s.action.is_protection_test()) {
        assert!(step.reversal.is_some(), "step {} has no reversal", step.id);
    }
}

#[tokio::test]
async fn the_ide_plan_is_capped_at_integrated_and_explains_why() {
    let plan = IdeHostedTool
        .plan_integration(&request(DevToolKind::GitHubCopilot, ProtectionProfile::Strict))
        .await
        .expect("planning must succeed");

    assert_eq!(plan.validate(), Ok(()));
    assert_eq!(plan.planned_level, ProtectionLevel::Integrated);
    assert!(!plan.has_interception_probe());

    let reasons: Vec<&str> = plan.unsupported.iter().map(|m| m.reason.as_str()).collect();
    assert!(
        reasons.iter().any(|r| r.contains("no launch command")),
        "the plan must carry the launch reason a user can act on: {reasons:?}"
    );
}

#[tokio::test]
async fn the_saas_plan_touches_nothing_local() {
    let plan = SaasTool
        .plan_integration(&request(
            DevToolKind::Custom("saas-agent".to_string()),
            ProtectionProfile::Recommended,
        ))
        .await
        .expect("planning must succeed");

    assert_eq!(plan.validate(), Ok(()));
    assert_eq!(plan.planned_level, ProtectionLevel::DetectedNotIntegrated);
    assert!(
        plan.affected_artifacts().is_empty(),
        "a SaaS tool has no local artifact to touch"
    );
    assert!(plan.steps.iter().all(|step| step.action.settings_scope().is_none()));
    assert_eq!(plan.unsupported.len(), 3);
}

#[tokio::test]
async fn observe_only_cannot_plan_protection_for_any_category() {
    // The profile clamps every category identically: monitoring is never
    // displayed as protection.
    let plan = CliTool
        .plan_integration(&request(DevToolKind::ClaudeCode, ProtectionProfile::ObserveOnly))
        .await
        .expect("planning must succeed");
    assert_eq!(plan.planned_level, ProtectionLevel::Integrated);
    assert_eq!(plan.validate(), Ok(()));
}

#[tokio::test]
async fn a_plan_that_over_claims_is_rejected_before_anything_runs() {
    // Same steps as the CLI plan, minus the probe: the claim no longer has a
    // way to be substantiated, and validation says so.
    let request = request(DevToolKind::ClaudeCode, ProtectionProfile::Recommended);
    let full = CliTool.plan_integration(&request).await.unwrap();
    let mut stripped = full.clone();
    stripped.steps.retain(|step| !step.action.is_protection_test());

    assert_eq!(full.validate(), Ok(()));
    assert!(matches!(
        stripped.validate(),
        Err(PlanError::UnsubstantiatedLevel { .. })
    ));
}

#[tokio::test]
async fn plans_serialize_and_render_for_review() {
    let plan = CliTool
        .plan_integration(&request(DevToolKind::ClaudeCode, ProtectionProfile::Recommended))
        .await
        .unwrap();

    let json = serde_json::to_string(&plan).expect("plans must be serializable");
    let restored: IntegrationPlan = serde_json::from_str(&json).expect("plans must round-trip");
    assert_eq!(restored, plan);

    let rendered = plan.render_dry_run();
    assert!(
        rendered.starts_with("integration plan cli-plan for ClaudeCode\n"),
        "{rendered}"
    );
    assert!(rendered.contains("  settings scope: user\n"), "{rendered}");
    assert!(rendered.contains("planned level: GatewayProtected"), "{rendered}");
    assert!(rendered.contains("unsupported:\n  - HostEnforcement:"), "{rendered}");
    // Every step is listed, numbered, with its flags.
    assert_eq!(rendered.matches("[required").count(), plan.required_steps().count());
}

#[tokio::test]
async fn status_reports_a_level_with_its_evidence_not_a_boolean() {
    let status = CliTool.integration_status(None).await.unwrap();
    // No receipt: a fully configured-looking host is still not integrated.
    assert_eq!(status.achieved_level(), ProtectionLevel::DetectedNotIntegrated);
    assert_eq!(status.phase, LifecyclePhase::DetectedNotIntegrated);
    // The evidence travels with the claim, split by how it was obtained.
    assert_eq!(status.exercised_evidence().count(), 1);
    assert_eq!(status.read_back_evidence().count(), 1);
}

#[tokio::test]
async fn verification_distinguishes_exercised_from_read_back_and_from_not_looking() {
    let receipt = sample_receipt();

    let cli = CliTool.verify_integration(&receipt).await.unwrap();
    assert!(cli.has_exercised_evidence());
    assert_eq!(
        cli.highest_justified_level(NOW, DEFAULT_FRESHNESS_WINDOW_SECS),
        ProtectionLevel::GatewayProtected
    );

    let ide = IdeHostedTool.verify_integration(&receipt).await.unwrap();
    assert!(!ide.has_exercised_evidence());
    assert_eq!(
        ide.highest_justified_level(NOW, DEFAULT_FRESHNESS_WINDOW_SECS),
        ProtectionLevel::Integrated,
        "read-back evidence alone can never justify a traffic claim"
    );

    let saas = SaasTool.verify_integration(&receipt).await.unwrap();
    assert!(matches!(saas.outcome, VerificationOutcome::Unverifiable { .. }));
    assert_eq!(
        saas.highest_justified_level(NOW, DEFAULT_FRESHNESS_WINDOW_SECS),
        ProtectionLevel::PartiallyIntegrated,
        "\"we did not look\" must not read as \"we looked and it was fine\""
    );
}

#[tokio::test]
async fn removal_is_derived_from_the_receipt_not_re_derived_from_the_host() {
    let receipt = sample_receipt();
    let plan = CliTool.plan_removal(&receipt).await.unwrap();
    assert_eq!(plan.validate(), Ok(()));
    assert_eq!(plan.steps.len(), receipt.reversal_actions().len());
    assert!(!plan.steps.is_empty());
}

#[tokio::test]
async fn the_launch_surface_carries_the_environment_interception_needs() {
    let launchable = CliTool.as_launchable().expect("this tool is launchable");
    let spec = LaunchSpec::new("agent-1")
        .with_args(vec!["--print".to_string()])
        .through_proxy("127.0.0.1:8080")
        .with_env("NODE_EXTRA_CA_CERTS", CliTool::CA_PATH);
    let command = launchable.build_launch_command(&spec).unwrap();

    let envs: Vec<(String, Option<String>)> = command
        .get_envs()
        .map(|(k, v)| {
            (
                k.to_string_lossy().into_owned(),
                v.map(|v| v.to_string_lossy().into_owned()),
            )
        })
        .collect();
    assert!(envs.contains(&("NODE_EXTRA_CA_CERTS".to_string(), Some(CliTool::CA_PATH.to_string()))));
    assert!(envs.contains(&("HTTPS_PROXY".to_string(), Some("127.0.0.1:8080".to_string()))));
}

#[tokio::test]
async fn the_mcp_surface_authors_a_step_rather_than_applying_one() {
    let mcp = CliTool.as_mcp_governed().expect("this tool is MCP-governed");
    assert_eq!(mcp.list_mcp_servers().await.unwrap().len(), 1);

    let step = mcp
        .plan_mcp_governance(&["filesystem".to_string()], &["shell".to_string()])
        .unwrap();
    match &step.action {
        StepAction::ConfigureMcpServers { allowed, denied } => {
            assert_eq!(allowed, &["filesystem".to_string()]);
            assert_eq!(denied, &["shell".to_string()]);
        }
        other => panic!("expected ConfigureMcpServers, got {other:?}"),
    }
}

#[tokio::test]
async fn an_incompatible_tool_version_is_reportable_rather_than_silently_degrading() {
    let supported = CliTool.version_support().supported_tool_versions;
    let too_old = supported.classify(Some(&ToolVersion::new(1, 9, 0)));
    assert!(too_old.is_incompatible());

    let state = StateDerivation {
        detected: true,
        receipt_present: true,
        required_steps: 1,
        required_steps_verified: 1,
        mismatched_artifacts: &[],
        compatibility: &too_old,
        schema_newer_than_core: false,
        evidence: &[],
        planned_level: ProtectionLevel::GatewayProtected,
        now_unix_secs: NOW,
        freshness_window_secs: DEFAULT_FRESHNESS_WINDOW_SECS,
    }
    .derive();

    match state {
        ProtectionState::Incompatible { remediation, .. } => {
            assert!(remediation.contains("upgrade"), "{remediation}");
        }
        other => panic!("expected Incompatible, got {other:?}"),
    }
}

/// A receipt shaped like one the service would have written for the CLI plan.
fn sample_receipt() -> IntegrationReceipt {
    use aa_devtool_contract::{ComponentVersions, StepReceipt};

    let step = IntegrationStep::new(
        "settings",
        StepAction::WriteManagedSettings {
            scope: SettingsScope::User,
            path: PathBuf::from("/home/dev/.claude/settings.json"),
            managed_keys: vec!["permissions".to_string()],
            content_sha256: "sha-settings".to_string(),
            merge: SettingsMerge::MergeManagedKeys,
            format: DocumentFormat::Json,
        },
        "write the managed settings block",
    )
    .with_reversal(StepAction::ManageArtifact {
        operation: ArtifactOperation::Remove,
        path: PathBuf::from("/home/dev/.claude/settings.json"),
    });

    IntegrationReceipt {
        schema_version: LIFECYCLE_SCHEMA_VERSION,
        receipt_id: "r1".to_string(),
        plan_id: "cli-plan".to_string(),
        tool: DevToolKind::ClaudeCode,
        profile: ProtectionProfile::Recommended,
        settings_scope: SettingsScope::User,
        applied_at_unix_secs: NOW,
        versions: ComponentVersions {
            core: ToolVersion::new(0, 0, 1),
            adapter: ToolVersion::new(0, 1, 0),
            lifecycle_schema: LIFECYCLE_SCHEMA_VERSION,
        },
        tool_version: Some(ToolVersion::new(2, 1, 220)),
        steps: vec![StepReceipt::applied(&step, Some("sha-settings".to_string()))],
        planned_level: ProtectionLevel::GatewayProtected,
        achieved_level: ProtectionLevel::GatewayProtected,
        achieved_evidence: vec![ProtectionEvidence::new(
            IntegrationCapability::ModelPathInterception,
            EvidenceKind::Exercised {
                outcome: ExerciseOutcome::Redacted,
            },
            NOW,
            "the synthetic secret was redacted before egress",
        )],
        verified_at_unix_secs: Some(NOW),
    }
}

#[test]
fn a_receipt_cannot_claim_protection_its_evidence_does_not_carry() {
    let good = sample_receipt();
    assert_eq!(good.validate(), Ok(()));

    // Swap the exercised interception evidence for a routing lever. Nothing else
    // changes — and the claim becomes unjustifiable.
    let mut routing = sample_receipt();
    routing.achieved_evidence = vec![ProtectionEvidence::new(
        IntegrationCapability::ModelGatewayBaseUrl,
        EvidenceKind::Exercised {
            outcome: ExerciseOutcome::Redacted,
        },
        NOW,
        "traffic was redirected to another base URL",
    )];
    assert!(routing.validate().is_err());
}
