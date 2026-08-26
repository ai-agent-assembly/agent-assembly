//! [`DevToolIntegration`] for the OpenAI Codex CLI — the native CA-trust plan
//! (AAASM-5856/AAASM-5917).
//!
//! # Why this is much smaller than `aa_devtool_claude_code::lifecycle`
//!
//! Claude Code's integration carries drift detection, an adjudicating
//! protection probe and bypass scanning (`aa_devtool_claude_code::{drift,
//! adjudicating_probe, bypass}`) because Claude Code has an endpoint-managed
//! settings surface and enough observable side channels to make those worth
//! building. Codex has neither: one configuration file
//! (`$HOME/.codex/config.json`), no endpoint-managed surface
//! ([`ProtectionLevel::HostEnforced`] is never reachable — see
//! [`CodexIntegration::capabilities`]), and this plan deliberately carries no
//! side-channel/MitM-hosts step. [`CodexIntegration::verify_integration`]
//! therefore has no adjudicating probe to run and reports
//! [`VerificationOutcome::Unverifiable`] for the model path rather than
//! building one — a probe that adjudicated nothing must never read as
//! protection (the same rule `UnadjudicatedProbe` encodes for Claude Code),
//! and a probe is not part of this ticket's scope. What this plan's launch
//! environment actually delivers is proven by the AAASM-5920 integration test,
//! which exercises the real proxy and its adjudication — not by anything this
//! adapter self-reports.
//!
//! # The CA mechanism this plan wires (AAASM-5856)
//!
//! Per `openai/codex`'s `codex-rs/http-client/src/custom_ca.rs`: Codex reads
//! `CODEX_CA_CERTIFICATE` first, falling back to `SSL_CERT_FILE` only when the
//! first is unset or empty, and is **additive** to the platform's built-in
//! roots (`add_root_certificate`, never `tls_built_in_root_certs(false)`) —
//! so a bare copy of the AA proxy CA PEM is the correct artifact, the same
//! shape `MaterialiseTrustMaterial` already produces for Claude Code. Only
//! `CODEX_CA_CERTIFICATE` is written; `SSL_CERT_FILE` is deliberately left
//! alone because it is the global OpenSSL variable and `build_launch_command`
//! sets env on the whole child process tree, including shell commands Codex's
//! sandbox runs — writing it there would replace every other TLS client's
//! default CA file for the session, not just Codex's.

use std::collections::BTreeMap;

use aa_devtool_contract::{
    now_unix_secs, sha256_hex, AdapterError, ArtifactObservation, ArtifactOperation, CapabilitySupport,
    DevToolCapabilities, DevToolInfo, DevToolIntegration, DevToolKind, EnvValue, EvidenceKind, GovernanceLevel,
    IntegrationCapability, IntegrationPlan, IntegrationReceipt, IntegrationRequest, IntegrationStatus, IntegrationStep,
    LaunchSpec, LaunchableTool, LifecyclePhase, NextLevel, PolicyPosture, ProbeDescriptor, ProtectionEvidence,
    ProtectionLevel, ProtectionProfile, ProtectionState, RemovalPlan, SettingsMerge, SettingsScope, StateDerivation,
    StepAction, StepExecutor, StepReceipt, SupportedToolVersions, ToolVersion, VerificationOutcome, VerificationResult,
    VersionCompatibility, VersionSupport, LIFECYCLE_SCHEMA_VERSION,
};
use async_trait::async_trait;

use crate::approval::{ApprovalLevel, ApprovalPolicy};
use crate::executor::CodexStepExecutor;
use crate::sandbox::CodexSandboxMode;
use crate::scope::{CodexPaths, ScopeError};
use crate::CodexAdapter;

const STEP_MANAGED_SETTINGS: &str = "managed-settings";
const STEP_PROXY_CA: &str = "proxy-ca";
const STEP_CA_CERTIFICATE: &str = "codex-ca-certificate";
const STEP_PROXY_ENV: &str = "proxy-env";
const STEP_PROTECTION_TEST: &str = "protection-test";

/// `CODEX_CA_CERTIFICATE` — Codex's own custom-CA environment variable. See the
/// module docs for why this is the only variable written.
const CA_ENV_VAR: &str = "CODEX_CA_CERTIFICATE";

// `allowed_domains`/`blocked_domains` are deliberately absent (AAASM-5856
// security review): `IntegrationRequest` carries a policy only by reference
// (ADR 0030 §5.5), so `managed_settings_json` has no `PolicyDocument` to
// derive a real list from — and `MergeManagedKeys` overwrites whatever is
// on disk with whatever key is present, so writing `[]` here would silently
// erase a real list a human (or a future policy-aware mechanism) had set.
// Codex's `Network-egress block` capability was already `L3`-in-name-only:
// the legacy `ApplyLegacyManagedSettings` step that used to derive these
// from the real policy has never been reachable through `FilesystemExecutor`
// (`aa-core/src/integration/engine.rs`'s `StepExecutor::apply` reports
// `Unsupported` for it), so this drops a key nothing was actually writing
// on the production install path — not a functional regression.
const MANAGED_KEYS: [&str; 2] = ["sandbox_mode", "approval_policy"];

const MODEL_HOST: &str = "api.openai.com";

/// The default local proxy address, matching
/// `aa_devtool_claude_code::lifecycle::DEFAULT_PROXY_ADDR`.
const DEFAULT_PROXY_ADDR: &str = "127.0.0.1:8899";

/// Lowest Codex CLI version this plan's launch environment can rely on.
///
/// `openai/codex` PR #14178 added `CODEX_CA_CERTIFICATE`/`SSL_CERT_FILE`
/// support for the login flow only; PR #14239 broadened it to every outbound
/// HTTPS and WebSocket client and moved the custom-CA code into
/// `custom_ca.rs` (both landed 2026-03-12 per the PR history). Neither PR's
/// merge commit could be mapped to a specific Codex CLI release from this
/// codebase alone — no `openai/codex` checkout or changelog is available
/// here. Secondary-source research (not the primary changelog) points to
/// v0.129.0 as the release where "a unified custom-CA subsystem covers every
/// outbound connection." This floor is therefore a **conservative,
/// moderate-confidence estimate**, not a verified pin — treat it as a
/// starting point for a follow-up ticket to confirm against the actual
/// `openai/codex` release notes, not as ground truth.
const CODEX_MIN_VERSION: &str = "0.129.0";

/// Native Codex integration: authors the plan that materialises the AA proxy
/// CA and injects [`CA_ENV_VAR`] into every governed launch (AAASM-5856).
pub struct CodexIntegration {
    paths: CodexPaths,
    adapter: CodexAdapter,
    proxy_url: String,
}

impl std::fmt::Debug for CodexIntegration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CodexIntegration")
            .field("proxy_url", &self.proxy_url)
            .finish_non_exhaustive()
    }
}

impl Default for CodexIntegration {
    fn default() -> Self {
        Self::new()
    }
}

impl CodexIntegration {
    /// The production integration: roots from the environment.
    pub fn new() -> Self {
        Self::with_paths(CodexPaths::from_env())
    }

    /// An integration over explicit roots. Tests use this so no test depends
    /// on the ambient `$HOME` or working directory.
    pub fn with_paths(paths: CodexPaths) -> Self {
        let mut adapter = CodexAdapter::default();
        if let Some(home) = paths.home() {
            adapter = adapter.with_home_dir(home.to_path_buf());
        }
        Self {
            paths,
            adapter,
            proxy_url: default_proxy_url(),
        }
    }

    /// Replace the detection adapter, so a test can pin the binary path and
    /// the version the probe reports.
    #[doc(hidden)]
    #[must_use]
    pub fn with_adapter(mut self, adapter: CodexAdapter) -> Self {
        self.adapter = adapter;
        self
    }

    /// Route the tool through a specific proxy.
    #[must_use]
    pub fn through_proxy(mut self, proxy_url: impl Into<String>) -> Self {
        self.proxy_url = proxy_url.into();
        self
    }

    /// The paths this integration reads and writes.
    pub fn paths(&self) -> &CodexPaths {
        &self.paths
    }

    /// An executor that knows every scope this integration can own, holding
    /// `rendered` for the steps that write bytes.
    ///
    /// Every scope rather than one, because observing and reversing start
    /// from a receipt and not from a plan: the service has no scope in hand
    /// at those moments.
    pub fn scoped_executor(&self, rendered: BTreeMap<String, String>) -> CodexStepExecutor {
        let mut executor = CodexStepExecutor::new();
        for scope in [SettingsScope::User, SettingsScope::Project, SettingsScope::Managed] {
            if let Ok(dir) = self.paths.launch_env_dir(scope) {
                executor = executor.with_scope(scope, dir);
            }
        }
        for (step_id, content) in rendered {
            executor = executor.with_content(step_id, content);
        }
        executor
    }

    /// The bytes each of `plan`'s steps writes, keyed by step id.
    ///
    /// Re-derived at apply time rather than carried in the plan: the digest
    /// the user reviewed is what the executor checks against.
    pub fn step_content(&self, plan: &IntegrationPlan) -> Result<BTreeMap<String, String>, AdapterError> {
        let mut rendered = BTreeMap::new();
        for step in &plan.steps {
            match &step.action {
                StepAction::WriteManagedSettings { .. } => {
                    rendered.insert(step.id.clone(), managed_settings_json(plan.profile)?);
                }
                StepAction::MaterialiseTrustMaterial { .. } => {
                    rendered.insert(step.id.clone(), self.read_ca_pem()?);
                }
                _ => {}
            }
        }
        Ok(rendered)
    }

    fn read_ca_pem(&self) -> Result<String, AdapterError> {
        let path = self.paths.ca_source().ok_or_else(|| {
            AdapterError::SettingsGenerationFailed(
                "the Agent Assembly proxy certificate authority has not been created on this host".to_string(),
            )
        })?;
        std::fs::read_to_string(path).map_err(AdapterError::SettingsApplyFailed)
    }

    fn detected_version(&self) -> Option<ToolVersion> {
        use aa_devtool_contract::DevToolAdapter as _;
        self.adapter.detect()?.version?.parse().ok()
    }

    fn compatibility(&self) -> VersionCompatibility {
        self.version_support()
            .supported_tool_versions
            .classify(self.detected_version().as_ref())
    }

    /// Every launch-environment step's evidence, read back from disk and
    /// compared against the receipt.
    ///
    /// Mirrors `ClaudeCodeIntegration::read_back_evidence`: `observe` is
    /// generic over `StepExecutor`, so the same logic applies unchanged.
    fn read_back_evidence(&self, receipt: &IntegrationReceipt, now: u64) -> Vec<ProtectionEvidence> {
        let executor = self.scoped_executor(BTreeMap::new());
        receipt
            .steps
            .iter()
            .filter(|step| step.applied && step.fingerprint.is_some())
            .map(|step| {
                let expected = step.fingerprint.as_deref().unwrap_or_default();
                let (matches, detail) = match executor.observe(step) {
                    ArtifactObservation::Present {
                        managed_fingerprint, ..
                    } => (
                        managed_fingerprint == expected,
                        format!("{} read back from the host", artifact_label(step)),
                    ),
                    ArtifactObservation::Missing => (false, format!("{} is missing", artifact_label(step))),
                    ArtifactObservation::Unreadable { reason } => {
                        (false, format!("{} could not be read: {reason}", artifact_label(step)))
                    }
                    other => (
                        false,
                        format!(
                            "{} returned an observation this build cannot read: {other:?}",
                            artifact_label(step)
                        ),
                    ),
                };
                ProtectionEvidence::new(
                    step_mechanism(&step.action),
                    EvidenceKind::ReadBack {
                        matches_receipt: matches,
                    },
                    now,
                    detail,
                )
            })
            .collect()
    }
}

#[async_trait]
impl DevToolIntegration for CodexIntegration {
    fn capabilities(&self) -> DevToolCapabilities {
        let interception = match self.paths.ca_source() {
            Some(_) => CapabilitySupport::Supported,
            None => CapabilitySupport::unsupported(
                "the Agent Assembly proxy certificate authority has not been created on this host, so \
                 Codex cannot be made to trust the intercepting proxy. Start the proxy once \
                 (`aasm proxy start`) and plan again",
            ),
        };

        DevToolCapabilities::new()
            .supported(IntegrationCapability::Discovery)
            .supported(IntegrationCapability::ManagedSettings)
            .supported(IntegrationCapability::ManagedLaunch)
            .supported(IntegrationCapability::HttpProxy)
            .declare(IntegrationCapability::ModelPathInterception, interception)
            .unsupported(
                IntegrationCapability::ModelGatewayBaseUrl,
                "Codex exposes no configurable model base-URL override this adapter renders; nothing here \
                 routes its traffic by base URL",
            )
            .unsupported(
                IntegrationCapability::Hooks,
                "the Codex CLI exposes no installable hook surface",
            )
            .unsupported(
                IntegrationCapability::McpDiscovery,
                "DevToolInfo::supports_mcp is false for Codex — it exposes no MCP server list",
            )
            .unsupported(
                IntegrationCapability::McpGovernance,
                "Codex exposes no MCP surface to govern",
            )
            .unsupported(
                IntegrationCapability::ToolActionApproval,
                "approval_policy is written into managed settings as part of ManagedSettings; nothing \
                 here independently verifies Codex honours a per-call approval decision",
            )
            .unsupported(
                IntegrationCapability::NativeIdeUi,
                "the Codex CLI is a terminal tool with no in-editor surface for status or approval prompts",
            )
            .unsupported(
                IntegrationCapability::HostEnforcement,
                "Codex has no endpoint-managed settings surface this adapter can address, so \
                 ProtectionLevel::HostEnforced is never reachable for it",
            )
    }

    fn detect(&self) -> Option<DevToolInfo> {
        use aa_devtool_contract::DevToolAdapter as _;
        self.adapter.detect()
    }

    fn version_support(&self) -> VersionSupport {
        VersionSupport {
            adapter_version: env!("CARGO_PKG_VERSION").parse().unwrap_or(ToolVersion::new(0, 0, 0)),
            lifecycle_schema_version: LIFECYCLE_SCHEMA_VERSION,
            supported_tool_versions: SupportedToolVersions::at_least(
                CODEX_MIN_VERSION.parse().unwrap_or(ToolVersion::new(0, 0, 0)),
            ),
        }
    }

    async fn plan_integration(&self, request: &IntegrationRequest) -> Result<IntegrationPlan, AdapterError> {
        let scope = request.settings_scope;
        let settings_path = self.paths.settings_path().map_err(scope_error)?;
        let launch_env = self.paths.launch_env_dir(scope).map_err(scope_error)?;
        let ca_pem = self.paths.proxy_ca_pem(scope).map_err(scope_error)?;
        let capabilities = self.capabilities();

        let interception_available = capabilities.is_effective(IntegrationCapability::ModelPathInterception);
        // Never HostEnforced — Codex has no endpoint-managed settings surface
        // this adapter can address (see `capabilities`).
        let ceiling = if interception_available {
            ProtectionLevel::GatewayProtected
        } else {
            ProtectionLevel::Integrated
        };
        let planned_level = request.effective_target_level().min(ceiling);

        let mut plan = IntegrationPlan::new(
            format!("codex-{scope}-{}", now_unix_secs()),
            request,
            planned_level,
            GovernanceLevel::L2Enforce,
        );

        // 1. Managed settings — sandbox_mode / approval_policy in
        //    $HOME/.codex/config.json. Unlike Claude Code there is no
        //    privileged endpoint-managed variant: Codex has one configuration
        //    surface, and it is always the developer's own file. Domain
        //    lists are not written here — see the `MANAGED_KEYS` comment.
        let settings = managed_settings_json(request.profile)?;
        plan = plan.with_step(IntegrationStep::new(
            STEP_MANAGED_SETTINGS,
            StepAction::WriteManagedSettings {
                scope,
                path: settings_path.clone(),
                managed_keys: MANAGED_KEYS.iter().map(|k| (*k).to_string()).collect(),
                content_sha256: sha256_hex(&settings),
                merge: SettingsMerge::MergeManagedKeys,
            },
            format!(
                "merge Agent Assembly's four managed keys into {} and leave every other key alone",
                settings_path.display()
            ),
        ));

        if interception_available {
            // 2. Trust material — a copy of the AA proxy CA. Must precede step
            //    3: Codex fails closed on an unreadable/unparseable CA bundle
            //    before any network traffic (custom_ca.rs), so the file has to
            //    exist before CODEX_CA_CERTIFICATE points at it.
            let pem = self.read_ca_pem()?;
            plan = plan.with_step(
                IntegrationStep::new(
                    STEP_PROXY_CA,
                    StepAction::MaterialiseTrustMaterial {
                        kind: aa_devtool_contract::TrustMaterialKind::ProxyCaCertificatePem,
                        path: ca_pem.clone(),
                        content_sha256: sha256_hex(&pem),
                    },
                    format!(
                        "copy the Agent Assembly proxy certificate authority to {} so Codex can be pointed \
                         at it without touching the system trust store",
                        ca_pem.display()
                    ),
                )
                .with_reversal(StepAction::ManageArtifact {
                    operation: ArtifactOperation::Remove,
                    path: ca_pem.clone(),
                }),
            );

            // 3. CODEX_CA_CERTIFICATE — see the module docs for why this is the
            //    only variable written (not SSL_CERT_FILE).
            plan = plan.with_step(
                IntegrationStep::new(
                    STEP_CA_CERTIFICATE,
                    StepAction::InjectLaunchEnvironment {
                        scope,
                        variable: CA_ENV_VAR.to_string(),
                        value: EnvValue::ArtifactPath(ca_pem.clone()),
                    },
                    format!(
                        "set {CA_ENV_VAR} for every governed Codex launch so its reqwest/rustls clients \
                         accept the intercepting proxy's certificates — without this the MitM handshake \
                         fails and nothing is inspected"
                    ),
                )
                .with_reversal(StepAction::ManageArtifact {
                    operation: ArtifactOperation::Remove,
                    path: launch_env.join(CA_ENV_VAR),
                }),
            );

            // 4. Proxy routing.
            let mut variables = BTreeMap::new();
            variables.insert("HTTPS_PROXY".to_string(), self.proxy_url.clone());
            variables.insert("HTTP_PROXY".to_string(), self.proxy_url.clone());
            plan = plan.with_step(
                IntegrationStep::new(
                    STEP_PROXY_ENV,
                    StepAction::ConfigureProxy {
                        scope,
                        variables: variables.clone(),
                    },
                    format!("route governed Codex launches through {}", self.proxy_url),
                )
                .with_reversal(StepAction::ConfigureProxy {
                    scope,
                    variables: BTreeMap::new(),
                }),
            );

            // Deliberately no side-channel/MitM-hosts step here (Claude Code's
            // equivalent step 5): this plan's only claim is the model-bound
            // path through CODEX_CA_CERTIFICATE, and Codex's own telemetry/
            // registry side channels are out of this ticket's scope.

            // 5. The protection test. Optional and inert at apply time — see
            //    the module docs for why this integration has no adjudicating
            //    probe to run it with. Its presence is what lets `planned_level`
            //    reach GatewayProtected at all: `IntegrationPlan::validate`
            //    requires a protection-test step for any level at or above it,
            //    on the theory that routing traffic elsewhere is not evidence
            //    that anything inspected it.
            plan = plan.with_step(
                IntegrationStep::new(
                    STEP_PROTECTION_TEST,
                    StepAction::RunProtectionTest {
                        probe: ProbeDescriptor {
                            id: "codex-model-path".to_string(),
                            mechanism: IntegrationCapability::ModelPathInterception,
                            description: format!(
                                "send a synthetic OpenAI-shaped secret down the {MODEL_HOST} path and let \
                                 the core adjudicate what the provider received"
                            ),
                        },
                    },
                    "verify that the model path is actually intercepted, not merely configured",
                )
                .optional(),
            );
        } else {
            plan = plan.declaring_unsupported(
                IntegrationCapability::ModelPathInterception,
                capabilities
                    .unsupported_reason(IntegrationCapability::ModelPathInterception)
                    .unwrap_or("model-path interception is unavailable on this host")
                    .to_string(),
            );
        }

        for capability in [
            IntegrationCapability::ModelGatewayBaseUrl,
            IntegrationCapability::Hooks,
            IntegrationCapability::McpDiscovery,
            IntegrationCapability::McpGovernance,
            IntegrationCapability::ToolActionApproval,
            IntegrationCapability::NativeIdeUi,
            IntegrationCapability::HostEnforcement,
        ] {
            if let Some(reason) = capabilities.unsupported_reason(capability) {
                plan = plan.declaring_unsupported(capability, reason.to_string());
            }
        }

        plan = plan
            .warn(
                "protection applies to sessions started through `aasm run codex`. A `codex` started \
                 directly inherits neither the proxy nor CODEX_CA_CERTIFICATE, and is not protected"
                    .to_string(),
            )
            .warn(
                "this integration has no adjudicating protection probe: the protection-test step is \
                 optional and inert, and `verify` reports the model path as unverifiable rather than \
                 exercised. Coverage for the launch environment comes from the AAASM-5920 integration \
                 test, not from this adapter's own verification"
                    .to_string(),
            )
            .warn("restart any running Codex session for the managed settings to take effect".to_string());

        Ok(plan)
    }

    async fn integration_status(
        &self,
        receipt: Option<&IntegrationReceipt>,
    ) -> Result<IntegrationStatus, AdapterError> {
        let now = now_unix_secs();
        let detected = self.detect();
        let compatibility = self.compatibility();

        let mut evidence: Vec<ProtectionEvidence> = Vec::new();
        if let Some(receipt) = receipt {
            evidence.extend(self.read_back_evidence(receipt, now));
            evidence.push(ProtectionEvidence::new(
                IntegrationCapability::ModelPathInterception,
                EvidenceKind::Absent {
                    reason: "this integration has no adjudicating protection probe; the model path is \
                             never reported as exercised"
                        .to_string(),
                },
                now,
                "the model path is configured but this adapter cannot exercise it".to_string(),
            ));
        }

        let planned_level = receipt.map_or(ProtectionLevel::NotInstalled, |r| r.planned_level);
        let derivation = StateDerivation {
            detected: detected.is_some(),
            receipt_present: receipt.is_some(),
            required_steps: receipt.map_or(0, IntegrationReceipt::required_steps),
            required_steps_verified: receipt.map_or(0, IntegrationReceipt::verified_required_steps),
            mismatched_artifacts: &[],
            compatibility: &compatibility,
            schema_newer_than_core: receipt.is_some_and(IntegrationReceipt::is_schema_newer_than_running_core),
            evidence: &evidence,
            planned_level,
            now_unix_secs: now,
            freshness_window_secs: aa_devtool_contract::DEFAULT_FRESHNESS_WINDOW_SECS,
        };
        let state = derivation.derive();

        let phase = match (&state, receipt) {
            (ProtectionState::Ladder(ProtectionLevel::NotInstalled), _) => LifecyclePhase::NotInstalled,
            (_, None) => LifecyclePhase::DetectedNotIntegrated,
            (_, Some(r)) if r.verified_required_steps() >= r.required_steps() && r.required_steps() > 0 => {
                LifecyclePhase::Installed
            }
            (_, Some(_)) => LifecyclePhase::PartiallyInstalled,
        };

        let achieved = state.achieved_level();
        let next_level = achieved.next_up().map(|level| NextLevel {
            level,
            blocked_because: next_level_reason(level, receipt.is_some()),
        });

        Ok(IntegrationStatus {
            tool: DevToolKind::Codex,
            phase,
            state,
            evidence,
            planned_level,
            adapter_ceiling: detected.map_or(GovernanceLevel::L0Discover, |i| i.governance_level),
            compatibility,
            next_level,
            observed_at_unix_secs: now,
            policy: PolicyPosture::Unknown {
                reason: "not resolved by the adapter".to_string(),
            },
        })
    }

    async fn verify_integration(&self, receipt: &IntegrationReceipt) -> Result<VerificationResult, AdapterError> {
        let now = now_unix_secs();
        let evidence = self.read_back_evidence(receipt, now);
        let mismatched: Vec<String> = evidence
            .iter()
            .filter(|e| matches!(e.kind, EvidenceKind::ReadBack { matches_receipt: false }))
            .map(|e| e.detail.clone())
            .collect();

        // No adjudicating probe — see the module docs. `Unverifiable` is the
        // documented contract for an adapter with no verification mechanism,
        // and is distinct from `Passed`: "we did not look" must never read as
        // "we looked and it was fine".
        let outcome = if !mismatched.is_empty() {
            VerificationOutcome::Failed {
                reason: format!(
                    "Agent Assembly-owned state no longer matches the receipt: {}",
                    mismatched.join("; ")
                ),
            }
        } else {
            VerificationOutcome::Unverifiable {
                reason: "this integration has no adjudicating protection probe to exercise the model \
                         path with; what the launch environment delivers is measured by the AAASM-5920 \
                         integration test, not by this adapter's own verification"
                    .to_string(),
            }
        };

        Ok(VerificationResult {
            verified_at_unix_secs: now,
            outcome,
            evidence,
        })
    }

    async fn plan_removal(&self, receipt: &IntegrationReceipt) -> Result<RemovalPlan, AdapterError> {
        let mut plan = RemovalPlan::new(removal_plan_id(receipt), DevToolKind::Codex);

        for step in receipt
            .steps
            .iter()
            .rev()
            .filter(|s| s.applied && !s.action.is_protection_test())
        {
            let summary = match &step.action {
                StepAction::WriteManagedSettings { path, .. } => format!(
                    "restore the four Agent Assembly-owned keys in {} to what they held before install, \
                     and leave everything you changed since alone",
                    path.display()
                ),
                StepAction::MaterialiseTrustMaterial { path, .. } => {
                    format!("delete the copied proxy certificate authority at {}", path.display())
                }
                StepAction::InjectLaunchEnvironment { variable, .. } => {
                    format!("stop injecting {variable} into governed launches")
                }
                StepAction::ConfigureProxy { .. } => {
                    "stop routing governed Codex launches through the Agent Assembly proxy".to_string()
                }
                StepAction::ManageArtifact { path, .. } => format!("delete {}", path.display()),
                other => format!("reverse the {} step", other.kind()),
            };
            let reversal = step.reversal.clone().unwrap_or_else(|| reversal_for(step));
            plan = plan.with_step(IntegrationStep::new(
                format!("undo-{}", step.step_id),
                reversal,
                summary,
            ));
        }

        for step in receipt.unrestorable_steps() {
            plan = plan.with_residual(format!(
                "{}: this step recorded no restorable prior state, so removal cannot prove it put \
                 anything back",
                artifact_label(step)
            ));
        }

        plan = plan
            .warn(
                "restore is semantics-exact, not byte-exact: the settings document is reserialised, so \
                 formatting and key order from before the install do not come back"
                    .to_string(),
            )
            .warn("restart any running Codex session for the removal to take effect".to_string());

        Ok(plan)
    }

    fn as_launchable(&self) -> Option<&dyn LaunchableTool> {
        Some(self)
    }
}

impl LaunchableTool for CodexIntegration {
    /// Build the governed launch — where `CODEX_CA_CERTIFICATE` actually
    /// reaches the tool.
    ///
    /// The launch environment the install materialised is applied first, then
    /// the caller's own [`LaunchSpec::env`], so a caller can override a
    /// variable for one run without editing what the receipt records.
    ///
    /// ADR 0036 D6: this method has **no production caller today** — `aasm run
    /// codex` reaches the tool via `CodexAdapter::build_launch_command` (the
    /// `self.adapter.build_launch_command` call below), which the outer
    /// `aa-cli::spawn_and_wait`/`effective_child_env` boundary already
    /// sanitizes (D6 review #8: that is the one real spawn). Do NOT add an
    /// `env_remove` here defensively — see the identical note on
    /// `ClaudeCodeIntegration::build_launch_command` for why duplicating
    /// removal without a confirmed real caller repeats a mistake ADR 0036's
    /// review process already corrected once.
    fn build_launch_command(&self, spec: &LaunchSpec) -> Result<std::process::Command, AdapterError> {
        use aa_devtool_contract::DevToolAdapter as _;
        let mut cmd =
            self.adapter
                .build_launch_command(&spec.tool_args, &spec.agent_id, spec.team_id.as_deref(), None)?;
        for (name, value) in crate::launch_env::installed_environment(&self.paths) {
            cmd.env(name, value);
        }

        // A proxy address the caller pinned for this run wins over the
        // receipted one, matching ClaudeCodeIntegration.
        if let Some(proxy) = &spec.proxy_addr {
            let url = if proxy.starts_with("http") {
                proxy.clone()
            } else {
                format!("http://{proxy}")
            };
            cmd.env("HTTPS_PROXY", &url);
            cmd.env("HTTP_PROXY", &url);
        }
        for (name, value) in &spec.env {
            cmd.env(name, value);
        }
        Ok(cmd)
    }
}

/// The managed settings block one profile resolves to.
///
/// Derived from the **profile**, not from a full policy document: a plan
/// carries a policy only by reference (ADR 0030 §5.5), mirroring
/// `aa_devtool_claude_code::lifecycle::managed_settings_json`. Deliberately
/// omits `allowed_domains`/`blocked_domains` — see the `MANAGED_KEYS`
/// comment for why a policy-derived list can't be produced here, and why
/// writing an empty one would be worse than omitting the key.
pub fn managed_settings_json(profile: ProtectionProfile) -> Result<String, AdapterError> {
    let (sandbox_mode, approval) = match profile {
        ProtectionProfile::Strict => (
            CodexSandboxMode::Ask,
            ApprovalPolicy {
                file_writes: ApprovalLevel::Prompt,
                shell_exec: ApprovalLevel::Prompt,
                network: ApprovalLevel::Prompt,
                mcp_calls: ApprovalLevel::Prompt,
            },
        ),
        ProtectionProfile::Recommended | ProtectionProfile::ObserveOnly => (
            CodexSandboxMode::Suggest,
            ApprovalPolicy {
                file_writes: ApprovalLevel::Auto,
                shell_exec: ApprovalLevel::Prompt,
                network: ApprovalLevel::Auto,
                mcp_calls: ApprovalLevel::Auto,
            },
        ),
    };
    let doc = serde_json::json!({
        "sandbox_mode": sandbox_mode,
        "approval_policy": approval,
    });
    serde_json::to_string(&doc).map_err(|e| AdapterError::SettingsGenerationFailed(e.to_string()))
}

fn scope_error(e: ScopeError) -> AdapterError {
    AdapterError::SettingsGenerationFailed(e.to_string())
}

fn default_proxy_url() -> String {
    let addr = std::env::var("AA_PROXY_ADDR")
        .ok()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| DEFAULT_PROXY_ADDR.to_string());
    if addr.starts_with("http://") || addr.starts_with("https://") {
        addr
    } else {
        format!("http://{addr}")
    }
}

fn step_mechanism(action: &StepAction) -> IntegrationCapability {
    match action {
        StepAction::WriteManagedSettings { .. } => IntegrationCapability::ManagedSettings,
        StepAction::MaterialiseTrustMaterial { .. } | StepAction::InjectLaunchEnvironment { .. } => {
            IntegrationCapability::ModelPathInterception
        }
        StepAction::ConfigureProxy { .. } => IntegrationCapability::HttpProxy,
        _ => IntegrationCapability::ManagedSettings,
    }
}

/// A stable, user-legible name for what a step touched, mirroring
/// `aa_devtool_claude_code::lifecycle::artifact_label`.
fn artifact_label(step: &StepReceipt) -> String {
    match &step.action {
        StepAction::InjectLaunchEnvironment { variable, .. } => format!("{variable} (launch environment)"),
        StepAction::ConfigureProxy { variables, .. } => {
            format!(
                "{} (launch environment)",
                variables.keys().cloned().collect::<Vec<_>>().join(", ")
            )
        }
        other => match other.affected_paths().first() {
            Some(path) => path.display().to_string(),
            None => format!("{} ({})", step.step_id, other.kind()),
        },
    }
}

fn next_level_reason(level: ProtectionLevel, installed: bool) -> String {
    match level {
        ProtectionLevel::HostEnforced => {
            "host enforcement is not reachable: Codex has no endpoint-managed settings surface".to_string()
        }
        ProtectionLevel::GatewayProtected => "this integration has no adjudicating protection probe; run \
                                               the AAASM-5920 integration test's launch to measure the \
                                               model path directly"
            .to_string(),
        _ if !installed => "nothing has been applied yet; run `aasm integrations install codex`".to_string(),
        _ => "not every required step of the applied plan verifies; run `aasm integrations repair codex`".to_string(),
    }
}

fn reversal_for(step: &StepReceipt) -> StepAction {
    match &step.action {
        StepAction::WriteManagedSettings {
            scope,
            path,
            managed_keys,
            merge,
            ..
        } => StepAction::WriteManagedSettings {
            scope: *scope,
            path: path.clone(),
            managed_keys: managed_keys.clone(),
            content_sha256: step
                .prior_state
                .as_ref()
                .map(|prior| prior.document_fingerprint.trim_start_matches("sha256:").to_string())
                .unwrap_or_default(),
            merge: *merge,
        },
        other => other.clone(),
    }
}

/// A stable identifier for a removal plan derived from `receipt`.
pub fn removal_plan_id(receipt: &IntegrationReceipt) -> String {
    format!("remove-{}", receipt.receipt_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aa_devtool_contract::{capability_conformance, DevToolKind, IntegrationRequest};

    fn integration(dir: &std::path::Path) -> CodexIntegration {
        let ca_dir = dir.join("ca");
        std::fs::create_dir_all(&ca_dir).unwrap();
        std::fs::write(ca_dir.join("ca-cert.pem"), "-----BEGIN CERTIFICATE-----\n").unwrap();
        let paths = CodexPaths::default()
            .with_home(dir.join("home"))
            .with_state(dir.join("state"))
            .with_ca_source(ca_dir.join("ca-cert.pem"));
        CodexIntegration::with_paths(paths)
    }

    fn request() -> IntegrationRequest {
        IntegrationRequest::new(DevToolKind::Codex, ProtectionProfile::Recommended, SettingsScope::User)
    }

    /// AAASM-5917's declared surface never disagrees with what it implements.
    #[test]
    fn capabilities_are_conformant() {
        let dir = tempfile::tempdir().unwrap();
        let integration = integration(dir.path());
        assert!(
            capability_conformance(&integration).is_empty(),
            "{:?}",
            capability_conformance(&integration)
        );
    }

    #[tokio::test]
    async fn plan_with_a_ca_source_reaches_gateway_protected_and_carries_four_steps_plus_a_probe() {
        let dir = tempfile::tempdir().unwrap();
        let integration = integration(dir.path());
        let plan = integration.plan_integration(&request()).await.unwrap();

        assert_eq!(plan.planned_level, ProtectionLevel::GatewayProtected);
        let ids: Vec<&str> = plan.steps.iter().map(|s| s.id.as_str()).collect();
        assert_eq!(
            ids,
            vec![
                STEP_MANAGED_SETTINGS,
                STEP_PROXY_CA,
                STEP_CA_CERTIFICATE,
                STEP_PROXY_ENV,
                STEP_PROTECTION_TEST,
            ]
        );
        // Trust material must precede the env injection that points at it —
        // Codex fails closed on an unreadable CA bundle before any traffic.
        let ca_index = ids.iter().position(|id| *id == STEP_PROXY_CA).unwrap();
        let env_index = ids.iter().position(|id| *id == STEP_CA_CERTIFICATE).unwrap();
        assert!(ca_index < env_index);
        plan.validate()
            .expect("a GatewayProtected plan needs a protection-test step, and this carries one");
    }

    #[tokio::test]
    async fn only_codex_ca_certificate_is_injected_never_ssl_cert_file() {
        let dir = tempfile::tempdir().unwrap();
        let integration = integration(dir.path());
        let plan = integration.plan_integration(&request()).await.unwrap();

        let injected: Vec<&String> = plan
            .steps
            .iter()
            .filter_map(|s| match &s.action {
                StepAction::InjectLaunchEnvironment { variable, .. } => Some(variable),
                _ => None,
            })
            .collect();
        assert_eq!(injected, vec![&CA_ENV_VAR.to_string()]);
    }

    #[tokio::test]
    async fn without_a_ca_source_the_plan_stays_at_integrated_and_declares_interception_unsupported() {
        let dir = tempfile::tempdir().unwrap();
        // No CA file written this time.
        let paths = CodexPaths::default()
            .with_home(dir.path().join("home"))
            .with_state(dir.path().join("state"))
            .with_ca_source(dir.path().join("ca").join("ca-cert.pem"));
        let integration = CodexIntegration::with_paths(paths);
        let plan = integration.plan_integration(&request()).await.unwrap();

        assert_eq!(plan.planned_level, ProtectionLevel::Integrated);
        assert!(plan
            .unsupported
            .iter()
            .any(|u| u.capability == IntegrationCapability::ModelPathInterception));
        assert!(plan.steps.iter().all(|s| !matches!(
            s.action,
            StepAction::MaterialiseTrustMaterial { .. } | StepAction::InjectLaunchEnvironment { .. }
        )));
    }

    #[tokio::test]
    async fn host_enforced_is_never_the_ceiling() {
        let dir = tempfile::tempdir().unwrap();
        let integration = integration(dir.path());
        let mut req = request();
        req.requested_level = ProtectionLevel::HostEnforced;
        let plan = integration.plan_integration(&req).await.unwrap();
        assert_eq!(
            plan.planned_level,
            ProtectionLevel::GatewayProtected,
            "Codex has no endpoint-managed settings surface, so HostEnforced is never reachable"
        );
    }
}
