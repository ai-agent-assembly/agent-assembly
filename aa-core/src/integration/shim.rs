//! Lets any pre-lifecycle [`DevToolAdapter`] satisfy the new contract without
//! being rewritten.
//!
//! # Why a shim rather than an edit to `DevToolAdapter`
//!
//! ADR 0030 §7 makes migration additive: `DevToolAdapter` is retained unchanged
//! for the whole migration, and the bridge is a separate generic type. Because
//! [`LegacyAdapterShim`] is generic over *any* `DevToolAdapter`, every existing
//! adapter — including the public `examples/aa-devtool-sample-myeditor`, and
//! including out-of-tree adapters this repo has never seen — keeps compiling and
//! gains a working lifecycle on the day the contract lands. Nothing breaks; a
//! third party migrates when they choose to.
//!
//! # What the shim deliberately refuses to claim
//!
//! A legacy adapter can substantiate exactly two things: it can detect
//! ([`detect`](DevToolAdapter::detect)) and it can render and write managed
//! settings ([`generate_managed_settings`](DevToolAdapter::generate_managed_settings)
//! and [`apply_settings`](DevToolAdapter::apply_settings)).
//!
//! Everything else the old trait exposes is either unverifiable or a documented
//! no-op: `apply_mcp_governance` returns `Ok(())` for tools without MCP, and
//! `build_launch_command` returns a run-time error for tools that cannot be
//! launched — so the shim cannot tell a working mechanism from a stub, and it
//! declares neither. Every other capability is
//! [`Unsupported`](super::CapabilitySupport::Unsupported) with a reason naming
//! the migration, which reads honestly to a user and shows up in the plan's
//! dry-run output.
//!
//! Consequently a shimmed adapter can never plan
//! [`GatewayProtected`](super::ProtectionLevel::GatewayProtected): it declares no
//! interception mechanism and authors no protection test, so the level it claims
//! is capped at [`Integrated`](super::ProtectionLevel::Integrated) and the plan
//! carries a warning saying so.

use std::fmt::Write as _;

use sha2::{Digest, Sha256};

use crate::dev_tool::{AdapterError, DevToolAdapter, DevToolInfo, DevToolKind};
use crate::policy::PolicyDocument;

use super::caller_env::CallerEnvironment;
use super::capability::{DevToolCapabilities, IntegrationCapability};
use super::plan::{IntegrationPlan, IntegrationRequest, RemovalPlan};
use super::policy_posture::PolicyPosture;
use super::receipt::IntegrationReceipt;
use super::state::{
    EvidenceKind, ProtectionEvidence, ProtectionLevel, ProtectionState, StateDerivation, DEFAULT_FRESHNESS_WINDOW_SECS,
};
use super::status::{IntegrationStatus, LifecyclePhase, NextLevel, VerificationResult};
use super::step::{IntegrationStep, StepAction};
use super::version::{SupportedToolVersions, ToolVersion, VersionSupport, LIFECYCLE_SCHEMA_VERSION};
use super::{now_unix_secs, DevToolIntegration};

/// The reason every unsubstantiated capability of a shimmed adapter carries.
///
/// Deliberately the same sentence everywhere so a user (and a `grep`) can tell
/// "this tool cannot do it" from "this adapter has not been migrated yet".
pub const LEGACY_UNSUPPORTED_REASON: &str =
    "legacy adapter — not migrated to the Developer Integration lifecycle (ADR 0030 §7)";

/// Hex-encoded SHA-256, used for the shim's content fingerprint.
fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// Bridges a pre-lifecycle [`DevToolAdapter`] onto [`DevToolIntegration`].
///
/// The policy document is supplied at construction rather than carried on
/// [`IntegrationRequest`]: the legacy trait needs a whole
/// [`PolicyDocument`] to render settings, and putting one on the request type
/// would create a field an untrusted caller could populate. The service resolves
/// the profile inside the trust boundary and hands the resolved document to the
/// shim (ADR 0030 matrix row 6).
pub struct LegacyAdapterShim<A: DevToolAdapter> {
    kind: DevToolKind,
    adapter: A,
    policy: PolicyDocument,
    version_support: VersionSupport,
}

impl<A: DevToolAdapter> LegacyAdapterShim<A> {
    /// Wrap `adapter`, which governs the tool identified by `kind`, rendering
    /// settings from `policy`.
    ///
    /// `kind` is explicit rather than derived from
    /// [`detect`](DevToolAdapter::detect) because detection returns `None` on a
    /// host where the tool is absent, and the lifecycle still has to be able to
    /// name the tool it is reporting `NotInstalled` for.
    pub fn new(kind: DevToolKind, adapter: A, policy: PolicyDocument) -> Self {
        Self {
            kind,
            adapter,
            policy,
            // A legacy adapter declares no version range of its own, so the shim
            // declares an unbounded one and lets the resulting
            // `Unknown`/`Compatible` classification flow through the normal state
            // derivation. It must be genuinely unbounded rather than `>= 0.0.0`:
            // a pre-release sorts below its release, so `0.0.0` would reject the
            // public sample's own `0.0.0-sample`.
            version_support: VersionSupport {
                adapter_version: super::version::core_version(),
                lifecycle_schema_version: LIFECYCLE_SCHEMA_VERSION,
                supported_tool_versions: SupportedToolVersions::any(),
            },
        }
    }

    /// Override the version range the shim reports, for a legacy adapter whose
    /// supported range is known out of band.
    #[must_use]
    pub fn with_version_support(mut self, version_support: VersionSupport) -> Self {
        self.version_support = version_support;
        self
    }

    /// The wrapped adapter.
    pub fn inner(&self) -> &A {
        &self.adapter
    }

    /// The tool this shim reports on.
    pub fn kind(&self) -> &DevToolKind {
        &self.kind
    }

    /// The tool version detected on this host, when it parses.
    fn detected_version(&self) -> Option<ToolVersion> {
        self.adapter.detect()?.version?.parse().ok()
    }
}

#[async_trait::async_trait]
impl<A: DevToolAdapter> DevToolIntegration for LegacyAdapterShim<A> {
    fn capabilities(&self) -> DevToolCapabilities {
        let mut caps = DevToolCapabilities::new()
            .supported(IntegrationCapability::Discovery)
            .supported(IntegrationCapability::ManagedSettings);
        for capability in IntegrationCapability::ALL {
            if matches!(
                capability,
                IntegrationCapability::Discovery | IntegrationCapability::ManagedSettings
            ) {
                continue;
            }
            caps = caps.unsupported(capability, LEGACY_UNSUPPORTED_REASON);
        }
        caps
    }

    fn detect(&self) -> Option<DevToolInfo> {
        self.adapter.detect()
    }

    fn version_support(&self) -> VersionSupport {
        self.version_support.clone()
    }

    async fn plan_integration(&self, request: &IntegrationRequest) -> Result<IntegrationPlan, AdapterError> {
        let rendered = self.adapter.generate_managed_settings(&self.policy).await?;
        let content_sha256 = sha256_hex(rendered.as_bytes());

        // The legacy trait renders and writes in two calls and never discloses
        // the destination, so the step cannot honestly name a file.
        let step = IntegrationStep::new(
            "legacy-managed-settings",
            StepAction::ApplyLegacyManagedSettings {
                scope: request.settings_scope,
                content_sha256,
            },
            "apply managed settings through the pre-lifecycle adapter",
        );

        let planned_level = request.effective_target_level().min(ProtectionLevel::Integrated);

        let mut plan = IntegrationPlan::new(
            format!("legacy-{}", now_unix_secs()),
            request,
            planned_level,
            self.adapter.governance_level(),
        )
        .with_step(step)
        .warn(
            "this adapter has not been migrated to the Developer Integration lifecycle; it can \
             apply managed settings but cannot intercept the model path, so protection above \
             Integrated is not reachable through it",
        );

        let capabilities = self.capabilities();
        for capability in IntegrationCapability::ALL {
            if let Some(reason) = capabilities.unsupported_reason(capability) {
                plan = plan.declaring_unsupported(capability, reason);
            }
        }

        Ok(plan)
    }

    async fn integration_status(
        &self,
        receipt: Option<&IntegrationReceipt>,
        // A legacy adapter has no environment-based bypass detection; accepted
        // only to satisfy the trait.
        _caller_env: Option<&CallerEnvironment>,
    ) -> Result<IntegrationStatus, AdapterError> {
        let now = now_unix_secs();
        let detected = self.adapter.detect();
        let compatibility = self
            .version_support
            .supported_tool_versions
            .classify(self.detected_version().as_ref());

        // A legacy adapter has no fingerprint recipe and no verification
        // mechanism, so the only honest evidence is the absence of both.
        let evidence = vec![ProtectionEvidence::new(
            IntegrationCapability::ManagedSettings,
            EvidenceKind::Absent {
                reason: LEGACY_UNSUPPORTED_REASON.to_string(),
            },
            now,
            "this adapter cannot read its managed settings back, so nothing can be verified",
        )];

        let planned_level = receipt
            .map(|r| r.planned_level)
            .unwrap_or(ProtectionLevel::DetectedNotIntegrated);

        let state = StateDerivation {
            detected: detected.is_some(),
            receipt_present: receipt.is_some(),
            required_steps: receipt.map(IntegrationReceipt::required_steps).unwrap_or(0),
            required_steps_verified: receipt.map(IntegrationReceipt::verified_required_steps).unwrap_or(0),
            mismatched_artifacts: &[],
            compatibility: &compatibility,
            schema_newer_than_core: receipt.is_some_and(IntegrationReceipt::is_schema_newer_than_running_core),
            evidence: &evidence,
            planned_level,
            now_unix_secs: now,
            freshness_window_secs: DEFAULT_FRESHNESS_WINDOW_SECS,
        }
        .derive();

        let phase = match (&state, receipt.is_some()) {
            (ProtectionState::Ladder(ProtectionLevel::NotInstalled), _) => LifecyclePhase::NotInstalled,
            (_, false) => LifecyclePhase::DetectedNotIntegrated,
            (_, true) => LifecyclePhase::PartiallyInstalled,
        };

        let next_level = state.achieved_level().next_up().map(|level| NextLevel {
            level,
            blocked_because: LEGACY_UNSUPPORTED_REASON.to_string(),
        });

        Ok(IntegrationStatus {
            tool: detected
                .as_ref()
                .map(|i| i.kind.clone())
                .unwrap_or_else(|| self.kind.clone()),
            phase,
            state,
            evidence,
            planned_level,
            adapter_ceiling: self.adapter.governance_level(),
            compatibility,
            next_level,
            observed_at_unix_secs: now,
            // A legacy adapter has no lifecycle service behind it to resolve a
            // policy, so this shim cannot answer the question — and must not
            // borrow an answer. `Unconfigured` would read as a finding about
            // the operator's policy rather than about this adapter's age.
            policy: PolicyPosture::Unknown {
                reason: format!("{LEGACY_UNSUPPORTED_REASON}; it resolves no policy of its own"),
            },
        })
    }

    async fn verify_integration(
        &self,
        _receipt: &IntegrationReceipt,
        _caller_env: Option<&CallerEnvironment>,
    ) -> Result<VerificationResult, AdapterError> {
        // Not `Failed` — nothing failed. Nothing was looked at.
        Ok(VerificationResult::unverifiable(
            now_unix_secs(),
            format!("{LEGACY_UNSUPPORTED_REASON}; it exposes no way to read its own settings back"),
        ))
    }

    async fn plan_removal(&self, receipt: &IntegrationReceipt) -> Result<RemovalPlan, AdapterError> {
        let mut plan = RemovalPlan::new(format!("legacy-removal-{}", now_unix_secs()), receipt.tool.clone());

        for (index, action) in receipt.reversal_actions().into_iter().enumerate() {
            plan = plan.with_step(IntegrationStep::new(
                format!("reverse-{index}"),
                action,
                "undo a step recorded in the receipt",
            ));
        }

        for step in receipt.irreversible_steps() {
            plan = plan.with_residual(format!(
                "step {:?} ({}) was applied by a pre-lifecycle adapter that does not report what it \
                 wrote; remove it by hand",
                step.step_id,
                step.action.kind()
            ));
        }

        if plan.steps.is_empty() {
            plan = plan.warn(
                "this adapter has not been migrated to the Developer Integration lifecycle and did \
                 not record how to undo what it applied",
            );
        }

        Ok(plan)
    }
}

impl<A: DevToolAdapter + std::fmt::Debug> std::fmt::Debug for LegacyAdapterShim<A> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LegacyAdapterShim")
            .field("kind", &self.kind)
            .field("adapter", &self.adapter)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dev_tool::GovernanceLevel;
    use crate::integration::capability::CapabilityResolution;

    /// Smallest legal `DevToolAdapter`, standing in for any unmigrated adapter.
    #[derive(Debug)]
    struct Legacy;

    #[async_trait::async_trait]
    impl DevToolAdapter for Legacy {
        fn detect(&self) -> Option<DevToolInfo> {
            None
        }

        async fn generate_managed_settings(&self, _policy: &PolicyDocument) -> Result<String, AdapterError> {
            Ok("{}".to_string())
        }

        async fn apply_settings(&self, _settings: &str) -> Result<(), AdapterError> {
            Ok(())
        }

        fn build_launch_command(
            &self,
            _tool_args: &[String],
            _agent_id: &str,
            _team_id: Option<&str>,
            _proxy_addr: Option<&str>,
        ) -> Result<std::process::Command, AdapterError> {
            Err(AdapterError::LaunchFailed("no launch command".to_string()))
        }

        async fn list_mcp_servers(&self) -> Result<Vec<crate::dev_tool::McpServerInfo>, AdapterError> {
            Ok(Vec::new())
        }

        async fn apply_mcp_governance(&self, _allowed: &[String], _denied: &[String]) -> Result<(), AdapterError> {
            Ok(())
        }

        fn governance_level(&self) -> GovernanceLevel {
            GovernanceLevel::L1Observe
        }
    }

    fn shim() -> LegacyAdapterShim<Legacy> {
        LegacyAdapterShim::new(
            DevToolKind::Custom("legacy".to_string()),
            Legacy,
            PolicyDocument {
                version: 1,
                name: "test".to_string(),
                rules: Vec::new(),
                enforcement_mode: crate::EnforcementMode::Enforce,
            },
        )
    }

    #[test]
    fn the_shim_declares_only_what_a_legacy_adapter_can_substantiate() {
        let caps = shim().capabilities();
        assert!(caps.is_effective(IntegrationCapability::Discovery));
        assert!(caps.is_effective(IntegrationCapability::ManagedSettings));

        // Everything else is an explicit, reasoned "no" — not silence, and not a
        // claim the shim cannot back.
        for capability in IntegrationCapability::ALL {
            if matches!(
                capability,
                IntegrationCapability::Discovery | IntegrationCapability::ManagedSettings
            ) {
                continue;
            }
            assert_eq!(
                caps.resolve(capability),
                CapabilityResolution::Unsupported,
                "{capability:?} must not be claimed by a shimmed adapter"
            );
            assert_eq!(caps.unsupported_reason(capability), Some(LEGACY_UNSUPPORTED_REASON));
        }

        assert!(!caps.can_intercept_model_path());
    }

    #[test]
    fn the_shim_exposes_no_optional_surfaces() {
        let shim = shim();
        assert!(shim.as_mcp_governed().is_none());
        assert!(shim.as_launchable().is_none());
        assert!(shim.as_hookable().is_none());
        assert!(super::super::capability_conformance(&shim).is_empty());
        assert_eq!(shim.inner().governance_level(), GovernanceLevel::L1Observe);
    }

    #[test]
    fn sha256_hex_is_stable() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }
}
