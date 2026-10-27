//! [`DevToolIntegration`] for GitHub Copilot in VS Code agent mode: a receipt-backed
//! install of the one VS Code setting Agent Assembly can honestly own
//! (AAASM-6297, J93).
//!
//! # Why one key, and why not the keys `apply_settings` writes
//!
//! VS Code's approvals documentation (`code.visualstudio.com/docs/agents/approvals`)
//! lists `chat.tools.global.autoApprove`. It does **not** list
//! `chat.tools.autoApprove`, `chat.mcp.requireApproval`, `chat.mcp.deny` or
//! `chat.agent.maxRequests`, all of which [`CopilotAdapter::apply_settings`]
//! writes. A receipt that claims ownership of a key nothing reads would report an
//! enforced posture that VS Code never applies, so none of those are managed keys
//! here. `chat.mcp.servers` and `github.copilot.enable` are the user's own
//! configuration and are never owned either.
//!
//! # Never loosen, never guess
//!
//! `chat.tools.global.autoApprove` has a total order only over booleans, so:
//! absent or `true` becomes `false` (the prior value is receipted and restored on
//! removal); an existing `false` is already as strict as it gets, so the key is
//! left out of the plan entirely and removal can never touch it (AAASM-6321's
//! keep-stricter contract); any other value, or a settings file that is not strict
//! JSON, is refused at plan time with the file left untouched. VS Code's
//! `settings.json` is JSONC, and rewriting a commented file through a strict
//! parser would silently delete the user's comments, so refusing is the only safe
//! answer until a comment-preserving editor exists.
//!
//! # Honest ceiling
//!
//! There is no model-path interception, MCP governance or host enforcement for
//! Copilot, so the ceiling is [`ProtectionLevel::Integrated`] and `verify` reads
//! the key back but reports [`VerificationOutcome::Unverifiable`]: that VS Code
//! honours the setting is not something this adapter exercises.

use std::path::{Path, PathBuf};

use aa_devtool_contract::{
    now_unix_secs, sha256_hex, AdapterError, ArtifactObservation, CallerEnvironment, DevToolCapabilities, DevToolInfo,
    DevToolIntegration, DevToolKind, DocumentFormat, EvidenceKind, FilesystemExecutor, GovernanceLevel,
    IntegrationCapability, IntegrationPlan, IntegrationReceipt, IntegrationRequest, IntegrationStatus, IntegrationStep,
    LifecyclePhase, NextLevel, PolicyPosture, ProtectionEvidence, ProtectionLevel, RemovalPlan, SettingsMerge,
    SettingsScope, StateDerivation, StepAction, StepExecutor, StepReceipt, SupportedToolVersions, ToolVersion,
    VerificationOutcome, VerificationResult, VersionCompatibility, VersionSupport, LIFECYCLE_SCHEMA_VERSION,
};
use async_trait::async_trait;

use crate::{CopilotAdapter, MIN_COPILOT_VERSION};

const STEP_MANAGED_SETTINGS: &str = "managed-settings";

/// The only key this integration owns. See the module docs.
const MANAGED_KEY: &str = "chat.tools.global.autoApprove";

/// The governance level this integration can truthfully claim. The legacy
/// adapter's `L2Enforce` described what its (undocumented) keys were meant to
/// do; this lifecycle writes one documented setting and verifies nothing about
/// VS Code honouring it, so it claims discovery only, consistent with the
/// `Integrated` ceiling and `ToolActionApproval` being unsupported.
const GOVERNANCE_CEILING: GovernanceLevel = GovernanceLevel::L0Discover;

/// GitHub Copilot's native lifecycle integration.
#[derive(Debug, Default)]
pub struct CopilotIntegration {
    adapter: CopilotAdapter,
}

impl CopilotIntegration {
    /// The production integration: VS Code's platform-default user settings path.
    pub fn new() -> Self {
        Self::default()
    }

    /// An integration over an adapter with explicit paths. Tests use this so no
    /// test depends on the ambient `$HOME`.
    #[must_use]
    pub fn with_adapter(adapter: CopilotAdapter) -> Self {
        Self { adapter }
    }

    fn user_settings_path(&self) -> Result<PathBuf, AdapterError> {
        self.adapter
            .resolve_settings_path()
            .ok_or_else(|| AdapterError::SettingsGenerationFailed("could not resolve VS Code settings path".into()))
    }

    /// The bytes each of `plan`'s steps writes, keyed by step id.
    ///
    /// Re-derived at apply time rather than carried in the plan, so the digest the
    /// user reviewed is what the executor checks: an edit made between plan and
    /// apply changes the rendering and the executor refuses the mismatch.
    pub async fn step_content(
        &self,
        plan: &IntegrationPlan,
    ) -> Result<std::collections::BTreeMap<String, String>, AdapterError> {
        let mut rendered = std::collections::BTreeMap::new();
        for step in &plan.steps {
            if let StepAction::WriteManagedSettings { path, .. } = &step.action {
                rendered.insert(step.id.clone(), render(path).await?.content);
            }
        }
        Ok(rendered)
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

    /// Read each applied step's artifact back from disk and compare it with the
    /// receipt.
    fn read_back_evidence(&self, receipt: &IntegrationReceipt, now: u64) -> Vec<ProtectionEvidence> {
        let executor = FilesystemExecutor::new();
        receipt
            .steps
            .iter()
            .filter(|step| step.applied && step.fingerprint.is_some())
            .map(|step| {
                if owns_no_keys(step) {
                    let (matches, detail) = posture_still_strict(step);
                    return ProtectionEvidence::new(
                        IntegrationCapability::ManagedSettings,
                        EvidenceKind::ReadBack {
                            matches_receipt: matches,
                        },
                        now,
                        detail,
                    );
                }
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
                    IntegrationCapability::ManagedSettings,
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

/// What this integration will write, and which keys it therefore owns.
struct Rendered {
    content: String,
    managed_keys: Vec<String>,
    /// The user already holds `false`, so there is nothing to write.
    already_strict: bool,
}

fn refusal(msg: String) -> AdapterError {
    AdapterError::SettingsApplyFailed(std::io::Error::new(std::io::ErrorKind::InvalidInput, msg))
}

/// Resolve what to write over the file at `path`, refusing anything it cannot
/// rank or parse strictly. The file is only read, never touched.
async fn render(path: &Path) -> Result<Rendered, AdapterError> {
    let existing: serde_json::Map<String, serde_json::Value> = match tokio::fs::read_to_string(path).await {
        Ok(raw) if raw.trim().is_empty() => serde_json::Map::new(),
        Ok(raw) => match serde_json::from_str::<serde_json::Value>(&raw) {
            Ok(serde_json::Value::Object(map)) => map,
            Ok(_) => {
                return Err(refusal(format!(
                    "{} is not a JSON object, refusing to touch it; fix the file and re-run",
                    path.display()
                )))
            }
            Err(e) => {
                return Err(refusal(format!(
                    "{} is not strict JSON (VS Code allows comments and trailing commas, which Agent \
                     Assembly cannot edit without deleting them), refusing to touch it: {e}. Remove the \
                     comments or trailing commas yourself, then re-run",
                    path.display()
                )))
            }
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => serde_json::Map::new(),
        Err(e) => return Err(AdapterError::SettingsApplyFailed(e)),
    };

    match existing.get(MANAGED_KEY) {
        None | Some(serde_json::Value::Bool(true)) => {}
        Some(serde_json::Value::Bool(false)) => {
            return Ok(Rendered {
                content: "{}".to_string(),
                managed_keys: Vec::new(),
                already_strict: true,
            })
        }
        Some(other) => {
            return Err(refusal(format!(
                "{} sets `{MANAGED_KEY}` to `{other}`, which Agent Assembly cannot rank and will not replace; \
                 change it to true or false yourself if you want Agent Assembly to manage it, then re-run",
                path.display()
            )))
        }
    }

    let mut doc = serde_json::Map::new();
    doc.insert(MANAGED_KEY.to_string(), serde_json::Value::Bool(false));
    let content = serde_json::to_string_pretty(&serde_json::Value::Object(doc))
        .map_err(|e| AdapterError::SettingsGenerationFailed(e.to_string()))?;
    Ok(Rendered {
        content,
        managed_keys: vec![MANAGED_KEY.to_string()],
        already_strict: false,
    })
}

#[async_trait]
impl DevToolIntegration for CopilotIntegration {
    fn capabilities(&self) -> DevToolCapabilities {
        DevToolCapabilities::new()
            .supported(IntegrationCapability::Discovery)
            .supported(IntegrationCapability::ManagedSettings)
            .unsupported(
                IntegrationCapability::ToolActionApproval,
                "chat.tools.global.autoApprove is written as managed settings; nothing here independently \
                 verifies VS Code honours a per-call approval decision",
            )
            .unsupported(
                IntegrationCapability::ManagedLaunch,
                "GitHub Copilot is a VS Code extension and cannot be launched by `aasm run`",
            )
            .unsupported(
                IntegrationCapability::ModelPathInterception,
                "Copilot's model traffic goes through GitHub's service and the VS Code extension host; this \
                 adapter installs no interception in that path",
            )
            .unsupported(
                IntegrationCapability::ModelGatewayBaseUrl,
                "Copilot exposes no configurable model base-URL override this adapter renders",
            )
            .unsupported(
                IntegrationCapability::HttpProxy,
                "this adapter does not route VS Code or its extensions through the Agent Assembly proxy",
            )
            .unsupported(
                IntegrationCapability::Hooks,
                "this adapter installs no Copilot hook surface",
            )
            .unsupported(
                IntegrationCapability::McpDiscovery,
                "the legacy adapter can list chat.mcp.servers, but this lifecycle does not surface it",
            )
            .unsupported(
                IntegrationCapability::McpGovernance,
                "chat.mcp.deny and chat.mcp.requireApproval are not documented VS Code settings, so no MCP \
                 allow/deny is installed",
            )
            .unsupported(
                IntegrationCapability::NativeIdeUi,
                "this adapter installs no in-editor status or approval surface",
            )
            .unsupported(
                IntegrationCapability::HostEnforcement,
                "VS Code user settings are the developer's own file, not an endpoint-managed surface, so \
                 ProtectionLevel::HostEnforced is never reachable",
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
                MIN_COPILOT_VERSION.parse().unwrap_or(ToolVersion::new(0, 0, 0)),
            ),
        }
    }

    async fn plan_integration(&self, request: &IntegrationRequest) -> Result<IntegrationPlan, AdapterError> {
        let scope = request.settings_scope;
        let settings_path = self.user_settings_path()?;
        if scope != SettingsScope::User {
            return Err(AdapterError::SettingsGenerationFailed(format!(
                "GitHub Copilot has no {scope}-scope settings surface Agent Assembly can manage; only the \
                 user scope ({}) is supported",
                settings_path.display()
            )));
        }

        let rendered = render(&settings_path).await?;
        let capabilities = self.capabilities();
        let planned_level = request.effective_target_level().min(ProtectionLevel::Integrated);

        let mut plan = IntegrationPlan::new(
            format!("copilot-{scope}-{}", now_unix_secs()),
            request,
            planned_level,
            GOVERNANCE_CEILING,
        );

        let summary = if rendered.already_strict {
            format!(
                "{} already sets `{MANAGED_KEY}` to false; nothing to write and nothing Agent Assembly will \
                 ever restore or delete. Status reports Integrated only while it stays false",
                settings_path.display()
            )
        } else {
            format!(
                "merge `{MANAGED_KEY}` = false into {} and leave every other key alone",
                settings_path.display()
            )
        };
        plan = plan.with_step(IntegrationStep::new(
            STEP_MANAGED_SETTINGS,
            StepAction::WriteManagedSettings {
                scope,
                path: settings_path,
                managed_keys: rendered.managed_keys,
                content_sha256: sha256_hex(&rendered.content),
                merge: SettingsMerge::MergeManagedKeys,
                format: DocumentFormat::Json,
            },
            summary,
        ));

        for capability in [
            IntegrationCapability::ManagedLaunch,
            IntegrationCapability::ModelPathInterception,
            IntegrationCapability::ModelGatewayBaseUrl,
            IntegrationCapability::HttpProxy,
            IntegrationCapability::Hooks,
            IntegrationCapability::McpDiscovery,
            IntegrationCapability::McpGovernance,
            IntegrationCapability::NativeIdeUi,
            IntegrationCapability::HostEnforcement,
        ] {
            if let Some(reason) = capabilities.unsupported_reason(capability) {
                plan = plan.declaring_unsupported(capability, reason.to_string());
            }
        }

        Ok(plan
            .warn(
                "the managed settings document is reserialised as strict JSON: formatting and key order from \
                 before the install do not come back on removal"
                    .to_string(),
            )
            .warn("reload VS Code for the setting to take effect".to_string()))
    }

    async fn integration_status(
        &self,
        receipt: Option<&IntegrationReceipt>,
        _caller_env: Option<&CallerEnvironment>,
    ) -> Result<IntegrationStatus, AdapterError> {
        let now = now_unix_secs();
        let detected = self.detect();
        let compatibility = self.compatibility();
        let evidence = receipt.map_or_else(Vec::new, |r| self.read_back_evidence(r, now));

        let planned_level = receipt.map_or(ProtectionLevel::NotInstalled, |r| {
            r.planned_level.min(ProtectionLevel::Integrated)
        });
        let state = StateDerivation {
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
        }
        .derive();

        let phase = match (&state, receipt) {
            (aa_devtool_contract::ProtectionState::Ladder(ProtectionLevel::NotInstalled), _) => {
                LifecyclePhase::NotInstalled
            }
            (_, None) => LifecyclePhase::DetectedNotIntegrated,
            (_, Some(r)) if r.verified_required_steps() >= r.required_steps() && r.required_steps() > 0 => {
                LifecyclePhase::Installed
            }
            (_, Some(_)) => LifecyclePhase::PartiallyInstalled,
        };

        let next_level = state.achieved_level().next_up().map(|level| NextLevel {
            level,
            blocked_because: next_level_reason(level, receipt.is_some()),
        });

        Ok(IntegrationStatus {
            tool: DevToolKind::GitHubCopilot,
            phase,
            state,
            evidence,
            planned_level,
            adapter_ceiling: detected.map_or(GOVERNANCE_CEILING, |i| i.governance_level.min(GOVERNANCE_CEILING)),
            compatibility,
            next_level,
            observed_at_unix_secs: now,
            policy: PolicyPosture::Unknown {
                reason: "not resolved by the adapter".to_string(),
            },
        })
    }

    async fn verify_integration(
        &self,
        receipt: &IntegrationReceipt,
        _caller_env: Option<&CallerEnvironment>,
    ) -> Result<VerificationResult, AdapterError> {
        let now = now_unix_secs();
        let evidence = self.read_back_evidence(receipt, now);
        let mismatched: Vec<String> = evidence
            .iter()
            .filter(|e| matches!(e.kind, EvidenceKind::ReadBack { matches_receipt: false }))
            .map(|e| e.detail.clone())
            .collect();

        let outcome = if !mismatched.is_empty() {
            VerificationOutcome::Failed {
                reason: format!(
                    "Agent Assembly-owned state no longer matches the receipt: {}",
                    mismatched.join("; ")
                ),
            }
        } else {
            VerificationOutcome::Unverifiable {
                reason: "the setting reads back as receipted, but this adapter has no probe that shows VS Code \
                         honouring it"
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
        let mut plan = RemovalPlan::new(removal_plan_id(receipt), DevToolKind::GitHubCopilot);

        for step in receipt
            .steps
            .iter()
            .rev()
            .filter(|s| s.applied && !s.action.is_protection_test())
        {
            let summary = match &step.action {
                StepAction::WriteManagedSettings { path, .. } => format!(
                    "restore the Agent Assembly-owned keys in {} to what they held before install, and leave \
                     everything you changed since alone",
                    path.display()
                ),
                other => format!("reverse the {} step", other.kind()),
            };
            plan = plan.with_step(IntegrationStep::new(
                format!("undo-{}", step.step_id),
                step.reversal.clone().unwrap_or_else(|| reversal_for(step)),
                summary,
            ));
        }

        for step in receipt.unrestorable_steps() {
            plan = plan.with_residual(format!(
                "{}: this step recorded no restorable prior state, so removal cannot prove it put anything back",
                artifact_label(step)
            ));
        }

        Ok(plan
            .warn(
                "restore is semantics-exact, not byte-exact: the settings document is reserialised, so \
                 formatting and key order from before the install do not come back"
                    .to_string(),
            )
            .warn("reload VS Code for the removal to take effect".to_string()))
    }
}

/// A step planned over a user value that was already `false` claims no key, so
/// the fingerprint it recorded covers nothing and could never show drift.
fn owns_no_keys(step: &StepReceipt) -> bool {
    matches!(&step.action, StepAction::WriteManagedSettings { managed_keys, .. } if managed_keys.is_empty())
}

/// For a step that owns no key, the posture the integration reports is "the
/// user's `chat.tools.global.autoApprove` is `false`"; read it back so the
/// report cannot stay green after the user loosens or deletes it.
fn posture_still_strict(step: &StepReceipt) -> (bool, String) {
    let label = artifact_label(step);
    let Some(path) = step.action.affected_paths().first().map(|p| (*p).to_path_buf()) else {
        return (false, format!("{label} has no path to read back"));
    };
    let strict = std::fs::read_to_string(&path)
        .ok()
        .and_then(|raw| serde_json::from_str::<serde_json::Value>(&raw).ok())
        .is_some_and(|doc| doc.get(MANAGED_KEY) == Some(&serde_json::Value::Bool(false)));
    if strict {
        (
            true,
            format!("{label}: `{MANAGED_KEY}` is still false (your own value; not owned by Agent Assembly)"),
        )
    } else {
        (
            false,
            format!("{label}: `{MANAGED_KEY}` is no longer false, and Agent Assembly owns no key there to restore"),
        )
    }
}

fn artifact_label(step: &StepReceipt) -> String {
    match step.action.affected_paths().first() {
        Some(path) => path.display().to_string(),
        None => format!("{} ({})", step.step_id, step.action.kind()),
    }
}

fn next_level_reason(level: ProtectionLevel, installed: bool) -> String {
    match level {
        ProtectionLevel::HostEnforced => {
            "host enforcement is not reachable: VS Code user settings are not an endpoint-managed surface".to_string()
        }
        ProtectionLevel::GatewayProtected => {
            "Copilot has no model-path interception this adapter can install".to_string()
        }
        _ if !installed => "nothing has been applied yet; run `aasm integrations install github-copilot`".to_string(),
        _ => "not every required step of the applied plan verifies; repair the integration".to_string(),
    }
}

fn reversal_for(step: &StepReceipt) -> StepAction {
    match &step.action {
        StepAction::WriteManagedSettings {
            scope,
            path,
            managed_keys,
            merge,
            format,
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
            format: *format,
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
    use aa_devtool_contract::{capability_conformance, ProtectionProfile};

    fn integration(dir: &Path) -> CopilotIntegration {
        CopilotIntegration::with_adapter(CopilotAdapter::with_paths(dir.join("ext"), dir.join("settings.json")))
    }

    fn request(scope: SettingsScope) -> IntegrationRequest {
        IntegrationRequest::new(DevToolKind::GitHubCopilot, ProtectionProfile::Recommended, scope)
    }

    #[test]
    fn capabilities_are_conformant() {
        let dir = tempfile::tempdir().unwrap();
        let violations = capability_conformance(&integration(dir.path()));
        assert!(violations.is_empty(), "{violations:?}");
    }

    #[test]
    fn only_documented_capabilities_are_supported() {
        let dir = tempfile::tempdir().unwrap();
        let caps = integration(dir.path()).capabilities();
        for cap in [
            IntegrationCapability::ModelPathInterception,
            IntegrationCapability::McpGovernance,
            IntegrationCapability::HostEnforcement,
        ] {
            assert!(
                caps.unsupported_reason(cap).is_some(),
                "{cap:?} must be declared unsupported"
            );
        }
        assert!(caps.is_effective(IntegrationCapability::ManagedSettings));
        assert!(
            caps.unsupported_reason(IntegrationCapability::ToolActionApproval)
                .is_some(),
            "nothing verifies VS Code honours the key, so approval gating must not be claimed"
        );
    }

    #[tokio::test]
    async fn plan_owns_exactly_the_documented_key_and_caps_at_integrated() {
        let dir = tempfile::tempdir().unwrap();
        let mut req = request(SettingsScope::User);
        req.requested_level = ProtectionLevel::HostEnforced;
        let plan = integration(dir.path()).plan_integration(&req).await.unwrap();
        assert_eq!(plan.planned_level, ProtectionLevel::Integrated);
        let [step] = plan.steps.as_slice() else {
            panic!("expected one step: {:?}", plan.steps)
        };
        let StepAction::WriteManagedSettings {
            managed_keys,
            format,
            merge,
            ..
        } = &step.action
        else {
            panic!("expected a settings step")
        };
        assert_eq!(managed_keys, &vec![MANAGED_KEY.to_string()]);
        assert_eq!(
            (*format, *merge),
            (DocumentFormat::Json, SettingsMerge::MergeManagedKeys)
        );
        plan.validate().unwrap();
    }

    #[tokio::test]
    async fn project_and_managed_scopes_are_refused_naming_the_scope() {
        let dir = tempfile::tempdir().unwrap();
        for scope in [SettingsScope::Project, SettingsScope::Managed] {
            let err = integration(dir.path())
                .plan_integration(&request(scope))
                .await
                .expect_err("Copilot has no such surface")
                .to_string();
            assert!(err.contains(&scope.to_string()), "{err}");
        }
    }

    #[tokio::test]
    async fn an_already_strict_value_is_dropped_from_the_managed_keys() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("settings.json"),
            r#"{"chat.tools.global.autoApprove": false}"#,
        )
        .unwrap();
        let plan = integration(dir.path())
            .plan_integration(&request(SettingsScope::User))
            .await
            .unwrap();
        let StepAction::WriteManagedSettings { managed_keys, .. } = &plan.steps[0].action else {
            panic!("expected a settings step")
        };
        assert!(managed_keys.is_empty(), "{managed_keys:?}");
    }

    #[tokio::test]
    async fn an_unrankable_value_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("settings.json"),
            r#"{"chat.tools.global.autoApprove": {"x": 1}}"#,
        )
        .unwrap();
        let err = integration(dir.path())
            .plan_integration(&request(SettingsScope::User))
            .await
            .expect_err("cannot be ranked")
            .to_string();
        assert!(err.contains(MANAGED_KEY) && err.contains("cannot rank"), "{err}");
    }

    #[tokio::test]
    async fn the_plan_and_status_do_not_claim_more_than_discovery() {
        let dir = tempfile::tempdir().unwrap();
        let ext = dir.path().join("ext").join("github.copilot-1.300.0");
        std::fs::create_dir_all(&ext).unwrap();
        std::fs::write(ext.join("package.json"), r#"{"version":"1.300.0"}"#).unwrap();
        let integration = integration(dir.path());
        assert!(integration.detect().is_some(), "fixture must make Copilot detectable");
        let plan = integration
            .plan_integration(&request(SettingsScope::User))
            .await
            .unwrap();
        assert_eq!(plan.adapter_ceiling, GovernanceLevel::L0Discover);
        let status = integration.integration_status(None, None).await.unwrap();
        assert_eq!(
            status.adapter_ceiling,
            GovernanceLevel::L0Discover,
            "the legacy adapter's L2Enforce must not leak into the lifecycle status"
        );
    }

    async fn refusal_for(body: &str) -> String {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("settings.json"), body).unwrap();
        integration(dir.path())
            .plan_integration(&request(SettingsScope::User))
            .await
            .expect_err(body)
            .to_string()
    }

    #[tokio::test]
    async fn null_string_and_non_object_values_are_refused() {
        for body in [
            r#"{"chat.tools.global.autoApprove": null}"#,
            r#"{"chat.tools.global.autoApprove": "false"}"#,
            r#"{"chat.tools.global.autoApprove": 0}"#,
        ] {
            let err = refusal_for(body).await;
            assert!(
                err.contains(MANAGED_KEY) && err.contains("cannot rank"),
                "{body}: {err}"
            );
        }
        for body in ["[]", "null", "\"x\"", "42"] {
            let err = refusal_for(body).await;
            assert!(err.contains("not a JSON object"), "{body}: {err}");
        }
    }

    #[tokio::test]
    async fn a_byte_order_mark_is_refused_untouched_and_whitespace_only_is_empty() {
        let bom = "\u{feff}{\"editor.fontSize\": 14}";
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        std::fs::write(&path, bom).unwrap();
        let err = integration(dir.path())
            .plan_integration(&request(SettingsScope::User))
            .await
            .expect_err("a BOM-prefixed file is not strict JSON to serde_json")
            .to_string();
        assert!(err.contains("not strict JSON"), "{err}");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), bom);

        std::fs::write(&path, " \n\t ").unwrap();
        let plan = integration(dir.path())
            .plan_integration(&request(SettingsScope::User))
            .await
            .expect("a whitespace-only file holds nothing to protect");
        let StepAction::WriteManagedSettings { managed_keys, .. } = &plan.steps[0].action else {
            panic!("expected a settings step")
        };
        assert_eq!(managed_keys, &vec![MANAGED_KEY.to_string()]);
    }
}
