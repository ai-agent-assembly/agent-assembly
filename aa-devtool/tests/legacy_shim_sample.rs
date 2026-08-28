//! The public sample adapter, driven through the new lifecycle contract.
//!
//! # What this file is actually asserting
//!
//! `examples/aa-devtool-sample-myeditor` is the reference a third-party adapter
//! author copies, and ADR 0030 §7 promises it keeps compiling and working
//! **unchanged** when the lifecycle contract lands. That promise is only worth
//! something if something exercises it, so this file takes the sample exactly as
//! it is — not a copy, not a variant — and runs the whole lifecycle over it
//! through [`LegacyAdapterShim`].
//!
//! It lives in `aa-devtool` rather than in the sample crate because the sample
//! must stay untouched: adding a test to it would be a change to the very thing
//! under test. The sample is a dev-dependency here, so if it stopped compiling
//! against the contract this file would not build.
//!
//! The second thing asserted is that the shim does not *flatter* the sample. A
//! bridge that let an unmigrated adapter report `Integrated` or claim MCP
//! governance (which the sample's `apply_mcp_governance` does implement, and
//! which the shim has no way to distinguish from the `Ok(())` stub the old trait
//! invites) would defeat the point of the migration. Every assertion below about
//! what the shim *refuses* to claim is as load-bearing as the ones about what it
//! produces.

use std::path::PathBuf;

use aa_devtool_contract::{
    capability_conformance, CapabilityResolution, DevToolAdapter, DevToolIntegration, DevToolKind, EnforcementMode,
    IntegrationCapability, LegacyAdapterShim, PolicyDocument, ProtectionLevel, ProtectionProfile, ProtectionState,
    SettingsScope, StepAction, VerificationOutcome, LEGACY_UNSUPPORTED_REASON,
};
use aa_devtool_sample_myeditor::{MyEditorAdapter, MYEDITOR_BIN_ENV, MYEDITOR_KIND_ID};

/// The sample's own MCP fixture, resolved from this crate so the sample is
/// consumed exactly as an out-of-tree adapter author would consume it.
fn fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../examples/aa-devtool-sample-myeditor/fixtures/mcp_servers.json")
}

fn policy() -> PolicyDocument {
    PolicyDocument {
        version: 1,
        name: "sample".to_string(),
        rules: Vec::new(),
        enforcement_mode: EnforcementMode::Enforce,
    }
}

fn shim() -> LegacyAdapterShim<MyEditorAdapter> {
    LegacyAdapterShim::new(
        DevToolKind::Custom(MYEDITOR_KIND_ID.to_string()),
        MyEditorAdapter::new(fixture_path()),
        policy(),
    )
}

fn request() -> aa_devtool_contract::IntegrationRequest {
    aa_devtool_contract::IntegrationRequest::new(
        DevToolKind::Custom(MYEDITOR_KIND_ID.to_string()),
        ProtectionProfile::Recommended,
        SettingsScope::User,
    )
}

/// Sets `MYEDITOR_BIN` for the duration of a test so the sample's env-var probe
/// succeeds. Nextest runs each test in its own process, so this cannot leak into
/// another test.
struct DetectableSample;

impl DetectableSample {
    fn new() -> Self {
        std::env::set_var(MYEDITOR_BIN_ENV, "/usr/local/bin/myeditor");
        Self
    }
}

impl Drop for DetectableSample {
    fn drop(&mut self) {
        std::env::remove_var(MYEDITOR_BIN_ENV);
    }
}

#[test]
fn the_unmodified_sample_satisfies_the_new_contract() {
    let shim = shim();

    // The legacy trait and the lifecycle trait are both satisfied by the same
    // object, which is the whole point of an additive migration.
    let _legacy: &dyn DevToolAdapter = shim.inner();
    let lifecycle: &dyn DevToolIntegration = &shim;
    assert!(
        lifecycle.detect().is_none(),
        "the sample only detects when its env var is set"
    );

    // And the shim's declaration is internally consistent.
    assert!(capability_conformance(lifecycle).is_empty());
}

#[test]
fn the_shim_declares_only_discovery_and_managed_settings() {
    let caps = shim().capabilities();
    assert!(caps.is_effective(IntegrationCapability::Discovery));
    assert!(caps.is_effective(IntegrationCapability::ManagedSettings));

    // The sample *does* implement `apply_mcp_governance`, and the shim still
    // refuses to claim MCP governance: from behind the legacy trait a working
    // implementation is indistinguishable from the `Ok(())` stub the old
    // contract invites, and an unverifiable claim is not made.
    assert_eq!(
        caps.resolve(IntegrationCapability::McpGovernance),
        CapabilityResolution::Unsupported
    );
    assert_eq!(
        caps.unsupported_reason(IntegrationCapability::McpGovernance),
        Some(LEGACY_UNSUPPORTED_REASON)
    );
    assert!(!caps.can_intercept_model_path());
}

#[tokio::test]
async fn the_sample_yields_a_valid_one_step_plan() {
    let _detectable = DetectableSample::new();
    let shim = shim();

    let plan = shim.plan_integration(&request()).await.expect("planning must succeed");

    assert_eq!(plan.validate(), Ok(()));
    assert_eq!(plan.steps.len(), 1);
    assert_eq!(plan.settings_scope, SettingsScope::User);

    // The step is the legacy-specific variant, because the old trait renders and
    // writes in two calls and never discloses where it wrote.
    match &plan.steps[0].action {
        StepAction::ApplyLegacyManagedSettings { scope, content_sha256 } => {
            assert_eq!(*scope, SettingsScope::User);
            assert_eq!(content_sha256.len(), 64, "a hex SHA-256 of the rendered settings");
        }
        other => panic!("expected ApplyLegacyManagedSettings, got {other:?}"),
    }

    // The digest is of what the sample actually rendered.
    let rendered = shim
        .inner()
        .generate_managed_settings(&policy())
        .await
        .expect("the sample renders settings");
    assert!(rendered.contains("aa-devtool-sample-myeditor"));

    // Capped at Integrated, with the reason visible in the dry run.
    assert_eq!(plan.planned_level, ProtectionLevel::Integrated);
    let rendered_plan = plan.render_dry_run();
    assert!(
        rendered_plan.contains("apply-legacy-managed-settings"),
        "{rendered_plan}"
    );
    assert!(rendered_plan.contains("warnings:"), "{rendered_plan}");
    assert!(
        rendered_plan.contains("cannot intercept the model path"),
        "{rendered_plan}"
    );
}

#[tokio::test]
async fn a_shimmed_plan_can_never_claim_gateway_protection() {
    let _detectable = DetectableSample::new();

    // Even when the caller explicitly asks for it.
    let plan = shim()
        .plan_integration(&request().requesting_level(ProtectionLevel::HostEnforced))
        .await
        .unwrap();
    assert_eq!(plan.planned_level, ProtectionLevel::Integrated);
    assert!(!plan.has_interception_probe());
    assert_eq!(plan.validate(), Ok(()));
}

#[tokio::test]
async fn status_without_a_receipt_stops_at_detected_not_integrated() {
    let _detectable = DetectableSample::new();
    let status = shim().integration_status(None, None).await.unwrap();

    assert_eq!(
        status.state,
        ProtectionState::Ladder(ProtectionLevel::DetectedNotIntegrated)
    );
    assert!(!status.has_exercised_evidence());
    // The gap is named rather than left silent.
    let next = status.next_level.expect("the next rung must be reported");
    assert_eq!(next.level, ProtectionLevel::PartiallyIntegrated);
    assert_eq!(next.blocked_because, LEGACY_UNSUPPORTED_REASON);
}

#[tokio::test]
async fn an_absent_sample_reports_not_installed() {
    // No env var: the sample's probe fails, and the shim must not invent a state.
    let status = shim().integration_status(None, None).await.unwrap();
    assert_eq!(status.state, ProtectionState::Ladder(ProtectionLevel::NotInstalled));
}

#[tokio::test]
async fn verification_reports_unverifiable_rather_than_passed() {
    let _detectable = DetectableSample::new();
    let shim = shim();
    let plan = shim.plan_integration(&request()).await.unwrap();

    let receipt = aa_devtool_contract::IntegrationReceipt {
        schema_version: aa_devtool_contract::LIFECYCLE_SCHEMA_VERSION,
        receipt_id: "r1".to_string(),
        plan_id: plan.plan_id.clone(),
        tool: DevToolKind::Custom(MYEDITOR_KIND_ID.to_string()),
        profile: ProtectionProfile::Recommended,
        settings_scope: SettingsScope::User,
        applied_at_unix_secs: aa_devtool_contract::now_unix_secs(),
        versions: shim.version_support().component_versions(),
        tool_version: Some("0.0.0-sample".parse().unwrap()),
        steps: vec![aa_devtool_contract::StepReceipt::applied(
            &plan.steps[0],
            Some("fingerprint".to_string()),
        )],
        planned_level: ProtectionLevel::Integrated,
        achieved_level: ProtectionLevel::PartiallyIntegrated,
        achieved_evidence: Vec::new(),
        verified_at_unix_secs: None,
    };
    assert_eq!(receipt.validate(), Ok(()));

    let result = shim.verify_integration(&receipt, None).await.unwrap();
    match &result.outcome {
        VerificationOutcome::Unverifiable { reason } => {
            assert!(reason.contains(LEGACY_UNSUPPORTED_REASON), "{reason}");
        }
        other => panic!("a legacy adapter must not report a verification it did not run: {other:?}"),
    }
    assert!(!result.has_exercised_evidence());

    // With a receipt present but nothing verifiable, the ladder rests at
    // PartiallyIntegrated — never at Integrated.
    let status = shim.integration_status(Some(&receipt), None).await.unwrap();
    assert_eq!(status.achieved_level(), ProtectionLevel::PartiallyIntegrated);

    // Removal is derived from the receipt, and admits what it cannot undo.
    let removal = shim.plan_removal(&receipt).await.unwrap();
    assert_eq!(removal.validate(), Ok(()));
    assert!(removal.steps.is_empty(), "the sample records no reversal action");
    assert_eq!(removal.residual.len(), 1);
    assert!(
        removal.residual[0].contains("remove it by hand"),
        "{:?}",
        removal.residual
    );
}
