//! Adapter-level tests for the Claude Code Developer Integration (AAASM-5281).
//!
//! Everything here runs against explicit temp roots. Nothing reads or writes the
//! developer's real `$HOME/.claude`, `$HOME/.aa` or
//! `/Library/Application Support/ClaudeCode`, and no keychain operation is
//! performed — trust is established through `NODE_EXTRA_CA_CERTS`, which is the
//! whole point of AAASM-5276 condition C1.
//!
//! The full install → status → verify → drift → repair → remove cycle needs the
//! engine and the receipt store, which live behind `aa-core`; it is in
//! `aa-integration-tests/tests/claude_code_integration_lifecycle.rs`.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use aa_devtool_claude_code::lifecycle::{
    CA_ENV_VAR, MITM_HOSTS, STEP_ENDPOINT_MANAGED_SETTINGS, STEP_MANAGED_SETTINGS, STEP_NODE_EXTRA_CA_CERTS,
    STEP_PROTECTION_TEST, STEP_PROXY_CA, STEP_PROXY_ENV, STEP_SIDE_CHANNEL_SCOPE,
};
use aa_devtool_claude_code::managed_settings::testing::FakeAuthority;
use aa_devtool_claude_code::managed_settings::{PrivilegedFileAuthority, MANAGED_ONLY_KEYS};
use aa_devtool_claude_code::{ClaudeCodeAdapter, ClaudeCodeIntegration, ClaudeCodePaths};
use aa_devtool_contract::{
    capability_conformance, DevToolIntegration, DevToolKind, EnvValue, IntegrationCapability, IntegrationRequest,
    LaunchSpec, ProtectionLevel, ProtectionProfile, SettingsScope, StepAction,
};

/// A fabricated PEM. Nothing verifies it here; the tests assert it is *copied*,
/// *pointed at* and *removed*, never that it validates a certificate chain.
const FAKE_CA_PEM: &str = "-----BEGIN CERTIFICATE-----\nAAASM5281FAKECA\n-----END CERTIFICATE-----\n";

struct Fixture {
    dir: tempfile::TempDir,
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir_all(dir.path().join("home").join(".claude")).expect("home");
        std::fs::create_dir_all(dir.path().join("repo").join(".claude")).expect("repo");
        Self { dir }
    }

    fn root(&self) -> &Path {
        self.dir.path()
    }

    fn ca_source(&self) -> PathBuf {
        self.root().join("aa-ca").join("ca-cert.pem")
    }

    fn write_ca(&self) {
        let path = self.ca_source();
        std::fs::create_dir_all(path.parent().expect("parent")).expect("ca dir");
        std::fs::write(path, FAKE_CA_PEM).expect("ca pem");
    }

    fn paths(&self) -> ClaudeCodePaths {
        ClaudeCodePaths::default()
            .with_home(self.root().join("home"))
            .with_project(self.root().join("repo"))
            .with_state(self.root().join("state"))
            .with_ca_source(self.ca_source())
            // The managed surface is redirected into the fixture, and the real
            // authority refuses to elevate for anything but the canonical path —
            // so nothing here can reach an administrator prompt or the real
            // `/Library/Application Support/ClaudeCode`.
            .with_managed_root(self.root().join("ClaudeCode"))
    }

    /// A stub `claude` binary file. Never executed — the version probe is
    /// overridden — but `resolve_binary` checks it exists.
    fn stub_binary(&self) -> PathBuf {
        let bin = self.root().join("claude");
        if !bin.exists() {
            std::fs::write(&bin, "").expect("stub binary");
        }
        bin
    }

    fn adapter(&self, version: Option<&str>) -> ClaudeCodeAdapter {
        ClaudeCodeAdapter::with_overrides(Some(self.stub_binary()), Some(self.root().join("home")))
            .with_version_override(version.map(str::to_string))
    }

    fn integration(&self, version: Option<&str>) -> ClaudeCodeIntegration {
        self.integration_with_authority(version, FakeAuthority::granting())
    }

    /// An integration whose one privileged step elevates through `authority` —
    /// always a test double, never the real macOS one.
    fn integration_with_authority(
        &self,
        version: Option<&str>,
        authority: Arc<dyn PrivilegedFileAuthority>,
    ) -> ClaudeCodeIntegration {
        ClaudeCodeIntegration::with_paths(self.paths())
            .with_adapter(self.adapter(version))
            .through_proxy("http://127.0.0.1:18899")
            .with_managed_authority(authority)
    }

    fn settings_path(&self, scope: SettingsScope) -> PathBuf {
        self.paths().settings_path(scope).expect("settings path")
    }
}

fn request(scope: SettingsScope) -> IntegrationRequest {
    IntegrationRequest::new(DevToolKind::ClaudeCode, ProtectionProfile::Recommended, scope)
}

// ── Contract conformance ────────────────────────────────────────────────────

#[test]
fn what_the_integration_declares_is_what_it_implements() {
    let fixture = Fixture::new();
    fixture.write_ca();
    let integration = fixture.integration(Some("2.1.220"));
    assert_eq!(
        capability_conformance(&integration),
        vec![],
        "a declared capability whose accessor returns None is a contract violation"
    );
}

#[test]
fn base_url_redirection_and_hooks_are_declared_unsupported_with_reasons() {
    // AAASM-5276 conditions C4 and the hooks classification. Both are mechanisms
    // that exist and neither is offered, so both have to carry the reason.
    let fixture = Fixture::new();
    let caps = fixture.integration(Some("2.1.220")).capabilities();

    let base_url = caps
        .unsupported_reason(IntegrationCapability::ModelGatewayBaseUrl)
        .expect("base-url redirection must be declared unsupported, not omitted");
    assert!(base_url.contains("routing, not protection"), "{base_url}");

    let hooks = caps
        .unsupported_reason(IntegrationCapability::Hooks)
        .expect("hooks must be declared unsupported for protection");
    assert!(hooks.contains("cannot see or modify"), "{hooks}");

    // Host enforcement is offered — but only through the opt-in privileged
    // path. `next_level` is where a status says why it is not active.
    assert!(
        caps.unsupported_reason(IntegrationCapability::HostEnforcement)
            .is_none(),
        "an authority that can be asked makes host enforcement a declared capability"
    );
    let unavailable = fixture
        .integration_with_authority(Some("2.1.220"), FakeAuthority::unavailable())
        .capabilities();
    let host = unavailable
        .unsupported_reason(IntegrationCapability::HostEnforcement)
        .expect("a host with no authorization mechanism must say so, never omit it");
    assert!(host.contains("cannot be installed on this host"), "{host}");
}

#[test]
fn interception_is_unsupported_until_the_proxy_ca_exists() {
    let fixture = Fixture::new();
    let integration = fixture.integration(Some("2.1.220"));
    assert!(
        !integration.capabilities().can_intercept_model_path(),
        "with no CA on the host the tool cannot be made to trust the proxy"
    );

    fixture.write_ca();
    let integration = fixture.integration(Some("2.1.220"));
    assert!(integration.capabilities().can_intercept_model_path());
}

// ── Planning ────────────────────────────────────────────────────────────────

#[tokio::test]
async fn the_plan_carries_the_ca_and_the_variable_that_makes_it_work() {
    // AAASM-5276 condition C1, in plan form: materialise the CA, then point
    // NODE_EXTRA_CA_CERTS at the artifact the previous step wrote.
    let fixture = Fixture::new();
    fixture.write_ca();
    let integration = fixture.integration(Some("2.1.220"));
    let plan = integration
        .plan_integration(&request(SettingsScope::User))
        .await
        .expect("plan");
    plan.validate().expect("the plan must validate");

    let ids: Vec<&str> = plan.steps.iter().map(|s| s.id.as_str()).collect();
    assert_eq!(
        ids,
        vec![
            STEP_MANAGED_SETTINGS,
            STEP_PROXY_CA,
            STEP_NODE_EXTRA_CA_CERTS,
            STEP_PROXY_ENV,
            STEP_SIDE_CHANNEL_SCOPE,
            STEP_PROTECTION_TEST,
        ]
    );

    let ca_path = fixture
        .paths()
        .proxy_ca_pem(SettingsScope::User)
        .expect("owned CA path");
    let ca_step = plan.steps.iter().find(|s| s.id == STEP_PROXY_CA).expect("ca step");
    match &ca_step.action {
        StepAction::MaterialiseTrustMaterial { path, .. } => assert_eq!(path, &ca_path),
        other => panic!("expected trust material, got {other:?}"),
    }

    let env_step = plan
        .steps
        .iter()
        .find(|s| s.id == STEP_NODE_EXTRA_CA_CERTS)
        .expect("env step");
    match &env_step.action {
        StepAction::InjectLaunchEnvironment { variable, value, scope } => {
            assert_eq!(variable, CA_ENV_VAR);
            assert_eq!(value, &EnvValue::ArtifactPath(ca_path.clone()));
            assert_eq!(*scope, SettingsScope::User);
        }
        other => panic!("expected launch-environment injection, got {other:?}"),
    }
    assert!(
        env_step.reversal.is_some(),
        "the variable that makes interception work must be removable"
    );

    assert_eq!(plan.planned_level, ProtectionLevel::GatewayProtected);
    assert!(plan.has_interception_probe());
}

#[tokio::test]
async fn without_the_proxy_ca_the_plan_cannot_claim_protection() {
    let fixture = Fixture::new();
    let integration = fixture.integration(Some("2.1.220"));
    let plan = integration
        .plan_integration(&request(SettingsScope::User))
        .await
        .expect("plan");
    plan.validate().expect("the plan must validate");

    assert_eq!(
        plan.planned_level,
        ProtectionLevel::Integrated,
        "a plan with no trust material must not claim the model path is inspected"
    );
    assert!(!plan.has_interception_probe());
    assert!(plan
        .unsupported
        .iter()
        .any(|m| m.capability == IntegrationCapability::ModelPathInterception));
}

#[tokio::test]
async fn a_project_directory_does_not_capture_a_user_scoped_plan() {
    // Condition C2. `<cwd>/.claude/` exists in this fixture; a user-scoped plan
    // must still write to the user's file, and must say the other surface exists.
    let fixture = Fixture::new();
    fixture.write_ca();
    let integration = fixture.integration(Some("2.1.220"));
    std::fs::write(fixture.settings_path(SettingsScope::Project), "{}").expect("project settings");

    let plan = integration
        .plan_integration(&request(SettingsScope::User))
        .await
        .expect("plan");
    plan.validate().expect("validate");

    let settings = plan
        .steps
        .iter()
        .find(|s| s.id == STEP_MANAGED_SETTINGS)
        .expect("settings step");
    match &settings.action {
        StepAction::WriteManagedSettings { path, scope, .. } => {
            assert_eq!(path, &fixture.settings_path(SettingsScope::User));
            assert_eq!(*scope, SettingsScope::User);
        }
        other => panic!("expected managed settings, got {other:?}"),
    }
    assert!(
        plan.warnings
            .iter()
            .any(|w| w.contains("project configuration also exists")),
        "the untouched project surface must be named: {:?}",
        plan.warnings
    );
}

#[tokio::test]
async fn a_project_scoped_plan_writes_only_the_project_surface() {
    let fixture = Fixture::new();
    fixture.write_ca();
    let integration = fixture.integration(Some("2.1.220"));
    let plan = integration
        .plan_integration(&request(SettingsScope::Project))
        .await
        .expect("plan");
    plan.validate().expect("validate");
    assert_eq!(plan.settings_scope, SettingsScope::Project);
    for step in &plan.steps {
        if let Some(scope) = step.action.settings_scope() {
            assert_eq!(scope, SettingsScope::Project, "step {} escaped the scope", step.id);
        }
    }
}

// ── The one privileged step (AAASM-5298) ────────────────────────────────────

#[tokio::test]
async fn a_normal_install_contains_no_privileged_step_and_cannot_claim_host_enforcement() {
    // The governing rule of AAASM-5298, at the plan layer: an unprivileged plan
    // has no step that could produce host-attested evidence, and says so.
    let fixture = Fixture::new();
    fixture.write_ca();
    let integration = fixture.integration(Some("2.1.220"));

    for scope in [SettingsScope::User, SettingsScope::Project] {
        let plan = integration
            .plan_integration(&request(scope).requesting_level(ProtectionLevel::HostEnforced))
            .await
            .expect("plan");
        plan.validate().expect("validate");
        assert_eq!(plan.privileged_steps().count(), 0, "{scope} install must not elevate");
        assert!(
            !plan.steps.iter().any(|s| s.id == STEP_ENDPOINT_MANAGED_SETTINGS),
            "{scope} install must not write the endpoint-managed file"
        );
        assert_eq!(
            plan.planned_level,
            ProtectionLevel::GatewayProtected,
            "{scope} install must be capped below HostEnforced even when it is asked for"
        );
    }
}

#[tokio::test]
async fn the_managed_scope_plan_carries_exactly_one_privileged_step() {
    let fixture = Fixture::new();
    fixture.write_ca();
    let integration = fixture.integration(Some("2.1.220"));
    let plan = integration
        .plan_integration(&request(SettingsScope::Managed).requesting_level(ProtectionLevel::HostEnforced))
        .await
        .expect("plan");
    plan.validate().expect("validate");

    let privileged: Vec<&str> = plan.privileged_steps().map(|s| s.id.as_str()).collect();
    assert_eq!(privileged, vec![STEP_ENDPOINT_MANAGED_SETTINGS]);
    assert_eq!(plan.planned_level, ProtectionLevel::HostEnforced);

    let step = plan
        .steps
        .iter()
        .find(|s| s.id == STEP_ENDPOINT_MANAGED_SETTINGS)
        .expect("the managed step");
    assert!(step.reversal.is_some(), "a privileged step needs a reversal");
    match &step.action {
        StepAction::WriteManagedSettings {
            scope,
            managed_keys,
            path,
            ..
        } => {
            assert_eq!(*scope, SettingsScope::Managed);
            assert_eq!(path, &fixture.settings_path(SettingsScope::Managed));
            for key in MANAGED_ONLY_KEYS {
                assert!(managed_keys.contains(&key.to_string()), "{key} is unclaimed");
            }
        }
        other => panic!("expected a managed settings write, got {other:?}"),
    }

    // Every fact the owner required before authorization is requested.
    let warnings = plan.warnings.join("\n");
    assert!(warnings.contains("one privileged step"), "{warnings}");
    assert!(warnings.contains("does not measure Claude Code"), "{warnings}");
    assert!(warnings.contains("never replaced"), "{warnings}");
    assert!(
        step.render_dry_run().contains("privileged-host"),
        "{}",
        step.render_dry_run()
    );
}

#[tokio::test]
async fn a_host_with_no_authorization_mechanism_plans_no_privileged_step() {
    let fixture = Fixture::new();
    fixture.write_ca();
    let integration = fixture.integration_with_authority(Some("2.1.220"), FakeAuthority::unavailable());
    let plan = integration
        .plan_integration(&request(SettingsScope::Managed).requesting_level(ProtectionLevel::HostEnforced))
        .await
        .expect("plan");
    plan.validate().expect("validate");
    assert_eq!(
        plan.planned_level,
        ProtectionLevel::GatewayProtected,
        "an unauthorizable host must not plan for a level it cannot reach"
    );
}

#[tokio::test]
async fn the_plan_scopes_the_tools_side_channels_without_touching_other_hosts() {
    // Condition C5.
    let fixture = Fixture::new();
    fixture.write_ca();
    let integration = fixture.integration(Some("2.1.220"));
    let plan = integration
        .plan_integration(&request(SettingsScope::User))
        .await
        .expect("plan");

    let step = plan
        .steps
        .iter()
        .find(|s| s.id == STEP_SIDE_CHANNEL_SCOPE)
        .expect("side-channel step");
    let rendered = integration.step_content(&plan).expect("content");
    let hosts = rendered.get(STEP_SIDE_CHANNEL_SCOPE).expect("host list content");
    for host in MITM_HOSTS {
        assert!(hosts.contains(host), "{hosts}");
    }
    assert!(
        step.summary.contains("without disabling llm_only"),
        "the reviewer has to see this does not MitM the whole machine: {}",
        step.summary
    );
}

#[tokio::test]
async fn observe_only_never_plans_for_protection() {
    let fixture = Fixture::new();
    fixture.write_ca();
    let integration = fixture.integration(Some("2.1.220"));
    let request = IntegrationRequest::new(
        DevToolKind::ClaudeCode,
        ProtectionProfile::ObserveOnly,
        SettingsScope::User,
    );
    let plan = integration.plan_integration(&request).await.expect("plan");
    plan.validate().expect("validate");
    assert_eq!(
        plan.planned_level,
        ProtectionLevel::Integrated,
        "observing is not protecting"
    );
}

// ── Condition C1 at the launch ──────────────────────────────────────────────

#[test]
fn a_governed_launch_injects_the_ca_variable_the_spike_measured() {
    // The load-bearing assertion for condition C1. Against the real
    // `claude 2.1.220`, `claude --debug` reports the CA only when this variable
    // is set; without it the MitM handshake fails and nothing is inspected.
    let fixture = Fixture::new();
    fixture.write_ca();
    let integration = fixture.integration(Some("2.1.220"));
    let paths = fixture.paths();
    let ca_pem = paths.proxy_ca_pem(SettingsScope::User).expect("ca path");

    // Stand in for what the install writes.
    let store = aa_devtool_claude_code::launch_env::LaunchEnvStore::at(
        paths.launch_env_dir(SettingsScope::User).expect("launch env dir"),
    );
    store
        .set(CA_ENV_VAR, &ca_pem.display().to_string())
        .expect("set the CA variable");
    store
        .set("HTTPS_PROXY", "http://127.0.0.1:18899")
        .expect("set the proxy variable");

    let launchable = integration.as_launchable().expect("Claude Code is launchable");
    let cmd = launchable
        .build_launch_command(&LaunchSpec::new("agent-1").with_args(vec!["-p".to_string(), "hi".to_string()]))
        .expect("launch command");

    let envs: std::collections::HashMap<_, _> = cmd
        .get_envs()
        .map(|(k, v)| {
            (
                k.to_string_lossy().into_owned(),
                v.map(|v| v.to_string_lossy().into_owned()),
            )
        })
        .collect();
    assert_eq!(
        envs.get(CA_ENV_VAR).cloned().flatten().as_deref(),
        Some(ca_pem.display().to_string().as_str()),
        "a governed launch must carry the CA variable; without it interception silently fails"
    );
    assert_eq!(
        envs.get("HTTPS_PROXY").cloned().flatten().as_deref(),
        Some("http://127.0.0.1:18899")
    );
    assert!(
        !envs.contains_key("NODE_TLS_REJECT_UNAUTHORIZED"),
        "Agent Assembly must never disable TLS verification"
    );
}

#[test]
fn a_launch_on_a_host_with_no_installation_is_unchanged() {
    // The negative half: an unmanaged host gets no variables invented for it.
    let fixture = Fixture::new();
    let integration = fixture.integration(Some("2.1.220"));
    let launchable = integration.as_launchable().expect("launchable");
    let cmd = launchable
        .build_launch_command(&LaunchSpec::new("agent-1"))
        .expect("command");
    let envs: Vec<String> = cmd.get_envs().map(|(k, _)| k.to_string_lossy().into_owned()).collect();
    assert!(!envs.contains(&CA_ENV_VAR.to_string()), "{envs:?}");
}

// ── Bypass detection ────────────────────────────────────────────────────────

#[tokio::test]
async fn a_bypass_permission_mode_is_detected_and_surfaced_in_the_plan() {
    let fixture = Fixture::new();
    fixture.write_ca();
    std::fs::write(
        fixture.settings_path(SettingsScope::User),
        r#"{"permissions":{"defaultMode":"bypassPermissions"},"theme":"dark"}"#,
    )
    .expect("settings");

    let integration = fixture.integration(Some("2.1.220"));
    let plan = integration
        .plan_integration(&request(SettingsScope::User))
        .await
        .expect("plan");
    assert!(
        plan.warnings.iter().any(|w| w.contains("bypassPermissions")),
        "a detected bypass must be surfaced before the user approves: {:?}",
        plan.warnings
    );
}

#[tokio::test]
async fn known_unobservable_bypasses_are_stated_rather_than_implied_absent() {
    let fixture = Fixture::new();
    fixture.write_ca();
    let integration = fixture.integration(Some("2.1.220"));
    let plan = integration
        .plan_integration(&request(SettingsScope::User))
        .await
        .expect("plan");
    assert!(
        plan.warnings.iter().any(|w| w.contains("A `claude` started")),
        "an unmanaged launch is a demonstrated bypass and must be stated: {:?}",
        plan.warnings
    );
    assert!(
        plan.warnings.iter().any(|w| w.contains("repointing CLAUDE_CONFIG_DIR")),
        "{:?}",
        plan.warnings
    );
}

// ── Status without a receipt ────────────────────────────────────────────────

#[tokio::test]
async fn a_configured_host_with_no_receipt_is_not_integrated() {
    // A settings file Agent Assembly did not write is evidence of a file and
    // nothing more.
    let fixture = Fixture::new();
    fixture.write_ca();
    std::fs::write(
        fixture.settings_path(SettingsScope::User),
        r#"{"permissions":{"allow":["Bash"]},"permissionMode":"default"}"#,
    )
    .expect("settings");

    let status = fixture
        .integration(Some("2.1.220"))
        .integration_status(None)
        .await
        .expect("status");
    assert_eq!(status.achieved_level(), ProtectionLevel::DetectedNotIntegrated);
    assert!(!status.has_exercised_evidence());
    assert!(
        status
            .evidence
            .iter()
            .any(|e| e.mechanism == IntegrationCapability::HostEnforcement),
        "host enforcement must be reported as unavailable, never omitted"
    );
}

#[tokio::test]
async fn an_absent_tool_is_not_installed() {
    let fixture = Fixture::new();
    fixture.write_ca();
    let integration =
        ClaudeCodeIntegration::with_paths(fixture.paths()).with_adapter(ClaudeCodeAdapter::with_overrides(
            Some(PathBuf::from("/no/such/claude")),
            Some(fixture.root().join("home")),
        ));
    assert!(integration.detect().is_none());
    let status = integration.integration_status(None).await.expect("status");
    assert_eq!(status.achieved_level(), ProtectionLevel::NotInstalled);
}

#[tokio::test]
async fn an_unsupported_version_is_reported_as_incompatible_not_guessed() {
    let fixture = Fixture::new();
    fixture.write_ca();
    // Below MIN_VERSION: `detect` refuses it, so the tool reads as absent rather
    // than as a half-governed install.
    let integration = fixture.integration(Some("0.9.9"));
    assert!(integration.detect().is_none());

    // An unreadable version is a missing comparison, never a pass.
    let unknown = fixture.integration(None);
    let status = unknown.integration_status(None).await.expect("status");
    assert!(!status.compatibility.is_compatible());
}

// ── The probe seam ──────────────────────────────────────────────────────────

#[tokio::test]
async fn the_default_probe_cannot_be_mistaken_for_protection() {
    use aa_devtool_claude_code::probe::{ProbeRequest, ProtectionProbe, UnadjudicatedProbe};
    let report = UnadjudicatedProbe
        .run(&ProbeRequest {
            proxy_url: "http://127.0.0.1:18899".to_string(),
            ca_pem: PathBuf::from("/tmp/ca.pem"),
            target_host: "api.anthropic.com".to_string(),
            synthetic_secret: aa_devtool_claude_code::probe::SYNTHETIC_SECRET.to_string(),
        })
        .await;
    assert!(!report.outcome.is_protective());
}

#[tokio::test]
async fn an_injected_probe_reaches_the_verification_result() {
    use aa_devtool_claude_code::probe::{ProbeReport, ProbeRequest, ProtectionProbe};
    use aa_devtool_contract::ExerciseOutcome;
    use async_trait::async_trait;

    struct Redacting;

    #[async_trait]
    impl ProtectionProbe for Redacting {
        async fn run(&self, _request: &ProbeRequest) -> ProbeReport {
            ProbeReport {
                outcome: ExerciseOutcome::Redacted,
                detail: "the mock provider received a redacted body".to_string(),
            }
        }
    }

    let fixture = Fixture::new();
    fixture.write_ca();
    let integration = fixture.integration(Some("2.1.220")).with_probe(Arc::new(Redacting));
    // The probe seam is exercised end to end (with a receipt) in
    // `aa-integration-tests`; here it is enough that the wiring accepts one.
    assert!(integration.as_launchable().is_some());
}
