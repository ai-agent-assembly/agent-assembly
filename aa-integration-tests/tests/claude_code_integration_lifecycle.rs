//! AAASM-5281 — the Claude Code Developer Integration, end to end against a
//! live `aa-proxy`, a real MitM CA and a TLS-terminating mock provider.
//!
//! # What this measures that a unit test cannot
//!
//! The whole ticket rests on AAASM-5276 condition C1: the proxy's MitM
//! handshake only succeeds if the tool trusts the Agent Assembly certificate
//! authority, and the product injected no CA-trust variable at all. Proving that
//! fix needs a real TLS handshake against a real intercepting proxy — a mock can
//! only prove that a string was written somewhere.
//!
//! So every protection assertion here runs traffic through a live
//! [`ProxyHarness`] whose upstream is a [`TlsCapturingUpstream`] recording
//! exactly what the provider received, and the negative case differs from the
//! positive one in **one variable**: whether the client trusts the CA the
//! install materialised and `NODE_EXTRA_CA_CERTS` points at.
//!
//! # Safety
//!
//! Every root is a temp directory injected explicitly. Nothing reads or writes
//! the developer's real `$HOME/.claude`, `$HOME/.aa` or
//! `/Library/Application Support/ClaudeCode`, and no keychain operation is
//! performed — [`RealHomeGuard`] fails the test loudly if the live settings file
//! changes. The secret is synthetic, prefixed `AAASM5281SYNTHETIC`, and matches
//! the deterministic scanner's `sk-ant-` pattern so redaction is genuinely
//! exercised.

/// The evidence ledger (AAASM-5465), declared once per test binary.
///
/// The support modules re-export it rather than declaring their own, because a
/// binary including two of them would otherwise load the same file twice.
#[path = "evidence/mod.rs"]
pub mod evidence;

#[allow(dead_code, unused_imports)]
mod spike_support;

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use aa_core::integration::{
    IntegrationRequest, ProtectionLevel, ProtectionProfile, ProtectionState, ReceiptStore, SettingsScope,
    VerificationOutcome,
};
use aa_core::DevToolKind;
use aa_devtool_claude_code::lifecycle::{CA_ENV_VAR, STEP_NODE_EXTRA_CA_CERTS, STEP_PROXY_CA};
use aa_devtool_claude_code::managed_settings::testing::FakeAuthority;
use aa_devtool_claude_code::managed_settings::PrivilegedFileAuthority;
use aa_devtool_claude_code::probe::{ProbeReport, ProbeRequest, ProtectionProbe, SYNTHETIC_SECRET};
use aa_devtool_claude_code::{ClaudeCodeAdapter, ClaudeCodeIntegration, ClaudeCodePaths};
use aa_devtool_contract::ExerciseOutcome;
use aa_proxy::config::CredentialAction;
use aa_proxy::tls::CaStore;
use aa_runtime::devint::adapters::claude_code_registration;
use aa_runtime::devint::{EngineLifecycle, IntegrationLifecycle, LifecycleTarget};
use async_trait::async_trait;
use base64::Engine as _;
use rustls::pki_types::CertificateDer;
use rustls::{ClientConfig, RootCertStore};
use spike_support::proxy_harness::{drive_emulated_client, install_crypto_provider, ProxyHarness, ANTHROPIC_HOST};
use spike_support::{find_secret, RealHomeGuard, TlsCapturingUpstream};

/// Unrelated user configuration that must survive every operation.
const USER_THEME: &str = "gruvbox";

// ── The probe ───────────────────────────────────────────────────────────────

/// A protection probe that can actually adjudicate, because the mock provider
/// records what it received.
///
/// This is the shape the production seam exists for: the default
/// `UnadjudicatedProbe` reports `Inconclusive` precisely because a client on the
/// near side of the proxy cannot see the forwarded body, and reporting
/// `Redacted` without seeing it would be the vacuous pass the evidence model
/// forbids.
struct MockProviderProbe {
    proxy_addr: SocketAddr,
    upstream: Arc<TlsCapturingUpstream>,
    /// When `false`, the probe client does **not** trust the CA the install
    /// materialised — standing in for a launch that never received
    /// `NODE_EXTRA_CA_CERTS`.
    trust_injected_ca: bool,
}

#[async_trait]
impl ProtectionProbe for MockProviderProbe {
    async fn run(&self, request: &ProbeRequest) -> ProbeReport {
        let before = self.upstream.request_count();

        let config = if self.trust_injected_ca {
            match client_trusting_pem(&request.ca_pem).await {
                Ok(config) => config,
                Err(e) => {
                    return ProbeReport {
                        outcome: ExerciseOutcome::Inconclusive,
                        detail: format!("the trust material could not be read: {e}"),
                    }
                }
            }
        } else {
            // An empty root store: exactly what a Node runtime that was never
            // given NODE_EXTRA_CA_CERTS sees when the proxy presents its
            // MitM-issued leaf.
            ClientConfig::builder()
                .with_root_certificates(RootCertStore::empty())
                .with_no_client_auth()
        };

        let prompt = format!("please audit this credential: {}", request.synthetic_secret);
        let result = match drive_emulated_client(self.proxy_addr, Arc::new(config), &prompt).await {
            Ok(result) => result,
            Err(e) => {
                return ProbeReport {
                    outcome: ExerciseOutcome::Inconclusive,
                    detail: format!("the probe could not reach the proxy: {e}"),
                }
            }
        };

        if let Some(response) = &result.inner_response {
            if response.starts_with("TLS error") {
                return ProbeReport {
                    outcome: ExerciseOutcome::Inconclusive,
                    detail: "the intercepting proxy's certificate was not trusted, so the model path \
                             was never inspected"
                        .to_string(),
                };
            }
        }

        let bodies: Vec<Vec<u8>> = self.upstream.bodies().into_iter().skip(before).collect();
        if bodies.is_empty() {
            return ProbeReport {
                outcome: ExerciseOutcome::Inconclusive,
                detail: "the provider recorded no request, so nothing was adjudicated".to_string(),
            };
        }
        match find_secret(&bodies, &request.synthetic_secret) {
            Some((idx, view, enc)) => ProbeReport {
                outcome: ExerciseOutcome::Leaked,
                detail: format!("the provider received the credential unredacted (body #{idx}, {view}, {enc})"),
            },
            None => ProbeReport {
                outcome: ExerciseOutcome::Redacted,
                detail: format!(
                    "{} request(s) reached the provider and none carried the credential",
                    bodies.len()
                ),
            },
        }
    }
}

/// A rustls client config trusting exactly one PEM file.
async fn client_trusting_pem(pem_path: &Path) -> anyhow::Result<ClientConfig> {
    let pem = tokio::fs::read_to_string(pem_path).await?;
    let body: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
    let der = base64::engine::general_purpose::STANDARD.decode(body)?;
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(der))?;
    Ok(ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth())
}

// ── Harness ─────────────────────────────────────────────────────────────────

struct Harness {
    _dir: tempfile::TempDir,
    home: PathBuf,
    state: PathBuf,
    service: EngineLifecycle,
    paths: ClaudeCodePaths,
    upstream: Arc<TlsCapturingUpstream>,
    _proxy: ProxyHarness,
    guard: RealHomeGuard,
}

impl Harness {
    async fn start(trust_injected_ca: bool) -> anyhow::Result<Self> {
        Self::start_with_authority(trust_injected_ca, FakeAuthority::granting()).await
    }

    async fn start_with_authority(
        trust_injected_ca: bool,
        authority: Arc<dyn PrivilegedFileAuthority>,
    ) -> anyhow::Result<Self> {
        install_crypto_provider();
        let guard = RealHomeGuard::capture();

        let dir = tempfile::tempdir()?;
        let home = dir.path().join("home");
        let repo = dir.path().join("repo");
        let state = dir.path().join("state");
        let ca_dir = dir.path().join("aa-ca");
        std::fs::create_dir_all(home.join(".claude"))?;
        std::fs::create_dir_all(&repo)?;
        std::fs::create_dir_all(&ca_dir)?;

        // The proxy's real CA — generated, persisted, and never installed into
        // any trust store.
        let ca = CaStore::load_or_create(&ca_dir)
            .await
            .map_err(|e| anyhow::anyhow!("ca: {e}"))?;
        let upstream = Arc::new(TlsCapturingUpstream::start(&ca, ANTHROPIC_HOST).await?);
        let proxy = ProxyHarness::start(&ca_dir, ca, CredentialAction::RedactOnly, upstream.addr, None).await?;

        let paths = ClaudeCodePaths::default()
            .with_home(&home)
            .with_project(&repo)
            .with_state(&state)
            .with_ca_source(ca_dir.join("ca-cert.pem"))
            // AAASM-5298: the endpoint-managed surface is redirected into the
            // fixture, and the real macOS authority refuses to elevate for
            // anything but the canonical path — so nothing here can reach an
            // administrator prompt or the real
            // `/Library/Application Support/ClaudeCode`.
            .with_managed_root(dir.path().join("ClaudeCode"));

        let stub_binary = dir.path().join("claude");
        std::fs::write(&stub_binary, "")?;

        let integration = Arc::new(
            ClaudeCodeIntegration::with_paths(paths.clone())
                .with_adapter(
                    ClaudeCodeAdapter::with_overrides(Some(stub_binary), Some(home.clone()))
                        .with_version_override(Some("2.1.220".to_string())),
                )
                .through_proxy(proxy.proxy_url())
                .with_probe(Arc::new(MockProviderProbe {
                    proxy_addr: proxy.addr,
                    upstream: Arc::clone(&upstream),
                    trust_injected_ca,
                }))
                .with_managed_authority(authority),
        );

        let service = EngineLifecycle::new(
            vec![claude_code_registration(integration)],
            ReceiptStore::at(state.join("store")),
        );

        Ok(Self {
            _dir: dir,
            home,
            state,
            service,
            paths,
            upstream,
            _proxy: proxy,
            guard,
        })
    }

    fn settings_path(&self) -> PathBuf {
        self.home.join(".claude").join("settings.json")
    }

    fn write_user_settings(&self, body: &str) {
        std::fs::write(self.settings_path(), body).expect("write settings");
    }

    fn read_user_settings(&self) -> serde_json::Value {
        let raw = std::fs::read_to_string(self.settings_path()).expect("read settings");
        serde_json::from_str(&raw).expect("settings json")
    }

    async fn install(&self) -> anyhow::Result<aa_core::integration::IntegrationReceipt> {
        let request = IntegrationRequest::new(
            DevToolKind::ClaudeCode,
            ProtectionProfile::Recommended,
            SettingsScope::User,
        );
        let plan = self.service.plan(request).await.map_err(|e| anyhow::anyhow!("{e}"))?;
        Ok(self
            .service
            .apply(&DevToolKind::ClaudeCode, &plan.plan_id, &LifecycleTarget::unspecified())
            .await
            .map_err(|e| anyhow::anyhow!("{e}"))?
            .receipt)
    }

    /// The opt-in, administrator-authorized install. Everything about it is
    /// explicit: the scope, the level it asks for, and the consent to the one
    /// privileged step.
    async fn install_managed(&self) -> anyhow::Result<aa_core::integration::IntegrationReceipt> {
        let request = IntegrationRequest::new(
            DevToolKind::ClaudeCode,
            ProtectionProfile::Recommended,
            SettingsScope::Managed,
        )
        .requesting_level(ProtectionLevel::HostEnforced)
        .allowing_privileged_host_steps();
        let plan = self.service.plan(request).await.map_err(|e| anyhow::anyhow!("{e}"))?;
        Ok(self
            .service
            .apply(&DevToolKind::ClaudeCode, &plan.plan_id, &LifecycleTarget::unspecified())
            .await
            .map_err(|e| anyhow::anyhow!("{e}"))?
            .receipt)
    }

    /// The same plan, without the consent the privileged step needs.
    async fn install_managed_without_consent(&self) -> anyhow::Result<String> {
        let request = IntegrationRequest::new(
            DevToolKind::ClaudeCode,
            ProtectionProfile::Recommended,
            SettingsScope::Managed,
        )
        .requesting_level(ProtectionLevel::HostEnforced);
        let plan = self.service.plan(request).await.map_err(|e| anyhow::anyhow!("{e}"))?;
        match self
            .service
            .apply(&DevToolKind::ClaudeCode, &plan.plan_id, &LifecycleTarget::unspecified())
            .await
        {
            Ok(_) => anyhow::bail!("an unconsented privileged step must not be applied"),
            Err(e) => Ok(e.to_string()),
        }
    }

    fn managed_settings_path(&self) -> PathBuf {
        self.paths.managed_settings_path()
    }

    fn ca_pem_path(&self) -> PathBuf {
        self.paths.proxy_ca_pem(SettingsScope::User).expect("ca path")
    }

    fn injected_env(&self) -> std::collections::BTreeMap<String, String> {
        aa_devtool_claude_code::launch_env::installed_environment(&self.paths)
    }

    fn finish(&self) {
        self.guard.assert_unchanged("AAASM-5281 lifecycle harness");
    }
}

// ── The cycle ───────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn install_status_verify_drift_repair_and_remove_are_one_cycle() -> anyhow::Result<()> {
    let h = Harness::start(true).await?;
    let tool = DevToolKind::ClaudeCode;
    h.write_user_settings(&format!(r#"{{"theme":"{USER_THEME}"}}"#));

    // ── install ────────────────────────────────────────────────────────────
    let receipt = h.install().await?;
    assert_eq!(receipt.settings_scope, SettingsScope::User);
    assert_eq!(
        receipt.achieved_level,
        ProtectionLevel::Integrated,
        "an apply configures; it does not exercise traffic"
    );
    assert!(h.ca_pem_path().is_file(), "condition C1: the CA must be materialised");
    assert_eq!(
        h.injected_env().get(CA_ENV_VAR).map(String::as_str),
        Some(h.ca_pem_path().display().to_string().as_str()),
        "condition C1: NODE_EXTRA_CA_CERTS must point at the materialised CA"
    );
    assert!(
        h.state.join("mitm-hosts.d").read_dir()?.next().is_some(),
        "condition C5: the side-channel host list must be written"
    );
    assert_eq!(
        h.read_user_settings()["theme"],
        serde_json::json!(USER_THEME),
        "an unrelated user key must survive the install"
    );

    // Repeated install is idempotent, down to the bytes.
    let before = std::fs::read(h.settings_path())?;
    let again = h.install().await?;
    assert_eq!(
        again.receipt_id, receipt.receipt_id,
        "a no-op reapply is not an upgrade"
    );
    assert_eq!(std::fs::read(h.settings_path())?, before);

    // ── status ─────────────────────────────────────────────────────────────
    let status = h
        .service
        .status(&tool, &LifecycleTarget::unspecified())
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    // The plan aimed at GatewayProtected and configuration alone cannot get
    // there, so the honest reading is Degraded with the gap named — not a
    // quietly smaller ladder rung.
    match &status.state {
        ProtectionState::Degraded {
            planned,
            achieved,
            reason,
        } => {
            assert_eq!(*planned, ProtectionLevel::GatewayProtected);
            assert_eq!(*achieved, ProtectionLevel::Integrated);
            assert!(
                reason.contains("has been produced and adjudicated") || reason.contains("verify claude-code"),
                "the gap a user can close must be named first: {reason}"
            );
        }
        other => panic!("expected a Degraded reading immediately after install, got {other:?}"),
    }
    assert!(
        !status.has_exercised_evidence(),
        "configuration alone must never look like traffic evidence"
    );
    assert!(status.next_level.is_some(), "the next rung up is always reported");

    // ── verify ─────────────────────────────────────────────────────────────
    let verification = h
        .service
        .verify(&tool, &LifecycleTarget::unspecified())
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    assert_eq!(
        verification.outcome,
        VerificationOutcome::Passed,
        "the probe traversed the intercepted path and the provider got a redacted body"
    );
    assert!(verification.has_exercised_evidence());
    assert!(
        h.upstream.request_count() > 0,
        "the mock provider must have recorded a request — otherwise 'no secret arrived' proves nothing"
    );

    let after_verify = h
        .service
        .status(&tool, &LifecycleTarget::unspecified())
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    assert_eq!(
        after_verify.achieved_level(),
        ProtectionLevel::GatewayProtected,
        "only exercised, adjudicated interception may raise the ladder this far"
    );

    // ── drift ──────────────────────────────────────────────────────────────
    // The user re-enables the bypass mode the install displaced, and separately
    // changes something of their own.
    let mut doc = h.read_user_settings();
    doc["permissions"]["defaultMode"] = serde_json::json!("bypassPermissions");
    doc["editor"] = serde_json::json!("nvim");
    std::fs::write(h.settings_path(), serde_json::to_string_pretty(&doc)?)?;

    let drifted = h
        .service
        .status(&tool, &LifecycleTarget::unspecified())
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    assert!(
        matches!(drifted.state, ProtectionState::Drifted { .. }),
        "a change to an Agent Assembly-owned key must be detected: {:?}",
        drifted.state
    );

    // ── repair ─────────────────────────────────────────────────────────────
    let (report, repaired) = h
        .service
        .repair(&tool, &LifecycleTarget::unspecified())
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    assert!(!report.repaired.is_empty(), "repair must name what it restored");
    assert!(
        !matches!(repaired.state, ProtectionState::Drifted { .. }),
        "{:?}",
        repaired.state
    );
    let after_repair = h.read_user_settings();
    assert_eq!(after_repair["permissions"]["defaultMode"], serde_json::json!("default"));
    assert_eq!(
        after_repair["editor"],
        serde_json::json!("nvim"),
        "a change the user made after install is theirs and must survive repair"
    );
    assert_eq!(after_repair["theme"], serde_json::json!(USER_THEME));

    // ── remove ─────────────────────────────────────────────────────────────
    let preview = h
        .service
        .remove(&tool, &LifecycleTarget::unspecified(), None)
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    assert!(!preview.steps.is_empty(), "the preview must show what will be undone");
    assert!(h.ca_pem_path().is_file(), "a preview must not remove anything");

    let removal = h
        .service
        .remove(&tool, &LifecycleTarget::unspecified(), Some(&preview.plan_id))
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    assert!(
        removal.residual.is_empty(),
        "nothing should be left behind: {:?}",
        removal.residual
    );
    assert!(!h.ca_pem_path().exists(), "the copied CA must be gone");
    assert!(
        !h.injected_env().contains_key(CA_ENV_VAR),
        "removal must stop injecting the CA variable"
    );
    let restored = h.read_user_settings();
    assert_eq!(restored["theme"], serde_json::json!(USER_THEME));
    assert_eq!(restored["editor"], serde_json::json!("nvim"));
    assert!(
        restored.get("permissions").is_none() && restored.get("permissionMode").is_none(),
        "removal must delete the keys Agent Assembly added: {restored}"
    );

    // Removing twice is idempotent from the client's point of view.
    assert!(h
        .service
        .remove(&tool, &LifecycleTarget::unspecified(), None)
        .await
        .is_err());

    h.finish();
    Ok(())
}

// ── Condition C1, proved load-bearing ───────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn without_the_injected_ca_the_protection_test_cannot_pass() -> anyhow::Result<()> {
    // Identical to the cycle above in every respect except one: the probe client
    // does not trust the certificate authority the install materialised and
    // NODE_EXTRA_CA_CERTS points at. That is the whole of AAASM-5276 condition
    // C1 — and without it the MitM handshake fails, so nothing is inspected.
    let h = Harness::start(false).await?;
    let tool = DevToolKind::ClaudeCode;
    h.write_user_settings("{}");
    h.install().await?;

    let verification = h
        .service
        .verify(&tool, &LifecycleTarget::unspecified())
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    assert!(
        !matches!(verification.outcome, VerificationOutcome::Passed),
        "a failed TLS handshake must not read as a pass: {:?}",
        verification.outcome
    );
    let status = h
        .service
        .status(&tool, &LifecycleTarget::unspecified())
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    assert!(
        status.achieved_level() < ProtectionLevel::GatewayProtected,
        "with the CA untrusted the model path is not intercepted, so protection must not be claimed: {:?}",
        status.state
    );
    h.finish();
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn verify_cannot_pass_on_configuration_alone() -> anyhow::Result<()> {
    // The second load-bearing guard: an integration with the default,
    // non-adjudicating probe is fully applied and fully read-back-verifiable,
    // and still must not reach GatewayProtected.
    let dir = tempfile::tempdir()?;
    let guard = RealHomeGuard::capture();
    let home = dir.path().join("home");
    let ca_dir = dir.path().join("aa-ca");
    std::fs::create_dir_all(home.join(".claude"))?;
    std::fs::create_dir_all(&ca_dir)?;
    std::fs::write(
        ca_dir.join("ca-cert.pem"),
        "-----BEGIN CERTIFICATE-----\nAAASM5281FAKE\n-----END CERTIFICATE-----\n",
    )?;
    let stub = dir.path().join("claude");
    std::fs::write(&stub, "")?;

    let paths = ClaudeCodePaths::default()
        .with_home(&home)
        .with_project(dir.path().join("repo"))
        .with_state(dir.path().join("state"))
        .with_ca_source(ca_dir.join("ca-cert.pem"));
    let integration = Arc::new(ClaudeCodeIntegration::with_paths(paths).with_adapter(
        ClaudeCodeAdapter::with_overrides(Some(stub), Some(home)).with_version_override(Some("2.1.220".to_string())),
    ));
    let service = EngineLifecycle::new(
        vec![claude_code_registration(integration)],
        ReceiptStore::at(dir.path().join("store")),
    );

    let tool = DevToolKind::ClaudeCode;
    let plan = service
        .plan(IntegrationRequest::new(
            tool.clone(),
            ProtectionProfile::Recommended,
            SettingsScope::User,
        ))
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    service
        .apply(&tool, &plan.plan_id, &LifecycleTarget::unspecified())
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    let verification = service
        .verify(&tool, &LifecycleTarget::unspecified())
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    assert!(
        !matches!(verification.outcome, VerificationOutcome::Passed),
        "an unadjudicated probe must not pass: {:?}",
        verification.outcome
    );
    let status = service
        .status(&tool, &LifecycleTarget::unspecified())
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    assert_eq!(
        status.achieved_level(),
        ProtectionLevel::Integrated,
        "configuration read back perfectly is still not protection"
    );
    guard.assert_unchanged("configuration-alone guard");
    Ok(())
}

// ── Secret hygiene ──────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn the_raw_secret_is_absent_from_every_artifact_while_the_finding_survives() -> anyhow::Result<()> {
    let h = Harness::start(true).await?;
    let tool = DevToolKind::ClaudeCode;
    h.write_user_settings("{}");
    h.install().await?;

    let verification = h
        .service
        .verify(&tool, &LifecycleTarget::unspecified())
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let status = h
        .service
        .status(&tool, &LifecycleTarget::unspecified())
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    let mut surfaces: Vec<(String, String)> = vec![
        ("verification".to_string(), serde_json::to_string(&verification)?),
        ("status".to_string(), serde_json::to_string(&status)?),
    ];
    // Every file Agent Assembly wrote, receipt and journal included.
    for entry in walk(&h.state) {
        let body = std::fs::read_to_string(&entry).unwrap_or_default();
        surfaces.push((entry.display().to_string(), body));
    }
    surfaces.push((
        "settings".to_string(),
        std::fs::read_to_string(h.settings_path()).unwrap_or_default(),
    ));

    for (label, body) in &surfaces {
        assert!(
            !body.contains(SYNTHETIC_SECRET),
            "the raw synthetic secret appeared in {label}"
        );
    }

    // The load-bearing other half: the *finding* must still be there, or the
    // absence above would be satisfied by recording nothing at all.
    let evidence = serde_json::to_string(&verification.evidence)?;
    assert!(
        evidence.contains("redacted") || evidence.contains("Redacted"),
        "the adjudicated outcome must survive redaction: {evidence}"
    );
    assert!(
        h.upstream.request_count() > 0,
        "traffic must have flowed for this assertion to mean anything"
    );

    h.finish();
    Ok(())
}

// ── Bypass detection ────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn a_bypass_condition_is_detected_and_surfaced_in_status() -> anyhow::Result<()> {
    let h = Harness::start(true).await?;
    let tool = DevToolKind::ClaudeCode;
    h.write_user_settings("{}");
    h.install().await?;

    // The user re-enables the mode the install displaced.
    let mut doc = h.read_user_settings();
    doc["permissions"]["defaultMode"] = serde_json::json!("bypassPermissions");
    std::fs::write(h.settings_path(), serde_json::to_string_pretty(&doc)?)?;

    let status = h
        .service
        .status(&tool, &LifecycleTarget::unspecified())
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let rendered = serde_json::to_string(&status)?;
    assert!(
        rendered.contains("bypassPermissions"),
        "a detected bypass must reach the status a user reads: {rendered}"
    );

    let verification = h
        .service
        .verify(&tool, &LifecycleTarget::unspecified())
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    assert!(
        !matches!(verification.outcome, VerificationOutcome::Passed),
        "verification must not pass while a known bypass is active: {:?}",
        verification.outcome
    );

    h.finish();
    Ok(())
}

/// Every file under `root`, recursively.
fn walk(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(root) else {
        return out;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            out.extend(walk(&path));
        } else {
            out.push(path);
        }
    }
    out
}

/// The removal plan names the two artifacts condition C1 depends on, so a user
/// reviewing a removal can see the trust material and the variable go.
#[tokio::test(flavor = "multi_thread")]
async fn the_removal_preview_names_the_trust_material_and_the_variable() -> anyhow::Result<()> {
    let h = Harness::start(true).await?;
    h.write_user_settings("{}");
    h.install().await?;

    let preview = h
        .service
        .remove(&DevToolKind::ClaudeCode, &LifecycleTarget::unspecified(), None)
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let rendered = preview.render_dry_run();
    assert!(rendered.contains(CA_ENV_VAR), "{rendered}");
    assert!(rendered.contains("certificate authority"), "{rendered}");
    assert!(preview.steps.iter().any(|s| s.id.contains(STEP_PROXY_CA)), "{rendered}");
    assert!(
        preview.steps.iter().any(|s| s.id.contains(STEP_NODE_EXTRA_CA_CERTS)),
        "{rendered}"
    );
    h.finish();
    Ok(())
}

// ── AAASM-5298: the one privileged step, end to end ─────────────────────────

/// The governing rule, measured through the engine rather than asserted in a
/// unit test: a successful **normal** installation, fully verified, with real
/// adjudicated traffic behind it, still cannot report `Host Enforced`.
#[tokio::test(flavor = "multi_thread")]
async fn a_successful_normal_install_cannot_reach_host_enforced() -> anyhow::Result<()> {
    let h = Harness::start(true).await?;
    let tool = DevToolKind::ClaudeCode;

    h.install().await?;
    let verification = h
        .service
        .verify(&tool, &LifecycleTarget::unspecified())
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    assert_eq!(verification.outcome, VerificationOutcome::Passed);

    let status = h
        .service
        .status(&tool, &LifecycleTarget::unspecified())
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    assert_eq!(
        status.achieved_level(),
        ProtectionLevel::GatewayProtected,
        "the best an unprivileged install can prove is that traffic was governed"
    );
    assert!(
        !h.managed_settings_path().exists(),
        "an unprivileged install must not write the endpoint-managed file"
    );
    assert!(
        !status
            .evidence
            .iter()
            .any(aa_core::integration::ProtectionEvidence::is_host_enforcement_grade),
        "a normal install must produce no host-attested evidence: {:?}",
        status.evidence
    );
    let next = status.next_level.as_ref().expect("the next rung is always reported");
    assert_eq!(next.level, ProtectionLevel::HostEnforced);
    assert!(
        next.blocked_because.contains("--install-managed-settings"),
        "the reason must name the opt-in: {}",
        next.blocked_because
    );

    h.finish();
    Ok(())
}

/// The authorized path: one privileged step, read back and verified, and only
/// then `Host Enforced` — reversed symmetrically on removal.
#[tokio::test(flavor = "multi_thread")]
async fn an_authorized_managed_install_reaches_host_enforced_and_is_reversible() -> anyhow::Result<()> {
    let h = Harness::start(true).await?;
    let tool = DevToolKind::ClaudeCode;

    let receipt = h.install_managed().await?;
    assert_eq!(receipt.settings_scope, SettingsScope::Managed);
    let installed = std::fs::read_to_string(h.managed_settings_path())?;
    assert!(installed.contains("disableBypassPermissionsMode"), "{installed}");

    // Configuration alone still does not raise the ladder past Integrated.
    let after_install = h
        .service
        .status(&tool, &LifecycleTarget::unspecified())
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    assert!(after_install.achieved_level() <= ProtectionLevel::Integrated);

    let verification = h
        .service
        .verify(&tool, &LifecycleTarget::unspecified())
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    assert_eq!(verification.outcome, VerificationOutcome::Passed);

    let status = h
        .service
        .status(&tool, &LifecycleTarget::unspecified())
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    assert_eq!(
        status.achieved_level(),
        ProtectionLevel::HostEnforced,
        "an authorized, read-back-verified managed install is the only route to this rung: {:?}",
        status.state
    );
    let attested = status
        .evidence
        .iter()
        .find(|e| e.is_host_enforcement_grade())
        .expect("host-attested evidence");
    assert!(
        attested.detail.contains("has not measured Claude Code"),
        "the attestation must state what it does not claim: {}",
        attested.detail
    );

    // ── removal is symmetric, including the no-prior-file case ─────────────
    let removal = h
        .service
        .remove(
            &tool,
            &LifecycleTarget::unspecified(),
            Some(&format!("remove-{}", receipt.receipt_id)),
        )
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    assert!(removal.residual.is_empty(), "{:?}", removal.residual);
    assert!(
        !h.managed_settings_path().exists(),
        "there was no managed file before the install, so there must be none after the removal"
    );

    h.finish();
    Ok(())
}

/// A privileged step the request did not consent to is refused by the service,
/// before the authority is ever asked.
#[tokio::test(flavor = "multi_thread")]
async fn the_privileged_step_is_refused_without_consent() -> anyhow::Result<()> {
    let h = Harness::start(true).await?;
    let message = h.install_managed_without_consent().await?;
    assert!(message.contains("changes host state"), "{message}");
    assert!(
        !h.managed_settings_path().exists(),
        "an unconsented plan must write nothing"
    );
    h.finish();
    Ok(())
}

/// Denied authorization is a failure, never a quieter install.
#[tokio::test(flavor = "multi_thread")]
async fn denied_authorization_fails_the_install_rather_than_downgrading_it() -> anyhow::Result<()> {
    let h = Harness::start_with_authority(true, FakeAuthority::denying()).await?;
    let err = h
        .install_managed()
        .await
        .expect_err("a denied authorization must fail the install");
    let message = err.to_string();
    assert!(message.contains("Permission Required"), "{message}");
    assert!(
        !h.managed_settings_path().exists(),
        "a denied install must leave nothing behind"
    );

    // And nothing claims host enforcement afterwards.
    let status = h
        .service
        .status(&DevToolKind::ClaudeCode, &LifecycleTarget::unspecified())
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    assert!(
        status.achieved_level() < ProtectionLevel::HostEnforced,
        "{:?}",
        status.state
    );
    h.finish();
    Ok(())
}

/// A read-back that does not match what was authorized prevents the success
/// receipt — the install fails and the host is put back.
#[tokio::test(flavor = "multi_thread")]
async fn a_read_back_mismatch_prevents_the_success_receipt() -> anyhow::Result<()> {
    let h = Harness::start_with_authority(
        true,
        FakeAuthority::corrupting(r#"{"disableBypassPermissionsMode":false}"#),
    )
    .await?;
    let err = h
        .install_managed()
        .await
        .expect_err("a read-back mismatch must fail the install");
    let message = err.to_string();
    assert!(message.contains("Read-back verification failed"), "{message}");
    assert!(
        !h.managed_settings_path().exists(),
        "the failed write must have been rolled back"
    );
    h.finish();
    Ok(())
}

/// A managed-settings file Agent Assembly did not write is never merged over.
#[tokio::test(flavor = "multi_thread")]
async fn a_third_party_managed_file_is_refused_and_left_alone() -> anyhow::Result<()> {
    const MDM_POLICY: &str = r#"{"disableBypassPermissionsMode":true,"permissions":{"deny":["Bash"]}}"#;
    let h = Harness::start(true).await?;
    let managed = h.managed_settings_path();
    std::fs::create_dir_all(managed.parent().expect("parent"))?;
    std::fs::write(&managed, MDM_POLICY)?;

    let err = h
        .install_managed()
        .await
        .expect_err("a file Agent Assembly did not write must not be replaced");
    assert!(err.to_string().contains("Conflicting managed settings"), "{err}");
    assert_eq!(
        std::fs::read_to_string(&managed)?,
        MDM_POLICY,
        "the third party's policy must be exactly as it was"
    );
    h.finish();
    Ok(())
}
