//! One installable Claude Code integration, wired to a live proxy and a
//! recording provider, with every root inside a temp tree.
//!
//! # What this drives
//!
//! The **production** lifecycle: `EngineLifecycle` over the same
//! `claude_code_registration` the runtime constructs, writing real receipts
//! through a real [`ReceiptStore`]. The Spike's `spike_support::{receipt,
//! status}` stand-ins are deliberately *not* promoted — AAASM-5276 recorded
//! them as scaffolding that AAASM-5278 supersedes, and a conformance suite that
//! asserted against them would be measuring the harness rather than the product.
//!
//! What *is* promoted from the Spike is the measurement apparatus: the MitM
//! proxy driver, the TLS-terminating provider that records every body, and the
//! [`RealHomeGuard`]. Those are instruments, not stand-ins.
//!
//! # Safety
//!
//! Every root — the config home, the project directory, the state directory and
//! the certificate-authority directory — is an explicitly injected temp path.
//! Nothing here reads or writes the developer's real `~/.claude`, `~/.aa` or
//! `~/.aasm`; no process-global environment variable is mutated; no keychain
//! operation is performed; `NODE_TLS_REJECT_UNAUTHORIZED` is never set. Each
//! harness captures a [`RealHomeGuard`] at construction and every scenario ends
//! by asserting it unchanged.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use aa_core::integration::{
    IntegrationPlan, IntegrationReceipt, IntegrationRequest, IntegrationStatus, ProtectionProfile, ReceiptStore,
    RemovalPlan, SettingsScope, VerificationResult,
};
use aa_core::DevToolKind;
use aa_devtool_claude_code::probe::{ProbeRequest, SYNTHETIC_SECRET};
use aa_devtool_claude_code::{ClaudeCodeAdapter, ClaudeCodeIntegration, ClaudeCodePaths};
use aa_proxy::audit_jsonl::ProxyAuditEntry;
use aa_proxy::config::CredentialAction;
use aa_proxy::tls::CaStore;
use aa_runtime::devint::adapters::claude_code_registration;
use aa_runtime::devint::lifecycle::RepairReport;
use aa_runtime::devint::{EngineLifecycle, IntegrationLifecycle};
use tokio::sync::mpsc;

use super::probe::AdjudicatingProbe;
use super::proxy::RestartableProxy;
use crate::spike_support::proxy_harness::{install_crypto_provider, ANTHROPIC_HOST};
use crate::spike_support::{RealHomeGuard, TlsCapturingUpstream};

/// The version the harness reports for the tool unless a scenario overrides it.
///
/// The release AAASM-5276 measured on the reference host, so the conformance
/// suite and the Spike's evidence describe the same tool.
pub const MEASURED_TOOL_VERSION: &str = "2.1.220";

/// Knobs a scenario turns. Everything else about a harness is fixed, so a
/// difference in outcome is attributable to the knob that was turned.
pub struct HarnessOptions {
    /// What the proxy does with a credential finding. `RedactOnly` is
    /// enforcement; `AlertOnly` is the observe-only profile's behaviour.
    pub credential_action: CredentialAction,
    /// The version the adapter reports, without executing anything.
    pub tool_version: String,
    /// Whether the probe trusts the certificate authority the install
    /// materialised — AAASM-5276 condition C1.
    pub trust_injected_ca: bool,
    /// A sink for the proxy's audit entries, when a scenario inspects them.
    pub audit_tx: Option<mpsc::Sender<ProxyAuditEntry>>,
}

impl Default for HarnessOptions {
    fn default() -> Self {
        Self {
            credential_action: CredentialAction::RedactOnly,
            tool_version: MEASURED_TOOL_VERSION.to_string(),
            trust_injected_ca: true,
            audit_tx: None,
        }
    }
}

/// One installable integration and everything needed to measure it.
pub struct ConformanceHarness {
    _dir: tempfile::TempDir,
    home: PathBuf,
    state: PathBuf,
    ca_dir: PathBuf,
    stub_binary: PathBuf,
    service: EngineLifecycle,
    paths: ClaudeCodePaths,
    /// The provider that records every body it is given.
    pub upstream: Arc<TlsCapturingUpstream>,
    /// The core, stoppable and restartable.
    pub proxy: RestartableProxy,
    /// Receipts on disk, for the tamper scenario.
    pub store: ReceiptStore,
    ca_trust: Arc<AtomicBool>,
    tool_version: String,
    guard: RealHomeGuard,
}

impl ConformanceHarness {
    /// A harness with default options.
    pub async fn start() -> anyhow::Result<Self> {
        Self::with_options(HarnessOptions::default()).await
    }

    /// A harness with the knobs a scenario needs turned.
    pub async fn with_options(options: HarnessOptions) -> anyhow::Result<Self> {
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

        // The proxy's real certificate authority: generated, persisted in the
        // temp tree, and never installed into any system trust store.
        let ca = CaStore::load_or_create(&ca_dir)
            .await
            .map_err(|e| anyhow::anyhow!("certificate authority: {e}"))?;
        let upstream = Arc::new(TlsCapturingUpstream::start(&ca, ANTHROPIC_HOST).await?);
        drop(ca);
        let proxy =
            RestartableProxy::start(&ca_dir, upstream.addr, options.credential_action, options.audit_tx).await?;

        let paths = ClaudeCodePaths::default()
            .with_home(&home)
            .with_project(&repo)
            .with_state(&state)
            .with_ca_source(ca_dir.join("ca-cert.pem"));

        // A file standing in for the binary: detection resolves a path and asks
        // the version probe, and the override answers without executing it. The
        // suite must run on hosts that have no `claude`.
        let stub_binary = dir.path().join("claude");
        std::fs::write(&stub_binary, "")?;

        let probe = AdjudicatingProbe::new(Arc::clone(&upstream));
        let ca_trust = probe.trust_switch();
        ca_trust.store(options.trust_injected_ca, Ordering::SeqCst);

        let store = ReceiptStore::at(state.join("store"));
        let service = build_service(
            &paths,
            &stub_binary,
            &home,
            &options.tool_version,
            &proxy.url(),
            Arc::new(probe),
            &store,
        );

        Ok(Self {
            _dir: dir,
            home,
            state,
            ca_dir,
            stub_binary,
            service,
            paths,
            upstream,
            proxy,
            store,
            ca_trust,
            tool_version: options.tool_version,
            guard,
        })
    }

    /// A second lifecycle service over the *same* installation, with the tool
    /// reporting `version`.
    ///
    /// This is how a tool upgrade is modelled: the receipt, the settings file,
    /// the trust material and the launch environment are all exactly as the
    /// original install left them, and only the version the host reports has
    /// moved. A migration that silently reads as drift, or an incompatible
    /// version that silently reads as protected, shows up here.
    pub fn service_reporting_version(&self, version: &str) -> EngineLifecycle {
        let probe = AdjudicatingProbe::new(Arc::clone(&self.upstream));
        probe
            .trust_switch()
            .store(self.ca_trust.load(Ordering::SeqCst), Ordering::SeqCst);
        build_service(
            &self.paths,
            &self.stub_binary,
            &self.home,
            version,
            &self.proxy.url(),
            Arc::new(probe),
            &self.store,
        )
    }

    /// A second lifecycle service over the *same* installation, driven by the
    /// **shipped** probe instead of the harness's.
    ///
    /// [`AdjudicatingProbe`] adjudicates by reading the mock provider the
    /// harness owns — an instrument no developer has. This service runs exactly
    /// what `aasm integrations verify claude-code` runs on a real host, so an
    /// outcome measured through it is a statement about the product rather than
    /// about the harness.
    pub fn service_with_shipped_probe(&self) -> EngineLifecycle {
        let integration = Arc::new(
            ClaudeCodeIntegration::with_paths(self.paths.clone())
                .with_adapter(
                    ClaudeCodeAdapter::with_overrides(Some(self.stub_binary.clone()), Some(self.home.clone()))
                        .with_version_override(Some(self.tool_version.clone())),
                )
                .through_proxy(self.proxy.url()),
        );
        EngineLifecycle::new(vec![claude_code_registration(integration)], self.store.clone())
    }

    /// Verify through the shipped probe.
    pub async fn verify_as_shipped(&self) -> anyhow::Result<VerificationResult> {
        self.service_with_shipped_probe()
            .verify(&self.tool())
            .await
            .map_err(|e| anyhow::anyhow!("{e}"))
    }

    /// The probe request a shipped probe is handed for this installation.
    ///
    /// Scenarios that turn one condition (an untrusted authority, a stopped
    /// core) build from this so nothing else about the run differs.
    pub fn shipped_probe_request(&self) -> ProbeRequest {
        ProbeRequest {
            proxy_url: self.proxy.url(),
            ca_pem: self.ca_pem_path(),
            target_host: ANTHROPIC_HOST.to_string(),
            synthetic_secret: SYNTHETIC_SECRET.to_string(),
        }
    }

    /// The tool every operation names.
    pub fn tool(&self) -> DevToolKind {
        DevToolKind::ClaudeCode
    }

    /// Turn condition C1 on or off without changing anything else.
    pub fn set_ca_trust(&self, trusted: bool) {
        self.ca_trust.store(trusted, Ordering::SeqCst);
    }

    /// Author a plan without applying it.
    pub async fn plan(&self, profile: ProtectionProfile) -> anyhow::Result<IntegrationPlan> {
        self.service
            .plan(IntegrationRequest::new(self.tool(), profile, SettingsScope::User))
            .await
            .map_err(|e| anyhow::anyhow!("{e}"))
    }

    /// Plan and apply under `profile`.
    pub async fn install(&self, profile: ProtectionProfile) -> anyhow::Result<IntegrationReceipt> {
        let plan = self.plan(profile).await?;
        self.service
            .apply(&self.tool(), &plan.plan_id)
            .await
            .map_err(|e| anyhow::anyhow!("{e}"))
    }

    /// Re-derive the protection state.
    pub async fn status(&self) -> anyhow::Result<IntegrationStatus> {
        self.service
            .status(&self.tool())
            .await
            .map_err(|e| anyhow::anyhow!("{e}"))
    }

    /// Run the protection test.
    pub async fn verify(&self) -> anyhow::Result<VerificationResult> {
        self.service
            .verify(&self.tool())
            .await
            .map_err(|e| anyhow::anyhow!("{e}"))
    }

    /// Restore Agent Assembly-owned state.
    pub async fn repair(&self) -> anyhow::Result<(RepairReport, IntegrationStatus)> {
        self.service
            .repair(&self.tool())
            .await
            .map_err(|e| anyhow::anyhow!("{e}"))
    }

    /// Author the reversal without performing it.
    pub async fn removal_preview(&self) -> anyhow::Result<RemovalPlan> {
        self.service
            .remove(&self.tool(), None)
            .await
            .map_err(|e| anyhow::anyhow!("{e}"))
    }

    /// Perform the reversal `plan_id` describes.
    pub async fn remove(&self, plan_id: &str) -> anyhow::Result<RemovalPlan> {
        self.service
            .remove(&self.tool(), Some(plan_id))
            .await
            .map_err(|e| anyhow::anyhow!("{e}"))
    }

    /// The lifecycle service, for the assertions that need the raw error.
    pub fn service(&self) -> &EngineLifecycle {
        &self.service
    }

    /// The state directory every Agent Assembly-owned artifact lands under.
    pub fn state(&self) -> &Path {
        &self.state
    }

    /// The certificate-authority directory the proxy persists into.
    pub fn ca_dir(&self) -> &Path {
        &self.ca_dir
    }

    /// The user's settings file.
    pub fn settings_path(&self) -> PathBuf {
        self.home.join(".claude").join("settings.json")
    }

    /// Replace the user's settings file wholesale.
    pub fn write_settings(&self, body: &str) {
        std::fs::write(self.settings_path(), body).expect("write settings");
    }

    /// The user's settings file as JSON.
    pub fn read_settings(&self) -> serde_json::Value {
        let raw = std::fs::read_to_string(self.settings_path()).expect("read settings");
        serde_json::from_str(&raw).expect("settings json")
    }

    /// The user's settings file as bytes, for byte-exactness comparisons.
    pub fn settings_bytes(&self) -> Option<Vec<u8>> {
        std::fs::read(self.settings_path()).ok()
    }

    /// Where the install copies the proxy certificate authority.
    pub fn ca_pem_path(&self) -> PathBuf {
        self.paths.proxy_ca_pem(SettingsScope::User).expect("ca path")
    }

    /// The per-integration MitM host list — condition C5.
    pub fn mitm_hosts_path(&self) -> PathBuf {
        self.paths.mitm_hosts_file(SettingsScope::User).expect("hosts path")
    }

    /// The environment a governed launch would inherit.
    pub fn injected_env(&self) -> BTreeMap<String, String> {
        aa_devtool_claude_code::launch_env::installed_environment(&self.paths)
    }

    /// Every file Agent Assembly wrote under the state root, plus the settings
    /// file — the surfaces a leak assertion has to cover.
    pub fn persisted_surfaces(&self) -> Vec<(String, String)> {
        let mut out: Vec<(String, String)> = walk(&self.state)
            .into_iter()
            .map(|p| {
                let body = std::fs::read_to_string(&p).unwrap_or_default();
                (p.display().to_string(), body)
            })
            .collect();
        out.push((
            self.settings_path().display().to_string(),
            std::fs::read_to_string(self.settings_path()).unwrap_or_default(),
        ));
        out
    }

    /// Assert the developer's live configuration is untouched. Every scenario
    /// ends with this.
    pub fn finish(&self, scenario: &str) {
        self.guard.assert_unchanged(scenario);
    }
}

/// Build a lifecycle service over one set of injected roots.
///
/// Factored out because the upgrade scenario needs a *second* service over the
/// same installation, and two hand-rolled constructions could disagree about a
/// path — which the digest check would then report as a plan nobody changed.
#[allow(clippy::too_many_arguments)]
fn build_service(
    paths: &ClaudeCodePaths,
    stub_binary: &Path,
    home: &Path,
    tool_version: &str,
    proxy_url: &str,
    probe: Arc<AdjudicatingProbe>,
    store: &ReceiptStore,
) -> EngineLifecycle {
    let integration = Arc::new(
        ClaudeCodeIntegration::with_paths(paths.clone())
            .with_adapter(
                ClaudeCodeAdapter::with_overrides(Some(stub_binary.to_path_buf()), Some(home.to_path_buf()))
                    .with_version_override(Some(tool_version.to_string())),
            )
            .through_proxy(proxy_url)
            .with_probe(probe),
    );
    EngineLifecycle::new(vec![claude_code_registration(integration)], store.clone())
}

/// Every file under `root`, recursively.
pub fn walk(root: &Path) -> Vec<PathBuf> {
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
