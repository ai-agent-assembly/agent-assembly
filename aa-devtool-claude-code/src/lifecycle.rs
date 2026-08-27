//! The native Developer Integration for Claude Code.
//!
//! # What this adds over [`ClaudeCodeAdapter`]
//!
//! The legacy adapter can detect the tool, render settings, write them and build
//! a launch command. It cannot answer *"is this developer actually protected
//! right now, and how do you know?"* — and, measured against the real
//! `claude 2.1.220` binary in AAASM-5276, the launch command it built could not
//! make the protection work at all: it injected `HTTPS_PROXY` and no CA-trust
//! variable, so the proxy's MitM handshake failed and `GatewayProtected` was
//! silently unreachable.
//!
//! [`ClaudeCodeIntegration`] is the lifecycle implementation, and it **reuses**
//! the legacy adapter for detection rather than duplicating it. Three things are
//! genuinely new:
//!
//! 1. **Condition C1 — trust material.** The plan materialises the proxy CA as a
//!    PEM Agent Assembly owns ([`StepAction::MaterialiseTrustMaterial`]) and
//!    points `NODE_EXTRA_CA_CERTS` at it
//!    ([`StepAction::InjectLaunchEnvironment`]). Both land in the plan, both are
//!    fingerprinted into the receipt, both are reversed by removal, and
//!    [`LaunchableTool::build_launch_command`] is where they reach the child
//!    process. Without the CA variable the MitM handshake fails, so this is the
//!    step the entire `GatewayProtected` claim rests on.
//! 2. **Condition C2 — explicit scope.** Every settings-touching step gets its
//!    path from [`ClaudeCodePaths`], which takes the scope as an argument and
//!    has no "whichever one exists in the working directory" branch.
//! 3. **Condition C5 — side channels.** One headless run produced four upstream
//!    requests, only two of which were `/v1/messages`. The plan writes a
//!    per-integration MitM host list the proxy unions into its own configuration,
//!    so this tool's side channels are scanned **without** flipping the global
//!    `llm_only` default and MitM-ing every host on the machine.
//!
//! # What it deliberately does not do
//!
//! * `ANTHROPIC_BASE_URL` redirection is declared
//!   [`Unsupported`](aa_devtool_contract::CapabilitySupport::Unsupported), not
//!   offered. AAASM-5276 measured it delivering the raw secret to the provider
//!   with no Agent Assembly component in the path (condition C4).
//! * Hooks are declared unsupported *for protection*: they govern tool and
//!   action execution and cannot see model-bound content, so no hook can carry a
//!   sensitive-data claim.
//! * `NODE_TLS_REJECT_UNAUTHORIZED` is never set, and its presence is reported
//!   as a bypass. A TLS failure is a finding.
//! * The macOS System Keychain is never touched.
//!
//! # The one privileged step, and why a normal install cannot reach it
//!
//! AAASM-5298 adds an **opt-in** endpoint managed-settings install
//! (`--scope managed`, which the CLI exposes as `--install-managed-settings`).
//! It is the only step in this integration marked
//! [`StepPrivilege::PrivilegedHost`](aa_devtool_contract::StepPrivilege), the
//! only one that asks for administrator authorization, and it is absent from
//! every user- and project-scoped plan. Its evidence is
//! [`EvidenceKind::HostAttested`] produced by re-reading the installed file and
//! checking content, ownership and permissions — and
//! [`StateDerivation`] admits `HostEnforced` from nothing else. A successful
//! normal installation therefore cannot imply `Host Enforced`; it has no step
//! that could produce the evidence.
//!
//! What the attestation does **not** claim: that Claude Code honours each
//! managed-only key at runtime. That needs a managed device and remains
//! unmeasured — see `docs/src/devtools/limitations.md`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use aa_devtool_contract::{
    now_unix_secs, sha256_hex, AdapterError, ArtifactObservation, ArtifactOperation, CapabilitySupport,
    DevToolCapabilities, DevToolInfo, DevToolIntegration, DevToolKind, DocumentFormat, EnvValue, EvidenceKind,
    GovernanceLevel, IntegrationCapability, IntegrationPlan, IntegrationReceipt, IntegrationRequest, IntegrationStatus,
    IntegrationStep, LaunchSpec, LaunchableTool, LifecyclePhase, McpGovernedTool, McpServerInfo, NextLevel,
    PolicyPosture, ProbeDescriptor, ProtectionEvidence, ProtectionLevel, ProtectionProfile, ProtectionState,
    RemovalPlan, SettingsMerge, SettingsScope, StateDerivation, StepAction, StepExecutor, StepReceipt,
    SupportedToolVersions, ToolVersion, VerificationOutcome, VerificationResult, VersionCompatibility, VersionSupport,
    DEFAULT_FRESHNESS_WINDOW_SECS, LIFECYCLE_SCHEMA_VERSION,
};
use async_trait::async_trait;

use crate::adjudicating_probe::ProxyAdjudicatedProbe;
use crate::bypass::{self, BypassFinding, LaunchEnvironment};
use crate::executor::ClaudeCodeStepExecutor;
use crate::managed_settings::{
    self, Authorization, MacOsAdminAuthority, ManagedSettingsInstaller, PrivilegedFileAuthority, MANAGED_ONLY_KEYS,
};
use crate::probe::{ProbeRequest, ProtectionProbe, SYNTHETIC_SECRET};
use crate::scope::{ClaudeCodePaths, ScopeError};
use crate::{ClaudeCodeAdapter, MIN_VERSION};

/// Step id for the managed settings write.
pub const STEP_MANAGED_SETTINGS: &str = "managed-settings";
/// Step id for materialising the proxy CA.
pub const STEP_PROXY_CA: &str = "proxy-ca";
/// Step id for the `NODE_EXTRA_CA_CERTS` injection — AAASM-5276 condition C1.
pub const STEP_NODE_EXTRA_CA_CERTS: &str = "node-extra-ca-certs";
/// Step id for the proxy environment.
pub const STEP_PROXY_ENV: &str = "proxy-env";
/// Step id for the per-integration MitM host list — condition C5.
pub const STEP_SIDE_CHANNEL_SCOPE: &str = "side-channel-scope";
/// Step id for the protection test.
pub const STEP_PROTECTION_TEST: &str = "protection-test";
/// Step id for the one privileged step — the endpoint managed-settings install
/// (AAASM-5298). Present only in a `managed`-scoped plan.
pub const STEP_ENDPOINT_MANAGED_SETTINGS: &str = "endpoint-managed-settings";

/// The CA-trust variable Claude Code's embedded Node runtime honours.
///
/// Measured in AAASM-5276: `claude --debug` reports
/// `CA certs: Appended extra certificates from NODE_EXTRA_CA_CERTS (…)`.
pub const CA_ENV_VAR: &str = "NODE_EXTRA_CA_CERTS";

/// Keys in `settings.json` Agent Assembly owns. Every other key in the file is
/// preserved, and drift is defined only over these.
pub const MANAGED_KEYS: [&str; 4] = [
    "permissions",
    "permissionMode",
    "enabledMcpjsonServers",
    "disabledMcpjsonServers",
];

/// The subset of [`MANAGED_KEYS`] an MCP-only step claims.
pub const MCP_KEYS: [&str; 2] = ["enabledMcpjsonServers", "disabledMcpjsonServers"];

/// Host the model-bound path is addressed to.
pub const MODEL_HOST: &str = "api.anthropic.com";

/// Hosts this integration asks the proxy to bring under interception.
///
/// `api.anthropic.com` is already a built-in LLM host; it is listed anyway so
/// the receipt states the scope rather than relying on a default that could
/// change. `*.anthropic.com` is the condition-C5 addition: one headless run in
/// AAASM-5276 produced an MCP-registry GET and a 130 KB
/// `POST /api/event_logging/v2/batch` alongside its two `/v1/messages` calls,
/// and a deployment scoped to the model endpoint alone would leave those
/// unscanned. The wildcard is leftmost-label only, matching the proxy's
/// allowlist grammar.
pub const MITM_HOSTS: [&str; 2] = ["api.anthropic.com", "*.anthropic.com"];

/// The default address `aa-proxy` binds to.
const DEFAULT_PROXY_ADDR: &str = "127.0.0.1:8899";

/// The Developer Integration for Claude Code.
pub struct ClaudeCodeIntegration {
    paths: ClaudeCodePaths,
    /// Reused for detection — AAASM-201's adapter stays the one implementation
    /// of "is Claude Code on this host and what version".
    adapter: ClaudeCodeAdapter,
    proxy_url: String,
    probe: Arc<dyn ProtectionProbe>,
    /// How the one privileged step obtains administrator authorization.
    managed_authority: Arc<dyn PrivilegedFileAuthority>,
    freshness_window_secs: u64,
}

impl std::fmt::Debug for ClaudeCodeIntegration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClaudeCodeIntegration")
            .field("proxy_url", &self.proxy_url)
            .finish_non_exhaustive()
    }
}

impl Default for ClaudeCodeIntegration {
    fn default() -> Self {
        Self::new()
    }
}

impl ClaudeCodeIntegration {
    /// The production integration: roots from the environment, the real
    /// detection path, and the shipped adjudicating probe.
    pub fn new() -> Self {
        Self::with_paths(ClaudeCodePaths::from_env())
    }

    /// An integration over explicit roots. The constructor tests use, so no test
    /// depends on the ambient `$HOME` or working directory.
    pub fn with_paths(paths: ClaudeCodePaths) -> Self {
        let adapter = ClaudeCodeAdapter::with_overrides(None, paths.home().map(PathBuf::from));
        Self {
            paths,
            adapter,
            proxy_url: default_proxy_url(),
            // AAASM-5300: the shipped default adjudicates. It produces traffic on
            // the protected path and reports only the verdict the proxy returns
            // for that request, which is what makes `GatewayProtected`
            // reachable at all — and it still reports `Inconclusive` on every
            // path it cannot measure, so nothing passes on configuration alone.
            probe: Arc::new(ProxyAdjudicatedProbe),
            // Safe as a default because it refuses to elevate for any target
            // that is not the canonical managed-settings path, and because no
            // unprivileged plan contains a step that would call it.
            managed_authority: Arc::new(MacOsAdminAuthority),
            freshness_window_secs: DEFAULT_FRESHNESS_WINDOW_SECS,
        }
    }

    /// Replace the authority the one privileged step elevates through.
    ///
    /// The seam every test substitutes, so no test can reach a real
    /// authorization prompt.
    #[must_use]
    pub fn with_managed_authority(mut self, authority: Arc<dyn PrivilegedFileAuthority>) -> Self {
        self.managed_authority = authority;
        self
    }

    /// The installer for the endpoint managed-settings file, when this host can
    /// address one.
    ///
    /// Ownership is expected to be root at the canonical path. A redirected
    /// managed root is a test seam where nothing is root-owned, so the check is
    /// anchored to whatever this process writes as — live in both cases rather
    /// than disabled in one.
    pub fn managed_installer(&self) -> Option<Arc<ManagedSettingsInstaller>> {
        let target = self.paths.settings_path(SettingsScope::Managed).ok()?;
        let work_dir = self.paths.owned_root(SettingsScope::Managed).ok()?.join("managed");
        let installer = ManagedSettingsInstaller::new(target, &work_dir, self.managed_authority.clone());
        if self.paths.managed_root_is_canonical() {
            return Some(Arc::new(installer));
        }
        std::fs::create_dir_all(&work_dir).ok()?;
        let uid = managed_settings::owner_uid(&work_dir)?;
        Some(Arc::new(installer.expecting_owner_uid(uid)))
    }

    /// Add the one privileged step, plus the warnings that make consenting to it
    /// informed.
    ///
    /// The step is `Required`: an endpoint-managed install whose managed write
    /// silently did not happen would report an integration that is exactly the
    /// unprivileged one, under a plan that claimed otherwise.
    fn with_endpoint_managed_step(
        &self,
        plan: IntegrationPlan,
        profile: ProtectionProfile,
        path: &std::path::Path,
    ) -> Result<IntegrationPlan, AdapterError> {
        let document = managed_settings::managed_settings_document(profile)?;
        // The disclosure the owner's model requires — path, reason, content,
        // diff, conflict, backup, rollback — travels to the client as plan
        // warnings, because the client renders the whole plan *before* it asks
        // for confirmation and never sees the adapter directly. Nothing here is
        // decorative: an authorization granted without the diff and the conflict
        // in front of the user is not informed consent.
        let disclosure = self
            .managed_installer()
            .map(|installer| installer.disclose(&document))
            .transpose()
            .map_err(|e| AdapterError::SettingsGenerationFailed(e.to_string()))?;

        let mut plan = plan
            .with_step(
                IntegrationStep::new(
                    STEP_ENDPOINT_MANAGED_SETTINGS,
                    StepAction::WriteManagedSettings {
                        scope: SettingsScope::Managed,
                        path: path.to_path_buf(),
                        managed_keys: MANAGED_ONLY_KEYS.iter().map(|k| (*k).to_string()).collect(),
                        content_sha256: sha256_hex(&document),
                        merge: SettingsMerge::Replace,
                        format: DocumentFormat::Json,
                    },
                    format!(
                        "install Agent Assembly's managed policy at {} — the only settings surface Claude \
                         Code treats as non-overridable — after backing up whatever is there, and verify it \
                         by reading it back",
                        path.display()
                    ),
                )
                .privileged(format!(
                    "Agent Assembly will ask for administrator authorization once, to place one file at {}. \
                     Nothing else runs with elevated privileges. Removing the integration reverses it.",
                    path.display()
                ))
                .with_reversal(StepAction::ManageArtifact {
                    operation: ArtifactOperation::Remove,
                    path: path.to_path_buf(),
                }),
            )
            .warn(format!(
                "this plan contains one privileged step. It writes {}, which is owned by the \
                 administrator; every other step in this plan writes files you already own",
                path.display()
            ))
            .warn(format!(
                "the managed-only keys this installs ({}) are documented by Anthropic as non-overridable. \
                 Agent Assembly verifies that the file is installed, owned as expected and not writable by \
                 you — it does not measure Claude Code's runtime handling of each key",
                MANAGED_ONLY_KEYS.join(", ")
            ))
            .warn(
                "a managed-settings file Agent Assembly did not write is never replaced. If one is already \
                 installed — for example by your organisation's device management — this plan refuses \
                 rather than merging over it"
                    .to_string(),
            );

        if let Some(disclosure) = &disclosure {
            plan = plan.warn(format!(
                "the exact content that will be written to {} (sha256:{}): {}",
                disclosure.target.display(),
                disclosure.proposed_sha256,
                disclosure.proposed.split_whitespace().collect::<Vec<_>>().join(" ")
            ));
            plan = plan.warn(if disclosure.diff.is_empty() {
                format!(
                    "{} already holds exactly this content; the install verifies it and asks for no \
                     authorization",
                    disclosure.target.display()
                )
            } else {
                format!("changes against what is on this host: {}", disclosure.diff.join("  "))
            });
            plan = plan.warn(disclosure.backup.clone());
            plan = plan.warn(disclosure.rollback.clone());
            if let Some(conflict) = &disclosure.conflict {
                plan = plan.warn(format!("CONFLICT — this plan will refuse: {conflict}"));
            }
        }

        if !self.paths.managed_root_is_canonical() {
            plan = plan.warn(format!(
                "AASM_CLAUDE_MANAGED_ROOT redirects the managed surface to {}. That is a test seam: the \
                 file written there is not the one Claude Code reads, and no administrator authorization \
                 is requested for it",
                path.display()
            ));
        }

        match self.managed_authority.availability() {
            Authorization::Available => {}
            Authorization::NonInteractive { detail } => {
                plan = plan.warn(format!(
                    "administrator authorization cannot be requested here: {detail}. This plan will fail \
                     rather than wait for credentials — run it from a terminal"
                ));
            }
            Authorization::Unavailable { detail } => {
                plan = plan.warn(format!(
                    "administrator authorization is unavailable on this host: {detail}"
                ));
            }
        }

        Ok(plan)
    }

    /// Replace the detection adapter, so a test can pin the binary path and the
    /// version the probe reports.
    #[doc(hidden)]
    #[must_use]
    pub fn with_adapter(mut self, adapter: ClaudeCodeAdapter) -> Self {
        self.adapter = adapter;
        self
    }

    /// Route the tool through a specific proxy.
    #[must_use]
    pub fn through_proxy(mut self, proxy_url: impl Into<String>) -> Self {
        self.proxy_url = proxy_url.into();
        self
    }

    /// Replace the probe that adjudicates what became of the model-bound
    /// traffic.
    ///
    /// The default is [`ProxyAdjudicatedProbe`]. A probe that cannot adjudicate
    /// — [`UnadjudicatedProbe`](crate::probe::UnadjudicatedProbe) — makes
    /// `verify` report the model path as configured but never exercised, and the
    /// protection level does not rise past `Integrated`.
    #[must_use]
    pub fn with_probe(mut self, probe: Arc<dyn ProtectionProbe>) -> Self {
        self.probe = probe;
        self
    }

    /// Narrow the window inside which verification evidence still counts.
    #[must_use]
    pub fn with_freshness_window(mut self, secs: u64) -> Self {
        self.freshness_window_secs = secs;
        self
    }

    /// The paths this integration reads and writes.
    pub fn paths(&self) -> &ClaudeCodePaths {
        &self.paths
    }

    /// An executor that knows every scope this integration can own, holding
    /// `rendered` for the steps that write bytes.
    ///
    /// Every scope rather than one, because observing and reversing start from a
    /// receipt and not from a plan: the service has no scope in hand at those
    /// moments, and an executor built for the wrong one would report a
    /// project-scoped install as unobservable and refuse to remove it.
    pub fn scoped_executor(&self, rendered: BTreeMap<String, String>) -> ClaudeCodeStepExecutor {
        let mut executor = ClaudeCodeStepExecutor::new();
        for scope in [SettingsScope::User, SettingsScope::Project, SettingsScope::Managed] {
            if let Ok(dir) = self.paths.launch_env_dir(scope) {
                executor = executor.with_scope(scope, dir);
            }
        }
        for (step_id, content) in rendered {
            executor = executor.with_content(step_id, content);
        }
        if let Some(installer) = self.managed_installer() {
            executor = executor.with_managed_installer(installer);
        }
        executor
    }

    /// The bytes each of `plan`'s steps writes, keyed by step id.
    ///
    /// Re-derived at apply time rather than carried in the plan: the digest the
    /// user reviewed is what the executor checks against, so a CA that was
    /// rotated between plan and apply fails closed instead of being written
    /// silently.
    pub fn step_content(&self, plan: &IntegrationPlan) -> Result<BTreeMap<String, String>, AdapterError> {
        let mut rendered = BTreeMap::new();
        for step in &plan.steps {
            match step.id.as_str() {
                STEP_MANAGED_SETTINGS => {
                    rendered.insert(step.id.clone(), managed_settings_json(plan.profile)?);
                }
                STEP_PROXY_CA => {
                    rendered.insert(step.id.clone(), self.read_ca_pem()?);
                }
                STEP_SIDE_CHANNEL_SCOPE => {
                    rendered.insert(step.id.clone(), mitm_hosts_document());
                }
                STEP_ENDPOINT_MANAGED_SETTINGS => {
                    rendered.insert(
                        step.id.clone(),
                        managed_settings::managed_settings_document(plan.profile)?,
                    );
                }
                _ => {}
            }
        }
        Ok(rendered)
    }

    /// The proxy CA certificate, read from where `aa-proxy` persists it.
    fn read_ca_pem(&self) -> Result<String, AdapterError> {
        let path = self.paths.ca_source_path().ok_or_else(|| {
            AdapterError::SettingsGenerationFailed(
                "the Agent Assembly proxy certificate authority location is unknown; set AA_CA_DIR".to_string(),
            )
        })?;
        std::fs::read_to_string(path).map_err(|e| {
            AdapterError::SettingsGenerationFailed(format!(
                "the Agent Assembly proxy certificate authority could not be read from {}: {e}. \
                 Start the proxy once (`aasm proxy start`) so it is created, then plan again",
                path.display()
            ))
        })
    }

    /// The version the detected binary reports, when one was detected.
    fn detected_version(&self) -> Option<ToolVersion> {
        use aa_devtool_contract::DevToolAdapter as _;
        self.adapter.detect()?.version?.parse().ok()
    }

    fn compatibility(&self) -> VersionCompatibility {
        self.version_support()
            .supported_tool_versions
            .classify(self.detected_version().as_ref())
    }

    /// The paths this call operates over.
    ///
    /// # Why this is per call and not the constructed `self.paths` (AAASM-5913)
    ///
    /// This integration is constructed once, at daemon boot. Every root it
    /// resolves then is a property of the host and stays true — except the project
    /// root, which is a property of *the caller of this particular request*. Two
    /// clients in two repositories share one instance of this struct, so reading a
    /// construction-time project root gave both of them whichever repository the
    /// daemon was launched in.
    ///
    /// `project_root` is threaded from
    /// [`IntegrationRequest::project_root`](aa_devtool_contract::IntegrationRequest::project_root)
    /// for the authoring verbs and from
    /// [`IntegrationReceipt::project_root`] for the receipt-driven ones. `None` at
    /// [`Project`](SettingsScope::Project) scope is an error and not a fallback:
    /// there is no working directory in this process that could honestly stand in
    /// for the caller's.
    fn effective_paths(
        &self,
        scope: SettingsScope,
        project_root: Option<&Path>,
    ) -> Result<ClaudeCodePaths, AdapterError> {
        match project_root {
            Some(root) => Ok(self.paths.clone().with_project(root)),
            // At user and managed scope the project root is only used to disclose
            // that a project configuration exists nearby; not knowing it costs one
            // warning, not correctness.
            None if scope != SettingsScope::Project => Ok(self.paths.clone()),
            None => Err(AdapterError::SettingsGenerationFailed(
                "this request writes the project settings scope but names no project. The \
                 developer-integration service is shared by every client on this host, so the \
                 project a change lands in is taken from the request and never from the service's \
                 own working directory"
                    .to_string(),
            )),
        }
    }

    /// Every bypass condition observable in `settings_path`, plus the ambient ones.
    ///
    /// The settings file is passed in rather than re-resolved from a scope: during
    /// `status` and `verify` the honest answer is the file the receipt records
    /// having written, and re-resolving a `Project` scope against this process's
    /// roots is how a bypass reading ended up describing a different repository's
    /// file (AAASM-5913).
    fn bypasses_at(&self, settings_path: Option<&Path>) -> Vec<BypassFinding> {
        let mut found = Vec::new();
        if let Some(path) = settings_path {
            if let Ok(raw) = std::fs::read_to_string(path) {
                found.extend(bypass::settings_bypasses(&path.display().to_string(), &raw));
            }
        }
        found.extend(bypass::environment_bypasses(&LaunchEnvironment::from_process()));
        found
    }

    /// Evidence rows for the bypasses, plus the one for host enforcement.
    ///
    /// Both are [`EvidenceKind::Absent`]: a bypass does not disprove the
    /// configuration, it makes the configuration unable to prove anything. An
    /// `Absent` reading only ever lowers the reported state, which is the whole
    /// behaviour needed here.
    fn limitation_evidence(&self, settings_path: Option<&Path>, now: u64) -> Vec<ProtectionEvidence> {
        let mut evidence: Vec<ProtectionEvidence> = self
            .bypasses_at(settings_path)
            .into_iter()
            .map(|finding| {
                ProtectionEvidence::new(
                    IntegrationCapability::ToolActionApproval,
                    EvidenceKind::Absent {
                        reason: finding.detail(),
                    },
                    now,
                    format!("bypass {}: {}", finding.id, finding.remediation),
                )
            })
            .collect();

        evidence.push(self.host_enforcement_evidence(now));
        evidence
    }

    /// Whether this adapter can offer an endpoint-managed install at all.
    ///
    /// A platform without an authorization mechanism is `Unsupported`; a
    /// terminal-less invocation is not — that is a runtime condition the plan
    /// warns about and the install refuses on, not a capability the adapter
    /// lacks.
    fn host_enforcement_support(&self) -> CapabilitySupport {
        match self.managed_authority.availability() {
            Authorization::Unavailable { detail } => CapabilitySupport::unsupported(format!(
                "endpoint-managed settings cannot be installed on this host: {detail}"
            )),
            _ => CapabilitySupport::Supported,
        }
    }

    /// The one observation that can raise the ladder to `HostEnforced`.
    ///
    /// [`EvidenceKind::HostAttested`] is produced **only** by reading the
    /// installed managed file back and checking its content, owner and
    /// permissions against what was authorized. Every other outcome — nothing
    /// installed, a digest that moved, an owner that is not the expected one, a
    /// mode that lets someone else rewrite it — is
    /// [`EvidenceKind::Absent`], which lowers and never raises.
    fn host_enforcement_evidence(&self, now: u64) -> ProtectionEvidence {
        let absent = |reason: String, detail: String| {
            ProtectionEvidence::new(
                IntegrationCapability::HostEnforcement,
                EvidenceKind::Absent { reason },
                now,
                detail,
            )
        };

        let Some(installer) = self.managed_installer() else {
            return absent(
                HOST_ENFORCEMENT_REASON.to_string(),
                format!(
                    "known bypasses this integration cannot observe: {}",
                    bypass::UNOBSERVABLE_BYPASSES
                ),
            );
        };

        match installer.verify_recorded() {
            Ok(attestation) => ProtectionEvidence::new(
                IntegrationCapability::HostEnforcement,
                EvidenceKind::HostAttested { healthy: true },
                now,
                format!("{}. {HOST_ATTESTATION_CAVEAT}", attestation.detail()),
            ),
            // A host that simply did not opt in reads as the plain reason. A
            // host that *did* opt in and no longer verifies is a different
            // situation, and the summary that says which one it is belongs in
            // front of the user.
            Err(managed_settings::ManagedSettingsError::NothingInstalled { .. }) => absent(
                HOST_ENFORCEMENT_REASON.to_string(),
                format!(
                    "known bypasses this integration cannot observe: {}",
                    bypass::UNOBSERVABLE_BYPASSES
                ),
            ),
            Err(e) => absent(
                format!("{HOST_ENFORCEMENT_REASON} ({})", e.summary()),
                format!(
                    "{e}; known bypasses this integration cannot observe: {}",
                    bypass::UNOBSERVABLE_BYPASSES
                ),
            ),
        }
    }

    /// Read every applied, fingerprinted step back off the host and compare it
    /// to what the receipt claims.
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
                    // `ArtifactObservation` is non-exhaustive: a reading this
                    // build does not understand is not a match. Missing evidence
                    // lowers the state; it never raises it.
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

    /// The probe request a receipt describes, when it describes one.
    fn probe_request(&self, receipt: &IntegrationReceipt) -> Option<ProbeRequest> {
        let ca = receipt.steps.iter().find_map(|step| match &step.action {
            StepAction::MaterialiseTrustMaterial { path, .. } if step.applied => Some(path.clone()),
            _ => None,
        })?;
        let proxy_url = receipt
            .steps
            .iter()
            .filter(|step| step.applied)
            .find_map(|step| match &step.action {
                StepAction::ConfigureProxy { variables, .. } => variables.get("HTTPS_PROXY").cloned(),
                _ => None,
            })
            .unwrap_or_else(|| self.proxy_url.clone());
        Some(ProbeRequest {
            proxy_url,
            ca_pem: ca,
            target_host: MODEL_HOST.to_string(),
            synthetic_secret: SYNTHETIC_SECRET.to_string(),
        })
    }
}

/// Why the model path is not yet proven, and what to do about it.
const PROBE_NOT_RUN_REASON: &str =
    "no probe traffic has been produced and adjudicated on the model path; run `aasm integrations verify claude-code`";

/// Why `HostEnforced` is not reachable from an unprivileged install.
///
/// Stated as a *reason it is not active here*, not as a blanket unavailability:
/// since AAASM-5298 there is a path to it, and it is opt-in, privileged and
/// verified. Kernel-level enforcement remains Linux-only and the proxy CA is
/// still never added to the macOS system trust store — trust is established
/// per-launch through `NODE_EXTRA_CA_CERTS`.
const HOST_ENFORCEMENT_REASON: &str = "host enforcement is not active: no endpoint-managed settings file \
     installed by Agent Assembly was verified on this host. Install it with \
     `aasm integrations install claude-code --install-managed-settings`, which asks for administrator \
     authorization for one file write. Kernel-level enforcement remains Linux-only, and Agent Assembly \
     never adds its certificate authority to the macOS system trust store";

/// What an endpoint-managed attestation does, and does not, claim.
const HOST_ATTESTATION_CAVEAT: &str = "Agent Assembly verified that the managed policy is installed, owned \
     as expected and not writable by you; it has not measured Claude Code's runtime handling of each \
     managed-only key";

/// The mechanism a step's artifact is evidence about.
fn step_mechanism(action: &StepAction) -> IntegrationCapability {
    match action {
        StepAction::WriteManagedSettings { .. } => IntegrationCapability::ManagedSettings,
        StepAction::MaterialiseTrustMaterial { .. } | StepAction::InjectLaunchEnvironment { .. } => {
            IntegrationCapability::ModelPathInterception
        }
        StepAction::ConfigureProxy { .. } => IntegrationCapability::HttpProxy,
        StepAction::ConfigureMcpServers { .. } => IntegrationCapability::McpGovernance,
        _ => IntegrationCapability::ManagedSettings,
    }
}

/// A stable, user-legible name for what a step touched.
///
/// A launch-environment step is named by its **variable**, not by the artifact
/// its value points at: `NODE_EXTRA_CA_CERTS` and the CA PEM step would
/// otherwise both report the same path, and a status listing the same file twice
/// reads as a duplicate rather than as two different observations.
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

/// The managed settings block one profile resolves to.
///
/// Derived from the **profile**, not from a policy document: a plan carries a
/// policy only by reference (ADR 0030 §5.5), and the digest the user reviewed at
/// plan time has to be reproducible at apply time from what the plan carries.
///
/// `permissions.defaultMode` is written explicitly, and that is deliberate: it
/// displaces a `bypassPermissions` a user had set, and because `permissions` is
/// an Agent Assembly-owned key, re-adding that mode afterwards is drift the
/// receipt can detect and repair can undo.
pub fn managed_settings_json(profile: ProtectionProfile) -> Result<String, AdapterError> {
    let default_mode = match profile {
        // `plan` makes Claude Code propose rather than act, which is the closest
        // native expression of "approval required for destructive classes".
        ProtectionProfile::Strict => "plan",
        ProtectionProfile::Recommended | ProtectionProfile::ObserveOnly => "default",
    };
    let doc = serde_json::json!({
        "permissions": {
            "allow": [],
            "deny": [],
            "defaultMode": default_mode,
        },
        "permissionMode": default_mode,
        "enabledMcpjsonServers": [],
        "disabledMcpjsonServers": [],
    });
    serde_json::to_string(&doc).map_err(|e| AdapterError::SettingsGenerationFailed(e.to_string()))
}

/// The MCP allow/deny block, rendered over the two MCP keys only.
fn mcp_settings_json(allowed: &[String], denied: &[String]) -> Result<String, AdapterError> {
    let doc = serde_json::json!({
        "enabledMcpjsonServers": allowed,
        "disabledMcpjsonServers": denied,
    });
    serde_json::to_string(&doc).map_err(|e| AdapterError::SettingsGenerationFailed(e.to_string()))
}

/// The per-integration MitM host list, one host per line.
pub fn mitm_hosts_document() -> String {
    let mut out = String::from("# Written by `aasm integrations install claude-code`.\n");
    out.push_str("# The proxy unions these into its MitM set without disabling llm_only.\n");
    for host in MITM_HOSTS {
        out.push_str(host);
        out.push('\n');
    }
    out
}

#[async_trait]
impl DevToolIntegration for ClaudeCodeIntegration {
    fn capabilities(&self) -> DevToolCapabilities {
        let interception = match self.paths.ca_source() {
            Some(_) => CapabilitySupport::Supported,
            None => CapabilitySupport::unsupported(
                "the Agent Assembly proxy certificate authority has not been created on this host, so \
                 the tool cannot be made to trust the intercepting proxy. Start the proxy once \
                 (`aasm proxy start`) and plan again",
            ),
        };

        DevToolCapabilities::new()
            .supported(IntegrationCapability::Discovery)
            .supported(IntegrationCapability::ManagedSettings)
            .supported(IntegrationCapability::ManagedLaunch)
            .supported(IntegrationCapability::HttpProxy)
            .supported(IntegrationCapability::McpDiscovery)
            .supported(IntegrationCapability::McpGovernance)
            .supported(IntegrationCapability::ToolActionApproval)
            .declare(IntegrationCapability::ModelPathInterception, interception)
            .unsupported(
                IntegrationCapability::ModelGatewayBaseUrl,
                "ANTHROPIC_BASE_URL redirection is routing, not protection: AAASM-5276 measured it \
                 delivering a synthetic secret to the provider with no Agent Assembly component in the \
                 path, and setting it in the shell additionally suppresses Claude Code's \
                 server-managed settings fetch",
            )
            .unsupported(
                IntegrationCapability::Hooks,
                "Claude Code hooks govern tool and action execution and cannot see or modify \
                 model-bound content, so no hook can carry a sensitive-data protection claim",
            )
            .unsupported(
                IntegrationCapability::NativeIdeUi,
                "Claude Code is a terminal CLI and has no in-editor surface for status or approval \
                 prompts",
            )
            .declare(IntegrationCapability::HostEnforcement, self.host_enforcement_support())
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
                MIN_VERSION.parse().unwrap_or(ToolVersion::new(1, 0, 0)),
            ),
        }
    }

    async fn plan_integration(&self, request: &IntegrationRequest) -> Result<IntegrationPlan, AdapterError> {
        let scope = request.settings_scope;
        // Resolved from *this request*, not from the roots this adapter was
        // constructed over: the project a project-scoped plan writes into belongs
        // to the caller, and this adapter is shared (AAASM-5913).
        let paths = self.effective_paths(scope, request.project_root.as_deref())?;
        let settings_path = paths.settings_path(scope).map_err(scope_error)?;
        let launch_env = paths.launch_env_dir(scope).map_err(scope_error)?;
        let ca_pem = paths.proxy_ca_pem(scope).map_err(scope_error)?;
        let hosts_file = paths.mitm_hosts_file(scope).map_err(scope_error)?;
        let capabilities = self.capabilities();

        let interception_available = capabilities.can_intercept_model_path();
        // The endpoint-managed surface is the only one that can carry a
        // bypass-resistance claim, so it is the only one whose ceiling is
        // `HostEnforced`. A user- or project-scoped plan cannot reach it —
        // which is the governing rule of AAASM-5298 expressed as a number.
        let host_enforcement_available = scope == SettingsScope::Managed
            && !matches!(self.managed_authority.availability(), Authorization::Unavailable { .. });
        let ceiling = match (interception_available, host_enforcement_available) {
            (true, true) => ProtectionLevel::HostEnforced,
            (true, false) => ProtectionLevel::GatewayProtected,
            (false, _) => ProtectionLevel::Integrated,
        };
        let planned_level = request.effective_target_level().min(ceiling);

        let mut plan = IntegrationPlan::new(
            authored_plan_id(scope, request.project_root.as_deref()),
            request,
            planned_level,
            GovernanceLevel::L2Enforce,
        );

        if scope == SettingsScope::Managed {
            // 1a. The one privileged step. Every fact the user has to weigh is
            //     in the plan *and* in the disclosure the CLI renders before the
            //     confirmation — the plan is what the service checks consent
            //     against, the disclosure is what makes that consent informed.
            plan = self.with_endpoint_managed_step(plan, request.profile, &settings_path)?;
        } else {
            // 1b. The unprivileged install: tool-action governance in a file the
            //     developer already owns, and not the data path.
            let settings = managed_settings_json(request.profile)?;
            plan = plan.with_step(IntegrationStep::new(
                STEP_MANAGED_SETTINGS,
                StepAction::WriteManagedSettings {
                    scope,
                    path: settings_path.clone(),
                    managed_keys: MANAGED_KEYS.iter().map(|k| (*k).to_string()).collect(),
                    content_sha256: sha256_hex(&settings),
                    merge: SettingsMerge::MergeManagedKeys,
                    format: DocumentFormat::Json,
                },
                format!(
                    "merge Agent Assembly's four managed keys into {} and leave every other key alone",
                    settings_path.display()
                ),
            ));
        }

        if interception_available {
            // 2. Trust material — condition C1, first half.
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
                        "copy the Agent Assembly proxy certificate authority to {} so Claude Code can be \
                         pointed at it without touching the system trust store",
                        ca_pem.display()
                    ),
                )
                .with_reversal(StepAction::ManageArtifact {
                    operation: ArtifactOperation::Remove,
                    path: ca_pem.clone(),
                }),
            );

            // 3. NODE_EXTRA_CA_CERTS — condition C1, the half the product was missing.
            plan = plan.with_step(
                IntegrationStep::new(
                    STEP_NODE_EXTRA_CA_CERTS,
                    StepAction::InjectLaunchEnvironment {
                        scope,
                        variable: CA_ENV_VAR.to_string(),
                        value: EnvValue::ArtifactPath(ca_pem.clone()),
                    },
                    format!(
                        "set {CA_ENV_VAR} for every governed launch so Claude Code's Node runtime accepts \
                         the intercepting proxy's certificates — without this the MitM handshake fails and \
                         nothing is inspected"
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
                    format!("route governed Claude Code launches through {}", self.proxy_url),
                )
                .with_reversal(StepAction::ConfigureProxy {
                    scope,
                    variables: BTreeMap::new(),
                }),
            );

            // 5. Side-channel scope — condition C5.
            plan = plan.with_step(
                IntegrationStep::new(
                    STEP_SIDE_CHANNEL_SCOPE,
                    StepAction::ManageArtifact {
                        operation: ArtifactOperation::Create,
                        path: hosts_file.clone(),
                    },
                    format!(
                        "ask the proxy to inspect {} for this integration, so the tool's telemetry and \
                         registry calls are scanned too — without disabling llm_only and intercepting \
                         every host on the machine",
                        MITM_HOSTS.join(", ")
                    ),
                )
                .with_reversal(StepAction::ManageArtifact {
                    operation: ArtifactOperation::Remove,
                    path: hosts_file,
                }),
            );

            // 6. The protection test. Optional: it mutates nothing, produces no
            //    fingerprint, and its result reaches the receipt through
            //    verification rather than through the apply.
            plan = plan.with_step(
                IntegrationStep::new(
                    STEP_PROTECTION_TEST,
                    StepAction::RunProtectionTest {
                        probe: ProbeDescriptor {
                            id: "claude-code-model-path".to_string(),
                            mechanism: IntegrationCapability::ModelPathInterception,
                            description: format!(
                                "send a synthetic Anthropic-shaped secret down the {MODEL_HOST} path and let \
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
            IntegrationCapability::HostEnforcement,
        ] {
            if let Some(reason) = capabilities.unsupported_reason(capability) {
                plan = plan.declaring_unsupported(capability, reason.to_string());
            }
        }

        plan = plan
            .warn(format!(
                "protection applies to sessions started through `aasm run claude`. A `claude` started \
                 directly inherits neither the proxy nor {CA_ENV_VAR}, and is not protected"
            ))
            .warn(format!(
                "known bypasses this integration cannot observe: {}",
                bypass::UNOBSERVABLE_BYPASSES
            ))
            .warn(
                "restore is semantics-exact, not byte-exact: the settings document is reserialised, so \
                 hand-chosen formatting and key order do not survive an install/remove cycle"
                    .to_string(),
            )
            .warn("restart any running Claude Code session for the managed settings to take effect".to_string());

        for surface in paths.detected_surfaces() {
            if surface.scope != scope {
                plan = plan.warn(format!(
                    "a {} configuration also exists at {} and this plan does not touch it",
                    surface.scope,
                    surface.path.display()
                ));
            }
        }

        for finding in self.bypasses_at(Some(&settings_path)) {
            plan = plan.warn(format!(
                "bypass detected — {}. {}",
                finding.detail(),
                finding.remediation
            ));
        }

        Ok(plan)
    }

    async fn integration_status(
        &self,
        receipt: Option<&IntegrationReceipt>,
    ) -> Result<IntegrationStatus, AdapterError> {
        let now = now_unix_secs();
        let detected = self.detect();
        let compatibility = self.compatibility();
        // The file the receipt records having written, not the file a scope would
        // resolve to in this process. `status` carries no request, so a
        // project-scoped receipt's own record is the only thing here that names
        // the right repository (AAASM-5913).
        //
        // With no receipt at all there is nothing installed to read bypasses out
        // of beyond the user surface, which is what an uninstalled host looks
        // like.
        let settings_path = match receipt.and_then(IntegrationReceipt::settings_file_path) {
            Some(path) => Some(path.to_path_buf()),
            None => self.paths.settings_path(SettingsScope::User).ok(),
        };

        let mut evidence: Vec<ProtectionEvidence> = Vec::new();
        if let Some(receipt) = receipt {
            evidence.extend(self.read_back_evidence(receipt, now));
            // Carry the exercised evidence the receipt recorded, at its original
            // timestamp: freshness is what turns "verified once, long ago" into
            // a lower level, and re-stamping it here would defeat that.
            evidence.extend(
                receipt
                    .achieved_evidence
                    .iter()
                    .filter(|e| e.kind.is_exercised())
                    .cloned(),
            );

            // The gap that actually explains a `Degraded` reading, named before
            // the standing limitations so the reason a user is shown leads with
            // the thing they can do something about. Without it the joined
            // reason would open with "host enforcement is unavailable", which is
            // true, permanent, and not why this integration is below its plan.
            let exercised_recently = evidence
                .iter()
                .any(|e| e.justifies_gateway_protection(now, self.freshness_window_secs));
            if !exercised_recently {
                evidence.push(ProtectionEvidence::new(
                    IntegrationCapability::ModelPathInterception,
                    EvidenceKind::Absent {
                        reason: PROBE_NOT_RUN_REASON.to_string(),
                    },
                    now,
                    "the model path is configured but has not been exercised".to_string(),
                ));
            }
        }
        evidence.extend(self.limitation_evidence(settings_path.as_deref(), now));

        let planned_level = receipt.map_or(ProtectionLevel::NotInstalled, |r| r.planned_level);
        let derivation = StateDerivation {
            detected: detected.is_some(),
            receipt_present: receipt.is_some(),
            required_steps: receipt.map_or(0, IntegrationReceipt::required_steps),
            required_steps_verified: receipt.map_or(0, IntegrationReceipt::verified_required_steps),
            // Drift is the service's classification; an adapter that also
            // decided it would be a second, disagreeing answer.
            mismatched_artifacts: &[],
            compatibility: &compatibility,
            schema_newer_than_core: receipt.is_some_and(IntegrationReceipt::is_schema_newer_than_running_core),
            evidence: &evidence,
            planned_level,
            now_unix_secs: now,
            freshness_window_secs: self.freshness_window_secs,
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
            blocked_because: self.next_level_reason(level, receipt.is_some()),
        });

        Ok(IntegrationStatus {
            tool: DevToolKind::ClaudeCode,
            phase,
            state,
            evidence,
            planned_level,
            adapter_ceiling: detected.map_or(GovernanceLevel::L0Discover, |i| i.governance_level),
            compatibility,
            next_level,
            observed_at_unix_secs: now,
            // An adapter governs one tool; the effective policy is a property of
            // the host and is the same for all of them. Resolving it here would
            // put one resolution per adapter behind a contract that says there
            // is one — so the adapter declares it unanswered and the lifecycle
            // service, which resolves once, fills it in (AAASM-5349).
            policy: PolicyPosture::Unknown {
                reason: "not resolved by the adapter".to_string(),
            },
        })
    }

    async fn verify_integration(&self, receipt: &IntegrationReceipt) -> Result<VerificationResult, AdapterError> {
        let now = now_unix_secs();
        let mut evidence = self.read_back_evidence(receipt, now);
        let mismatched: Vec<String> = evidence
            .iter()
            .filter(|e| matches!(e.kind, EvidenceKind::ReadBack { matches_receipt: false }))
            .map(|e| e.detail.clone())
            .collect();

        let mut missing: Vec<String> = Vec::new();
        let mut exercised_protectively = false;

        match self.probe_request(receipt) {
            Some(request) => {
                let report = self.probe.run(&request).await;
                exercised_protectively = report.outcome.is_protective();
                if !exercised_protectively {
                    missing.push(report.detail.clone());
                }
                evidence.push(ProtectionEvidence::new(
                    IntegrationCapability::ModelPathInterception,
                    EvidenceKind::Exercised {
                        outcome: report.outcome,
                    },
                    now,
                    report.detail,
                ));
            }
            None => missing.push(
                "this integration applied no trust material, so there is no intercepted model path to \
                 exercise"
                    .to_string(),
            ),
        }

        // The file this integration recorded having written, so a project-scoped
        // verify reads the caller's repository and not whichever one this shared
        // process was started in (AAASM-5913).
        let settings_path = receipt.settings_file_path();
        let bypasses = self.bypasses_at(settings_path);
        for finding in &bypasses {
            missing.push(finding.detail());
        }
        evidence.extend(self.limitation_evidence(settings_path, now));

        let outcome = if !mismatched.is_empty() {
            VerificationOutcome::Failed {
                reason: format!(
                    "Agent Assembly-owned state no longer matches the receipt: {}",
                    mismatched.join("; ")
                ),
            }
        } else if exercised_protectively && bypasses.is_empty() {
            VerificationOutcome::Passed
        } else {
            VerificationOutcome::PartiallyPassed { missing }
        };

        Ok(VerificationResult {
            verified_at_unix_secs: now,
            outcome,
            evidence,
        })
    }

    async fn plan_removal(&self, receipt: &IntegrationReceipt) -> Result<RemovalPlan, AdapterError> {
        let mut plan = RemovalPlan::new(removal_plan_id(receipt), DevToolKind::ClaudeCode);
        let mut managed_removal_needs_authorization = false;

        // A protection test mutated nothing, so there is nothing to undo and
        // nothing a reviewer needs to approve. Listing it would make the
        // removal preview describe an action that will not happen.
        for step in receipt
            .steps
            .iter()
            .rev()
            .filter(|s| s.applied && !s.action.is_protection_test())
        {
            let summary = match &step.action {
                StepAction::WriteManagedSettings {
                    scope: SettingsScope::Managed,
                    path,
                    ..
                } => {
                    managed_removal_needs_authorization = true;
                    format!(
                        "restore the managed-settings file at {} to what was there before the install, or \
                         delete it when there was nothing — asking for administrator authorization again",
                        path.display()
                    )
                }
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
                    "stop routing governed launches through the Agent Assembly proxy".to_string()
                }
                StepAction::ManageArtifact { path, .. } => {
                    format!("delete {}", path.display())
                }
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
            .warn("restart any running Claude Code session for the removal to take effect".to_string());

        if managed_removal_needs_authorization {
            plan = plan.warn(
                "this removal reverses a privileged step and will ask for administrator authorization \
                 once. Removal is symmetric: a file that was there before the install is restored from \
                 the backup, and a host that had none goes back to having none"
                    .to_string(),
            );
        }

        Ok(plan)
    }

    fn as_mcp_governed(&self) -> Option<&dyn McpGovernedTool> {
        Some(self)
    }

    fn as_launchable(&self) -> Option<&dyn LaunchableTool> {
        Some(self)
    }
}

impl ClaudeCodeIntegration {
    fn next_level_reason(&self, level: ProtectionLevel, installed: bool) -> String {
        match level {
            ProtectionLevel::HostEnforced => HOST_ENFORCEMENT_REASON.to_string(),
            ProtectionLevel::GatewayProtected => PROBE_NOT_RUN_REASON.to_string(),
            _ if !installed => "nothing has been applied yet; run `aasm integrations install claude-code`".to_string(),
            _ => "not every required step of the applied plan verifies; run \
                  `aasm integrations repair claude-code`"
                .to_string(),
        }
    }
}

/// How a removal preview describes undoing a step the plan gave no reversal for.
///
/// A managed-settings step is the only one that has none, and deliberately: its
/// reversal is *restore these keys to what the receipt recorded*, which is not a
/// mutation any [`StepAction`] can name without the prior content in hand. The
/// engine performs it from the receipt's prior-state record.
///
/// Describing it as `ManageArtifact { Remove, <settings file> }` would render as
/// "delete your settings file", which is the opposite of what happens. Naming
/// the same file and the same keys renders as what removal actually does, and
/// the digest is the fingerprint of the document as it stood **before** the
/// install — the state being restored.
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
        other => StepAction::ManageArtifact {
            operation: ArtifactOperation::Remove,
            path: other
                .affected_paths()
                .first()
                .cloned()
                .unwrap_or_else(|| PathBuf::from(&step.step_id)),
        },
    }
}

/// The removal plan id a receipt produces, stable across calls so a caller can
/// review a removal and then execute the plan it reviewed.
pub fn removal_plan_id(receipt: &IntegrationReceipt) -> String {
    format!("remove-{}", receipt.receipt_id)
}

/// The id of a newly authored plan: which installation it is about, and a nonce
/// that makes it this authoring and no other.
///
/// # Why a clock was the wrong identity (AAASM-5913)
///
/// The id used to be `claude-code-{scope}-{unix_secs}`, and the service caches
/// authored plans in a process-global map keyed by it. Two clients planning
/// `--scope project` within the same second — one in project A, one in project B
/// — produced the *same* id, so the second authoring silently replaced the
/// first. The client in A would then apply the id it had been handed and write
/// Agent Assembly's managed keys into B's checked-in `.claude/settings.json`:
/// its own consent, another repository's tracked file, and no `prior_state`
/// recorded against A to reverse.
///
/// A clock cannot distinguish two projects because it is not about them. So the
/// id names the project, and carries 128 bits of OS entropy that no concurrent
/// authoring can repeat.
///
/// # Why the project is a digest and not the path
///
/// A plan id is rendered to the terminal, carried in log lines, and embedded in
/// the receipt id. None of those places need a developer's directory layout, and
/// a path in an identifier is a path that leaks by being copied.
///
/// The digest is **identity, not the check**. It is truncated, and it is taken
/// from a lossy rendering of the path — neither is safe to authorise on. What
/// actually refuses another project's plan is the full canonical-path comparison
/// at apply time; a fingerprint nobody compares would be decoration, and one
/// that is compared does not need to be short.
fn authored_plan_id(scope: SettingsScope, project_root: Option<&Path>) -> String {
    // Only a project-scope plan *is about* a project. At user and managed scope a
    // root is optional context for a disclosure, and digesting it would say this
    // host-wide plan belongs to whichever directory the caller happened to be in.
    let about = match (scope, project_root) {
        (SettingsScope::Project, Some(root)) => {
            let digest = sha256_hex(&root.to_string_lossy());
            format!("p{}", &digest[..16])
        }
        // Refused by `IntegrationPlan::validate`, which is where the refusal
        // belongs. The id still has to be constructible to get there.
        (SettingsScope::Project, None) => "punnamed".to_string(),
        _ => "hostwide".to_string(),
    };
    format!("claude-code-{scope}-{about}-{}", uuid::Uuid::new_v4().simple())
}

impl LaunchableTool for ClaudeCodeIntegration {
    /// Build the governed launch — where condition C1 actually reaches the tool.
    ///
    /// The launch environment the install materialised is applied first, then the
    /// caller's own [`LaunchSpec::env`], so a caller can override a variable for
    /// one run without editing what the receipt records.
    ///
    /// ADR 0036 D6: this method has **no production caller today** — `aasm run
    /// claude` reaches the tool via [`ClaudeCodeAdapter::build_launch_command`]
    /// (the `self.adapter.build_launch_command` call below), which the outer
    /// `aa-cli::spawn_and_wait`/`effective_child_env` boundary already
    /// sanitizes (D6 review #8: that is the one real spawn, and removal must
    /// happen exactly once, at that outer site). Do NOT add an `env_remove`
    /// here defensively "just in case" — a future caller of this trait method
    /// may or may not route through that same boundary, and duplicating
    /// removal without knowing which is exactly the ordering mistake ADR
    /// 0036's review #8 spent a full round correcting. If this method ever
    /// gains a real caller, re-derive the correct removal site from that
    /// caller's actual spawn path first.
    fn build_launch_command(&self, spec: &LaunchSpec) -> Result<std::process::Command, AdapterError> {
        use aa_devtool_contract::DevToolAdapter as _;
        // The adapter resolves its own launch environment from the ambient
        // roots, which is right for `aasm run claude`. This integration may have
        // been constructed over different roots — a test, or a caller that
        // pinned a state directory — so its own paths are overlaid on top.
        let mut cmd =
            self.adapter
                .build_launch_command(&spec.tool_args, &spec.agent_id, spec.team_id.as_deref(), None)?;
        for (name, value) in crate::launch_env::installed_environment(&self.paths) {
            cmd.env(name, value);
        }

        // A proxy address the caller pinned for this run wins over the receipted
        // one: the address is a runtime fact, and a session routed at a proxy
        // that is not listening is worse than one routed at the live address.
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

#[async_trait]
impl McpGovernedTool for ClaudeCodeIntegration {
    async fn list_mcp_servers(&self) -> Result<Vec<McpServerInfo>, AdapterError> {
        use aa_devtool_contract::DevToolAdapter as _;
        self.adapter.list_mcp_servers().await
    }

    fn plan_mcp_governance(&self, allowed: &[String], denied: &[String]) -> Result<IntegrationStep, AdapterError> {
        let path = self.paths.settings_path(SettingsScope::User).map_err(scope_error)?;
        let content = mcp_settings_json(allowed, denied)?;
        Ok(IntegrationStep::new(
            "mcp-governance",
            StepAction::WriteManagedSettings {
                scope: SettingsScope::User,
                path,
                managed_keys: MCP_KEYS.iter().map(|k| (*k).to_string()).collect(),
                content_sha256: sha256_hex(&content),
                merge: SettingsMerge::MergeManagedKeys,
                format: DocumentFormat::Json,
            },
            "apply the MCP allow/deny list to Claude Code's settings",
        ))
    }
}

impl ClaudeCodeIntegration {
    /// An executor loaded with the content `plan` describes, ready to apply it.
    ///
    /// # Errors
    ///
    /// Propagates any failure to render the bytes a step describes.
    pub fn loaded_executor(&self, plan: &IntegrationPlan) -> Result<Box<dyn StepExecutor + Send>, AdapterError> {
        Ok(Box::new(self.scoped_executor(self.step_content(plan)?)))
    }
}
