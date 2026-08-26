//! In-crate harness for driving a real DI-API server over a real socket.
//!
//! `#[cfg(test)]` only. It exists because the properties this ticket has to
//! prove — a token scoped to tool A cannot touch tool B, a revoked token stops
//! working immediately, a downgrade is refused — are properties of the *served
//! socket*, not of a function. Asserting them against an in-process helper
//! would prove the helper.
//!
//! [`FakeLifecycle`] stands in for AAASM-5278's service, which owns
//! `aa-core/src/integration/**` and `aa-devtool*` and is being written in
//! parallel. The DI-API is deliberately built against the
//! [`IntegrationLifecycle`] port rather than that implementation, so the fake
//! is a complete substitute for it here and the two branches do not collide.
//! It also lets a test assert something a real adapter could not be made to do
//! on demand: return a plan whose steps are stuffed with secrets.

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use tokio::io::{BufReader, BufWriter};
use tokio::net::UnixStream;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

use aa_core::dev_tool::{DevToolKind, GovernanceLevel};
use aa_core::integration::{
    DevToolCapabilities, EnvValue, IntegrationCapability, IntegrationPlan, IntegrationReceipt, IntegrationRequest,
    IntegrationStatus, IntegrationStep, LifecyclePhase, PolicyProfileRef, ProtectionLevel, ProtectionProfile,
    ProtectionState, RemovalPlan, SettingsScope, StepAction, StepReceipt, SupportedToolVersions, ToolVersion,
    VerificationOutcome, VerificationResult, VersionCompatibility, VersionSupport, LIFECYCLE_SCHEMA_VERSION,
};
use aa_proto::assembly::devint::v1 as wire;

use super::apply_outcome::ApplyMutation;
use super::audit::RecordingAuditSink;
use super::codec::{self, DiFrame, DiResponseFrame};
use super::lifecycle::{
    AppliedIntegration, ApprovalInput, ApprovalRelayReceipt, IntegrationLifecycle, LifecycleError, RepairReport,
    ScopedSecurityEvent, ToolDescriptor, VerdictKind,
};
use super::projection::tool_id;
use super::provenance::RuntimeProvenance;
use super::scope::TokenScope;
use super::server::{DevIntServer, DevIntServerConfig, DevIntServices};
use super::token::{CapabilityToken, TokenRecord, TokenStore};
use super::verb::DiVerb;

/// The sentinel a poisoned fixture carries. Its absence from every response and
/// every audit event is the data-minimisation assertion.
pub const LEAK_SENTINEL: &str = "sk-live-THISMUSTNEVERLEAVE-0123456789";

/// A `Hello` offering the given DI-API versions and a readable lifecycle
/// schema.
pub fn hello_offering(di_api_versions: &[u32]) -> wire::Hello {
    wire::Hello {
        client_name: "test-client".to_string(),
        client_version: "1.0.0".to_string(),
        di_api_versions: di_api_versions.to_vec(),
        lifecycle_schema_versions: vec![LIFECYCLE_SCHEMA_VERSION],
    }
}

/// How the fake lifecycle should answer.
#[derive(Debug, Clone, Default)]
enum Behaviour {
    #[default]
    Succeed,
    Refuse(String),
}

/// A stand-in for AAASM-5278's lifecycle service.
#[derive(Debug)]
pub struct FakeLifecycle {
    behaviour: Behaviour,
    mutation: ApplyMutation,
    calls: AtomicUsize,
}

/// `Changed` rather than a derived default.
///
/// [`ApplyMutation`] deliberately has no `Default`: the whole point of the type
/// is that no outcome is the one you get for free. The fake has to pick one, and
/// it picks the answer an ordinary first install gives.
impl Default for FakeLifecycle {
    fn default() -> Self {
        Self {
            behaviour: Behaviour::default(),
            mutation: ApplyMutation::Changed,
            calls: AtomicUsize::new(0),
        }
    }
}

impl FakeLifecycle {
    /// A fake that refuses every operation with `detail`.
    pub fn refusing(detail: impl Into<String>) -> Self {
        Self {
            behaviour: Behaviour::Refuse(detail.into()),
            ..Self::default()
        }
    }

    /// A fake whose `apply` states `mutation`.
    ///
    /// The seam that makes every wire outcome reachable over a **real socket**
    /// rather than only through the projection function. This build's own
    /// service states two of the five, so without it `failed` and `unsupported`
    /// would be tested against a struct literal and never against a frame — and
    /// a frame is where the contract lives (AAASM-5674).
    pub fn reporting(mutation: ApplyMutation) -> Self {
        Self {
            mutation,
            ..Self::default()
        }
    }

    /// How many lifecycle operations have been invoked. Used to assert that a
    /// refused request never reached the port at all.
    pub fn calls(&self) -> usize {
        self.calls.load(Ordering::Relaxed)
    }

    fn enter(&self) -> Result<(), LifecycleError> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        match &self.behaviour {
            Behaviour::Succeed => Ok(()),
            Behaviour::Refuse(detail) => Err(LifecycleError::Refused { detail: detail.clone() }),
        }
    }
}

/// A plan whose every value-bearing leaf carries [`LEAK_SENTINEL`].
///
/// A real adapter would not do this, which is exactly why the fake must: the
/// question is whether the *projection* can leak, not whether today's adapters
/// happen to hold anything worth leaking.
pub fn poisoned_plan(tool: &DevToolKind) -> IntegrationPlan {
    let request = IntegrationRequest::new(tool.clone(), ProtectionProfile::Recommended, SettingsScope::User)
        .with_policy_profile(PolicyProfileRef {
            id: "team-default".to_string(),
            display_name: "Team default".to_string(),
            digest: "sha256:abcd".to_string(),
        });
    let mut plan = IntegrationPlan::new(
        "plan-1",
        &request,
        ProtectionLevel::GatewayProtected,
        GovernanceLevel::L2Enforce,
    );
    plan.steps = vec![
        IntegrationStep::new(
            "settings",
            StepAction::WriteManagedSettings {
                scope: SettingsScope::User,
                path: PathBuf::from("/home/dev/.claude/settings.json"),
                managed_keys: vec!["aasm.gatewayUrl".to_string()],
                content_sha256: "abc123".to_string(),
                merge: aa_core::integration::SettingsMerge::MergeManagedKeys,
            },
            "Write the managed settings block",
        ),
        IntegrationStep::new(
            "env",
            StepAction::InjectLaunchEnvironment {
                scope: SettingsScope::User,
                variable: "ANTHROPIC_AUTH_TOKEN".to_string(),
                value: EnvValue::Literal(LEAK_SENTINEL.to_string()),
            },
            "Inject the launch environment",
        ),
    ];
    plan.warnings = vec!["The tool must be restarted for this to take effect".to_string()];
    plan
}

/// A status fixture for tests in sibling modules.
pub fn fake_status_for_tests() -> IntegrationStatus {
    fake_status(&DevToolKind::ClaudeCode)
}

fn fake_status(tool: &DevToolKind) -> IntegrationStatus {
    IntegrationStatus {
        tool: tool.clone(),
        phase: LifecyclePhase::Installed,
        state: ProtectionState::Ladder(ProtectionLevel::Integrated),
        evidence: Vec::new(),
        planned_level: ProtectionLevel::GatewayProtected,
        adapter_ceiling: GovernanceLevel::L2Enforce,
        compatibility: VersionCompatibility::Compatible {
            detected: ToolVersion::new(2, 1, 220),
        },
        next_level: None,
        observed_at_unix_secs: 1_700_000_000,
        policy: aa_core::integration::policy_posture::PolicyPosture::Unknown {
            reason: "test fixture; no policy resolved".to_string(),
        },
    }
}

#[async_trait]
impl IntegrationLifecycle for FakeLifecycle {
    async fn list_tools(&self) -> Result<Vec<ToolDescriptor>, LifecycleError> {
        self.enter()?;
        Ok(vec![ToolDescriptor {
            tool: DevToolKind::ClaudeCode,
            display_name: "Claude Code".to_string(),
            detected: true,
            detected_version: Some(ToolVersion::new(2, 1, 220)),
            compatibility: VersionCompatibility::Compatible {
                detected: ToolVersion::new(2, 1, 220),
            },
            capabilities: DevToolCapabilities::new()
                .supported(IntegrationCapability::Discovery)
                .unsupported(IntegrationCapability::ManagedLaunch, "no launch command"),
            adapter_ceiling: GovernanceLevel::L2Enforce,
        }])
    }

    async fn plan(&self, request: IntegrationRequest) -> Result<IntegrationPlan, LifecycleError> {
        self.enter()?;
        Ok(poisoned_plan(&request.tool))
    }

    async fn apply(&self, tool: &DevToolKind, plan_id: &str) -> Result<AppliedIntegration, LifecycleError> {
        self.enter()?;
        let plan = poisoned_plan(tool);
        let receipt = IntegrationReceipt {
            schema_version: LIFECYCLE_SCHEMA_VERSION,
            receipt_id: "receipt-1".to_string(),
            plan_id: if plan_id.is_empty() {
                "plan-1".to_string()
            } else {
                plan_id.to_string()
            },
            tool: tool.clone(),
            profile: ProtectionProfile::Recommended,
            settings_scope: SettingsScope::User,
            applied_at_unix_secs: 1_700_000_000,
            versions: VersionSupport {
                adapter_version: ToolVersion::new(1, 0, 0),
                lifecycle_schema_version: LIFECYCLE_SCHEMA_VERSION,
                supported_tool_versions: SupportedToolVersions::any(),
            }
            .component_versions(),
            tool_version: Some(ToolVersion::new(2, 1, 220)),
            steps: plan
                .steps
                .iter()
                .map(|s| StepReceipt::applied(s, Some("fingerprint-1".to_string())))
                .collect(),
            planned_level: ProtectionLevel::GatewayProtected,
            achieved_level: ProtectionLevel::Integrated,
            achieved_evidence: Vec::new(),
            verified_at_unix_secs: None,
        };
        Ok(AppliedIntegration {
            receipt,
            mutation: self.mutation.clone(),
        })
    }

    async fn status(&self, tool: &DevToolKind) -> Result<IntegrationStatus, LifecycleError> {
        self.enter()?;
        Ok(fake_status(tool))
    }

    async fn verify(&self, _tool: &DevToolKind) -> Result<VerificationResult, LifecycleError> {
        self.enter()?;
        Ok(VerificationResult {
            verified_at_unix_secs: 1_700_000_000,
            outcome: VerificationOutcome::Passed,
            evidence: Vec::new(),
        })
    }

    async fn repair(&self, tool: &DevToolKind) -> Result<(RepairReport, IntegrationStatus), LifecycleError> {
        self.enter()?;
        Ok((
            RepairReport {
                repaired: vec!["settings".to_string()],
                unrepairable: Vec::new(),
            },
            fake_status(tool),
        ))
    }

    async fn remove(&self, tool: &DevToolKind, _plan_id: Option<&str>) -> Result<RemovalPlan, LifecycleError> {
        self.enter()?;
        Ok(RemovalPlan::new("removal-1", tool.clone()))
    }

    async fn scoped_events(
        &self,
        _tool: &DevToolKind,
        _limit: u32,
        _since_unix_secs: u64,
    ) -> Result<Vec<ScopedSecurityEvent>, LifecycleError> {
        self.enter()?;
        Ok(vec![ScopedSecurityEvent {
            occurred_at_unix_secs: 1_700_000_000,
            verdict_kind: VerdictKind::Redacted,
            mechanism: IntegrationCapability::ModelPathInterception,
            count: 2,
            redaction_labels: vec!["anthropic_api_key".to_string()],
        }])
    }

    async fn relay_approval(
        &self,
        _tool: &DevToolKind,
        approval_id: &str,
        input: ApprovalInput,
    ) -> Result<ApprovalRelayReceipt, LifecycleError> {
        self.enter()?;
        Ok(ApprovalRelayReceipt {
            approval_id: approval_id.to_string(),
            relayed: input,
            accepted_at_unix_secs: 1_700_000_000,
        })
    }
}

/// A running DI-API server on a temporary socket.
pub struct TestServer {
    socket_path: PathBuf,
    tokens: TokenStore,
    audit: RecordingAuditSink,
    lifecycle: Arc<FakeLifecycle>,
    provenance: Arc<RuntimeProvenance>,
    cancel: CancellationToken,
    tracker: TaskTracker,
    // Kept alive so the socket directory outlives the server. `Option` because
    // a server bound into a *caller-owned* directory has none of its own — that
    // is how two servers end up in one directory (AAASM-5628).
    _dir: Option<tempfile::TempDir>,
}

impl TestServer {
    /// Bind and run a server backed by `lifecycle`, reporting this build.
    pub async fn start(lifecycle: FakeLifecycle) -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let socket_path = dir.path().join("run").join("devint.sock");
        Self::bind_at(socket_path, Some(dir), lifecycle, RuntimeProvenance::detect()).await
    }

    /// Bind and run a server that reports `provenance` as its build identity.
    ///
    /// The seam that makes AAASM-5628's first falsification reproducible: a
    /// runtime from build A answering a client from build B otherwise needs two
    /// compilations, so the property would go untested and the check would be
    /// free to rot.
    pub async fn start_reporting(lifecycle: FakeLifecycle, provenance: RuntimeProvenance) -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let socket_path = dir.path().join("run").join("devint.sock");
        Self::bind_at(socket_path, Some(dir), lifecycle, provenance).await
    }

    /// Bind and run a server at an exact path the caller owns.
    ///
    /// Lets two servers share one directory, which is the only shape the
    /// duplicate-runtime failure can take: a second bind on the *same* path
    /// unlinks the first, so two reachable runtimes always sit on two names.
    pub async fn start_at(socket_path: PathBuf, lifecycle: FakeLifecycle) -> Self {
        Self::bind_at(socket_path, None, lifecycle, RuntimeProvenance::detect()).await
    }

    async fn bind_at(
        socket_path: PathBuf,
        dir: Option<tempfile::TempDir>,
        lifecycle: FakeLifecycle,
        provenance: RuntimeProvenance,
    ) -> Self {
        let server = DevIntServer::bind(DevIntServerConfig {
            socket_path: socket_path.clone(),
            max_connections: 8,
        })
        .expect("bind");

        let tokens = TokenStore::new();
        let audit = RecordingAuditSink::new();
        let lifecycle = Arc::new(lifecycle);
        let provenance = Arc::new(provenance);
        let cancel = CancellationToken::new();
        let tracker = TaskTracker::new();

        let services = DevIntServices {
            lifecycle: Arc::clone(&lifecycle) as Arc<dyn IntegrationLifecycle>,
            tokens: tokens.clone(),
            audit: Arc::new(audit.clone()),
            provenance: Arc::clone(&provenance),
        };
        tracker.spawn(server.run(tracker.clone(), cancel.clone(), services));

        Self {
            socket_path,
            tokens,
            audit,
            lifecycle,
            provenance,
            cancel,
            tracker,
            _dir: dir,
        }
    }

    /// The build identity this server reports over the handshake.
    pub fn provenance(&self) -> &RuntimeProvenance {
        &self.provenance
    }

    /// The socket this server is listening on.
    pub fn socket_path(&self) -> &std::path::Path {
        &self.socket_path
    }

    /// The enrolment book, for revocation and rotation tests.
    pub fn tokens(&self) -> &TokenStore {
        &self.tokens
    }

    /// Everything the server has audited.
    pub fn audit(&self) -> &RecordingAuditSink {
        &self.audit
    }

    /// The fake lifecycle, for asserting whether it was reached at all.
    pub fn lifecycle(&self) -> &FakeLifecycle {
        &self.lifecycle
    }

    /// Enrol a client and get its token.
    pub fn enrol(&self, client_name: &str, scope: TokenScope) -> (CapabilityToken, TokenRecord) {
        self.tokens
            .issue(client_name, scope, aa_core::integration::now_unix_secs(), 3600)
    }

    /// Enrol a client whose token has already expired.
    pub fn enrol_expired(&self, client_name: &str, scope: TokenScope) -> (CapabilityToken, TokenRecord) {
        let long_ago = aa_core::integration::now_unix_secs().saturating_sub(7200);
        self.tokens.issue(client_name, scope, long_ago, 3600)
    }

    /// Open a connection without negotiating.
    pub async fn connect_raw(&self) -> RawClient {
        let stream = UnixStream::connect(&self.socket_path).await.expect("connect");
        let (reader, writer) = stream.into_split();
        RawClient {
            reader: BufReader::new(reader),
            writer: BufWriter::new(writer),
            next_request_id: 1,
        }
    }

    /// Block until the audit sink has at least `count` events, so a test does
    /// not race the server's own task.
    pub async fn wait_for_audit(&self, count: usize) {
        for _ in 0..200 {
            if self.audit.events().len() >= count {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        panic!("audit sink never reached {count} events");
    }

    /// Stop the server.
    pub async fn shutdown(self) {
        self.cancel.cancel();
        self.tracker.close();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), self.tracker.wait()).await;
    }
}

/// A client that speaks the wire directly, with no negotiation performed.
pub struct RawClient {
    reader: BufReader<tokio::net::unix::OwnedReadHalf>,
    writer: BufWriter<tokio::net::unix::OwnedWriteHalf>,
    next_request_id: u64,
}

impl RawClient {
    /// Send a `Hello`.
    pub async fn send_hello(&mut self, hello: wire::Hello) {
        codec::write_client_frame(&mut self.writer, DiFrame::Hello(hello))
            .await
            .expect("write hello");
    }

    /// Send a fully-specified request.
    pub async fn send_raw(&mut self, request: wire::Request) {
        codec::write_client_frame(&mut self.writer, DiFrame::Request(Box::new(request)))
            .await
            .expect("write request");
    }

    /// Send a simple verb request.
    pub async fn send_request(&mut self, verb: DiVerb, tool: &str, token: Option<&CapabilityToken>, request_id: u64) {
        self.send_raw(build_request(verb, tool, token, request_id)).await;
    }

    /// Read one server frame.
    pub async fn read(&mut self) -> DiResponseFrame {
        codec::read_response_frame(&mut self.reader).await.expect("read frame")
    }

    /// Read one server frame, allowing for a closed connection.
    pub async fn try_read(&mut self) -> Option<DiResponseFrame> {
        codec::read_response_frame(&mut self.reader).await.ok()
    }

    /// Send a request and read its response.
    pub async fn request(&mut self, verb: DiVerb, tool: &str, token: Option<&CapabilityToken>) -> DiResponseFrame {
        let request_id = self.next_request_id;
        self.next_request_id += 1;
        self.send_request(verb, tool, token, request_id).await;
        self.read().await
    }

    /// Send a fully-specified request and read its response.
    pub async fn send_raw_request(&mut self, request: wire::Request) -> DiResponseFrame {
        self.send_raw(request).await;
        self.read().await
    }
}

/// Build a plain verb request.
pub fn build_request(verb: DiVerb, tool: &str, token: Option<&CapabilityToken>, request_id: u64) -> wire::Request {
    wire::Request {
        request_id,
        verb: verb.to_wire() as i32,
        capability_token: token.map(|t| t.expose().to_string()).unwrap_or_default(),
        tool_id: tool.to_string(),
        plan: matches!(verb, DiVerb::Plan).then(|| wire::PlanArgs {
            profile: "recommended".to_string(),
            requested_level: "gateway_protected".to_string(),
            settings_scope: "user".to_string(),
            allow_privileged_host_steps: false,
            policy_profile_id: "team-default".to_string(),
            // User scope, so no project is named — the field is only mandatory
            // at project scope (AAASM-5913).
            project_root: String::new(),
        }),
        apply: matches!(verb, DiVerb::Apply).then(|| wire::ApplyArgs {
            plan_id: "plan-1".to_string(),
        }),
        remove: matches!(verb, DiVerb::Remove).then(|| wire::RemoveArgs {
            plan_id: "plan-1".to_string(),
        }),
        events: matches!(verb, DiVerb::ScopedEvents).then(|| wire::ScopedEventsArgs {
            limit: 10,
            since_unix_secs: 0,
        }),
        approval: matches!(verb, DiVerb::ApprovalRelay).then(|| wire::ApprovalRelayArgs {
            approval_id: "approval-1".to_string(),
            user_input: "approve".to_string(),
        }),
    }
}

/// Connect, negotiate, and assert the negotiation was usable.
pub async fn connect_and_negotiate(server: &TestServer, hello: wire::Hello) -> RawClient {
    let mut client = server.connect_raw().await;
    client.send_hello(hello).await;
    match client.read().await {
        DiResponseFrame::HelloAck(_) => client,
        other => panic!("expected HelloAck, got {other:?}"),
    }
}

/// The tool id every fixture uses.
pub fn claude_code_id() -> String {
    tool_id(&DevToolKind::ClaudeCode)
}
