//! Serves a **real** DI-API socket so the TypeScript reference client can be
//! contract-tested against the thing it will actually talk to.
//!
//! # Why this binary exists at all
//!
//! The properties AAASM-5282 has to prove — a token scoped to tool A cannot act
//! on tool B, no response the client receives carries a secret, a downgrade is
//! surfaced rather than swallowed — are properties of the *served socket*, not
//! of a function and certainly not of a mock. A TypeScript test that asserted
//! them against a hand-written fake server would prove the fake was polite.
//!
//! `aa-runtime`'s own harness (`devint::testkit`) is `#[cfg(test)]`, so it is
//! not linkable from here, and AAASM-5280 owns `aa-runtime`/`aa-cli` while this
//! ticket is in flight. This binary therefore stands up
//! [`aa_runtime::devint::DevIntServer`] — the real server, the real codec, the
//! real token store, the real scope check — behind a stand-in
//! [`IntegrationLifecycle`], and touches neither crate.
//!
//! # The lifecycle stand-in is deliberately hostile
//!
//! [`FakeLifecycle`] returns a plan whose environment-injection step carries
//! [`LEAK_SENTINEL`] as a literal value. A real adapter would not, which is
//! exactly why the fake must: the question the leak test asks is whether the
//! *projection* can leak, not whether today's adapters happen to hold anything
//! worth leaking. If `StepView` ever grows a value-bearing field, the sentinel
//! reaches the client and the TypeScript test fails.
//!
//! # Protocol
//!
//! Prints one JSON line on stdout once the socket is bound and the fixture
//! tokens are enrolled, then serves until stdin closes or SIGTERM arrives.
//! Stdin-close is the shutdown signal because a test runner that dies takes its
//! child's stdin with it, so the harness cannot outlive the suite that spawned
//! it.

use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use tokio::io::AsyncReadExt;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

use aa_core::dev_tool::{DevToolKind, GovernanceLevel};
use aa_core::integration::policy_posture::{PolicyPosture, PolicyState};
use aa_core::integration::{
    now_unix_secs, DevToolCapabilities, EnvValue, EvidenceKind, ExerciseOutcome, IntegrationCapability,
    IntegrationPlan, IntegrationReceipt, IntegrationRequest, IntegrationStatus, IntegrationStep, LifecyclePhase,
    NextLevel, PolicyProfileRef, ProtectionEvidence, ProtectionLevel, ProtectionProfile, ProtectionState, RemovalPlan,
    SettingsMerge, SettingsScope, StepAction, StepReceipt, SupportedToolVersions, ToolVersion, VerificationOutcome,
    VerificationResult, VersionCompatibility, VersionSupport, LIFECYCLE_SCHEMA_VERSION,
};
use aa_runtime::devint::audit::TracingAuditSink;
use aa_runtime::devint::lifecycle::{
    ApprovalInput, ApprovalRelayReceipt, RepairReport, ScopedSecurityEvent, ToolDescriptor, VerdictKind,
};
use aa_runtime::devint::{
    DevIntServer, DevIntServerConfig, DevIntServices, DiVerb, IntegrationLifecycle, LifecycleError, TokenScope,
    ToolScope,
};

/// The secret a poisoned fixture carries. Its absence from everything the
/// client receives is the data-minimisation assertion.
const LEAK_SENTINEL: &str = "sk-live-THISMUSTNEVERLEAVE-0123456789";

/// A second sentinel, planted where an *event* projection could leak it.
const EVENT_SENTINEL: &str = "sk-live-EVENTMUSTNEVERLEAVE-9876543210";

/// A stand-in for AAASM-5278's lifecycle service.
struct FakeLifecycle;

impl FakeLifecycle {
    /// Refuse any tool the fixture does not know, so `UNKNOWN_TOOL` is
    /// reachable from a test rather than hypothetical.
    fn known(tool: &DevToolKind) -> Result<(), LifecycleError> {
        match tool {
            DevToolKind::ClaudeCode | DevToolKind::Codex => Ok(()),
            other => Err(LifecycleError::UnknownTool {
                tool_id: format!("{other:?}"),
            }),
        }
    }
}

/// A plan whose every value-bearing leaf carries [`LEAK_SENTINEL`].
fn poisoned_plan(tool: &DevToolKind) -> IntegrationPlan {
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
                managed_keys: vec!["permissions".to_string(), "enabledMcpjsonServers".to_string()],
                content_sha256: "abc123".to_string(),
                merge: SettingsMerge::MergeManagedKeys,
            },
            "Write the managed settings block",
        ),
        IntegrationStep::new(
            "env",
            StepAction::InjectLaunchEnvironment {
                scope: SettingsScope::User,
                variable: "ANTHROPIC_AUTH_TOKEN".to_string(),
                // The poison. A `StepView` has no field able to hold it.
                value: EnvValue::Literal(LEAK_SENTINEL.to_string()),
            },
            "Inject the launch environment",
        ),
    ];
    plan.warnings = vec!["The tool must be restarted for this to take effect".to_string()];
    plan
}

/// A status carrying **both** kinds of evidence, so a client can be checked for
/// showing them separately (`product-brief.md` §7.4).
///
/// Note the deliberate mismatch: the exercised evidence says `Blocked`, which is
/// protective, while the state is only `Integrated`. A client that ranked
/// evidence would be tempted to display `Gateway Protected` here. The service
/// decided `Integrated`, so `Integrated` is the only honest answer, and the
/// contract test asserts the client renders exactly that.
fn fake_status(tool: &DevToolKind) -> IntegrationStatus {
    IntegrationStatus {
        tool: tool.clone(),
        phase: LifecyclePhase::Installed,
        state: ProtectionState::Ladder(ProtectionLevel::Integrated),
        evidence: vec![
            ProtectionEvidence::new(
                IntegrationCapability::ManagedSettings,
                EvidenceKind::ReadBack { matches_receipt: true },
                1_700_000_000,
                "managed keys match the receipt",
            ),
            ProtectionEvidence::new(
                IntegrationCapability::ModelPathInterception,
                EvidenceKind::Exercised {
                    outcome: ExerciseOutcome::Blocked,
                },
                1_700_000_100,
                "probe blocked before egress",
            ),
            ProtectionEvidence::new(
                IntegrationCapability::HostEnforcement,
                EvidenceKind::Absent {
                    reason: "no host enforcement layer on this platform".to_string(),
                },
                1_700_000_100,
                "not available in this MVP",
            ),
        ],
        planned_level: ProtectionLevel::GatewayProtected,
        adapter_ceiling: GovernanceLevel::L2Enforce,
        compatibility: VersionCompatibility::Compatible {
            detected: ToolVersion::new(2, 1, 220),
        },
        next_level: Some(NextLevel {
            level: ProtectionLevel::GatewayProtected,
            blocked_because: "no core-side probe observation in the freshness window".to_string(),
        }),
        observed_at_unix_secs: 1_700_000_200,
        // A second deliberate mismatch, for the same reason as the one above:
        // the ladder says Integrated while the policy says a governed launch
        // would be refused. The two dimensions are independent — an integration
        // can be installed and working with no policy to run anything under —
        // and a client that collapsed them would report one as the other.
        policy: PolicyPosture::Resolved {
            state: PolicyState::Unconfigured,
            source: None,
            detail: "no policy artifact found; a governed launch is refused".to_string(),
        },
    }
}

#[async_trait]
impl IntegrationLifecycle for FakeLifecycle {
    async fn list_tools(&self) -> Result<Vec<ToolDescriptor>, LifecycleError> {
        Ok(vec![
            ToolDescriptor {
                tool: DevToolKind::ClaudeCode,
                display_name: "Claude Code".to_string(),
                detected: true,
                detected_version: Some(ToolVersion::new(2, 1, 220)),
                compatibility: VersionCompatibility::Compatible {
                    detected: ToolVersion::new(2, 1, 220),
                },
                capabilities: DevToolCapabilities::new()
                    .supported(IntegrationCapability::Discovery)
                    .supported(IntegrationCapability::ManagedSettings)
                    .unsupported(IntegrationCapability::HostEnforcement, "not available on this platform"),
                adapter_ceiling: GovernanceLevel::L2Enforce,
            },
            ToolDescriptor {
                tool: DevToolKind::Codex,
                display_name: "Codex".to_string(),
                detected: true,
                detected_version: Some(ToolVersion::new(1, 0, 0)),
                compatibility: VersionCompatibility::Compatible {
                    detected: ToolVersion::new(1, 0, 0),
                },
                capabilities: DevToolCapabilities::new().supported(IntegrationCapability::Discovery),
                adapter_ceiling: GovernanceLevel::L1Observe,
            },
        ])
    }

    async fn plan(&self, request: IntegrationRequest) -> Result<IntegrationPlan, LifecycleError> {
        Self::known(&request.tool)?;
        Ok(poisoned_plan(&request.tool))
    }

    async fn apply(&self, tool: &DevToolKind, plan_id: &str) -> Result<IntegrationReceipt, LifecycleError> {
        Self::known(tool)?;
        let plan = poisoned_plan(tool);
        Ok(IntegrationReceipt {
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
            // Planned ≠ achieved on purpose: the service downgrades, and the
            // client must show what the service decided.
            achieved_level: ProtectionLevel::Integrated,
            achieved_evidence: Vec::new(),
            verified_at_unix_secs: None,
        })
    }

    async fn status(&self, tool: &DevToolKind) -> Result<IntegrationStatus, LifecycleError> {
        Self::known(tool)?;
        Ok(fake_status(tool))
    }

    async fn verify(&self, tool: &DevToolKind) -> Result<VerificationResult, LifecycleError> {
        Self::known(tool)?;
        Ok(VerificationResult {
            verified_at_unix_secs: 1_700_000_300,
            outcome: VerificationOutcome::Passed,
            evidence: vec![ProtectionEvidence::new(
                IntegrationCapability::ModelPathInterception,
                EvidenceKind::Exercised {
                    outcome: ExerciseOutcome::Redacted,
                },
                1_700_000_300,
                "synthetic secret redacted before egress",
            )],
        })
    }

    async fn repair(&self, tool: &DevToolKind) -> Result<(RepairReport, IntegrationStatus), LifecycleError> {
        Self::known(tool)?;
        Ok((
            RepairReport {
                repaired: vec!["settings".to_string()],
                unrepairable: Vec::new(),
            },
            fake_status(tool),
        ))
    }

    async fn remove(&self, tool: &DevToolKind, _plan_id: Option<&str>) -> Result<RemovalPlan, LifecycleError> {
        Self::known(tool)?;
        Ok(RemovalPlan::new("removal-1", tool.clone()))
    }

    async fn scoped_events(
        &self,
        tool: &DevToolKind,
        _limit: u32,
        _since_unix_secs: u64,
    ) -> Result<Vec<ScopedSecurityEvent>, LifecycleError> {
        Self::known(tool)?;
        Ok(vec![ScopedSecurityEvent {
            occurred_at_unix_secs: 1_700_000_400,
            verdict_kind: VerdictKind::Redacted,
            mechanism: IntegrationCapability::ModelPathInterception,
            count: 2,
            // The label, never the value. `EVENT_SENTINEL` is what the value
            // *was*; it appears nowhere a client can reach.
            redaction_labels: vec!["anthropic_api_key".to_string()],
        }])
    }

    async fn relay_approval(
        &self,
        tool: &DevToolKind,
        approval_id: &str,
        input: ApprovalInput,
    ) -> Result<ApprovalRelayReceipt, LifecycleError> {
        Self::known(tool)?;
        Ok(ApprovalRelayReceipt {
            approval_id: approval_id.to_string(),
            relayed: input,
            accepted_at_unix_secs: 1_700_000_500,
        })
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let socket_path = std::env::args()
        .nth(1)
        .ok_or("usage: aa-devint-harness <socket-path>")?;
    let socket_path = PathBuf::from(socket_path);

    let server = DevIntServer::bind(DevIntServerConfig {
        socket_path: socket_path.clone(),
        max_connections: 8,
    })?;

    let tokens = aa_runtime::devint::TokenStore::new();
    let now = now_unix_secs();

    // The fixture enrolments. Each exists to make one boundary testable from
    // TypeScript; none of them is a shape a plugin should copy except
    // `claude_only`, which is what a per-tool integration client actually gets.
    let full = tokens
        .issue(
            "harness-full",
            TokenScope::full_lifecycle(ToolScope::AllTools),
            now,
            3600,
        )
        .0;
    let claude_only = tokens
        .issue(
            "harness-claude-only",
            TokenScope::full_lifecycle(ToolScope::tools(["claude-code"])),
            now,
            3600,
        )
        .0;
    let read_only = tokens
        .issue(
            "harness-read-only",
            TokenScope::read_only(ToolScope::AllTools),
            now,
            3600,
        )
        .0;
    let status_only = tokens
        .issue(
            "harness-status-only",
            TokenScope::new(ToolScope::tools(["claude-code"]), [DiVerb::Status]),
            now,
            3600,
        )
        .0;
    // Issued in the past with a TTL that has already elapsed.
    let expired = tokens
        .issue(
            "harness-expired",
            TokenScope::full_lifecycle(ToolScope::AllTools),
            now.saturating_sub(7200),
            3600,
        )
        .0;

    let services = DevIntServices {
        lifecycle: Arc::new(FakeLifecycle) as Arc<dyn IntegrationLifecycle>,
        tokens,
        audit: Arc::new(TracingAuditSink),
    };

    let cancel = CancellationToken::new();
    let tracker = TaskTracker::new();
    tracker.spawn(server.run(tracker.clone(), cancel.clone(), services));

    let ready = serde_json::json!({
        "socket": socket_path,
        "leakSentinel": LEAK_SENTINEL,
        "eventSentinel": EVENT_SENTINEL,
        "tokens": {
            "full": full.expose(),
            "claudeOnly": claude_only.expose(),
            "readOnly": read_only.expose(),
            "statusOnly": status_only.expose(),
            "expired": expired.expose(),
        }
    });
    println!("{ready}");

    // Serve until the parent goes away. Reading stdin to EOF is the shutdown
    // signal: a test runner that dies closes it, so the harness cannot outlive
    // the suite that spawned it and leave a socket behind.
    let mut stdin = tokio::io::stdin();
    let mut sink = [0u8; 64];
    loop {
        tokio::select! {
            read = stdin.read(&mut sink) => {
                if matches!(read, Ok(0) | Err(_)) {
                    break;
                }
            }
            _ = tokio::signal::ctrl_c() => break,
        }
    }

    cancel.cancel();
    tracker.close();
    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), tracker.wait()).await;
    Ok(())
}
