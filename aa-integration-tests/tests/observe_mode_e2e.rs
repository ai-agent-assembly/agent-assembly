//! AAASM-1573 / F116 ST-R — Tool Execution Sandbox / Observe Mode E2E.
//!
//! Acceptance attestation for the sandbox / dry-run enforcement posture
//! delivered in AAASM-1553. The feature implementation (gateway evaluator
//! branch in AAASM-1556, CLI flag in AAASM-1558, audit filter in
//! AAASM-1559) is already covered by per-crate unit and integration tests;
//! this file is the F116 acceptance lens that pins the contract from the
//! operator's seat.
//!
//! ## Test cases
//!
//! * **ST-R-1** — Observe + deny rule → agent NOT blocked; one shadow
//!   audit entry with `dry_run: true` and `shadow_decision: "deny"`.
//! * **ST-R-2** — Observe + allow decision → no shadow event emitted.
//! * **ST-R-3** — `aasm run --observe` prints the sandbox banner and
//!   injects `AA_ENFORCEMENT_MODE=observe` into the child env.
//! * **ST-R-4** — Regression guard: enforce + deny still blocks; no
//!   shadow event in the audit channel.
//! * **ST-R-5** — Per-agent override: two agents under one deny policy
//!   resolve independently (one observed, one enforced).
//!
//! ## ST-R-6 (Python SDK observe mode) — deferred
//!
//! AAASM-1560 is closed but the Python SDK is missing the
//! `enforcement_mode=` kwarg on `init_assembly()`. The matching test will
//! land in `python-sdk/test/integration/` once that gap is filled — a
//! follow-up subtask under AAASM-1553 is filed for the SDK plumbing.
//!
//! ## Why the per-agent override mechanism
//!
//! `policy_service.rs` resolves the effective mode as
//! `resolve_enforcement_mode(agent_override, EnforcementMode::Enforce)`
//! — the second argument is hardcoded today, so the `enforcement_mode`
//! field on a `PolicyDocument` does not yet influence runtime behaviour.
//! Every ST-R-N case below therefore drives the posture through the
//! per-agent override set on `AgentRecord.enforcement_mode`, matching
//! how the spec said operators would gradually roll out observe mode
//! agent-by-agent.

use std::collections::{BTreeMap, VecDeque};
use std::net::SocketAddr;
use std::path::Path;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use std::time::Duration;

use aa_core::{AuditEntry, GovernanceLevel};
use aa_gateway::registry::convert::proto_agent_id_to_key;
use aa_gateway::registry::store::AgentRecord;
use aa_gateway::registry::{AgentRegistry, AgentStatus};
use aa_gateway::service::PolicyServiceImpl;
use aa_gateway::PolicyEngine;
use aa_proto::assembly::common::v1::{ActionType, AgentId as ProtoAgentId, Decision};
use aa_proto::assembly::policy::v1::policy_service_client::PolicyServiceClient;
use aa_proto::assembly::policy::v1::policy_service_server::PolicyServiceServer;
use aa_proto::assembly::policy::v1::{action_context::Action, ActionContext, CheckActionRequest, ToolCallContext};
use chrono::Utc;
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tonic::transport::Server;

/// Resolve a fixture path under `aa-integration-tests/tests/common/fixtures/`.
fn fixture_path(rel: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/common/fixtures")
        .join(rel)
}

/// Boot a `PolicyService` gRPC server backed by `policy_fixture`, returning
/// the bound address, a handle to the registry (so the test can install
/// per-agent enforcement_mode overrides), and the audit-entry receiver the
/// test asserts on.
async fn start_gateway_with_policy_fixture(
    policy_fixture: &str,
) -> (SocketAddr, Arc<AgentRegistry>, mpsc::Receiver<AuditEntry>) {
    let path = fixture_path(policy_fixture);
    let (alert_tx, _) = tokio::sync::broadcast::channel::<aa_gateway::budget::BudgetAlert>(64);
    let engine = Arc::new(PolicyEngine::load_from_file(&path, alert_tx).expect("policy fixture must load cleanly"));
    let registry = Arc::new(AgentRegistry::new());
    let (audit_tx, audit_rx) = mpsc::channel::<AuditEntry>(4096);
    let audit_drops = Arc::new(AtomicU64::new(0));
    let service = PolicyServiceImpl::with_registry(
        Arc::clone(&engine),
        Arc::clone(&registry),
        audit_tx,
        audit_drops,
        [0u8; 32],
    );

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind 127.0.0.1:0");
    let addr = listener.local_addr().expect("local_addr");

    tokio::spawn(async move {
        let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);
        Server::builder()
            .add_service(PolicyServiceServer::new(service))
            .serve_with_incoming(incoming)
            .await
            .expect("tonic Server::serve_with_incoming");
    });

    // The server is ready once it has accepted the first poll; a brief sleep
    // beats writing a TCP probe loop here.
    tokio::time::sleep(Duration::from_millis(50)).await;
    (addr, registry, audit_rx)
}

/// Build and register an `AgentRecord` carrying an optional per-agent
/// `enforcement_mode` override. `None` leaves the agent on the policy
/// default (which today is hardcoded `Enforce`).
fn register_agent_with_mode(
    registry: &AgentRegistry,
    agent_name: &str,
    proto_id: &ProtoAgentId,
    mode: Option<aa_core::EnforcementMode>,
) {
    let key = proto_agent_id_to_key(proto_id);
    let record = AgentRecord {
        agent_id: key,
        name: agent_name.into(),
        framework: "custom".into(),
        version: "1.0.0".into(),
        risk_tier: 0,
        tool_names: vec![],
        public_key: "pk".into(),
        credential_token: "tok".into(),
        metadata: BTreeMap::new(),
        registered_at: Utc::now(),
        last_heartbeat: Utc::now(),
        status: AgentStatus::Active,
        pid: None,
        session_count: 0,
        last_event: None,
        policy_violations_count: 0,
        active_sessions: vec![],
        recent_events: VecDeque::new(),
        recent_traces: vec![],
        layer: None,
        governance_level: GovernanceLevel::default(),
        parent_agent_id: None,
        team_id: None,
        depth: 0,
        delegation_reason: None,
        spawned_by_tool: None,
        root_agent_id: None,
        children: vec![],
        parent_key: None,
        enforcement_mode: mode,
    };
    registry.register(record).expect("register agent");
}

/// Build a `CheckActionRequest` for the given agent invoking `tool_name`.
fn tool_call_request_for(proto_id: &ProtoAgentId, tool_name: &str) -> CheckActionRequest {
    CheckActionRequest {
        agent_id: Some(proto_id.clone()),
        credential_token: "tok".into(),
        trace_id: format!("trace-{tool_name}"),
        span_id: "span-1".into(),
        action_type: ActionType::ToolCall as i32,
        context: Some(ActionContext {
            action: Some(Action::ToolCall(ToolCallContext {
                tool_name: tool_name.into(),
                tool_source: "test".into(),
                args_json: b"{}".to_vec(),
                target_url: String::new(),
            })),
        }),
    }
}

/// Drain audit entries that arrive within a short bounded window. The
/// `record_audit` call site is fire-and-forget, so the entry may not be on
/// the channel synchronously with the `CheckAction` response. Returns all
/// entries collected before the timeout.
async fn drain_audit_entries(audit_rx: &mut mpsc::Receiver<AuditEntry>) -> Vec<AuditEntry> {
    let mut out = vec![];
    for _ in 0..10 {
        match tokio::time::timeout(Duration::from_millis(50), audit_rx.recv()).await {
            Ok(Some(entry)) => out.push(entry),
            Ok(None) | Err(_) => break,
        }
    }
    out
}

// ── ST-R-1 ──────────────────────────────────────────────────────────────────

/// **ST-R-1** — An agent registered with `enforcement_mode = Observe`
/// hits a deny rule. The gateway must rewrite the decision to `Allow`
/// (the agent proceeds) and the audit log must carry exactly one entry
/// tagged `dry_run: true` with `shadow_decision: "deny"`.
#[tokio::test]
async fn st_r_1_observe_mode_deny_rule_returns_allow_and_dry_run_audit() {
    let (addr, registry, mut audit_rx) = start_gateway_with_policy_fixture("policies/bash_deny.yaml").await;

    let proto_id = ProtoAgentId {
        org_id: "org-st-r-1".into(),
        team_id: "team-st-r-1".into(),
        agent_id: "observe-agent".into(),
    };
    register_agent_with_mode(
        &registry,
        "observe-agent",
        &proto_id,
        Some(aa_core::EnforcementMode::Observe),
    );

    let mut client = PolicyServiceClient::connect(format!("http://{addr}"))
        .await
        .expect("connect to PolicyService");
    let resp = client
        .check_action(tool_call_request_for(&proto_id, "bash"))
        .await
        .expect("check_action RPC")
        .into_inner();

    assert_eq!(
        resp.decision,
        Decision::Allow as i32,
        "ST-R-1: observe mode must rewrite Deny → Allow on the response so the agent proceeds",
    );

    let entries = drain_audit_entries(&mut audit_rx).await;
    assert_eq!(
        entries.len(),
        1,
        "ST-R-1: expected exactly one shadow audit entry, got {}",
        entries.len(),
    );
    let payload: serde_json::Value =
        serde_json::from_str(entries[0].payload()).expect("ST-R-1: shadow audit payload must be valid JSON");
    assert_eq!(
        payload["dry_run"],
        serde_json::Value::Bool(true),
        "ST-R-1: shadow audit entry must carry dry_run: true",
    );
    assert_eq!(
        payload["shadow_decision"], "deny",
        "ST-R-1: shadow_decision must record the suppressed Deny outcome",
    );
}

// ── ST-R-2 ──────────────────────────────────────────────────────────────────

/// **ST-R-2** — An agent in observe mode dispatches a tool whose policy
/// outcome is already `Allow`. The response stays `Allow` (same as enforce
/// mode), and the audit entry must NOT carry `dry_run` or `shadow_decision`
/// — observe mode only fabricates shadow metadata for would-be violations.
/// Otherwise shadow-volume in the audit log would mirror all traffic
/// instead of just the would-be deny / redact / pending outcomes
/// operators care about.
#[tokio::test]
async fn st_r_2_observe_mode_allow_decision_emits_no_shadow_metadata() {
    // `allow_deny_mixed.yaml` exposes `read_file: allow: true`; reusing the
    // existing F116 fixture keeps the observe-mode allow path under the same
    // policy schema other ST-X tests already validate.
    let (addr, registry, mut audit_rx) = start_gateway_with_policy_fixture("policies/allow_deny_mixed.yaml").await;

    let proto_id = ProtoAgentId {
        org_id: "org-st-r-2".into(),
        team_id: "team-st-r-2".into(),
        agent_id: "observe-clean-agent".into(),
    };
    register_agent_with_mode(
        &registry,
        "observe-clean-agent",
        &proto_id,
        Some(aa_core::EnforcementMode::Observe),
    );

    let mut client = PolicyServiceClient::connect(format!("http://{addr}"))
        .await
        .expect("connect to PolicyService");
    let resp = client
        .check_action(tool_call_request_for(&proto_id, "read_file"))
        .await
        .expect("check_action RPC")
        .into_inner();
    assert_eq!(
        resp.decision,
        Decision::Allow as i32,
        "ST-R-2: explicit-allow tool must continue to return Allow under observe mode",
    );

    let entries = drain_audit_entries(&mut audit_rx).await;
    assert_eq!(
        entries.len(),
        1,
        "ST-R-2: an Allow decision still produces one audit entry (the live ToolCallIntercepted record), got {}",
        entries.len(),
    );
    let payload: serde_json::Value =
        serde_json::from_str(entries[0].payload()).expect("ST-R-2: audit payload must be valid JSON");
    assert!(
        payload.get("dry_run").is_none(),
        "ST-R-2: Allow-decision audit entries in observe mode must NOT carry dry_run, got: {payload}",
    );
    assert!(
        payload.get("shadow_decision").is_none(),
        "ST-R-2: Allow-decision audit entries in observe mode must NOT carry shadow_decision, got: {payload}",
    );
}

// ── ST-R-3 ──────────────────────────────────────────────────────────────────

/// **ST-R-3** — `aasm run --observe --dry-run <tool>` surfaces the sandbox
/// posture to the operator before any tool output and injects
/// `AA_ENFORCEMENT_MODE=observe` into the planned child environment.
///
/// `--dry-run` short-circuits gateway registration (see `run.rs:520`), so
/// the F116 attestation here is the operator-visible contract only: the
/// banner, the env-var plan, and the audit-list filter hint. The
/// registration-payload + gateway-side `RegisterRequest.enforcement_mode`
/// path is already attested by AAASM-1556 / AAASM-1558 crate-level tests
/// — re-driving it from `aa-integration-tests` would require pre-building
/// the `aasm` binary against a live local gateway, which adds CI cost
/// without strengthening the F116 contract.
#[test]
fn st_r_3_aasm_run_observe_emits_banner_and_env_injection() {
    let out = std::process::Command::new(env!("CARGO"))
        .args([
            "run",
            "--quiet",
            "-p",
            "aa-cli",
            "--bin",
            "aasm",
            "--",
            "run",
            "claude",
            "--observe",
            "--dry-run",
        ])
        .output()
        .expect("aasm run --observe --dry-run must execute");

    assert!(
        out.status.success(),
        "ST-R-3: aasm run --observe --dry-run should exit 0; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("[AAASM] Running in sandbox/observe mode"),
        "ST-R-3: observe banner must be printed to stderr before tool output:\n{stderr}",
    );
    assert!(
        stderr.contains("aa audit list --dry-run-only"),
        "ST-R-3: banner must point operators at the dry-run audit filter:\n{stderr}",
    );

    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("AA_ENFORCEMENT_MODE=observe"),
        "ST-R-3: dry-run plan must show AA_ENFORCEMENT_MODE=observe in the env section:\n{stdout}",
    );
}

// ── ST-R-4 ──────────────────────────────────────────────────────────────────

/// **ST-R-4** — Regression guard: adding observe mode must not alter the
/// enforce-mode behaviour for agents that did not opt in. Same bash-deny
/// policy as ST-R-1, but the agent registers with `enforcement_mode: None`
/// — the resolver falls back to the hardcoded `Enforce` default. The
/// gateway must return `Deny`, and the resulting audit entry must NOT
/// carry `dry_run` or `shadow_decision`. If anyone ever flips the resolver
/// default, this assertion catches it before the next ST-R-1 run reports
/// a misleading green.
#[tokio::test]
async fn st_r_4_enforce_mode_deny_still_blocks_and_emits_no_shadow_event() {
    let (addr, registry, mut audit_rx) = start_gateway_with_policy_fixture("policies/bash_deny.yaml").await;

    let proto_id = ProtoAgentId {
        org_id: "org-st-r-4".into(),
        team_id: "team-st-r-4".into(),
        agent_id: "enforce-agent".into(),
    };
    register_agent_with_mode(&registry, "enforce-agent", &proto_id, None);

    let mut client = PolicyServiceClient::connect(format!("http://{addr}"))
        .await
        .expect("connect to PolicyService");
    let resp = client
        .check_action(tool_call_request_for(&proto_id, "bash"))
        .await
        .expect("check_action RPC")
        .into_inner();
    assert_eq!(
        resp.decision,
        Decision::Deny as i32,
        "ST-R-4: enforce mode must still block deny rules (reason={:?})",
        resp.reason,
    );

    let entries = drain_audit_entries(&mut audit_rx).await;
    assert_eq!(
        entries.len(),
        1,
        "ST-R-4: enforce + deny still produces one audit entry, got {}",
        entries.len(),
    );
    let payload: serde_json::Value =
        serde_json::from_str(entries[0].payload()).expect("ST-R-4: audit payload must be valid JSON");
    assert!(
        payload.get("dry_run").is_none(),
        "ST-R-4: enforce-mode audit entry must not carry dry_run, got: {payload}",
    );
    assert!(
        payload.get("shadow_decision").is_none(),
        "ST-R-4: enforce-mode audit entry must not carry shadow_decision, got: {payload}",
    );
}

// ── ST-R-5 ──────────────────────────────────────────────────────────────────

/// **ST-R-5** — Per-agent override isolation. Two agents share one
/// bash-deny policy. The "experimental" agent registers with
/// `enforcement_mode: Observe`; the "trusted" agent registers with no
/// override. Each must resolve to its own mode independently — observe
/// mode for one agent must not leak across to other agents under the
/// same policy. This is the AC that makes gradual observe-mode rollouts
/// safe: tag a single agent, validate, expand.
#[tokio::test]
async fn st_r_5_per_agent_override_isolates_observe_from_enforce_under_one_policy() {
    let (addr, registry, _audit_rx) = start_gateway_with_policy_fixture("policies/bash_deny.yaml").await;

    let experimental_id = ProtoAgentId {
        org_id: "org-st-r-5".into(),
        team_id: "team-st-r-5".into(),
        agent_id: "experimental-agent".into(),
    };
    let trusted_id = ProtoAgentId {
        org_id: "org-st-r-5".into(),
        team_id: "team-st-r-5".into(),
        agent_id: "trusted-agent".into(),
    };
    register_agent_with_mode(
        &registry,
        "experimental-agent",
        &experimental_id,
        Some(aa_core::EnforcementMode::Observe),
    );
    register_agent_with_mode(&registry, "trusted-agent", &trusted_id, None);

    let mut client = PolicyServiceClient::connect(format!("http://{addr}"))
        .await
        .expect("connect to PolicyService");

    let experimental_resp = client
        .check_action(tool_call_request_for(&experimental_id, "bash"))
        .await
        .expect("check_action RPC (experimental)")
        .into_inner();
    let trusted_resp = client
        .check_action(tool_call_request_for(&trusted_id, "bash"))
        .await
        .expect("check_action RPC (trusted)")
        .into_inner();

    assert_eq!(
        experimental_resp.decision,
        Decision::Allow as i32,
        "ST-R-5: experimental agent (observe override) must proceed under the bash-deny policy",
    );
    assert_eq!(
        trusted_resp.decision,
        Decision::Deny as i32,
        "ST-R-5: trusted agent (no override) must remain blocked by the same policy (reason={:?})",
        trusted_resp.reason,
    );
}
