//! HORO-1375 AC-6 — corporate-vs-personal precedence test.
//!
//! With personal-observe active as the policy default, a per-agent
//! `enforcement_mode` override (managed policy, or an enterprise temporary
//! shadow window) must ALWAYS win over the profile's default. This is the
//! core acceptance criterion of the whole ticket: personal-observe supplies
//! the fallback ONLY, never the final word.

use std::collections::BTreeMap;
use std::io::Write;
use std::net::SocketAddr;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use std::time::Duration;

use aa_core::{AuditEntry, EnforcementMode, GovernanceLevel};
use aa_gateway::engine::{resolve_enforcement_mode, PolicyDefaultMode};
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

/// Legitimately mint a personal-observe `PolicyDefaultMode` via the real boot
/// gate — not a shortcut construction — so this test exercises the actual
/// production path the founder's structural invariant is meant to protect.
fn personal_observe_default() -> PolicyDefaultMode {
    let mut cfg = aa_core::config::GatewayConfig::default();
    cfg.observation.profile = aa_core::config::ObservationProfile::PersonalObserve;
    let dep = aa_core::observation::PersonalObserveDeployment {
        config: &cfg,
        bind_addr: "127.0.0.1:7700".parse().unwrap(),
        auth_is_off: false,
    };
    match aa_core::observation::authorize_personal_observe(dep, |_| None).expect("gate must grant") {
        aa_core::observation::PersonalObserveOutcome::Granted(grant) => PolicyDefaultMode::personal_observe(&grant),
        aa_core::observation::PersonalObserveOutcome::NotRequested => panic!("expected Granted"),
    }
}

#[test]
fn agent_override_always_wins_through_the_real_resolver() {
    let default = personal_observe_default();

    assert_eq!(
        resolve_enforcement_mode(Some(EnforcementMode::Enforce), default).get(),
        EnforcementMode::Enforce,
        "managed policy (Enforce override) must win over the personal-observe default"
    );
    assert_eq!(
        resolve_enforcement_mode(Some(EnforcementMode::Observe), default).get(),
        EnforcementMode::Observe,
        "an enterprise shadow window (still expiry-capped elsewhere) must resolve to Observe"
    );
    assert_eq!(
        resolve_enforcement_mode(Some(EnforcementMode::Disabled), default).get(),
        EnforcementMode::Disabled
    );
    assert_eq!(
        resolve_enforcement_mode(None, default).get(),
        EnforcementMode::Observe,
        "None (no override) is the profile's ONLY effect: it alone resolves to Observe"
    );
}

#[test]
fn no_override_resolves_to_enforce_under_the_standard_default() {
    // Sanity/contrast: without personal-observe, None resolves to Enforce —
    // proves the profile's effect is isolated to the personal-observe case
    // above, not a general change to `resolve_enforcement_mode`.
    assert_eq!(
        resolve_enforcement_mode(None, PolicyDefaultMode::enforce()).get(),
        EnforcementMode::Enforce
    );
}

// ── End-to-end variant: a real CheckAction against a DENY policy, for an
// agent with Some(Enforce), returns Deny — not an audited Allow — while
// personal-observe is active as the service's policy default. ────────────

const DENY_BASH_POLICY: &str = r#"
version: "1"
tools:
  bash:
    allow: false
"#;

async fn start_server_with_policy_default(
    policy_yaml: &str,
    policy_default_mode: PolicyDefaultMode,
) -> (SocketAddr, Arc<AgentRegistry>) {
    let mut tmp = tempfile::NamedTempFile::new().unwrap();
    write!(tmp, "{}", policy_yaml).unwrap();
    tmp.flush().unwrap();

    let (alert_tx, _) = tokio::sync::broadcast::channel::<aa_gateway::budget::BudgetAlert>(64);
    let engine = Arc::new(PolicyEngine::load_from_file(tmp.path(), alert_tx).unwrap());
    let registry = Arc::new(AgentRegistry::new());
    let (audit_tx, mut audit_rx) = mpsc::channel::<AuditEntry>(4096);
    let audit_drops = Arc::new(AtomicU64::new(0));
    // Drain the channel so the writer side never blocks.
    tokio::spawn(async move { while audit_rx.recv().await.is_some() {} });
    let service = PolicyServiceImpl::with_registry(
        Arc::clone(&engine),
        Arc::clone(&registry),
        audit_tx,
        audit_drops,
        [0u8; 32],
    )
    .with_policy_default_mode(policy_default_mode);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _tmp = tmp;
        let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);
        Server::builder()
            .add_service(PolicyServiceServer::new(service))
            .serve_with_incoming(incoming)
            .await
            .unwrap();
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    (addr, registry)
}

fn register(registry: &AgentRegistry, proto_id: &ProtoAgentId, credential_token: &str, mode: Option<EnforcementMode>) {
    let record = AgentRecord {
        agent_id: proto_agent_id_to_key(proto_id),
        name: proto_id.agent_id.clone(),
        framework: "custom".into(),
        version: "1.0.0".into(),
        risk_tier: 0,
        tool_names: vec![],
        public_key: "pk".into(),
        credential_token: credential_token.into(),
        metadata: BTreeMap::new(),
        registered_at: Utc::now(),
        last_heartbeat: Utc::now(),
        status: AgentStatus::Active,
        pid: None,
        session_count: 0,
        last_event: None,
        active_sessions: vec![],
        recent_events: Default::default(),
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
        enforcement_mode_expires_at: None,
        org_id: None,
    };
    registry.register(record).unwrap();
}

fn bash_check_request(proto_id: ProtoAgentId, credential_token: &str) -> CheckActionRequest {
    CheckActionRequest {
        agent_id: Some(proto_id),
        credential_token: credential_token.into(),
        trace_id: format!("trace-{credential_token}"),
        span_id: "span-1".into(),
        action_type: ActionType::ToolCall as i32,
        context: Some(ActionContext {
            action: Some(Action::ToolCall(ToolCallContext {
                tool_name: "bash".into(),
                tool_source: "test".into(),
                args_json: b"{}".to_vec(),
                target_url: String::new(),
            })),
        }),
        caller_agent_id: None,
    }
}

#[tokio::test]
async fn managed_enforce_override_denies_even_while_personal_observe_is_active() {
    let (addr, registry) = start_server_with_policy_default(DENY_BASH_POLICY, personal_observe_default()).await;

    let proto_id = ProtoAgentId {
        org_id: "org".into(),
        team_id: "team".into(),
        agent_id: "enforce-agent".into(),
    };
    register(&registry, &proto_id, "tok-enforce", Some(EnforcementMode::Enforce));

    let mut client = PolicyServiceClient::connect(format!("http://{addr}")).await.unwrap();
    let resp = client
        .check_action(bash_check_request(proto_id, "tok-enforce"))
        .await
        .unwrap()
        .into_inner();

    assert_eq!(
        resp.decision,
        Decision::Deny as i32,
        "an agent with an explicit Enforce override must be denied, not audited as an Allow, \
         even while personal-observe is active as the service's policy default"
    );
}

#[tokio::test]
async fn no_override_agent_is_allowed_but_shadow_recorded_while_personal_observe_is_active() {
    let (addr, registry) = start_server_with_policy_default(DENY_BASH_POLICY, personal_observe_default()).await;

    let proto_id = ProtoAgentId {
        org_id: "org".into(),
        team_id: "team".into(),
        agent_id: "no-override-agent".into(),
    };
    // No per-agent override — this is the ONLY agent personal-observe affects.
    register(&registry, &proto_id, "tok-none", None);

    let mut client = PolicyServiceClient::connect(format!("http://{addr}")).await.unwrap();
    let resp = client
        .check_action(bash_check_request(proto_id, "tok-none"))
        .await
        .unwrap()
        .into_inner();

    assert_eq!(
        resp.decision,
        Decision::Allow as i32,
        "an agent with no override is the profile's effect: the would-be deny is masked to Allow"
    );
}
