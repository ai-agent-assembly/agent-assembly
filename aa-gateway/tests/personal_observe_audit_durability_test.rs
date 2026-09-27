//! HORO-1375 AC-7 — audit durability test.
//!
//! With personal-observe active, an action that would have been denied
//! produces an `AuditEntry` with `dry_run = true` and `shadow_decision =
//! "deny"`; that entry survives a simulated restart in the durable JSONL and
//! `verify_chain` reports `Verified`. The entry's source agent carries no
//! per-agent override at the time of the decision — i.e. the allow came from
//! the personal-observe policy default, not from an agent override.

use std::collections::BTreeMap;
use std::io::Write;
use std::net::SocketAddr;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use std::time::Duration;

use aa_core::{AuditEntry, GovernanceLevel};
use aa_gateway::audit::{AuditChain, AuditWriter, VerifyOutcome};
use aa_gateway::engine::PolicyDefaultMode;
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
use tonic::transport::Server;

const DENY_BASH_POLICY: &str = r#"
version: "1"
tools:
  bash:
    allow: false
"#;

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

fn register(registry: &AgentRegistry, proto_id: &ProtoAgentId, credential_token: &str) {
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
        // No per-agent override — this agent's effective mode comes ENTIRELY
        // from the personal-observe policy default under test.
        enforcement_mode: None,
        enforcement_mode_expires_at: None,
        org_id: None,
    };
    registry.register(record).unwrap();
}

async fn start_server(audit_jsonl_dir: &std::path::Path) -> (SocketAddr, Arc<AgentRegistry>) {
    let mut tmp = tempfile::NamedTempFile::new().unwrap();
    write!(tmp, "{}", DENY_BASH_POLICY).unwrap();
    tmp.flush().unwrap();

    let (alert_tx, _) = tokio::sync::broadcast::channel::<aa_gateway::budget::BudgetAlert>(64);
    let engine = Arc::new(PolicyEngine::load_from_file(tmp.path(), alert_tx).unwrap());
    let registry = Arc::new(AgentRegistry::new());

    let (audit_tx, audit_rx) = tokio::sync::mpsc::channel::<AuditEntry>(4096);
    let writer = AuditWriter::new(audit_jsonl_dir.to_path_buf(), "local", "local", audit_rx)
        .await
        .expect("writer must construct");
    tokio::spawn(writer.run());
    let chain = Arc::new(AuditChain::new(audit_tx, Arc::new(AtomicU64::new(0)), [0u8; 32], 0));

    let service = PolicyServiceImpl::with_registry(
        Arc::clone(&engine),
        Arc::clone(&registry),
        tokio::sync::mpsc::channel(1).0, // throwaway; replaced by with_shared_chain
        Arc::new(AtomicU64::new(0)),
        [0u8; 32],
    )
    .with_shared_chain(chain)
    .with_policy_default_mode(personal_observe_default());

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

#[tokio::test]
async fn personal_observe_deny_is_audited_dry_run_and_survives_a_restart() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let audit_dir = tmp.path().join("audit-jsonl");

    let (addr, registry) = start_server(&audit_dir).await;

    let proto_id = ProtoAgentId {
        org_id: "org".into(),
        team_id: "team".into(),
        agent_id: "ac7-agent".into(),
    };
    register(&registry, &proto_id, "tok-ac7");
    // Sanity: no per-agent override — the effective Observe comes entirely
    // from the personal-observe policy default.
    assert_eq!(
        registry
            .get(&proto_agent_id_to_key(&proto_id))
            .unwrap()
            .enforcement_mode,
        None
    );

    let mut client = PolicyServiceClient::connect(format!("http://{addr}")).await.unwrap();
    let resp = client
        .check_action(CheckActionRequest {
            agent_id: Some(proto_id),
            credential_token: "tok-ac7".into(),
            trace_id: "trace-ac7".into(),
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
        })
        .await
        .unwrap()
        .into_inner();

    // The would-be deny is masked to Allow at the RPC response layer.
    assert_eq!(resp.decision, Decision::Allow as i32);

    // Poll the durable file for the dry-run audit entry.
    let chain_path = aa_gateway::server::audit_file_path(&audit_dir, "local", "local");
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    let mut found = None;
    while std::time::Instant::now() < deadline {
        if let Ok(raw) = tokio::fs::read_to_string(&chain_path).await {
            for line in raw.lines().filter(|l| !l.is_empty()) {
                let entry: serde_json::Value = serde_json::from_str(line).unwrap();
                // `AuditEntry.payload` is a JSON-ENCODED STRING field (see
                // `aa-core/src/audit.rs`'s `AuditEntry` struct), not a nested
                // object — the dry_run/shadow_decision fields set by
                // `record_audit` live inside that string, one parse deeper.
                let Some(payload_str) = entry.get("payload").and_then(|p| p.as_str()) else {
                    continue;
                };
                let Ok(payload) = serde_json::from_str::<serde_json::Value>(payload_str) else {
                    continue;
                };
                if payload.get("dry_run") == Some(&serde_json::Value::Bool(true)) {
                    found = Some(payload);
                    break;
                }
            }
        }
        if found.is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let entry = found.expect("a dry_run audit entry must be persisted to the durable JSONL");
    assert_eq!(entry["shadow_decision"], "deny");

    // The entry survives a simulated restart: reopen the SAME file with
    // `AuditWriter::verify_chain` (a fresh reader, no in-memory state carried
    // over) and confirm it still verifies.
    let result = AuditWriter::verify_chain(&chain_path)
        .await
        .expect("verify_chain must run");
    assert_eq!(result.outcome, VerifyOutcome::Verified);
    assert!(result.entries_checked >= 1);
}
