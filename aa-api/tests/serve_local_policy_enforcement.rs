//! AAASM-5006 — the local-mode gRPC listener must serve real policy
//! enforcement (`CheckAction`), not just agent registration, so one
//! `aa-api-server` process (`aasm start --mode local`) can serve both the
//! `/api/v1/*` operator surface and the enforcement RPC an SDK/runtime calls.
//!
//! `$AA_POLICY` is process-wide, so this scenario lives in its own test
//! binary (one env-mutating `#[tokio::test]` per file), per the convention in
//! `aa-api/tests/policy_source_file.rs`.
//!
//! Drives the real production wiring end to end: a gRPC `CheckAction` call
//! against `AppState`'s `$AA_POLICY`-loaded engine, over the SAME registry
//! and audit chain the REST surface reads/writes.

use std::collections::{BTreeMap, VecDeque};
use std::future::pending;
use std::net::SocketAddr;

use aa_api::auth::scope::RequireRead;
use aa_api::auth::{AuthenticatedCaller, Tenant};
use aa_api::pagination::PaginationParams;
use aa_api::routes::logs::{list_logs, LogFilterParams};
use aa_api::state::{AppState, LocalAuth};
use aa_gateway::audit::VerifyOutcome;
use aa_gateway::registry::convert::proto_agent_id_to_key;
use aa_gateway::registry::store::AgentRecord;
use aa_gateway::registry::AgentStatus;
use aa_proto::assembly::common::v1::{ActionType, AgentId as ProtoAgentId, Decision};
use aa_proto::assembly::policy::v1::action_context::Action;
use aa_proto::assembly::policy::v1::policy_service_client::PolicyServiceClient;
use aa_proto::assembly::policy::v1::{ActionContext, CheckActionRequest, ToolCallContext};
use axum::extract::{Extension, Query};
use axum::response::IntoResponse;
use chrono::Utc;

/// A discriminating fixture: `read_file` is allowed, `delete_file` is denied.
/// A deny-everything policy would let a hardcoded-Deny regression pass this
/// suite — the allow case is the falsifier for that.
const POLICY_YAML: &str = r#"
version: "1"
tools:
  read_file:
    allow: true
  delete_file:
    allow: false
"#;

const CREDENTIAL_TOKEN: &str = "aaasm-5006-token";

fn admin_caller() -> AuthenticatedCaller {
    AuthenticatedCaller {
        key_id: "aaasm-5006-test-operator".to_string(),
        scopes: vec![aa_api::auth::scope::Scope::Admin, aa_api::auth::scope::Scope::Read],
        tenant: Tenant {
            org_id: None,
            team_id: None,
        },
    }
}

fn proto_agent() -> ProtoAgentId {
    ProtoAgentId {
        org_id: String::new(),
        team_id: String::new(),
        agent_id: "aaasm-5006-agent".to_string(),
    }
}

fn agent_record(proto_id: &ProtoAgentId) -> AgentRecord {
    AgentRecord {
        agent_id: proto_agent_id_to_key(proto_id),
        name: proto_id.agent_id.clone(),
        framework: "test".into(),
        version: "1.0.0".into(),
        risk_tier: 0,
        tool_names: vec![],
        public_key: "pk".into(),
        credential_token: CREDENTIAL_TOKEN.into(),
        metadata: BTreeMap::new(),
        registered_at: Utc::now(),
        last_heartbeat: Utc::now(),
        status: AgentStatus::Active,
        pid: None,
        session_count: 0,
        last_event: None,
        active_sessions: vec![],
        recent_events: VecDeque::new(),
        recent_traces: vec![],
        layer: None,
        governance_level: aa_core::GovernanceLevel::default(),
        parent_agent_id: None,
        team_id: None,
        depth: 0,
        delegation_reason: None,
        spawned_by_tool: None,
        root_agent_id: None,
        children: vec![],
        parent_key: None,
        enforcement_mode: None,
        enforcement_mode_expires_at: None,
        org_id: None,
    }
}

fn tool_call_request(agent: &ProtoAgentId, credential_token: &str, tool_name: &str) -> CheckActionRequest {
    CheckActionRequest {
        agent_id: Some(agent.clone()),
        credential_token: credential_token.into(),
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
        caller_agent_id: None,
    }
}

#[tokio::test]
async fn local_mode_grpc_check_action_returns_a_real_policy_verdict() {
    let policy_dir = tempfile::tempdir().expect("temp policy dir");
    let policy_file = policy_dir.path().join("policy.yaml");
    std::fs::write(&policy_file, POLICY_YAML).expect("write policy file");
    std::env::set_var("AA_POLICY", &policy_file);
    let state = AppState::local_hardened(LocalAuth::Off)
        .await
        .expect("local_hardened state builds");
    std::env::remove_var("AA_POLICY");

    let proto_id = proto_agent();
    state
        .agent_registry
        .register(agent_record(&proto_id))
        .expect("register test agent");

    let registry = std::sync::Arc::clone(&state.agent_registry);
    let policy_engine = std::sync::Arc::clone(&state.policy_engine);
    let approval_queue = std::sync::Arc::clone(&state.approval_queue);
    let audit_chain = state.audit_chain.clone();

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral gRPC port");
    let grpc_addr: SocketAddr = listener.local_addr().expect("local_addr");
    let endpoint = format!("http://{grpc_addr}");

    let serve = aa_api::server::serve_agent_plane_grpc(
        listener,
        registry,
        policy_engine,
        approval_queue,
        audit_chain,
        aa_gateway::engine::PolicyDefaultMode::enforce(),
        pending::<()>(),
    );

    let work = async {
        let mut client = PolicyServiceClient::connect(endpoint)
            .await
            .expect("connect to embedded gRPC PolicyService");

        // (1) discriminating verdict — allow.
        let allow_resp = client
            .check_action(tool_call_request(&proto_id, CREDENTIAL_TOKEN, "read_file"))
            .await
            .expect("check_action (allow) succeeds")
            .into_inner();
        assert_eq!(
            allow_resp.decision,
            Decision::Allow as i32,
            "read_file must be allowed by the fixture policy"
        );

        // (1) discriminating verdict — deny by policy.
        let deny_resp = client
            .check_action(tool_call_request(&proto_id, CREDENTIAL_TOKEN, "delete_file"))
            .await
            .expect("check_action (deny) succeeds")
            .into_inner();
        assert_eq!(
            deny_resp.decision,
            Decision::Deny as i32,
            "delete_file must be denied by the fixture policy"
        );
        assert_ne!(deny_resp.reason, "", "a policy deny must carry a reason");

        // (2) credential negative control — falsifies a registry-less service.
        let mismatch_resp = client
            .check_action(tool_call_request(&proto_id, "wrong-token", "read_file"))
            .await
            .expect("check_action (bad credential) succeeds")
            .into_inner();
        assert_eq!(
            mismatch_resp.decision,
            Decision::Deny as i32,
            "a mismatched credential token must be denied regardless of policy"
        );
        assert!(
            mismatch_resp.reason.contains("credential"),
            "the mismatch must be attributed to the credential, got: {}",
            mismatch_resp.reason
        );
    };

    tokio::select! {
        served = serve => panic!("gRPC server exited before the test work finished: {served:?}"),
        () = work => {}
    }

    // (3) chain continuity — the constructed-then-replaced service must not
    // fork or close the shared chain the REST surface also writes to.
    let path = state.audit_reader.dir().join("local-local.jsonl");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    let mut last = None;
    loop {
        match aa_gateway::audit::AuditWriter::verify_chain(&path).await {
            Ok(result) if result.entries_checked >= 3 => {
                last = Some(result);
                break;
            }
            Ok(result) => last = Some(result),
            Err(_) => {}
        }
        if std::time::Instant::now() >= deadline {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    let result = last.expect("verify_chain ran at least once");
    assert!(
        result.entries_checked >= 3,
        "expected at least 3 audit entries (allow, deny, credential-mismatch), got {}",
        result.entries_checked
    );
    assert_eq!(
        result.outcome,
        VerifyOutcome::Verified,
        "the gRPC-served decisions must chain-verify against the SAME file the REST surface reads"
    );

    // (4) one-process proof — the gRPC-enforced decisions surface on the REST
    // route of the SAME AppState, which is the ticket's actual claim.
    //
    // Filtered by the audit entry's own `agent_id` — `hash_to_16(claimed_agent_id)`,
    // the hash of the bare `agent_id` string alone (`record_audit`,
    // `convert::claimed_agent_id`), NOT `proto_agent_id_to_key`'s hash of the
    // full `{org, team, agent_id}` triple the registry uses as its key. Uses
    // `list_logs` (org/tenant-scoped, no registry lookup) rather than the
    // per-agent decisions route, which additionally requires the queried id to
    // resolve in the registry — a separate concern this test isn't about.
    let hex_id = aa_gateway::service::convert::hash_to_16(&proto_id.agent_id)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    let response = list_logs(
        RequireRead(admin_caller()),
        Extension(state.clone()),
        Query(PaginationParams {
            page: None,
            per_page: None,
        }),
        Query(LogFilterParams {
            agent_id: Some(hex_id),
            event_type: None,
            org_id: None,
        }),
    )
    .await
    .into_response();
    assert_eq!(response.status(), axum::http::StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("read response body");
    let page: serde_json::Value = serde_json::from_slice(&body).expect("response body is valid JSON");
    assert!(
        page["items"].as_array().is_some_and(|items| !items.is_empty()),
        "the gRPC-enforced decisions must be visible via the REST /api/v1/logs route on the same AppState, got: {page}"
    );
}
