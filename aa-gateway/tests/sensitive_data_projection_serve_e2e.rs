//! The shipped entrypoint really wires the sensitive-data projection
//! (AAASM-5440).
//!
//! `sensitive_data_projection_boot_test` proves
//! `attach_sensitive_data_projection` works; this proves
//! [`aa_gateway::server::serve_tcp`] — the function `aasm-gateway` itself calls
//! — invokes it. Without this the composition helper could be correct and
//! unreferenced, which is exactly the shape of "operationally dead code".
//!
//! Nothing here is a fixture standing in for production: the gateway is booted
//! by its own `serve_tcp`, driven over a real gRPC socket by the generated
//! client, and the assertion is made against the SQLite file the boot was
//! configured with, read through a connection the gateway does not own.
//!
//! # What this does *not* cover, stated plainly
//!
//! `serve_uds` performs the identical wiring, and is **not** covered here. A
//! Unix-socket tonic client needs a `hyper_util` connector that `aa-gateway`
//! does not depend on, and adding a dependency for one test was not in this
//! ticket's scope. So the UDS entrypoint's call to
//! `attach_sensitive_data_projection` is verified by review and by the compiler
//! — its `projection` binding is consumed by `drain_sensitive_data_projection`
//! at the end of the function — but not by an executable assertion. A mutation
//! that removed the wiring from `serve_uds` alone would not fail any test.
//!
//! # Process isolation
//!
//! This file sets `HOME`, `AA_AUDIT_DIR` and the projection variable, and boots
//! a server that writes under them. It therefore contains exactly one test, and
//! that test must be the only thing in its process — which is what `cargo
//! nextest`, this repository's harness, guarantees.

use std::collections::{BTreeMap, VecDeque};
use std::io::Write;
use std::sync::Arc;
use std::time::Duration;

use aa_core::GovernanceLevel;
use aa_gateway::registry::convert::proto_agent_id_to_key;
use aa_gateway::registry::store::AgentRecord;
use aa_gateway::registry::{AgentRegistry, AgentStatus};
use aa_gateway::server::SENSITIVE_DATA_PROJECTION_DB_ENV;
use aa_gateway::storage::sensitive_data::{SensitiveDataEventFilter, SensitiveDataProjection, TenantScope};
use aa_gateway::storage::{SqliteBackend, SqliteConfig};
use aa_proto::assembly::common::v1::{ActionType, AgentId as ProtoAgentId};
use aa_proto::assembly::policy::v1::policy_service_client::PolicyServiceClient;
use aa_proto::assembly::policy::v1::{action_context::Action, ActionContext, CheckActionRequest, ToolCallContext};
use chrono::Utc;

const ORG: &str = "acme";
const TOKEN: &str = "token-e2e";
/// AWS's own published documentation key — recognised by the built-in scanner,
/// and backed by no account.
const SYNTHETIC_AWS_KEY: &str = "AKIAIOSFODNN7EXAMPLE";

/// **The shipped gateway writes the projection.**
///
/// Boots `serve_tcp` with the projection configured, sends one governed tool
/// call carrying a synthetic credential over the real gRPC surface, and waits
/// for the row to become durable in the configured database.
///
/// The wait is a poll rather than a sleep because the write is deliberately off
/// the enforcement path: the RPC returns before the drain has persisted
/// anything, and that ordering is the feature, not a race to paper over.
#[tokio::test]
async fn serve_tcp_persists_a_finding_through_the_real_grpc_surface() {
    let dir = tempfile::tempdir().expect("temp dir");
    // Redirect every path the serve path writes to — budget state, the escalation
    // database, the audit chain — into the temp directory, so booting a real
    // gateway leaves nothing behind in the developer's home.
    std::env::set_var("HOME", dir.path());
    std::env::set_var("AA_AUDIT_DIR", dir.path().join("audit"));
    let db = dir.path().join("projection.db");
    std::env::set_var(SENSITIVE_DATA_PROJECTION_DB_ENV, &db);

    let mut policy = tempfile::NamedTempFile::new().unwrap();
    writeln!(policy, "version: \"1\"").unwrap();
    policy.flush().unwrap();

    let agent = ProtoAgentId {
        org_id: ORG.into(),
        team_id: "billing".into(),
        agent_id: "leaky-agent".into(),
    };
    let registry = Arc::new(AgentRegistry::new());
    registry.register(record(&agent)).expect("register agent");

    // Bind to pick a free port, then release it for `serve_tcp` to take. The
    // window is a few microseconds and the alternative is a hardcoded port that
    // collides with whatever else the machine is running.
    let probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = probe.local_addr().unwrap();
    drop(probe);

    let (alert_tx, _alert_rx) = tokio::sync::broadcast::channel(64);
    let queue = aa_runtime::approval::ApprovalQueue::new();
    let policy_path = policy.path().to_path_buf();
    let serve = tokio::spawn(async move {
        // Held so the policy file outlives the server.
        let _policy = policy;
        // `serve_tcp`'s error is a bare `Box<dyn Error>`, which is not `Send`;
        // rendered here so the future this task returns is spawnable.
        aa_gateway::server::serve_tcp(&policy_path, &addr.to_string(), registry, queue, alert_tx, None)
            .await
            .map_err(|e| e.to_string())
    });

    let mut client = connect(addr).await;
    let response = client
        .check_action(leaky_request(&agent))
        .await
        .expect("check_action over the booted gateway")
        .into_inner();
    let rules = response.redact.as_ref().map_or(0, |r| r.rules.len());
    assert!(
        rules > 0,
        "the gateway did not detect the synthetic credential, so a missing row \
         would prove nothing about the projection: {response:?}"
    );

    let stored = wait_for_rows(&db).await;
    assert_eq!(
        stored, 1,
        "`serve_tcp` did not write the sensitive-data projection it was configured with"
    );

    serve.abort();
}

fn record(proto_id: &ProtoAgentId) -> AgentRecord {
    AgentRecord {
        agent_id: proto_agent_id_to_key(proto_id),
        name: proto_id.agent_id.clone(),
        framework: "custom".into(),
        version: "1.0.0".into(),
        risk_tier: 0,
        tool_names: vec![],
        public_key: "pk".into(),
        credential_token: TOKEN.into(),
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
        governance_level: GovernanceLevel::default(),
        parent_agent_id: None,
        team_id: Some("billing".into()),
        // The authoritative tenancy the projection is scoped by. Without it the
        // decision is refused rather than written, and this test would be
        // asserting the wrong thing.
        org_id: Some(ORG.into()),
        depth: 0,
        delegation_reason: None,
        spawned_by_tool: None,
        root_agent_id: None,
        children: vec![],
        parent_key: None,
        enforcement_mode: None,
        enforcement_mode_expires_at: None,
    }
}

fn leaky_request(agent: &ProtoAgentId) -> CheckActionRequest {
    CheckActionRequest {
        agent_id: Some(agent.clone()),
        credential_token: TOKEN.into(),
        trace_id: "trace-e2e".into(),
        span_id: "span-e2e".into(),
        action_type: ActionType::ToolCall as i32,
        context: Some(ActionContext {
            action: Some(Action::ToolCall(ToolCallContext {
                tool_name: "http_post".into(),
                tool_source: "test".into(),
                args_json: SYNTHETIC_AWS_KEY.as_bytes().to_vec(),
                target_url: String::new(),
            })),
        }),
        caller_agent_id: None,
    }
}

/// Retry until the freshly booted server is accepting, or give up loudly.
async fn connect(addr: std::net::SocketAddr) -> PolicyServiceClient<tonic::transport::Channel> {
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    loop {
        match PolicyServiceClient::connect(format!("http://{addr}")).await {
            Ok(client) => return client,
            Err(e) if std::time::Instant::now() < deadline => {
                let _ = e;
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            Err(e) => panic!("the booted gateway never accepted a connection: {e}"),
        }
    }
}

/// Poll the configured database until the projection row is durable.
async fn wait_for_rows(db: &std::path::Path) -> u64 {
    let filter = SensitiveDataEventFilter::new(TenantScope::new(ORG, ORG).expect("well-formed scope"));
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    loop {
        if let Ok(store) = SqliteBackend::open(&SqliteConfig { path: db.to_path_buf() }).await {
            if let Ok(count) = store.count_sensitive_data_events(&filter).await {
                if count > 0 || std::time::Instant::now() >= deadline {
                    return count;
                }
            }
        }
        if std::time::Instant::now() >= deadline {
            return 0;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}
