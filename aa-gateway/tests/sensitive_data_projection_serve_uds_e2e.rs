//! The shipped UDS entrypoint really wires the sensitive-data projection
//! (AAASM-5656).
//!
//! `sensitive_data_projection_serve_e2e` proves the same thing for
//! [`aa_gateway::server::serve_tcp`]. This is its counterpart for
//! [`aa_gateway::server::serve_uds`] — the *other* production transport, and
//! until this file existed the only one whose projection wiring no test
//! asserted: a mutation deleting it from `serve_uds` alone failed nothing.
//! Two transports, two independent proofs; neither borrows the other's.
//!
//! Nothing here is a fixture standing in for production: the gateway is booted
//! by its own `serve_uds`, driven over a real Unix-socket gRPC connection by
//! the generated client, and the assertion is made against the SQLite file the
//! boot was configured with, read through a connection the gateway does not
//! own.
//!
//! # The two kills are disjoint, and that was executed
//!
//! Both mutations were run against the full `cargo nextest run -p aa-gateway`
//! suite (1257 tests, `--no-fail-fast`), each replacing one transport's
//! `attach_sensitive_data_projection` call with `let projection = None;`:
//!
//! | Mutation | Failing tests | Suite |
//! | --- | --- | --- |
//! | `serve_uds` stops attaching | this file's test, and only it | 1256 passed, 1 failed |
//! | `serve_tcp` stops attaching | `serve_tcp_persists_a_finding_…`, and only it | 1256 passed, 1 failed |
//!
//! Each transport's test survives the *other* transport's mutation, which is
//! the property that makes either kill attributable. Recorded here rather than
//! in a commit message because the next person to edit these files needs it.
//!
//! # No new dependency was needed
//!
//! AAASM-5440 recorded a Unix-socket tonic client as needing a `hyper_util`
//! connector `aa-gateway` does not depend on. That was true of older tonic;
//! it is not true of the pinned 0.14, which resolves a `unix:` endpoint to its
//! own built-in UDS connector. The client below is therefore built from
//! `tonic::transport::Endpoint` alone.
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
const TOKEN: &str = "token-uds-e2e";
/// AWS's own published documentation key — recognised by the built-in scanner,
/// and backed by no account.
const SYNTHETIC_AWS_KEY: &str = "AKIAIOSFODNN7EXAMPLE";

/// **The shipped gateway writes the projection on the UDS transport too.**
///
/// Boots `serve_uds` with the projection configured, sends one governed tool
/// call carrying a synthetic credential over a real Unix-socket gRPC
/// connection, and waits for the row to become durable in the configured
/// database.
///
/// The wait is a poll rather than a sleep because the write is deliberately off
/// the enforcement path: the RPC returns before the drain has persisted
/// anything, and that ordering is the feature, not a race to paper over.
#[tokio::test]
async fn serve_uds_persists_a_finding_through_the_real_grpc_surface() {
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

    // A short name under the temp directory: `sun_path` is capped at ~104 bytes
    // on macOS, and a long fixture name silently turns into a bind failure.
    let socket = dir.path().join("gw.sock");

    let (alert_tx, _alert_rx) = tokio::sync::broadcast::channel(64);
    let queue = aa_runtime::approval::ApprovalQueue::new();
    let policy_path = policy.path().to_path_buf();
    let socket_path = socket.clone();
    let serve = tokio::spawn(async move {
        // Held so the policy file outlives the server.
        let _policy = policy;
        // `serve_uds`'s error is a bare `Box<dyn Error>`, which is not `Send`;
        // rendered here so the future this task returns is spawnable.
        aa_gateway::server::serve_uds(&policy_path, &socket_path, registry, queue, alert_tx, None)
            .await
            .map_err(|e| e.to_string())
    });

    let mut client = connect(&socket).await;
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
        "`serve_uds` did not write the sensitive-data projection it was configured with"
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
        trace_id: "trace-uds-e2e".into(),
        span_id: "span-uds-e2e".into(),
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

/// Retry until the freshly booted server is accepting on the socket, or give up
/// loudly.
///
/// `Endpoint::from_shared` routes a `unix:` target through tonic's own
/// `UdsConnector`, so no third-party connector is involved — the transport
/// under test is the one the shipped client library would use.
async fn connect(socket: &std::path::Path) -> PolicyServiceClient<tonic::transport::Channel> {
    let target = format!("unix://{}", socket.display());
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    loop {
        let attempt = async {
            tonic::transport::Endpoint::from_shared(target.clone())
                .map_err(|e| e.to_string())?
                .connect()
                .await
                .map_err(|e| e.to_string())
        };
        match attempt.await {
            Ok(channel) => return PolicyServiceClient::new(channel),
            Err(e) if std::time::Instant::now() < deadline => {
                let _ = e;
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            Err(e) => panic!("the booted gateway never accepted a connection on {target}: {e}"),
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
