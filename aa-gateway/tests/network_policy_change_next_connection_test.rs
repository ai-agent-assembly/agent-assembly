//! AAASM-6261 (golden journey J83, part b): a policy change takes effect on the
//! NEXT egress connection for the same agent.
//!
//! Drives the real `PolicyService.CheckAction` gRPC path with the exact
//! `NetworkCall` request shape `aa-proxy` sends on every CONNECT
//! (`aa-proxy/src/network_enforce.rs`), and swaps the live policy through the
//! production hot-swap entry point `PolicyEngine::apply_yaml` (the same call the
//! HTTP policy API makes). Nothing in the decision path is mocked; the proxy adds
//! no caching of its own, so the gateway's epoch-keyed decision cache is the only
//! place a stale verdict could survive a swap.

use std::io::Write;
use std::net::SocketAddr;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;

use aa_gateway::policy::history::{FsHistoryStore, HistoryConfig};
use aa_gateway::service::PolicyServiceImpl;
use aa_gateway::PolicyEngine;
use aa_proto::assembly::common::v1::{ActionType, AgentId as ProtoAgentId, Decision};
use aa_proto::assembly::policy::v1::policy_service_client::PolicyServiceClient;
use aa_proto::assembly::policy::v1::policy_service_server::PolicyServiceServer;
use aa_proto::assembly::policy::v1::{action_context::Action, ActionContext, CheckActionRequest, NetworkCallContext};
use tokio::net::TcpListener;
use tonic::transport::Server;

const ALLOW_HOST_A_ONLY: &str = "version: \"1\"\nnetwork:\n  allowlist:\n    - a.allowed.example\n";
const ALLOW_HOST_B_ONLY: &str = "version: \"1\"\nnetwork:\n  allowlist:\n    - b.allowed.example\n";
const HOST_A: &str = "a.allowed.example";
const HOST_B: &str = "b.allowed.example";

/// Boots the real PolicyService over loopback and returns its address plus the
/// engine handle the test uses to hot-swap the live policy.
async fn start_gateway(initial_yaml: &str) -> (SocketAddr, Arc<PolicyEngine>) {
    let mut tmp = tempfile::NamedTempFile::new().unwrap();
    write!(tmp, "{initial_yaml}").unwrap();
    tmp.flush().unwrap();

    let (alert_tx, _) = tokio::sync::broadcast::channel::<aa_gateway::budget::BudgetAlert>(64);
    let engine = Arc::new(PolicyEngine::load_from_file(tmp.path(), alert_tx).unwrap());
    let (audit_tx, _audit_rx) = tokio::sync::mpsc::channel(4096);
    let service = PolicyServiceImpl::new(Arc::clone(&engine), audit_tx, Arc::new(AtomicU64::new(0)), [0u8; 32]);

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
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    (addr, engine)
}

/// Same request `aa-proxy` builds per CONNECT, always for the same agent.
fn connect_request(host: &str) -> CheckActionRequest {
    CheckActionRequest {
        agent_id: Some(ProtoAgentId {
            org_id: "org".into(),
            team_id: "team".into(),
            agent_id: "agent-j83".into(),
        }),
        credential_token: "tok_test".into(),
        trace_id: "trace-j83".into(),
        span_id: "span-j83".into(),
        action_type: ActionType::NetworkCall as i32,
        context: Some(ActionContext {
            action: Some(Action::NetworkCall(NetworkCallContext {
                host: host.into(),
                port: 443,
                protocol: "https".into(),
                in_allowlist: false,
            })),
        }),
        caller_agent_id: None,
    }
}

/// One brand-new connection to the gateway, one egress check; mirrors a new CONNECT.
async fn decide(addr: SocketAddr, host: &str) -> i32 {
    let mut client = PolicyServiceClient::connect(format!("http://{addr}")).await.unwrap();
    client
        .check_action(connect_request(host))
        .await
        .unwrap()
        .into_inner()
        .decision
}

#[tokio::test]
async fn policy_swap_changes_the_verdict_for_the_next_connection_of_the_same_agent() {
    let (addr, engine) = start_gateway(ALLOW_HOST_A_ONLY).await;
    let hist_dir = tempfile::tempdir().unwrap();
    let history = FsHistoryStore::new(HistoryConfig {
        history_dir: hist_dir.path().to_path_buf(),
        max_versions: 50,
    });

    // Policy A. Paired controls: the allowlisted host is allowed, the other denied.
    // The first lookups also populate any decision cache, so a stale entry would
    // be observable after the swap.
    assert_eq!(decide(addr, HOST_A).await, Decision::Allow as i32, "A: host A allowed");
    assert_eq!(decide(addr, HOST_B).await, Decision::Deny as i32, "A: host B denied");

    // Swap A -> B through the production hot-swap path.
    engine
        .apply_yaml(ALLOW_HOST_B_ONLY, Some("j83"), &history)
        .await
        .unwrap();

    // Next connections, same agent, under policy B: verdicts flip both ways.
    assert_eq!(
        decide(addr, HOST_A).await,
        Decision::Deny as i32,
        "B: host A now denied"
    );
    assert_eq!(
        decide(addr, HOST_B).await,
        Decision::Allow as i32,
        "B: host B now allowed"
    );

    // And back B -> A: the property is symmetric, not a one-shot.
    engine
        .apply_yaml(ALLOW_HOST_A_ONLY, Some("j83"), &history)
        .await
        .unwrap();
    assert_eq!(
        decide(addr, HOST_A).await,
        Decision::Allow as i32,
        "A again: host A allowed"
    );
    assert_eq!(
        decide(addr, HOST_B).await,
        Decision::Deny as i32,
        "A again: host B denied"
    );
}
