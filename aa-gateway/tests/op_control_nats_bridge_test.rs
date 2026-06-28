//! Cross-process op-control end-to-end test (AAASM-3883, ADR 0011).
//!
//! Proves the full kill-switch path across the real two-process split, with a
//! **real NATS server** via `testcontainers-modules` (requires Docker — no
//! delivery is faked):
//!
//! 1. an operator halt is published to the NATS op-control subject (the aa-api
//!    side, [`OpControlNatsPublisher`]);
//! 2. the gateway bridge ([`spawn_bridge`]) receives it and forwards it into the
//!    in-process [`OpControlPublisher`] that `op_control_stream` serves;
//! 3. a gRPC `op_control_stream` subscriber receives the halt under the reserved
//!    op-id; and
//! 4. fed into the runtime's [`OpControlStore`], it records `Terminated` — the
//!    state the per-request check consults regardless of any `trace_id`.

use std::io::Write;
use std::net::SocketAddr;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use std::time::{Duration, Instant};

use aa_gateway::ops::nats::spawn_bridge;
use aa_gateway::ops::{OpControlNatsConfig, OpControlNatsPublisher, OpControlPublisher, SharedOpControlPublisher};
use aa_gateway::service::PolicyServiceImpl;
use aa_gateway::PolicyEngine;
use aa_proto::assembly::common::v1::AgentId as ProtoAgentId;
use aa_proto::assembly::policy::v1::policy_service_client::PolicyServiceClient;
use aa_proto::assembly::policy::v1::policy_service_server::PolicyServiceServer;
use aa_proto::assembly::policy::v1::{OpControlSignal, OpControlSubscribeRequest};
use testcontainers_modules::nats::Nats;
use testcontainers_modules::testcontainers::core::IntoContainerPort;
use testcontainers_modules::testcontainers::runners::AsyncRunner;
use testcontainers_modules::testcontainers::{ContainerAsync, ImageExt};
use tokio::net::TcpListener;
use tokio::time::timeout;
use tonic::transport::Server;

/// Reserve an ephemeral host port, then release it so the container can bind it.
fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("bind ephemeral port")
        .local_addr()
        .expect("local addr")
        .port()
}

/// Start a NATS container with its client port pinned to `host_port`.
async fn start_nats(host_port: u16) -> ContainerAsync<Nats> {
    Nats::default()
        .with_mapped_port(host_port, 4222.tcp())
        .start()
        .await
        .expect("start nats testcontainer (is Docker running?)")
}

/// Start a PolicyService gRPC server with the given in-process publisher
/// attached, returning the bound address (mirrors `op_control_stream_test`).
async fn start_server(publisher: SharedOpControlPublisher) -> SocketAddr {
    let mut tmp = tempfile::NamedTempFile::new().unwrap();
    writeln!(tmp, "version: \"1\"").unwrap();
    tmp.flush().unwrap();

    let (alert_tx, _) = tokio::sync::broadcast::channel::<aa_gateway::budget::BudgetAlert>(64);
    let engine = PolicyEngine::load_from_file(tmp.path(), alert_tx).unwrap();
    let (audit_tx, _audit_rx) = tokio::sync::mpsc::channel(4096);
    let audit_drops = Arc::new(AtomicU64::new(0));
    let service =
        PolicyServiceImpl::new(Arc::new(engine), audit_tx, audit_drops, [0u8; 32]).with_ops_publisher(publisher);

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
    addr
}

fn agent(id: &str) -> ProtoAgentId {
    ProtoAgentId {
        org_id: "org".into(),
        team_id: "team".into(),
        agent_id: id.into(),
    }
}

/// Block until the in-process publisher reports at least one subscriber (the
/// gRPC `op_control_stream` has registered server-side).
async fn await_grpc_subscriber(publisher: &SharedOpControlPublisher) {
    for _ in 0..40 {
        if publisher.subscriber_count() >= 1 {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("gRPC op_control_stream subscriber never registered");
}

/// An operator halt published to the NATS op-control subject is bridged into the
/// gateway broadcast, delivered over `op_control_stream` under the reserved
/// `agent:{id}` key, and recorded as `Terminated` by the runtime store.
#[tokio::test]
async fn agent_halt_published_to_nats_reaches_op_control_stream_and_halts_runtime() {
    let host_port = free_port();
    let url = format!("nats://127.0.0.1:{host_port}");
    let _nats = start_nats(host_port).await;

    // Gateway process: in-process broadcast + NATS bridge feeding it + gRPC server.
    let publisher = Arc::new(OpControlPublisher::new());
    let _bridge = spawn_bridge(OpControlNatsConfig::new(url.clone()), Arc::clone(&publisher));
    let addr = start_server(Arc::clone(&publisher)).await;

    // Runtime: subscribe to op_control_stream for agent-7.
    let mut client = PolicyServiceClient::connect(format!("http://{addr}")).await.unwrap();
    let mut stream = client
        .op_control_stream(OpControlSubscribeRequest {
            agent_id: Some(agent("agent-7")),
        })
        .await
        .unwrap()
        .into_inner();
    await_grpc_subscriber(&publisher).await;

    // aa-api process: publish an agent-wide terminate onto the NATS subject. The
    // bridge's subscription registers asynchronously, so retry the publish until
    // the stream yields (Terminate is idempotent, so repeats are safe).
    let api_publisher = OpControlNatsPublisher::connect(&OpControlNatsConfig::new(url.clone()))
        .await
        .expect("aa-api side connects to NATS");

    let deadline = Instant::now() + Duration::from_secs(15);
    let msg = loop {
        assert!(
            Instant::now() < deadline,
            "halt never arrived over op_control_stream via NATS"
        );
        api_publisher
            .publish_agent_halt(agent("agent-7"), OpControlSignal::Terminate)
            .await
            .expect("publish agent halt to NATS");
        match timeout(Duration::from_millis(400), stream.message()).await {
            Ok(Ok(Some(msg))) => break msg,
            _ => continue,
        }
    };

    assert_eq!(msg.op_id, aa_runtime::op_control::agent_halt_op_id("agent-7"));
    assert_eq!(msg.op_id, "agent:agent-7");
    assert_eq!(msg.signal, OpControlSignal::Terminate as i32);

    // The runtime applies the delivered signal to its op-control store; the
    // reserved agent key reads as Terminated, which the per-request check honors
    // independently of any trace_id.
    let store = aa_runtime::op_control::OpControlStore::new();
    store.apply(&msg.op_id, msg.signal());
    assert_eq!(
        store.state(&aa_runtime::op_control::agent_halt_op_id("agent-7")),
        Some(aa_runtime::op_control::OpState::Terminated),
    );
}

/// A fleet-wide halt published to the NATS global subject is bridged and
/// delivered to a subscriber under the reserved global op-id `"*"`.
#[tokio::test]
async fn global_halt_published_to_nats_reaches_all_op_control_streams() {
    let host_port = free_port();
    let url = format!("nats://127.0.0.1:{host_port}");
    let _nats = start_nats(host_port).await;

    let publisher = Arc::new(OpControlPublisher::new());
    let _bridge = spawn_bridge(OpControlNatsConfig::new(url.clone()), Arc::clone(&publisher));
    let addr = start_server(Arc::clone(&publisher)).await;

    let mut client = PolicyServiceClient::connect(format!("http://{addr}")).await.unwrap();
    let mut stream = client
        .op_control_stream(OpControlSubscribeRequest {
            agent_id: Some(agent("agent-a")),
        })
        .await
        .unwrap()
        .into_inner();
    await_grpc_subscriber(&publisher).await;

    let api_publisher = OpControlNatsPublisher::connect(&OpControlNatsConfig::new(url.clone()))
        .await
        .expect("aa-api side connects to NATS");

    let deadline = Instant::now() + Duration::from_secs(15);
    let msg = loop {
        assert!(
            Instant::now() < deadline,
            "global halt never arrived over op_control_stream via NATS"
        );
        api_publisher
            .publish_global_halt(OpControlSignal::Terminate)
            .await
            .expect("publish global halt to NATS");
        match timeout(Duration::from_millis(400), stream.message()).await {
            Ok(Ok(Some(msg))) => break msg,
            _ => continue,
        }
    };

    assert_eq!(msg.op_id, aa_runtime::op_control::GLOBAL_HALT_OP_ID);
    assert_eq!(msg.op_id, "*");
    assert_eq!(msg.signal, OpControlSignal::Terminate as i32);
}
