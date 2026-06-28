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
use aa_gateway::ops::{
    HaltDelivery, OpControlNatsConfig, OpControlNatsPublisher, OpControlPublisher, OpsRegistry,
    SharedOpControlPublisher,
};
use aa_gateway::service::PolicyServiceImpl;
use aa_gateway::PolicyEngine;
use aa_proto::assembly::common::v1::AgentId as ProtoAgentId;
use aa_proto::assembly::policy::v1::policy_service_client::PolicyServiceClient;
use aa_proto::assembly::policy::v1::policy_service_server::PolicyServiceServer;
use aa_proto::assembly::policy::v1::{OpControlSignal, OpControlSubscribeRequest};
use testcontainers_modules::nats::{Nats, NatsServerCmd};
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

/// Start a NATS container with **JetStream enabled** (`-js`) and its client port
/// pinned to `host_port`. AAASM-3885 moved op-control onto a durable JetStream
/// stream, so the server must run JetStream — a plain NATS server would never ACK
/// the publish (the honest-failure path).
async fn start_nats(host_port: u16) -> ContainerAsync<Nats> {
    let cmd = NatsServerCmd::default().with_jetstream();
    Nats::default()
        .with_cmd(&cmd)
        .with_mapped_port(host_port, 4222.tcp())
        .start()
        .await
        .expect("start nats testcontainer (is Docker running?)")
}

/// Idempotently create the durable op-control JetStream stream (what the gateway
/// boot does). Used by the durability test to persist a halt **before** any
/// gateway consumer exists.
async fn ensure_stream(url: &str) {
    let client = async_nats::connect(url).await.expect("connect to NATS");
    let context = async_nats::jetstream::new(client);
    aa_gateway::ops::nats::ensure_op_control_stream(&context)
        .await
        .expect("ensure op-control JetStream stream");
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
        .expect("aa-api side connects to NATS")
        .with_ack_timeout(Duration::from_millis(500));

    let deadline = Instant::now() + Duration::from_secs(15);
    let msg = loop {
        assert!(
            Instant::now() < deadline,
            "halt never arrived over op_control_stream via NATS"
        );
        // The bridge creates the JetStream stream asynchronously at startup, so an
        // early publish may fail to be ACKed until the stream exists — tolerate that
        // and retry (Terminate is idempotent, so repeats are safe).
        let _ = api_publisher
            .publish_agent_halt(agent("agent-7"), OpControlSignal::Terminate)
            .await;
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
        .expect("aa-api side connects to NATS")
        .with_ack_timeout(Duration::from_millis(500));

    let deadline = Instant::now() + Duration::from_secs(15);
    let msg = loop {
        assert!(
            Instant::now() < deadline,
            "global halt never arrived over op_control_stream via NATS"
        );
        // Tolerate an early pre-stream publish failure and retry (see above).
        let _ = api_publisher.publish_global_halt(OpControlSignal::Terminate).await;
        match timeout(Duration::from_millis(400), stream.message()).await {
            Ok(Ok(Some(msg))) => break msg,
            _ => continue,
        }
    };

    assert_eq!(msg.op_id, aa_runtime::op_control::GLOBAL_HALT_OP_ID);
    assert_eq!(msg.op_id, "*");
    assert_eq!(msg.signal, OpControlSignal::Terminate as i32);
}

/// **The AAASM-3885 durability test.** A halt is published while **no** gateway
/// consumer is subscribed; the bridge is started only afterwards. Because the halt
/// was durably persisted to JetStream (publish ACK awaited), the late-subscribing
/// bridge replays it (DeliverPolicy::All within retention) and delivers it over
/// `op_control_stream` — proving 200 means persisted-and-will-be-delivered, not
/// merely accepted onto the bus. This is the property CORE NATS (AAASM-3883) could
/// not provide.
#[tokio::test]
async fn halt_published_with_no_consumer_is_delivered_to_a_later_subscriber() {
    let host_port = free_port();
    let url = format!("nats://127.0.0.1:{host_port}");
    let _nats = start_nats(host_port).await;

    // The durable stream exists (the gateway created it at boot) but NO consumer /
    // bridge is reading it yet.
    ensure_stream(&url).await;

    // aa-api publishes an agent-wide terminate. The publish ACK is awaited, so a
    // success here means the halt is durably persisted in the stream.
    let api_publisher = OpControlNatsPublisher::connect(&OpControlNatsConfig::new(url.clone()))
        .await
        .expect("aa-api side connects to NATS");
    api_publisher
        .publish_agent_halt(agent("agent-9"), OpControlSignal::Terminate)
        .await
        .expect("durable publish of halt with no consumer must be ACKed");

    // Only NOW does a gateway come up: in-process broadcast + gRPC server + a
    // runtime subscriber, then the bridge that replays the persisted halt.
    let publisher = Arc::new(OpControlPublisher::new());
    let addr = start_server(Arc::clone(&publisher)).await;

    let mut client = PolicyServiceClient::connect(format!("http://{addr}")).await.unwrap();
    let mut stream = client
        .op_control_stream(OpControlSubscribeRequest {
            agent_id: Some(agent("agent-9")),
        })
        .await
        .unwrap()
        .into_inner();
    await_grpc_subscriber(&publisher).await;

    // Bridge starts after the halt was already published and persisted.
    let _bridge = spawn_bridge(OpControlNatsConfig::new(url.clone()), Arc::clone(&publisher));

    // The replayed, persisted halt is delivered over op_control_stream.
    let msg = timeout(Duration::from_secs(15), stream.message())
        .await
        .expect("persisted halt should be delivered to the late subscriber")
        .expect("stream ok")
        .expect("stream yields the persisted halt");

    assert_eq!(msg.op_id, aa_runtime::op_control::agent_halt_op_id("agent-9"));
    assert_eq!(msg.signal, OpControlSignal::Terminate as i32);

    // It records Terminated in the runtime store, independent of any trace_id.
    let store = aa_runtime::op_control::OpControlStore::new();
    store.apply(&msg.op_id, msg.signal());
    assert_eq!(
        store.state(&aa_runtime::op_control::agent_halt_op_id("agent-9")),
        Some(aa_runtime::op_control::OpState::Terminated),
    );
}

/// Honest-failure: with JetStream up but **no op-control stream created**, a
/// publish is never ACKed, so the publisher returns an error and the registry maps
/// it to `HaltDelivery::ChannelError` (the `503`) — never a silent-drop `200`.
#[tokio::test]
async fn publish_without_a_ready_stream_is_an_honest_failure_not_a_silent_200() {
    let host_port = free_port();
    let url = format!("nats://127.0.0.1:{host_port}");
    let _nats = start_nats(host_port).await; // JetStream enabled, but no stream ensured.

    let publisher = OpControlNatsPublisher::connect(&OpControlNatsConfig::new(url))
        .await
        .expect("connect to NATS")
        .with_ack_timeout(Duration::from_millis(500));

    // The raw publisher surfaces the un-acked publish as an error.
    let result = publisher
        .publish_agent_halt(agent("agent-x"), OpControlSignal::Terminate)
        .await;
    assert!(
        result.is_err(),
        "publish to a non-existent stream must be an honest error (-> 503), not a silent 200",
    );

    // And through the registry, the operator endpoint sees ChannelError (-> 503),
    // never Delivered.
    let registry = OpsRegistry::new().with_nats_publisher(Arc::new(publisher));
    match registry
        .halt_agent_delivery(agent("agent-x"), OpControlSignal::Terminate)
        .await
    {
        HaltDelivery::ChannelError(_) => {}
        other => panic!("expected ChannelError (503), got {other:?}"),
    }
}
