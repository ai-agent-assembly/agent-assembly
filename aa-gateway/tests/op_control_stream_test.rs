//! Integration tests for AAASM-1653: the gateway's OpControlStream
//! server-streaming RPC subscribes to an attached `OpControlPublisher`
//! and forwards filtered envelopes to the gRPC client.

use std::io::Write;
use std::net::SocketAddr;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use std::time::Duration;

use aa_gateway::ops::{OpControlPublisher, OpsRegistry, SharedOpControlPublisher};
use aa_gateway::service::PolicyServiceImpl;
use aa_gateway::PolicyEngine;
use aa_proto::assembly::common::v1::AgentId as ProtoAgentId;
use aa_proto::assembly::policy::v1::policy_service_client::PolicyServiceClient;
use aa_proto::assembly::policy::v1::policy_service_server::PolicyServiceServer;
use aa_proto::assembly::policy::v1::{OpControlSignal, OpControlSubscribeRequest};
use tokio::net::TcpListener;
use tokio::time::timeout;
use tonic::transport::Server;

/// Start a PolicyService gRPC server with the given (optional) publisher
/// attached, returning the bound address.
async fn start_server(publisher: Option<SharedOpControlPublisher>) -> SocketAddr {
    let mut tmp = tempfile::NamedTempFile::new().unwrap();
    writeln!(tmp, "version: \"1\"").unwrap();
    tmp.flush().unwrap();

    let (alert_tx, _) = tokio::sync::broadcast::channel::<aa_gateway::budget::BudgetAlert>(64);
    let engine = PolicyEngine::load_from_file(tmp.path(), alert_tx).unwrap();
    let (audit_tx, _audit_rx) = tokio::sync::mpsc::channel(4096);
    let audit_drops = Arc::new(AtomicU64::new(0));
    let mut service = PolicyServiceImpl::new(Arc::new(engine), audit_tx, audit_drops, [0u8; 32])
        .with_ops_registry(Arc::new(OpsRegistry::new()));
    if let Some(p) = publisher {
        service = service.with_ops_publisher(p);
    }

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

#[tokio::test]
async fn subscriber_receives_published_envelope_addressed_to_them() {
    let publisher = Arc::new(OpControlPublisher::new());
    let addr = start_server(Some(Arc::clone(&publisher))).await;

    let mut client = PolicyServiceClient::connect(format!("http://{addr}")).await.unwrap();
    let mut stream = client
        .op_control_stream(OpControlSubscribeRequest {
            agent_id: Some(agent("agent-7")),
        })
        .await
        .unwrap()
        .into_inner();

    // Let the server-side subscription register before publishing.
    for _ in 0..20 {
        if publisher.subscriber_count() > 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert_eq!(publisher.subscriber_count(), 1, "stream should have subscribed");

    publisher.publish(agent("agent-7"), "trace-1:span-1".into(), OpControlSignal::Pause);

    let msg = timeout(Duration::from_secs(2), stream.message())
        .await
        .expect("recv did not time out")
        .expect("stream did not error")
        .expect("stream had a message");
    assert_eq!(msg.op_id, "trace-1:span-1");
    assert_eq!(msg.signal, OpControlSignal::Pause as i32);
    assert_eq!(msg.sequence, 0);
}

#[tokio::test]
async fn subscriber_ignores_envelopes_for_other_agents() {
    let publisher = Arc::new(OpControlPublisher::new());
    let addr = start_server(Some(Arc::clone(&publisher))).await;

    let mut client = PolicyServiceClient::connect(format!("http://{addr}")).await.unwrap();
    let mut stream = client
        .op_control_stream(OpControlSubscribeRequest {
            agent_id: Some(agent("agent-7")),
        })
        .await
        .unwrap()
        .into_inner();

    for _ in 0..20 {
        if publisher.subscriber_count() > 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }

    // Two publishes: one to a different agent (filtered out), one to the
    // subscriber (delivered). The delivered one should arrive first since
    // the filter just skips non-matches.
    publisher.publish(agent("agent-other"), "trace-x:span-0".into(), OpControlSignal::Pause);
    publisher.publish(agent("agent-7"), "trace-7:span-0".into(), OpControlSignal::Resume);

    let msg = timeout(Duration::from_secs(2), stream.message())
        .await
        .expect("recv did not time out")
        .unwrap()
        .expect("stream had a message");
    assert_eq!(msg.op_id, "trace-7:span-0");
    assert_eq!(msg.signal, OpControlSignal::Resume as i32);
}

#[tokio::test]
async fn missing_publisher_returns_unavailable() {
    let addr = start_server(None).await;
    let mut client = PolicyServiceClient::connect(format!("http://{addr}")).await.unwrap();

    // tonic's server-streaming returns the Status on the initial response
    // when the handler errors before yielding anything. Most clients can
    // discover this either on the initial call or by polling the stream.
    let initial = client
        .op_control_stream(OpControlSubscribeRequest {
            agent_id: Some(agent("agent-7")),
        })
        .await;
    let err = match initial {
        Err(e) => e,
        Ok(resp) => resp
            .into_inner()
            .message()
            .await
            .expect_err("expected error from stream"),
    };
    assert_eq!(err.code(), tonic::Code::Unavailable);
}

// ── AAASM-3881: operator agent-wide / global halts under reserved op-ids ────

/// Block until the publisher reports at least `n` subscribers (the gRPC stream
/// has registered server-side) or a short deadline elapses.
async fn await_subscribers(publisher: &SharedOpControlPublisher, n: usize) {
    for _ in 0..40 {
        if publisher.subscriber_count() >= n {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("expected at least {n} subscribers");
}

/// An operator agent-wide terminate emitted by the gateway (via the OpsRegistry
/// halt path that the ops API drives) is delivered to the agent's stream under
/// the reserved `agent:{agent_id}` op-id — the key AAASM-3873 makes the runtime
/// consult on every request — and, fed into the runtime's op-control store,
/// records the agent as Terminated regardless of any trace_id.
#[tokio::test]
async fn agent_level_terminate_delivered_under_reserved_agent_key_and_halts() {
    let publisher = Arc::new(OpControlPublisher::new());
    let addr = start_server(Some(Arc::clone(&publisher))).await;
    // The registry shares the same publisher the policy service streams from —
    // this is exactly the wiring the ops API uses to emit a halt.
    let registry = OpsRegistry::new().with_publisher(Arc::clone(&publisher));

    let mut client = PolicyServiceClient::connect(format!("http://{addr}")).await.unwrap();
    let mut stream = client
        .op_control_stream(OpControlSubscribeRequest {
            agent_id: Some(agent("agent-7")),
        })
        .await
        .unwrap()
        .into_inner();
    await_subscribers(&publisher, 1).await;

    // Operator issues an agent-wide terminate for agent-7.
    assert!(registry.halt_agent(agent("agent-7"), OpControlSignal::Terminate));

    let msg = timeout(Duration::from_secs(2), stream.message())
        .await
        .expect("recv did not time out")
        .expect("stream did not error")
        .expect("stream had a message");
    assert_eq!(msg.op_id, aa_runtime::op_control::agent_halt_op_id("agent-7"));
    assert_eq!(msg.op_id, "agent:agent-7");
    assert_eq!(msg.signal, OpControlSignal::Terminate as i32);

    // Prove the runtime would halt: applying the delivered signal to the
    // runtime's op-control store records the agent's reserved key as Terminated,
    // which the per-request check consults independently of any trace_id.
    let store = aa_runtime::op_control::OpControlStore::new();
    store.apply(&msg.op_id, msg.signal());
    assert_eq!(
        store.state(&aa_runtime::op_control::agent_halt_op_id("agent-7")),
        Some(aa_runtime::op_control::OpState::Terminated),
    );
}

/// An agent-wide halt for one agent must not leak to a different agent's stream.
#[tokio::test]
async fn agent_level_halt_does_not_reach_other_agents() {
    let publisher = Arc::new(OpControlPublisher::new());
    let addr = start_server(Some(Arc::clone(&publisher))).await;
    let registry = OpsRegistry::new().with_publisher(Arc::clone(&publisher));

    let mut client_other = PolicyServiceClient::connect(format!("http://{addr}")).await.unwrap();
    let mut other = client_other
        .op_control_stream(OpControlSubscribeRequest {
            agent_id: Some(agent("agent-other")),
        })
        .await
        .unwrap()
        .into_inner();
    await_subscribers(&publisher, 1).await;

    registry.halt_agent(agent("agent-7"), OpControlSignal::Terminate);

    assert!(
        timeout(Duration::from_millis(300), other.message()).await.is_err(),
        "an agent-7 halt must not be delivered to agent-other",
    );
}

/// A global halt is delivered to every connected subscriber regardless of their
/// agent_id, under the reserved global op-id `"*"`.
#[tokio::test]
async fn global_terminate_delivered_to_all_subscribers() {
    let publisher = Arc::new(OpControlPublisher::new());
    let addr = start_server(Some(Arc::clone(&publisher))).await;
    let registry = OpsRegistry::new().with_publisher(Arc::clone(&publisher));

    let mut client_a = PolicyServiceClient::connect(format!("http://{addr}")).await.unwrap();
    let mut a = client_a
        .op_control_stream(OpControlSubscribeRequest {
            agent_id: Some(agent("agent-a")),
        })
        .await
        .unwrap()
        .into_inner();
    let mut client_b = PolicyServiceClient::connect(format!("http://{addr}")).await.unwrap();
    let mut b = client_b
        .op_control_stream(OpControlSubscribeRequest {
            agent_id: Some(agent("agent-b")),
        })
        .await
        .unwrap()
        .into_inner();
    await_subscribers(&publisher, 2).await;

    assert!(registry.halt_global(OpControlSignal::Terminate));

    for stream in [&mut a, &mut b] {
        let msg = timeout(Duration::from_secs(2), stream.message())
            .await
            .expect("recv did not time out")
            .expect("stream did not error")
            .expect("stream had a message");
        assert_eq!(msg.op_id, aa_runtime::op_control::GLOBAL_HALT_OP_ID);
        assert_eq!(msg.op_id, "*");
        assert_eq!(msg.signal, OpControlSignal::Terminate as i32);
    }
}

#[tokio::test]
async fn missing_agent_id_returns_invalid_argument() {
    let publisher = Arc::new(OpControlPublisher::new());
    let addr = start_server(Some(publisher)).await;
    let mut client = PolicyServiceClient::connect(format!("http://{addr}")).await.unwrap();

    let initial = client
        .op_control_stream(OpControlSubscribeRequest { agent_id: None })
        .await;
    let err = match initial {
        Err(e) => e,
        Ok(resp) => resp
            .into_inner()
            .message()
            .await
            .expect_err("expected error from stream"),
    };
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
}
