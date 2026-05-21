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
