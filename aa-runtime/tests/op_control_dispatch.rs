//! Dispatch test for [`aa_runtime::op_control`] (AAASM-3805).
//!
//! The op-control kill switch's end-to-end path against the real gateway lives
//! in `aa-integration-tests`, which does not run under `-p aa-runtime`, leaving
//! the client's stream-consumption loop (`subscribe_once` + `run`) uncovered for
//! this crate alone.
//!
//! This test stands up a minimal in-process `PolicyService` over loopback whose
//! `OpControlStream` pushes a Pause then a Terminate for one op, and asserts the
//! client applies them to the shared [`OpControlStore`] — proving the runtime
//! actually observes the operator's kill switch (the bug AAASM-3491 fixed: a
//! terminate that nothing on the execution path consumed).

use std::pin::Pin;
use std::time::Duration;

use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tokio_stream::Stream;
use tonic::transport::Server;
use tonic::{Request, Response, Status};

use aa_proto::assembly::common::v1::AgentId;
use aa_proto::assembly::policy::v1::policy_service_server::{PolicyService, PolicyServiceServer};
use aa_proto::assembly::policy::v1::{
    BatchCheckRequest, BatchCheckResponse, CheckActionRequest, CheckActionResponse, OpControlMessage, OpControlSignal,
    OpControlSubscribeRequest,
};
use aa_runtime::op_control::{OpControlClient, OpControlStore, OpState};

/// A mock gateway whose only live method is `op_control_stream`; it pushes a
/// Pause then a Terminate for one op, then closes the stream.
struct MockPolicyService;

#[tonic::async_trait]
impl PolicyService for MockPolicyService {
    async fn check_action(
        &self,
        _request: Request<CheckActionRequest>,
    ) -> Result<Response<CheckActionResponse>, Status> {
        Err(Status::unimplemented("not exercised by the op-control consumer test"))
    }

    async fn batch_check(&self, _request: Request<BatchCheckRequest>) -> Result<Response<BatchCheckResponse>, Status> {
        Err(Status::unimplemented("not exercised by the op-control consumer test"))
    }

    type OpControlStreamStream = Pin<Box<dyn Stream<Item = Result<OpControlMessage, Status>> + Send>>;

    async fn op_control_stream(
        &self,
        _request: Request<OpControlSubscribeRequest>,
    ) -> Result<Response<Self::OpControlStreamStream>, Status> {
        let messages = vec![
            Ok(OpControlMessage {
                op_id: "trace-1:span-1".to_string(),
                signal: OpControlSignal::Pause as i32,
                sequence: 1,
            }),
            Ok(OpControlMessage {
                op_id: "trace-1:span-1".to_string(),
                signal: OpControlSignal::Terminate as i32,
                sequence: 2,
            }),
        ];
        Ok(Response::new(Box::pin(tokio_stream::iter(messages))))
    }
}

#[tokio::test]
async fn client_applies_pushed_kill_switch_signals_to_store() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind loopback");
    let addr = listener.local_addr().expect("local_addr");
    let server = tokio::spawn(async move {
        Server::builder()
            .add_service(PolicyServiceServer::new(MockPolicyService))
            .serve_with_incoming(TcpListenerStream::new(listener))
            .await
            .expect("mock gateway serve");
    });

    let store = OpControlStore::new();
    let agent = AgentId {
        org_id: String::new(),
        team_id: String::new(),
        agent_id: "agent-1".to_string(),
    };
    let handle = OpControlClient::start(format!("http://{addr}"), agent, store.clone());

    // The terminate is sticky and terminal, so once the store reads Terminated
    // for the op we know both pushed signals were consumed in order.
    tokio::time::timeout(Duration::from_secs(5), async {
        while store.state("trace-1:span-1") != Some(OpState::Terminated) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("client did not apply the pushed kill-switch signals within 5s");

    assert_eq!(
        store.state("trace-1:span-1"),
        Some(OpState::Terminated),
        "an operator terminate pushed over the stream must reach the runtime store"
    );
    // An op the gateway never mentioned stays runnable.
    assert_eq!(store.state("trace-1:span-2"), None);

    handle.abort();
    server.abort();
}
