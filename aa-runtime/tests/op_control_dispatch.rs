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
//!
//! AAASM-5009: the mock now also enforces a credential, mirroring the real
//! gateway's `op_control_stream` auth (`aa-gateway/src/service/policy_service.rs`)
//! closely enough to catch the defect that ticket fixed — [`OpControlClient`]
//! opening the stream with no metadata at all, which every shipped gateway
//! rejects. A mock that ignored the request (as this file's previous version
//! did) passes a client that never attaches a credential just as well as a
//! correct one.

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

/// Metadata key the real gateway's credential-auth interceptor reads
/// (`aa-gateway/src/iam/grpc_auth.rs::CREDENTIAL_METADATA_KEY`). Duplicated
/// here for the same reason `aa_runtime::op_control` duplicates it: this test
/// crate depends on neither `aa-gateway`'s internals nor `aa-runtime`'s
/// private constant.
const CREDENTIAL_METADATA_KEY: &str = "x-aa-credential-token";

/// The only credential this mock accepts.
const VALID_TOKEN: &str = "test-token-abc123";

/// A mock gateway whose only live method is `op_control_stream`. Rejects a
/// request whose `x-aa-credential-token` metadata doesn't match
/// [`VALID_TOKEN`] with `Status::unauthenticated`, matching the real gateway's
/// rejection code for a missing/invalid credential; otherwise pushes a Pause
/// then a Terminate for one op, then closes the stream.
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
        request: Request<OpControlSubscribeRequest>,
    ) -> Result<Response<Self::OpControlStreamStream>, Status> {
        let presented = request
            .metadata()
            .get(CREDENTIAL_METADATA_KEY)
            .and_then(|v| v.to_str().ok());
        if presented != Some(VALID_TOKEN) {
            return Err(Status::unauthenticated(
                "op_control_stream requires a valid credential token",
            ));
        }

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

/// Start the mock gateway on an ephemeral loopback port; returns its address
/// and the server task's handle.
async fn start_mock_gateway() -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind loopback");
    let addr = listener.local_addr().expect("local_addr");
    let server = tokio::spawn(async move {
        Server::builder()
            .add_service(PolicyServiceServer::new(MockPolicyService))
            .serve_with_incoming(TcpListenerStream::new(listener))
            .await
            .expect("mock gateway serve");
    });
    (addr, server)
}

#[tokio::test]
async fn client_applies_pushed_kill_switch_signals_to_store_when_credential_matches() {
    let (addr, server) = start_mock_gateway().await;

    let store = OpControlStore::new();
    let agent = AgentId {
        org_id: String::new(),
        team_id: String::new(),
        agent_id: "agent-1".to_string(),
    };
    let handle = OpControlClient::start(
        format!("http://{addr}"),
        agent,
        Some(VALID_TOKEN.to_string()),
        store.clone(),
    );

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

/// AAASM-5009 regression: a subscription opened with no credential must not
/// reach the pushed signals at all — the mock rejects it exactly as a real
/// credential-enforcing gateway does, and the store must stay empty rather
/// than somehow observing the terminate. Before the fix, [`OpControlClient`]
/// had no way to attach a credential in the first place; this is the control
/// that would have kept passing against that defect if it only asserted "the
/// client eventually gives up" instead of asserting on the store's content.
#[tokio::test]
async fn store_stays_empty_when_no_credential_is_configured_against_a_credential_enforcing_gateway() {
    let (addr, server) = start_mock_gateway().await;

    let store = OpControlStore::new();
    let agent = AgentId {
        org_id: String::new(),
        team_id: String::new(),
        agent_id: "agent-1".to_string(),
    };
    let handle = OpControlClient::start(format!("http://{addr}"), agent, None, store.clone());

    // Give the reconnect loop several rejected attempts' worth of real time —
    // long enough that the pushed signals would have landed if the mock ever
    // accepted the subscription.
    tokio::time::sleep(Duration::from_millis(500)).await;

    assert_eq!(
        store.state("trace-1:span-1"),
        None,
        "an unauthenticated subscription must never observe the gateway's signals"
    );

    handle.abort();
    server.abort();
}
