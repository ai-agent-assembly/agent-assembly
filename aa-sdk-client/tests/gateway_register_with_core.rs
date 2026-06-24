//! AAASM-3398 with-core acceptance: `AssemblyClient::register` against a live
//! (mock) gateway gRPC `AgentLifecycleService` issues a `credential_token`, and
//! that token is carried on a subsequent `CheckAction` so the gateway can
//! authenticate the registered agent and surface a `DENY`.
//!
//! This exercises the full ADR 0004 path the SDK is responsible for: the direct
//! SDK→gateway Register call (real tonic), the token being stored, and the token
//! riding on the `CheckActionRequest` that the runtime forwards to the gateway's
//! `PolicyService`. The runtime is represented by a forwarder task that relays
//! the `IpcCommand::QueryPolicy` request to the mock gateway and returns its
//! response — the same hop a real `aa-runtime` performs.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::Mutex as StdMutex;

use aa_proto::assembly::agent::v1::agent_lifecycle_service_server::{
    AgentLifecycleService, AgentLifecycleServiceServer,
};
use aa_proto::assembly::agent::v1::{
    ControlCommand, ControlStreamRequest, DeregisterRequest, DeregisterResponse, HeartbeatRequest, HeartbeatResponse,
    RegisterRequest, RegisterResponse,
};
use aa_proto::assembly::common::v1::Decision;
use aa_proto::assembly::policy::v1::policy_service_server::{PolicyService, PolicyServiceServer};
use aa_proto::assembly::policy::v1::{
    BatchCheckRequest, BatchCheckResponse, CheckActionRequest, CheckActionResponse, OpControlMessage,
    OpControlSubscribeRequest,
};
use aa_sdk_client::ipc::{IpcCommand, IpcHandle};
use aa_sdk_client::{AssemblyClient, AssemblyConfig};
use tokio::net::TcpListener;
use tokio_stream::wrappers::{ReceiverStream, TcpListenerStream};
use tonic::{Request, Response, Status};

const ISSUED_TOKEN: &str = "issued-credential-token-xyz";

/// Mock gateway `AgentLifecycleService` — validates the inbound did:key +
/// public_key (mirroring the real gateway) and issues a fixed token.
#[derive(Default)]
struct MockLifecycle;

#[tonic::async_trait]
impl AgentLifecycleService for MockLifecycle {
    async fn register(&self, request: Request<RegisterRequest>) -> Result<Response<RegisterResponse>, Status> {
        let req = request.into_inner();
        let agent_id = req
            .agent_id
            .as_ref()
            .ok_or_else(|| Status::invalid_argument("missing agent_id"))?;
        if !agent_id.agent_id.starts_with("did:key:z") {
            return Err(Status::invalid_argument("agent_id is not a did:key"));
        }
        // The real gateway requires a 32-byte (64 hex char) Ed25519 key.
        if req.public_key.len() != 64 || hex::decode(&req.public_key).is_err() {
            return Err(Status::invalid_argument("public_key must be 64 hex chars"));
        }
        Ok(Response::new(RegisterResponse {
            credential_token: ISSUED_TOKEN.to_string(),
            assigned_policy: "default-policy".to_string(),
            heartbeat_interval_sec: 30,
            ..Default::default()
        }))
    }

    async fn heartbeat(&self, _: Request<HeartbeatRequest>) -> Result<Response<HeartbeatResponse>, Status> {
        Err(Status::unimplemented("not used in this test"))
    }

    async fn deregister(&self, _: Request<DeregisterRequest>) -> Result<Response<DeregisterResponse>, Status> {
        Err(Status::unimplemented("not used in this test"))
    }

    type ControlStreamStream = ReceiverStream<Result<ControlCommand, Status>>;

    async fn control_stream(
        &self,
        _: Request<ControlStreamRequest>,
    ) -> Result<Response<Self::ControlStreamStream>, Status> {
        Err(Status::unimplemented("not used in this test"))
    }
}

/// Mock gateway `PolicyService` — records the credential token it sees and
/// denies every action, standing in for an authenticated deny decision.
struct MockPolicy {
    seen_token: Arc<StdMutex<Option<String>>>,
}

#[tonic::async_trait]
impl PolicyService for MockPolicy {
    async fn check_action(
        &self,
        request: Request<CheckActionRequest>,
    ) -> Result<Response<CheckActionResponse>, Status> {
        let req = request.into_inner();
        *self.seen_token.lock().unwrap() = Some(req.credential_token.clone());
        Ok(Response::new(CheckActionResponse {
            decision: Decision::Deny as i32,
            reason: "denied by mock policy".to_string(),
            ..Default::default()
        }))
    }

    async fn batch_check(&self, _: Request<BatchCheckRequest>) -> Result<Response<BatchCheckResponse>, Status> {
        Err(Status::unimplemented("not used in this test"))
    }

    type OpControlStreamStream = ReceiverStream<Result<OpControlMessage, Status>>;

    async fn op_control_stream(
        &self,
        _: Request<OpControlSubscribeRequest>,
    ) -> Result<Response<Self::OpControlStreamStream>, Status> {
        Err(Status::unimplemented("not used in this test"))
    }
}

/// Start both mock gateway services on one ephemeral port.
async fn start_gateway(seen_token: Arc<StdMutex<Option<String>>>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let policy = MockPolicy { seen_token };

    tokio::spawn(async move {
        let incoming = TcpListenerStream::new(listener);
        tonic::transport::Server::builder()
            .add_service(AgentLifecycleServiceServer::new(MockLifecycle))
            .add_service(PolicyServiceServer::new(policy))
            .serve_with_incoming(incoming)
            .await
            .unwrap();
    });

    tokio::time::sleep(std::time::Duration::from_millis(80)).await;
    addr
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn register_then_check_carries_token_and_surfaces_deny() {
    let seen_token = Arc::new(StdMutex::new(None));
    let addr = start_gateway(seen_token.clone()).await;
    let endpoint = format!("http://{addr}");

    // Build a client over an in-process IPC channel that a forwarder task drains
    // (the "runtime" hop). query_policy blocking-sends onto this channel.
    let (cmd_tx, mut cmd_rx) = tokio::sync::mpsc::channel::<IpcCommand>(16);
    let ipc = IpcHandle { cmd_tx, thread: None };
    let client = Arc::new(AssemblyClient::new(ipc, vec![]));

    let config = AssemblyConfig {
        agent_id: "with-core-agent".to_string(),
        socket_path: None,
        gateway_endpoint: Some(endpoint.clone()),
        team_id: None,
        parent_agent_id: None,
        sdk_version: None,
    };

    // 1) Register directly against the mock gateway — issues + stores the token.
    let assigned = client
        .register(&config, "with-core-agent".into(), "custom".into())
        .await
        .expect("register against live gateway should succeed");
    assert_eq!(assigned, "default-policy");
    assert_eq!(client.credential_token().as_deref(), Some(ISSUED_TOKEN));

    // 2) Forwarder task: drain one QueryPolicy command and relay it to the mock
    //    gateway PolicyService over gRPC, mirroring the aa-runtime forward.
    let forwarder = tokio::spawn(async move {
        if let Some(IpcCommand::QueryPolicy { request, resp }) = cmd_rx.recv().await {
            let mut gw = aa_proto::assembly::policy::v1::policy_service_client::PolicyServiceClient::connect(endpoint)
                .await
                .unwrap();
            let decision = gw.check_action(*request).await.unwrap().into_inner();
            resp.send(decision).unwrap();
        }
    });

    // 3) Run the blocking query_policy on a worker thread; the stored token is
    //    attached automatically.
    let client_for_check = client.clone();
    let response = tokio::task::spawn_blocking(move || client_for_check.query_policy(CheckActionRequest::default()))
        .await
        .unwrap()
        .expect("query_policy should return the gateway decision");

    forwarder.await.unwrap();

    // The gateway saw the registration token on the CheckAction request …
    assert_eq!(seen_token.lock().unwrap().as_deref(), Some(ISSUED_TOKEN));
    // … and the DENY decision surfaced back through query_policy.
    assert_eq!(response.decision, Decision::Deny as i32);
    assert_eq!(response.reason, "denied by mock policy");
}
