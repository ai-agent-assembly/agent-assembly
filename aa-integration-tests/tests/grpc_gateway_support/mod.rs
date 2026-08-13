// Shared across several `cli_run*` test binaries; not every binary uses every
// helper, so dead-code warnings here are noise.
#![allow(dead_code)]

//! A real gateway `AgentLifecycleService` for the `aasm run` suites (AAASM-5323).
//!
//! # Why this replaced a mock HTTP gateway
//!
//! These files used to stand up an axum server answering
//! `POST /api/v1/agents` and read the launched session's identity out of its
//! response. That route does not exist — `aa-api` mounts `list_agents` and
//! nothing else on it — so the mock was answering a call no gateway serves, and
//! every identity value it "issued" was fiction the CLI copied into the child's
//! environment.
//!
//! `aasm run` now registers over gRPC through the same handshake the SDKs use,
//! so the gateway here is the genuine `AgentLifecycleServiceImpl`. That also
//! makes the session-monitoring assertions real: whether the gateway knows about
//! the session is a question about the registry, not about what a mock recorded.

use std::sync::Arc;

use aa_gateway::registry::AgentRegistry;
use aa_gateway::service::AgentLifecycleServiceImpl;
use aa_proto::assembly::agent::v1::agent_lifecycle_service_server::{
    AgentLifecycleService, AgentLifecycleServiceServer,
};
use aa_proto::assembly::agent::v1::{
    ChallengeRequest, ChallengeResponse, ControlStreamRequest, DeregisterRequest, DeregisterResponse, HeartbeatRequest,
    HeartbeatResponse, RegisterRequest, RegisterResponse,
};
use aa_proto::assembly::common::v1::AgentId as ProtoAgentId;
use tonic::{Request, Response, Status};

/// A live gateway lifecycle service on loopback, plus the registry behind it.
pub struct GrpcGateway {
    endpoint: String,
    registry: Arc<AgentRegistry>,
    seen: Session,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    serving: Option<tokio::task::JoinHandle<()>>,
}

/// What the gateway was told, in order — the monitoring half of the claim these
/// suites make. The registry alone cannot answer it: a session that opened and
/// closed leaves no record there, which is indistinguishable from one that never
/// opened.
#[derive(Clone, Default)]
pub struct Session {
    registered: Arc<std::sync::Mutex<Vec<RegisterRequest>>>,
    deregistered: Arc<std::sync::Mutex<Vec<String>>>,
}

impl Session {
    /// The `RegisterRequest`s the gateway received.
    pub fn registrations(&self) -> Vec<RegisterRequest> {
        self.registered
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// The `did:key`s the gateway was asked to deregister.
    pub fn deregistrations(&self) -> Vec<String> {
        self.deregistered
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
}

impl GrpcGateway {
    /// Bind on a free loopback port and serve until dropped.
    pub async fn start() -> anyhow::Result<Self> {
        let registry = Arc::new(AgentRegistry::new());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let (tx, rx) = tokio::sync::oneshot::channel();

        let seen = Session::default();
        let service = Observed {
            inner: AgentLifecycleServiceImpl::new(Arc::clone(&registry)),
            seen: seen.clone(),
        };
        let serving = tokio::spawn(async move {
            let _ = tonic::transport::Server::builder()
                .add_service(AgentLifecycleServiceServer::new(service))
                .serve_with_incoming_shutdown(tokio_stream::wrappers::TcpListenerStream::new(listener), async {
                    let _ = rx.await;
                })
                .await;
        });

        Ok(Self {
            endpoint: format!("http://{addr}"),
            registry,
            seen,
            shutdown: Some(tx),
            serving: Some(serving),
        })
    }

    /// The value to pass to a child `aasm` as `AA_GATEWAY_ENDPOINT`.
    ///
    /// Passed per-child rather than set on the test process: several of these
    /// suites run concurrently, and a process-global variable would let one
    /// test's launch register against another test's gateway.
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// The registry the service writes to.
    pub fn registry(&self) -> &Arc<AgentRegistry> {
        &self.registry
    }

    /// What the gateway was told about sessions opening and closing.
    pub fn session(&self) -> &Session {
        &self.seen
    }

    /// Whether an agent with `did` (scoped to `team`) is currently registered.
    pub fn holds(&self, team: Option<&str>, did: &str) -> bool {
        self.registry.get(&registry_key(team, did)).is_some()
    }
}

impl Drop for GrpcGateway {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        if let Some(handle) = self.serving.take() {
            handle.abort();
        }
    }
}

/// The `did:key` `aasm run --agent-id <identity>` registered under, read back
/// from the durable identity key the launch enrolled in `state_dir`.
///
/// Read with `aa-sdk-client`'s own store — the one the CLI writes through — so a
/// change to how identity is resolved moves the expectation with it instead of
/// leaving these tests asserting a value nothing produces.
///
/// Deliberately a *load*, not a load-or-enrol: since AAASM-5332 the DID is a
/// rendering of a randomly generated key, so the only way this can name the DID
/// the child registered is by reading the key the child actually created. If the
/// launch enrolled nothing, this panics rather than quietly minting a second
/// identity and comparing it against itself.
pub fn expected_did(state_dir: &std::path::Path, identity: &str) -> String {
    aa_sdk_client::IdentityStore::at(state_dir.join("identity"))
        .load(identity)
        .unwrap_or_else(|e| panic!("the launch should have enrolled a durable identity key for `{identity}`: {e}"))
        .did_key()
}

/// The registry key the gateway files that identity under, hex-encoded — the
/// value `aasm run` exports as `AA_REGISTRATION_ID`.
pub fn expected_registration_id(team: Option<&str>, did: &str) -> String {
    hex::encode(registry_key(team, did))
}

fn registry_key(team: Option<&str>, did: &str) -> [u8; 16] {
    aa_gateway::registry::convert::proto_agent_id_to_key(&ProtoAgentId {
        org_id: String::new(),
        team_id: team.unwrap_or_default().to_string(),
        agent_id: did.to_string(),
    })
}

/// The real service with a tap on the two lifecycle calls these suites assert
/// on. Every method delegates — the tap observes, it never decides.
struct Observed {
    inner: AgentLifecycleServiceImpl,
    seen: Session,
}

#[tonic::async_trait]
impl AgentLifecycleService for Observed {
    async fn request_challenge(&self, req: Request<ChallengeRequest>) -> Result<Response<ChallengeResponse>, Status> {
        self.inner.request_challenge(req).await
    }

    async fn register(&self, req: Request<RegisterRequest>) -> Result<Response<RegisterResponse>, Status> {
        let submitted = req.get_ref().clone();
        let response = self.inner.register(req).await;
        if response.is_ok() {
            self.seen
                .registered
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(submitted);
        }
        response
    }

    async fn heartbeat(&self, req: Request<HeartbeatRequest>) -> Result<Response<HeartbeatResponse>, Status> {
        self.inner.heartbeat(req).await
    }

    async fn deregister(&self, req: Request<DeregisterRequest>) -> Result<Response<DeregisterResponse>, Status> {
        let did = req
            .get_ref()
            .agent_id
            .as_ref()
            .map(|id| id.agent_id.clone())
            .unwrap_or_default();
        let response = self.inner.deregister(req).await;
        if response.is_ok() {
            self.seen
                .deregistered
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(did);
        }
        response
    }

    type ControlStreamStream = <AgentLifecycleServiceImpl as AgentLifecycleService>::ControlStreamStream;

    async fn control_stream(
        &self,
        req: Request<ControlStreamRequest>,
    ) -> Result<Response<Self::ControlStreamStream>, Status> {
        self.inner.control_stream(req).await
    }
}
