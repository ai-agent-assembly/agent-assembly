// Shared by several `aasm run` test binaries; not every binary uses every
// helper, so dead-code warnings here are noise.
#![allow(dead_code)]

//! A **real** gateway `AgentLifecycleService` for the tests that measure what
//! `aasm run` registers (AAASM-5323).
//!
//! # Why the real service and not a mock
//!
//! The claim under test is that the CLI passes the *gateway's* registration
//! gate — a well-formed Ed25519 key, a `did:key` that embeds that exact key
//! (AAASM-4787), and a possession proof over a single-use server-issued nonce
//! (AAASM-3591 / AAASM-3866). A mock proves only that the CLI agrees with the
//! mock, and the mock is written by the same hand as the code it is checking; it
//! would happily accept a request with no proof at all, which is precisely the
//! defect the gate exists to catch. So these tests run
//! `aa_gateway::service::AgentLifecycleServiceImpl` over real tonic, against a
//! real `AgentRegistry`, and read the verdict off the thing that ships.

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
use tonic::{Request, Response, Status};

/// A live gateway lifecycle service on loopback, plus the registry behind it.
pub struct TestGateway {
    endpoint: String,
    registry: Arc<AgentRegistry>,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    serving: Option<tokio::task::JoinHandle<()>>,
}

impl TestGateway {
    /// Bind on a free loopback port and serve until dropped.
    pub async fn start() -> anyhow::Result<Self> {
        Self::bind(None).await
    }

    /// As [`start`](Self::start), but every `Register` the gateway receives is
    /// also appended to `seen` before it is handled.
    ///
    /// This is what lets a bypass test attack the CLI's **literal wire bytes**
    /// rather than a reconstruction of them. A reconstruction is written by the
    /// same hand as the test and can quietly drift from what the CLI actually
    /// sends, at which point the "bypass is refused" claim is about a request
    /// nothing produces.
    pub async fn start_recording(seen: Arc<std::sync::Mutex<Vec<RegisterRequest>>>) -> anyhow::Result<Self> {
        Self::bind(Some(seen)).await
    }

    async fn bind(seen: Option<Arc<std::sync::Mutex<Vec<RegisterRequest>>>>) -> anyhow::Result<Self> {
        let registry = Arc::new(AgentRegistry::new());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let (tx, rx) = tokio::sync::oneshot::channel();

        let service = Recording {
            inner: AgentLifecycleServiceImpl::new(Arc::clone(&registry)),
            seen,
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
            shutdown: Some(tx),
            serving: Some(serving),
        })
    }

    /// The `AA_GATEWAY_ENDPOINT` value that reaches this gateway.
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// The registry the service writes to — the only honest way to ask whether a
    /// registration actually landed.
    pub fn registry(&self) -> &Arc<AgentRegistry> {
        &self.registry
    }
}

impl Drop for TestGateway {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        if let Some(handle) = self.serving.take() {
            handle.abort();
        }
    }
}

/// Point the SDK/CLI gateway-endpoint resolution at `endpoint` for the lifetime
/// of the guard.
///
/// `AA_GATEWAY_ENDPOINT` is process-global, so the guard also takes the shared
/// env lock — two tests racing on it would each measure the other's gateway.
pub struct GatewayEnv {
    _lock: std::sync::MutexGuard<'static, ()>,
    prior: Option<String>,
}

impl GatewayEnv {
    pub fn point_at(endpoint: &str) -> Self {
        let lock = env_lock().lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let prior = std::env::var("AA_GATEWAY_ENDPOINT").ok();
        std::env::set_var("AA_GATEWAY_ENDPOINT", endpoint);
        Self { _lock: lock, prior }
    }
}

impl Drop for GatewayEnv {
    fn drop(&mut self) {
        match self.prior.take() {
            Some(v) => std::env::set_var("AA_GATEWAY_ENDPOINT", v),
            None => std::env::remove_var("AA_GATEWAY_ENDPOINT"),
        }
    }
}

fn env_lock() -> &'static std::sync::Mutex<()> {
    static LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
    LOCK.get_or_init(|| std::sync::Mutex::new(()))
}

/// The real service with an optional tap on `Register`.
///
/// Every method delegates: the tap records, it never decides. A wrapper that
/// answered anything itself would be a mock again, and the point of this harness
/// is that the verdicts come from `AgentLifecycleServiceImpl`.
struct Recording {
    inner: AgentLifecycleServiceImpl,
    seen: Option<Arc<std::sync::Mutex<Vec<RegisterRequest>>>>,
}

#[tonic::async_trait]
impl AgentLifecycleService for Recording {
    async fn request_challenge(&self, req: Request<ChallengeRequest>) -> Result<Response<ChallengeResponse>, Status> {
        self.inner.request_challenge(req).await
    }

    async fn register(&self, req: Request<RegisterRequest>) -> Result<Response<RegisterResponse>, Status> {
        if let Some(ref seen) = self.seen {
            seen.lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(req.get_ref().clone());
        }
        self.inner.register(req).await
    }

    async fn heartbeat(&self, req: Request<HeartbeatRequest>) -> Result<Response<HeartbeatResponse>, Status> {
        self.inner.heartbeat(req).await
    }

    async fn deregister(&self, req: Request<DeregisterRequest>) -> Result<Response<DeregisterResponse>, Status> {
        self.inner.deregister(req).await
    }

    type ControlStreamStream = <AgentLifecycleServiceImpl as AgentLifecycleService>::ControlStreamStream;

    async fn control_stream(
        &self,
        req: Request<ControlStreamRequest>,
    ) -> Result<Response<Self::ControlStreamStream>, Status> {
        self.inner.control_stream(req).await
    }
}
