//! AAASM-6261 (J83) AC2: what the proxy tells the gateway about who is behind a
//! connection, measured against a real second OS process.
//!
//! Two properties are kept apart, and each test is named for the one it measures:
//!
//! * **proxy identity**: this proxy instance is bound to agent X by a
//!   gateway-validated launch grant. The proxy sends the registered triple and
//!   the grant in `launch_grant`, never the registration token and never the
//!   `AA_AGENT_ID` label, and refuses an `Allow` the gateway did not bind.
//! * **connection origin**: the process opening a connection is the governed
//!   agent. Not verified and not claimed: a second process of the same user that
//!   reaches the proxy's port is attributed to the launch, measured below.
//!
//! The stub gateway records exactly what each `CheckAction` carried and answers
//! `BOUND` only for a registered `(agent, grant)` pair, so an attribution can only
//! appear in these results if the proxy sent one. Whether the real gateway binds
//! and audits correctly is `aa-integration-tests/tests/proxy_launch_grant.rs`.

use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use aa_proto::assembly::common::v1::AgentIdentityAssurance;
use aa_proto::assembly::policy::v1::action_context::Action;
use aa_proto::assembly::policy::v1::policy_service_server::{PolicyService, PolicyServiceServer};
use aa_proto::assembly::policy::v1::{
    BatchCheckRequest, BatchCheckResponse, CheckActionRequest, CheckActionResponse, OpControlMessage,
    OpControlSubscribeRequest,
};
use aa_proxy::audit_jsonl::{ProxyAuditDecision, ProxyAuditEntry, RefusalRule};
use aa_proxy::config::{CredentialAction, ProxyConfig};
use aa_proxy::credentials::LaunchGrant;
use aa_proxy::tls::CaStore;
use aa_runtime::pipeline::PipelineEvent;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{broadcast, mpsc};
use tonic::codegen::tokio_stream::Stream;
use tonic::{Request, Response, Status};

const HOST: &str = "hooks.example.com";
const DID_A: &str = "did:key:launch-a";
const GRANT_A: &str = "grant-launch-a-synthetic";
const DID_B: &str = "did:key:launch-b";
const GRANT_B: &str = "grant-launch-b-synthetic";
/// Labels the launches carry. They must never reach the gateway.
const LABEL_A: &str = "label-of-launch-a";
const LABEL_B: &str = "label-of-launch-b";

/// What one network `CheckAction` carried: `(agent_id, launch_grant, credential_token)`.
type Claim = (String, String, String);

/// A gateway stand-in that knows which `(agent, grant)` pairs are minted.
struct StubGateway {
    minted: Vec<(String, String)>,
    denied_agent: String,
    seen: Arc<Mutex<Vec<Claim>>>,
}

#[tonic::async_trait]
impl PolicyService for StubGateway {
    async fn check_action(&self, req: Request<CheckActionRequest>) -> Result<Response<CheckActionResponse>, Status> {
        let request = req.get_ref();
        let is_network = matches!(
            request.context.as_ref().and_then(|c| c.action.as_ref()),
            Some(Action::NetworkCall(_))
        );
        let agent = request
            .agent_id
            .as_ref()
            .map(|a| a.agent_id.clone())
            .unwrap_or_default();
        if is_network {
            self.seen.lock().unwrap().push((
                agent.clone(),
                request.launch_grant.clone(),
                request.credential_token.clone(),
            ));
        }
        let bound = self.minted.contains(&(agent.clone(), request.launch_grant.clone()));
        let assurance = if bound {
            AgentIdentityAssurance::Bound
        } else if agent.is_empty() {
            AgentIdentityAssurance::Unattributed
        } else {
            AgentIdentityAssurance::Asserted
        };
        let deny = is_network && bound && agent == self.denied_agent;
        Ok(Response::new(CheckActionResponse {
            decision: if deny {
                aa_proto::assembly::common::v1::Decision::Deny as i32
            } else {
                aa_proto::assembly::common::v1::Decision::Allow as i32
            },
            reason: if deny {
                format!("network egress denied for {agent}")
            } else {
                String::new()
            },
            agent_identity_assurance: assurance as i32,
            ..Default::default()
        }))
    }

    async fn batch_check(&self, _req: Request<BatchCheckRequest>) -> Result<Response<BatchCheckResponse>, Status> {
        Err(Status::unimplemented("stub"))
    }

    type OpControlStreamStream = Pin<Box<dyn Stream<Item = Result<OpControlMessage, Status>> + Send + 'static>>;

    async fn op_control_stream(
        &self,
        _req: Request<OpControlSubscribeRequest>,
    ) -> Result<Response<Self::OpControlStreamStream>, Status> {
        Err(Status::unimplemented("stub"))
    }
}

fn minted() -> Vec<(String, String)> {
    vec![
        (DID_A.to_string(), GRANT_A.to_string()),
        (DID_B.to_string(), GRANT_B.to_string()),
    ]
}

async fn spawn_gateway(denied_agent: &str) -> (String, Arc<Mutex<Vec<Claim>>>) {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    let service = StubGateway {
        minted: minted(),
        denied_agent: denied_agent.to_string(),
        seen: Arc::clone(&seen),
    };
    tokio::spawn(async move {
        let _ = tonic::transport::Server::builder()
            .add_service(PolicyServiceServer::new(service))
            .serve(addr)
            .await;
    });
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    (format!("http://{addr}"), seen)
}

fn grant(did: &str, grant: &str) -> LaunchGrant {
    LaunchGrant::new(String::new(), String::new(), did.to_string(), grant.to_string())
}

async fn start_proxy(
    gateway: &str,
    grant: Option<LaunchGrant>,
    label: Option<&str>,
    ca_dir: &std::path::Path,
) -> (SocketAddr, mpsc::Receiver<ProxyAuditEntry>) {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let ca = CaStore::load_or_create(ca_dir).await.unwrap();
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    let config = ProxyConfig {
        bind_addr: addr,
        ca_dir: ca_dir.to_path_buf(),
        cert_cache_capacity: 8,
        llm_only: true,
        mitm_hosts: vec![HOST.to_string()],
        denied_hosts: Vec::new(),
        network_allowlist: Vec::new(),
        skip_upstream_tls_verify: true,
        credential_action: CredentialAction::AlertOnly,
        upstream_override: None,
        gateway_endpoint: Some(gateway.to_string()),
        mcp_fail_open: false,
        network_fail_open: false,
        agent_id: label.map(str::to_string),
        ready_file: None,
        parent_pid: None,
        allow_private_connect_targets: true,
        trusted_config_path: None,
    };
    let (event_tx, _event_rx) = broadcast::channel::<PipelineEvent>(16);
    let (audit_tx, audit_rx) = mpsc::channel(16);
    let mut server = aa_proxy::proxy::ProxyServer::new_with_audit_sink(config, ca, event_tx, Some(audit_tx));
    if let Some(grant) = grant {
        server = server.with_launch_grant(grant);
    }
    tokio::spawn(async move {
        let _ = server.run().await;
    });
    tokio::time::sleep(std::time::Duration::from_millis(80)).await;
    (addr, audit_rx)
}

async fn next_record(rx: &mut mpsc::Receiver<ProxyAuditEntry>) -> ProxyAuditEntry {
    tokio::time::timeout(std::time::Duration::from_secs(5), rx.recv())
        .await
        .expect("the proxy persisted no audit record within 5 s")
        .expect("audit channel closed")
}

/// Send a CONNECT and return the status line the proxy answered with.
async fn connect_status(proxy: SocketAddr) -> String {
    let mut stream = TcpStream::connect(proxy).await.unwrap();
    let connect = format!("CONNECT {HOST}:443 HTTP/1.1\r\nHost: {HOST}:443\r\n\r\n");
    stream.write_all(connect.as_bytes()).await.unwrap();
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).await.unwrap();
    line
}

/// The same CONNECT, opened by a **separate OS process** (`bash` with its own
/// `/dev/tcp`) that holds no secret and no label: the stand-in for any other
/// process of the same user that can reach the proxy's loopback port.
async fn connect_status_from_another_process(proxy: SocketAddr) -> String {
    let script = format!(
        "exec 3<>/dev/tcp/127.0.0.1/{port}; printf 'CONNECT {HOST}:443 HTTP/1.1\\r\\nHost: {HOST}:443\\r\\n\\r\\n' >&3; head -n 1 <&3",
        port = proxy.port()
    );
    let out = tokio::process::Command::new("bash")
        .args(["-c", &script])
        .output()
        .await
        .expect("spawn a second process");
    assert_ne!(out.stdout.len(), 0, "the second process got no answer: {out:?}");
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// Each governed proxy sends its own registered triple and grant and nothing else:
/// the labels are swapped against the grants, so a proxy that sent its label would
/// be recorded under the other launch's name, and no registration token appears.
#[tokio::test]
async fn each_launch_sends_its_own_grant_and_never_a_label_or_registration_token() {
    let dir_a = tempfile::tempdir().unwrap();
    let dir_b = tempfile::tempdir().unwrap();
    let (gateway, seen) = spawn_gateway(DID_B).await;
    let (proxy_a, _audit_a) = start_proxy(&gateway, Some(grant(DID_A, GRANT_A)), Some(LABEL_B), dir_a.path()).await;
    let (proxy_b, mut audit_b) = start_proxy(&gateway, Some(grant(DID_B, GRANT_B)), Some(LABEL_A), dir_b.path()).await;

    assert!(
        connect_status(proxy_a).await.contains("200"),
        "A is bound and not denied"
    );
    assert!(
        !connect_status(proxy_b).await.contains("200"),
        "B is the bound agent the stub denies"
    );
    assert_eq!(
        *seen.lock().unwrap(),
        vec![
            (DID_A.to_string(), GRANT_A.to_string(), String::new()),
            (DID_B.to_string(), GRANT_B.to_string(), String::new())
        ]
    );
    let refusal = next_record(&mut audit_b).await;
    assert_eq!(refusal.decision, ProxyAuditDecision::Blocked);
    assert_eq!(refusal.refusal_rule, Some(RefusalRule::GatewayEgressPolicy));
}

/// A proxy with no grant claims nothing, even with a label.
#[tokio::test]
async fn a_proxy_without_a_grant_claims_no_identity() {
    let dir = tempfile::tempdir().unwrap();
    let (gateway, seen) = spawn_gateway(DID_B).await;
    let (standalone, _audit) = start_proxy(&gateway, None, Some("a-label-it-must-not-send"), dir.path()).await;
    assert!(connect_status(standalone).await.contains("200"));
    assert_eq!(
        *seen.lock().unwrap(),
        vec![(String::new(), String::new(), String::new())]
    );
}

/// A governed proxy refuses an `Allow` the gateway did not bind. The stub says
/// `Allow` + `Asserted` for a grant it never minted, which is what an unvalidating
/// or downgraded gateway would say.
#[tokio::test]
async fn a_governed_proxy_refuses_an_allow_the_gateway_did_not_bind() {
    let (dir_ok, dir_bad) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let (gateway, seen) = spawn_gateway(DID_B).await;
    let (ok, _a) = start_proxy(&gateway, Some(grant(DID_A, GRANT_A)), None, dir_ok.path()).await;
    assert!(
        connect_status(ok).await.contains("200"),
        "positive control: a minted grant is bound"
    );
    let (bad, _b) = start_proxy(&gateway, Some(grant(DID_A, "grant-never-minted")), None, dir_bad.path()).await;
    let status = connect_status(bad).await;
    assert!(
        !status.contains("200"),
        "an Allow that was only asserted must be refused: {status:?}"
    );
    assert_eq!(
        seen.lock().unwrap().last(),
        Some(&(DID_A.to_string(), "grant-never-minted".to_string(), String::new())),
        "fixture check: the unminted grant reached the gateway, which allowed it"
    );
}

/// MEASURED: connection origin is NOT verified. A separate same-user OS process
/// that reaches launch A's proxy is served, and the gateway is sent launch A's
/// triple and grant for it, exactly as for A's own connection. It is attributed to
/// the launch. What bounds the damage is only that it must reach the proxy; it
/// needs no secret to do so.
#[tokio::test]
async fn another_same_user_process_reaching_the_proxy_is_attributed_to_the_launch() {
    let dir = tempfile::tempdir().unwrap();
    let (gateway, seen) = spawn_gateway(DID_B).await;
    let (proxy, _audit) = start_proxy(&gateway, Some(grant(DID_A, GRANT_A)), Some(LABEL_A), dir.path()).await;

    let from_agent = connect_status(proxy).await;
    let from_other = connect_status_from_another_process(proxy).await;
    assert!(from_agent.contains("200"), "{from_agent:?}");
    assert!(
        from_other.contains("200"),
        "measured: served with no secret: {from_other:?}"
    );
    let claims = seen.lock().unwrap().clone();
    assert_eq!(claims.len(), 2, "{claims:?}");
    assert_eq!(
        claims[0], claims[1],
        "the gateway cannot tell the agent's connection from the other process's"
    );
    assert_eq!(claims[1], (DID_A.to_string(), GRANT_A.to_string(), String::new()));
}
