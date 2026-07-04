//! AAASM-4121 — a self-registering agent must not be able to weaken its own
//! enforcement posture.
//!
//! `enforcement_mode` is a downgrade lever: a stored `Observe`/`Disabled` mode
//! rewrites a policy `Deny` into an audited `Allow` on the `CheckAction` hot
//! path. `Register` is the unauthenticated bootstrap path (gated only by an
//! Ed25519 possession-proof, which proves key ownership — not authorization), so
//! a client-supplied `enforcement_mode = Observe` on that path must be ignored
//! and default to `Enforce`.
//!
//! Regression guard: self-register with `enforcement_mode = OBSERVE`, then a
//! `CheckAction` on a denied tool must still return `Deny`.

use std::io::Write;
use std::net::SocketAddr;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use std::time::Duration;

use aa_gateway::registry::AgentRegistry;
use aa_gateway::service::{AgentLifecycleServiceImpl, PolicyServiceImpl};
use aa_gateway::PolicyEngine;
use aa_proto::assembly::agent::v1::agent_lifecycle_service_client::AgentLifecycleServiceClient;
use aa_proto::assembly::agent::v1::agent_lifecycle_service_server::AgentLifecycleServiceServer;
use aa_proto::assembly::agent::v1::{ChallengeRequest, RegisterRequest};
use aa_proto::assembly::common::v1::{ActionType, AgentId as ProtoAgentId, Decision};
use aa_proto::assembly::policy::v1::policy_service_client::PolicyServiceClient;
use aa_proto::assembly::policy::v1::policy_service_server::PolicyServiceServer;
use aa_proto::assembly::policy::v1::{action_context::Action, ActionContext, CheckActionRequest, ToolCallContext};
use ed25519_dalek::Signer;
use tokio::net::TcpListener;
use tonic::transport::{Channel, Server};

/// Deterministic Ed25519 test key; its public half is used as the agent's
/// `public_key` and the challenge is signed with the private half.
fn test_signing_key() -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&[42u8; 32])
}

fn test_public_key_hex() -> String {
    hex::encode(test_signing_key().verifying_key().as_bytes())
}

fn test_agent_id() -> ProtoAgentId {
    ProtoAgentId {
        org_id: "org-test".into(),
        team_id: "team-test".into(),
        agent_id: "did:key:z6Mkm5rByiqq5UNbvPFPfXtGJwdg2kD1T".into(),
    }
}

const DENY_BASH_POLICY: &str = r#"
version: "1"
tools:
  bash:
    allow: false
"#;

/// Start one gRPC server exposing both the `AgentLifecycleService` (Register) and
/// the `PolicyService` (CheckAction) against a single shared registry + a
/// deny-bash policy engine, so a self-registration on one path is observed by the
/// enforcement decision on the other.
async fn start_combined_server() -> SocketAddr {
    let mut tmp = tempfile::NamedTempFile::new().unwrap();
    write!(tmp, "{}", DENY_BASH_POLICY).unwrap();
    tmp.flush().unwrap();

    let (alert_tx, _) = tokio::sync::broadcast::channel::<aa_gateway::budget::BudgetAlert>(64);
    let engine = Arc::new(PolicyEngine::load_from_file(tmp.path(), alert_tx).unwrap());
    let registry = Arc::new(AgentRegistry::new());

    let lifecycle = AgentLifecycleServiceImpl::new(Arc::clone(&registry));
    let (audit_tx, _audit_rx) = tokio::sync::mpsc::channel(4096);
    let policy = PolicyServiceImpl::with_registry(
        Arc::clone(&engine),
        Arc::clone(&registry),
        audit_tx,
        Arc::new(AtomicU64::new(0)),
        [0u8; 32],
    );

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        let _tmp = tmp;
        let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);
        Server::builder()
            .add_service(AgentLifecycleServiceServer::new(lifecycle))
            .add_service(PolicyServiceServer::new(policy))
            .serve_with_incoming(incoming)
            .await
            .unwrap();
    });

    tokio::time::sleep(Duration::from_millis(50)).await;
    addr
}

/// Drive the two-step registration handshake and submit Register with `req`,
/// signing the server-issued nonce with the test key.
async fn register_with_challenge(
    client: &mut AgentLifecycleServiceClient<Channel>,
    mut req: RegisterRequest,
) -> String {
    let challenge = client
        .request_challenge(ChallengeRequest {
            agent_id: req.agent_id.clone(),
            public_key: req.public_key.clone(),
        })
        .await
        .unwrap()
        .into_inner();
    req.possession_proof = test_signing_key().sign(&challenge.nonce).to_bytes().to_vec();
    req.registration_nonce = challenge.nonce;
    client.register(req).await.unwrap().into_inner().credential_token
}

#[tokio::test]
async fn self_registration_with_observe_mode_is_ignored_deny_still_enforced() {
    let addr = start_combined_server().await;
    let proto_id = test_agent_id();

    // Self-register claiming enforcement_mode = OBSERVE (proto value 2), which —
    // if honored — would downgrade this agent's denies to audited allows.
    let mut lifecycle_client = AgentLifecycleServiceClient::connect(format!("http://{addr}"))
        .await
        .unwrap();
    let register_req = RegisterRequest {
        agent_id: Some(proto_id.clone()),
        public_key: test_public_key_hex(),
        enforcement_mode: 2, // EnforcementMode::Observe
        ..Default::default()
    };
    let credential_token = register_with_challenge(&mut lifecycle_client, register_req).await;

    // CheckAction on a denied tool must still return Deny — the client-supplied
    // Observe mode must have been dropped in favor of the server default Enforce.
    let mut policy_client = PolicyServiceClient::connect(format!("http://{addr}")).await.unwrap();
    let resp = policy_client
        .check_action(CheckActionRequest {
            agent_id: Some(proto_id),
            credential_token,
            trace_id: "trace-4121".into(),
            span_id: "span-1".into(),
            action_type: ActionType::ToolCall as i32,
            context: Some(ActionContext {
                action: Some(Action::ToolCall(ToolCallContext {
                    tool_name: "bash".into(),
                    tool_source: "test".into(),
                    args_json: b"{}".to_vec(),
                    target_url: String::new(),
                })),
            }),
            caller_agent_id: None,
        })
        .await
        .unwrap()
        .into_inner();

    assert_eq!(
        resp.decision,
        Decision::Deny as i32,
        "self-registered Observe mode must be ignored; deny rule must still enforce (got reason {:?})",
        resp.reason,
    );
}
