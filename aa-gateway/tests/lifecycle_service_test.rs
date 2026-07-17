//! Integration tests for the AgentLifecycleService gRPC endpoint.
//!
//! Starts a tonic server on a random TCP port, connects a client,
//! and exercises the full Register → Heartbeat → ControlStream → Deregister lifecycle.

use std::net::SocketAddr;
use std::sync::Arc;

use aa_gateway::registry::AgentRegistry;
use aa_gateway::service::AgentLifecycleServiceImpl;
use aa_proto::assembly::agent::v1::agent_lifecycle_service_client::AgentLifecycleServiceClient;
use aa_proto::assembly::agent::v1::agent_lifecycle_service_server::AgentLifecycleServiceServer;
use aa_proto::assembly::agent::v1::{
    ChallengeRequest, ControlStreamRequest, DeregisterRequest, HeartbeatRequest, RegisterRequest, RegisterResponse,
};
use aa_proto::assembly::common::v1::AgentId as ProtoAgentId;
use tokio::net::TcpListener;
use tonic::transport::{Channel, Server};

// ── Helpers ────────────────────────────────────────────────────────────────

/// The deterministic test keypair. Register/RequestChallenge now bind the
/// `agent_id` did:key to `public_key` (AAASM-4787) — rejecting a did:key that
/// does not encode the same Ed25519 key as `public_key` — so the fixture derives
/// the did:key, the `public_key`, and the possession proof from one keypair. The
/// identity matches [`register_with_sdk_derived_did_key_is_accepted`] so both
/// resolve to the same did:key.
fn test_keypair() -> aa_sdk_client::AgentKeypair {
    aa_sdk_client::AgentKeypair::derive("my-agent-001")
}

/// The fixture's hex-encoded Ed25519 public key — the same key its `agent_id`
/// did:key encodes.
fn test_ed25519_public_key_hex() -> String {
    test_keypair().public_key_hex()
}

/// AAASM-3866: drive the two-step registration handshake against a live server.
///
/// Requests a fresh server nonce for `req`'s `agent_id` + `public_key`, signs it
/// with the shared [`test_keypair`], and submits Register with the nonce + proof.
/// Any `possession_proof` / `registration_nonce` already set on `req` is
/// overwritten — the server-issued nonce is authoritative. Negative cases where
/// the server rejects the challenge itself (e.g. malformed key/id) surface that
/// error. Use [`register_with_challenge_as`] when a request carries a `public_key`
/// other than the shared fixture's.
async fn register_with_challenge(
    client: &mut AgentLifecycleServiceClient<Channel>,
    req: RegisterRequest,
) -> Result<tonic::Response<RegisterResponse>, tonic::Status> {
    register_with_challenge_as(client, &test_keypair(), req).await
}

/// Like [`register_with_challenge`] but signs the possession proof with `kp` — for
/// topology tests where each agent carries its own keypair so its `agent_id`
/// did:key binds to its own `public_key` (AAASM-4787). `kp` must be the keypair
/// whose `public_key` the request declares.
async fn register_with_challenge_as(
    client: &mut AgentLifecycleServiceClient<Channel>,
    kp: &aa_sdk_client::AgentKeypair,
    mut req: RegisterRequest,
) -> Result<tonic::Response<RegisterResponse>, tonic::Status> {
    let agent_id = req.agent_id.clone().expect("agent_id must be set for challenge");
    let public_key = req.public_key.clone();
    let challenge = client
        .request_challenge(ChallengeRequest {
            agent_id: Some(agent_id),
            public_key,
        })
        .await?
        .into_inner();
    req.possession_proof = kp.sign(&challenge.nonce).to_vec();
    req.registration_nonce = challenge.nonce;
    client.register(req).await
}

fn test_agent_id() -> ProtoAgentId {
    ProtoAgentId {
        org_id: "org-test".into(),
        team_id: "team-test".into(),
        agent_id: test_keypair().did_key(),
    }
}

/// Start an AgentLifecycleService gRPC server and return the address + registry.
async fn start_server() -> (SocketAddr, Arc<AgentRegistry>) {
    let registry = Arc::new(AgentRegistry::new());
    let service = AgentLifecycleServiceImpl::new(Arc::clone(&registry));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let registry_clone = Arc::clone(&registry);
    tokio::spawn(async move {
        let _reg = registry_clone;
        let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);
        Server::builder()
            .add_service(AgentLifecycleServiceServer::new(service))
            .serve_with_incoming(incoming)
            .await
            .unwrap();
    });

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    (addr, registry)
}

/// Start a server with a policy engine attached (for auto-resume tests).
async fn start_server_with_engine(
    policy_yaml: &str,
) -> (SocketAddr, Arc<AgentRegistry>, Arc<aa_gateway::PolicyEngine>) {
    use aa_gateway::PolicyEngine;

    let registry = Arc::new(AgentRegistry::new());

    // Write the policy YAML to a temp file and load it.
    let mut tmp = tempfile::NamedTempFile::new().unwrap();
    std::io::Write::write_all(&mut tmp, policy_yaml.as_bytes()).unwrap();
    let (alert_tx, _) = tokio::sync::broadcast::channel::<aa_gateway::budget::BudgetAlert>(64);
    let engine = Arc::new(PolicyEngine::load_from_file(tmp.path(), alert_tx).unwrap());

    let service = AgentLifecycleServiceImpl::with_policy_engine(Arc::clone(&registry), Arc::clone(&engine));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);
        Server::builder()
            .add_service(AgentLifecycleServiceServer::new(service))
            .serve_with_incoming(incoming)
            .await
            .unwrap();
    });

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    (addr, registry, engine)
}

/// AAASM-4032: start a server whose lifecycle service runs under an explicit
/// tenancy posture, so the registration invariant can be exercised.
async fn start_server_with_tenancy(mode: aa_gateway::service::TenancyMode) -> (SocketAddr, Arc<AgentRegistry>) {
    let registry = Arc::new(AgentRegistry::new());
    let service = AgentLifecycleServiceImpl::new(Arc::clone(&registry)).with_tenancy_mode(mode);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let registry_clone = Arc::clone(&registry);
    tokio::spawn(async move {
        let _reg = registry_clone;
        let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);
        Server::builder()
            .add_service(AgentLifecycleServiceServer::new(service))
            .serve_with_incoming(incoming)
            .await
            .unwrap();
    });

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    (addr, registry)
}

// ── Full lifecycle test ────────────────────────────────────────────────────

#[tokio::test]
async fn full_lifecycle_register_heartbeat_control_stream_deregister() {
    let (addr, _registry) = start_server().await;
    let mut client = AgentLifecycleServiceClient::connect(format!("http://{addr}"))
        .await
        .unwrap();

    let agent_id = test_agent_id();
    let public_key = test_ed25519_public_key_hex();

    // 1. Register
    let reg_resp = register_with_challenge(
        &mut client,
        RegisterRequest {
            agent_id: Some(agent_id.clone()),
            name: "lifecycle-test-agent".into(),
            framework: "custom".into(),
            version: "1.0.0".into(),
            risk_tier: 0,
            tool_names: vec!["tool_a".into()],
            public_key: public_key.clone(),
            metadata: Default::default(),
            ..Default::default()
        },
    )
    .await
    .unwrap()
    .into_inner();

    let token = reg_resp.credential_token;
    assert!(!token.is_empty());
    assert_eq!(reg_resp.heartbeat_interval_sec, 30);

    // 2. Heartbeat
    let hb_resp = client
        .heartbeat(HeartbeatRequest {
            agent_id: Some(agent_id.clone()),
            credential_token: token.clone(),
            active_runs: 1,
            actions_count: 10,
        })
        .await
        .unwrap()
        .into_inner();

    assert!(!hb_resp.should_suspend);

    // 3. ControlStream — open a stream and verify it's alive
    let stream_resp = client
        .control_stream(ControlStreamRequest {
            agent_id: Some(agent_id.clone()),
            credential_token: token.clone(),
        })
        .await;
    assert!(stream_resp.is_ok());

    // 4. Deregister
    let dereg_resp = client
        .deregister(DeregisterRequest {
            agent_id: Some(agent_id.clone()),
            credential_token: token,
            reason: "test cleanup".into(),
        })
        .await
        .unwrap()
        .into_inner();

    assert!(dereg_resp.success);
}

// ── Error case tests ───────────────────────────────────────────────────────

#[tokio::test]
async fn register_with_invalid_public_key_returns_error() {
    let (addr, _registry) = start_server().await;
    let mut client = AgentLifecycleServiceClient::connect(format!("http://{addr}"))
        .await
        .unwrap();

    let status = register_with_challenge(
        &mut client,
        RegisterRequest {
            agent_id: Some(test_agent_id()),
            name: "bad-key-agent".into(),
            framework: "custom".into(),
            version: "1.0.0".into(),
            risk_tier: 0,
            tool_names: vec![],
            public_key: "not_valid_hex_key".into(),
            metadata: Default::default(),
            ..Default::default()
        },
    )
    .await
    .unwrap_err();

    assert_eq!(status.code(), tonic::Code::InvalidArgument);
}

/// AAASM-152 regression: Register must reject an `agent_id` that is not a
/// syntactically-valid `did:key` DID.
#[tokio::test]
async fn register_with_non_did_agent_id_returns_invalid_argument() {
    let (addr, _registry) = start_server().await;
    let mut client = AgentLifecycleServiceClient::connect(format!("http://{addr}"))
        .await
        .unwrap();

    let status = register_with_challenge(
        &mut client,
        RegisterRequest {
            agent_id: Some(ProtoAgentId {
                org_id: "org-test".into(),
                team_id: "team-test".into(),
                // Non-empty, but not a did:key — must be rejected.
                agent_id: "agent-lifecycle-1".into(),
            }),
            name: "malformed-id-agent".into(),
            framework: "custom".into(),
            version: "1.0.0".into(),
            risk_tier: 0,
            tool_names: vec![],
            public_key: test_ed25519_public_key_hex(),
            metadata: Default::default(),
            ..Default::default()
        },
    )
    .await
    .unwrap_err();

    assert_eq!(status.code(), tonic::Code::InvalidArgument);
    assert!(
        status.message().contains("did:key"),
        "error should mention did:key, got: {}",
        status.message()
    );
}

/// AAASM-3387 regression: a plain agent identifier run through the shared SDK
/// client's `did:key` derivation is ACCEPTED by the live Register RPC. This is
/// the end-to-end proof that SDK-originated registration succeeds against the
/// gateway's did:key validation (the broken example→live-core path).
#[tokio::test]
async fn register_with_sdk_derived_did_key_is_accepted() {
    let (addr, _registry) = start_server().await;
    let mut client = AgentLifecycleServiceClient::connect(format!("http://{addr}"))
        .await
        .unwrap();

    // A human-readable agent_id of the kind SDKs configure today — which the
    // gateway rejects verbatim — converted via the shared SDK derivation.
    let plain_agent_id = "my-agent-001";
    let did = aa_sdk_client::agent_id_to_did_key(plain_agent_id);
    assert!(did.starts_with("did:key:z"), "derived DID must be a did:key, got {did}");

    let resp = register_with_challenge(
        &mut client,
        RegisterRequest {
            agent_id: Some(ProtoAgentId {
                org_id: "org-test".into(),
                team_id: "team-test".into(),
                agent_id: did.clone(),
            }),
            name: "sdk-derived-agent".into(),
            framework: "custom".into(),
            version: "1.0.0".into(),
            risk_tier: 0,
            tool_names: vec![],
            public_key: test_ed25519_public_key_hex(),
            metadata: Default::default(),
            ..Default::default()
        },
    )
    .await
    .expect("SDK-derived did:key must be accepted by Register")
    .into_inner();

    assert!(!resp.credential_token.is_empty());
}

#[tokio::test]
async fn heartbeat_with_wrong_token_returns_unauthenticated() {
    let (addr, _registry) = start_server().await;
    let mut client = AgentLifecycleServiceClient::connect(format!("http://{addr}"))
        .await
        .unwrap();

    let agent_id = test_agent_id();

    // Register first
    register_with_challenge(
        &mut client,
        RegisterRequest {
            agent_id: Some(agent_id.clone()),
            name: "auth-test-agent".into(),
            framework: "custom".into(),
            version: "1.0.0".into(),
            risk_tier: 0,
            tool_names: vec![],
            public_key: test_ed25519_public_key_hex(),
            metadata: Default::default(),
            ..Default::default()
        },
    )
    .await
    .unwrap();

    // Heartbeat with wrong token
    let status = client
        .heartbeat(HeartbeatRequest {
            agent_id: Some(agent_id),
            credential_token: "wrong-token".into(),
            active_runs: 0,
            actions_count: 0,
        })
        .await
        .unwrap_err();

    assert_eq!(status.code(), tonic::Code::Unauthenticated);
}

#[tokio::test]
async fn deregister_unregistered_agent_returns_not_found() {
    let (addr, _registry) = start_server().await;
    let mut client = AgentLifecycleServiceClient::connect(format!("http://{addr}"))
        .await
        .unwrap();

    let status = client
        .deregister(DeregisterRequest {
            agent_id: Some(test_agent_id()),
            credential_token: "any-token".into(),
            reason: "test".into(),
        })
        .await
        .unwrap_err();

    assert_eq!(status.code(), tonic::Code::Unauthenticated);
}

#[tokio::test]
async fn duplicate_register_returns_already_exists() {
    let (addr, _registry) = start_server().await;
    let mut client = AgentLifecycleServiceClient::connect(format!("http://{addr}"))
        .await
        .unwrap();

    let req = RegisterRequest {
        agent_id: Some(test_agent_id()),
        name: "dup-agent".into(),
        framework: "custom".into(),
        version: "1.0.0".into(),
        risk_tier: 0,
        tool_names: vec![],
        public_key: test_ed25519_public_key_hex(),
        metadata: Default::default(),
        ..Default::default()
    };

    register_with_challenge(&mut client, req.clone()).await.unwrap();

    let status = register_with_challenge(&mut client, req).await.unwrap_err();
    assert_eq!(status.code(), tonic::Code::AlreadyExists);
}

// ── Heartbeat suspend signaling ──────────────────────────────────────────

#[tokio::test]
async fn heartbeat_returns_should_suspend_true_for_suspended_agent() {
    use aa_gateway::registry::SuspendReason;

    let (addr, registry) = start_server().await;
    let mut client = AgentLifecycleServiceClient::connect(format!("http://{addr}"))
        .await
        .unwrap();

    let agent_id = test_agent_id();
    let public_key = test_ed25519_public_key_hex();

    let reg_resp = register_with_challenge(
        &mut client,
        RegisterRequest {
            agent_id: Some(agent_id.clone()),
            name: "suspend-test-agent".into(),
            framework: "custom".into(),
            version: "1.0.0".into(),
            risk_tier: 0,
            tool_names: vec![],
            public_key,
            metadata: Default::default(),
            ..Default::default()
        },
    )
    .await
    .unwrap()
    .into_inner();

    let token = reg_resp.credential_token;

    // Suspend the agent directly via the registry
    use aa_gateway::registry::convert::proto_agent_id_to_key;
    let agent_key = proto_agent_id_to_key(&agent_id);
    registry
        .suspend_agent(&agent_key, SuspendReason::BudgetExceeded)
        .unwrap();

    // Heartbeat should return should_suspend = true
    let hb_resp = client
        .heartbeat(HeartbeatRequest {
            agent_id: Some(agent_id),
            credential_token: token,
            active_runs: 0,
            actions_count: 0,
        })
        .await
        .unwrap()
        .into_inner();

    assert!(hb_resp.should_suspend);
}

#[tokio::test]
async fn heartbeat_returns_should_suspend_false_for_active_agent() {
    let (addr, _registry) = start_server().await;
    let mut client = AgentLifecycleServiceClient::connect(format!("http://{addr}"))
        .await
        .unwrap();

    let agent_id = test_agent_id();
    let public_key = test_ed25519_public_key_hex();

    let reg_resp = register_with_challenge(
        &mut client,
        RegisterRequest {
            agent_id: Some(agent_id.clone()),
            name: "active-test-agent".into(),
            framework: "custom".into(),
            version: "1.0.0".into(),
            risk_tier: 0,
            tool_names: vec![],
            public_key,
            metadata: Default::default(),
            ..Default::default()
        },
    )
    .await
    .unwrap()
    .into_inner();

    let token = reg_resp.credential_token;

    let hb_resp = client
        .heartbeat(HeartbeatRequest {
            agent_id: Some(agent_id),
            credential_token: token,
            active_runs: 0,
            actions_count: 0,
        })
        .await
        .unwrap()
        .into_inner();

    assert!(!hb_resp.should_suspend);
}

// ── Heartbeat auto-resume ────────────────────────────────────────────────

#[tokio::test]
async fn heartbeat_auto_resumes_budget_suspended_agent_when_budget_reset() {
    use aa_gateway::registry::convert::proto_agent_id_to_key;
    use aa_gateway::registry::{AgentStatus, SuspendReason};

    let yaml = "budget:\n  daily_limit_usd: 10.0\n  action_on_exceed: suspend\n";
    let (addr, registry, _engine) = start_server_with_engine(yaml).await;

    let mut client = AgentLifecycleServiceClient::connect(format!("http://{addr}"))
        .await
        .unwrap();

    let agent_id = test_agent_id();
    let reg_resp = register_with_challenge(
        &mut client,
        RegisterRequest {
            agent_id: Some(agent_id.clone()),
            name: "auto-resume-agent".into(),
            framework: "custom".into(),
            version: "1.0.0".into(),
            risk_tier: 0,
            tool_names: vec![],
            public_key: test_ed25519_public_key_hex(),
            metadata: Default::default(),
            ..Default::default()
        },
    )
    .await
    .unwrap()
    .into_inner();
    let token = reg_resp.credential_token;

    // Suspend the agent as if budget was exceeded
    let agent_key = proto_agent_id_to_key(&agent_id);
    registry
        .suspend_agent(&agent_key, SuspendReason::BudgetExceeded)
        .unwrap();

    // Heartbeat: engine has no spend recorded → is_within_budget() = true → auto-resume
    let hb_resp = client
        .heartbeat(HeartbeatRequest {
            agent_id: Some(agent_id.clone()),
            credential_token: token.clone(),
            active_runs: 0,
            actions_count: 0,
        })
        .await
        .unwrap()
        .into_inner();

    assert!(!hb_resp.should_suspend, "agent should have been auto-resumed");

    // Verify the registry status was updated to Active
    let status = registry.agent_status(&agent_key).unwrap();
    assert_eq!(status, AgentStatus::Active);
}

#[tokio::test]
async fn heartbeat_does_not_resume_manually_suspended_agent() {
    use aa_gateway::registry::convert::proto_agent_id_to_key;
    use aa_gateway::registry::{AgentStatus, SuspendReason};

    let yaml = "budget:\n  daily_limit_usd: 10.0\n  action_on_exceed: suspend\n";
    let (addr, registry, _engine) = start_server_with_engine(yaml).await;

    let mut client = AgentLifecycleServiceClient::connect(format!("http://{addr}"))
        .await
        .unwrap();

    let agent_id = test_agent_id();
    let reg_resp = register_with_challenge(
        &mut client,
        RegisterRequest {
            agent_id: Some(agent_id.clone()),
            name: "manual-suspend-agent".into(),
            framework: "custom".into(),
            version: "1.0.0".into(),
            risk_tier: 0,
            tool_names: vec![],
            public_key: test_ed25519_public_key_hex(),
            metadata: Default::default(),
            ..Default::default()
        },
    )
    .await
    .unwrap()
    .into_inner();
    let token = reg_resp.credential_token;

    // Manually suspend the agent
    let agent_key = proto_agent_id_to_key(&agent_id);
    registry.suspend_agent(&agent_key, SuspendReason::Manual).unwrap();

    // Heartbeat: manual suspension is not auto-resumable
    let hb_resp = client
        .heartbeat(HeartbeatRequest {
            agent_id: Some(agent_id),
            credential_token: token,
            active_runs: 0,
            actions_count: 0,
        })
        .await
        .unwrap()
        .into_inner();

    assert!(hb_resp.should_suspend, "manually suspended agent must not auto-resume");

    let status = registry.agent_status(&agent_key).unwrap();
    assert_eq!(status, AgentStatus::Suspended(SuspendReason::Manual));
}

// ── Topology echo (AAASM-208 / AAASM-933) ────────────────────────────────

#[tokio::test]
async fn register_echoes_parent_agent_id_and_team_id() {
    let (addr, _registry) = start_server().await;
    let mut client = AgentLifecycleServiceClient::connect(format!("http://{addr}"))
        .await
        .unwrap();

    // Register the parent first so the sub-agent can be accepted. Each agent
    // carries its own keypair so its did:key binds to its own public_key.
    let parent_kp = aa_sdk_client::AgentKeypair::derive("echo-parent");
    let parent_id = ProtoAgentId {
        org_id: "org-echo".into(),
        team_id: "team-echo".into(),
        agent_id: parent_kp.did_key(),
    };
    register_with_challenge_as(
        &mut client,
        &parent_kp,
        RegisterRequest {
            agent_id: Some(parent_id),
            name: "parent-agent".into(),
            framework: "custom".into(),
            version: "1.0.0".into(),
            risk_tier: 0,
            tool_names: vec![],
            public_key: parent_kp.public_key_hex(),
            metadata: Default::default(),
            ..Default::default()
        },
    )
    .await
    .unwrap();

    let child_kp = aa_sdk_client::AgentKeypair::derive("echo-child");
    let agent_id = ProtoAgentId {
        org_id: "org-echo".into(),
        team_id: "team-echo".into(),
        agent_id: child_kp.did_key(),
    };

    let reg_resp = register_with_challenge_as(
        &mut client,
        &child_kp,
        RegisterRequest {
            agent_id: Some(agent_id),
            name: "echo-agent".into(),
            framework: "custom".into(),
            version: "1.0.0".into(),
            risk_tier: 0,
            tool_names: vec![],
            public_key: child_kp.public_key_hex(),
            metadata: Default::default(),
            parent_agent_id: Some(parent_kp.did_key()),
            ..Default::default()
        },
    )
    .await
    .unwrap()
    .into_inner();

    assert_eq!(reg_resp.parent_agent_id, Some(parent_kp.did_key()));
    assert_eq!(reg_resp.team_id, Some("team-echo".into()));
    // root_agent_id must be echoed back — parent is root so root = parent's key
    assert!(reg_resp.root_agent_id.is_some());
    assert_eq!(reg_resp.root_agent_id.as_deref().unwrap().len(), 16);
}

#[tokio::test]
async fn register_without_topology_returns_none_echo_fields() {
    let (addr, _registry) = start_server().await;
    let mut client = AgentLifecycleServiceClient::connect(format!("http://{addr}"))
        .await
        .unwrap();

    let agent_id = ProtoAgentId {
        org_id: "org-no-topo".into(),
        team_id: String::new(),
        agent_id: test_keypair().did_key(),
    };

    let reg_resp = register_with_challenge(
        &mut client,
        RegisterRequest {
            agent_id: Some(agent_id),
            name: "no-topo-agent".into(),
            framework: "custom".into(),
            version: "1.0.0".into(),
            risk_tier: 0,
            tool_names: vec![],
            public_key: test_ed25519_public_key_hex(),
            metadata: Default::default(),
            ..Default::default()
        },
    )
    .await
    .unwrap()
    .into_inner();

    assert_eq!(reg_resp.parent_agent_id, None);
    assert_eq!(reg_resp.team_id, None, "empty team_id must normalize to None");
}

// ── root_agent_id computation (AAASM-1005) ────────────────────────────────

#[tokio::test]
async fn root_agent_id_for_root_agent_is_set_to_self() {
    let (addr, _registry) = start_server().await;
    let mut client = AgentLifecycleServiceClient::connect(format!("http://{addr}"))
        .await
        .unwrap();

    let agent_proto_id = ProtoAgentId {
        org_id: "root-org".into(),
        team_id: "root-team".into(),
        agent_id: test_keypair().did_key(),
    };
    let expected_key = aa_gateway::registry::convert::proto_agent_id_to_key(&agent_proto_id);

    let resp = register_with_challenge(
        &mut client,
        RegisterRequest {
            agent_id: Some(agent_proto_id),
            name: "root-A".into(),
            framework: "custom".into(),
            version: "1.0.0".into(),
            risk_tier: 0,
            tool_names: vec![],
            public_key: test_ed25519_public_key_hex(),
            metadata: Default::default(),
            ..Default::default()
        },
    )
    .await
    .unwrap()
    .into_inner();

    let echoed = resp.root_agent_id.expect("root agent must receive root_agent_id");
    assert_eq!(
        echoed.as_slice(),
        expected_key.as_slice(),
        "root agent's root_agent_id must equal its own key"
    );
}

#[tokio::test]
async fn root_agent_id_chains_3_levels() {
    let (addr, _registry) = start_server().await;
    let mut client = AgentLifecycleServiceClient::connect(format!("http://{addr}"))
        .await
        .unwrap();

    let org = "chain-org";
    let team = "chain-team";

    // Register A (root). Each agent carries its own keypair (AAASM-4787).
    let kp_a = aa_sdk_client::AgentKeypair::derive("chain-A");
    let proto_a = ProtoAgentId {
        org_id: org.into(),
        team_id: team.into(),
        agent_id: kp_a.did_key(),
    };
    let key_a = aa_gateway::registry::convert::proto_agent_id_to_key(&proto_a);
    register_with_challenge_as(
        &mut client,
        &kp_a,
        RegisterRequest {
            agent_id: Some(proto_a),
            name: "A".into(),
            framework: "custom".into(),
            version: "1.0.0".into(),
            risk_tier: 0,
            tool_names: vec![],
            public_key: kp_a.public_key_hex(),
            metadata: Default::default(),
            ..Default::default()
        },
    )
    .await
    .unwrap();

    // Register B (parent = A).
    let kp_b = aa_sdk_client::AgentKeypair::derive("chain-B");
    let proto_b = ProtoAgentId {
        org_id: org.into(),
        team_id: team.into(),
        agent_id: kp_b.did_key(),
    };
    register_with_challenge_as(
        &mut client,
        &kp_b,
        RegisterRequest {
            agent_id: Some(proto_b),
            name: "B".into(),
            framework: "custom".into(),
            version: "1.0.0".into(),
            risk_tier: 0,
            tool_names: vec![],
            public_key: kp_b.public_key_hex(),
            metadata: Default::default(),
            parent_agent_id: Some(kp_a.did_key()),
            ..Default::default()
        },
    )
    .await
    .unwrap();

    // Register C (parent = B). C's root_agent_id must equal A's key.
    let kp_c = aa_sdk_client::AgentKeypair::derive("chain-C");
    let proto_c = ProtoAgentId {
        org_id: org.into(),
        team_id: team.into(),
        agent_id: kp_c.did_key(),
    };
    let resp_c = register_with_challenge_as(
        &mut client,
        &kp_c,
        RegisterRequest {
            agent_id: Some(proto_c),
            name: "C".into(),
            framework: "custom".into(),
            version: "1.0.0".into(),
            risk_tier: 0,
            tool_names: vec![],
            public_key: kp_c.public_key_hex(),
            metadata: Default::default(),
            parent_agent_id: Some(kp_b.did_key()),
            ..Default::default()
        },
    )
    .await
    .unwrap()
    .into_inner();

    let c_root = resp_c.root_agent_id.expect("C must receive root_agent_id");
    assert_eq!(
        c_root.as_slice(),
        key_a.as_slice(),
        "C's root_agent_id must chain back to A"
    );
}

// ── TTL / sweep integration tests ─────────────────────────────────────────

/// Shared helper: start a server with an audit channel wired in.
/// Returns (addr, registry, audit_rx).
async fn start_server_with_audit() -> (
    SocketAddr,
    Arc<AgentRegistry>,
    tokio::sync::mpsc::Receiver<aa_core::AuditEntry>,
) {
    let registry = Arc::new(AgentRegistry::new());
    let (audit_tx, audit_rx) = tokio::sync::mpsc::channel::<aa_core::AuditEntry>(64);
    let service = AgentLifecycleServiceImpl::new(Arc::clone(&registry)).with_audit_tx(audit_tx);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);
        Server::builder()
            .add_service(AgentLifecycleServiceServer::new(service))
            .serve_with_incoming(incoming)
            .await
            .unwrap();
    });

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    (addr, registry, audit_rx)
}

/// Helper: build a minimal AgentRecord with controllable registered_at.
fn aged_record_for_test(
    agent_key: [u8; 16],
    team_id: &str,
    registered_at: chrono::DateTime<chrono::Utc>,
) -> aa_gateway::AgentRecord {
    use std::collections::BTreeMap;
    aa_gateway::AgentRecord {
        agent_id: agent_key,
        name: "ttl-test-agent".into(),
        framework: "test".into(),
        version: "0.0.1".into(),
        risk_tier: 0,
        tool_names: vec![],
        public_key: test_ed25519_public_key_hex(),
        credential_token: "sweep-test-token".into(),
        metadata: BTreeMap::new(),
        registered_at,
        last_heartbeat: registered_at,
        status: aa_gateway::AgentStatus::Active,
        pid: None,
        session_count: 0,
        last_event: None,
        policy_violations_count: 0,
        active_sessions: vec![],
        recent_events: Default::default(),
        recent_traces: vec![],
        layer: None,
        governance_level: aa_core::GovernanceLevel::default(),
        parent_agent_id: None,
        team_id: Some(team_id.to_owned()),
        depth: 0,
        delegation_reason: None,
        spawned_by_tool: None,
        root_agent_id: Some(agent_key),
        children: vec![],
        parent_key: None,
        enforcement_mode: None,
        org_id: None,
    }
}

/// Heartbeat triggers sweep and deregisters agents past max_agent_age.
#[tokio::test]
async fn heartbeat_triggers_sweep_and_deregisters_aged_agent() {
    use aa_gateway::registry::convert::proto_agent_id_to_key;

    let (addr, registry, _audit_rx) = start_server_with_audit().await;
    let mut client = AgentLifecycleServiceClient::connect(format!("http://{addr}"))
        .await
        .unwrap();

    // Insert an agent registered 2 hours ago; max age is 1 hour.
    let proto_id = ProtoAgentId {
        org_id: "org-sweep".into(),
        team_id: "team-sweep".into(),
        agent_id: "aged-agent".into(),
    };
    let agent_key = proto_agent_id_to_key(&proto_id);
    let registered_at = chrono::Utc::now() - chrono::Duration::hours(2);
    let record = aged_record_for_test(agent_key, "team-sweep", registered_at);
    registry.register(record).unwrap();
    registry.set_team_max_age("team-sweep", 3600); // 1 hour

    // Send a heartbeat on behalf of the aged agent. This triggers sweep.
    client
        .heartbeat(HeartbeatRequest {
            agent_id: Some(proto_id.clone()),
            credential_token: "sweep-test-token".into(),
            active_runs: 0,
            actions_count: 0,
        })
        .await
        .unwrap();

    // After the heartbeat, the agent must be Deregistered.
    assert_eq!(
        registry.get(&agent_key).unwrap().status,
        aa_gateway::AgentStatus::Deregistered,
        "aged agent must be deregistered by sweep during heartbeat"
    );
}

/// Heartbeat sweep emits AgentForceDeregistered audit entry for each evicted agent.
#[tokio::test]
async fn heartbeat_sweep_emits_audit_event_for_aged_agent() {
    use aa_core::AuditEventType;
    use aa_gateway::registry::convert::proto_agent_id_to_key;

    let (addr, registry, mut audit_rx) = start_server_with_audit().await;
    let mut client = AgentLifecycleServiceClient::connect(format!("http://{addr}"))
        .await
        .unwrap();

    let proto_id = ProtoAgentId {
        org_id: "org-audit".into(),
        team_id: "team-audit".into(),
        agent_id: "audit-aged-agent".into(),
    };
    let agent_key = proto_agent_id_to_key(&proto_id);
    let registered_at = chrono::Utc::now() - chrono::Duration::hours(3);
    let record = aged_record_for_test(agent_key, "team-audit", registered_at);
    registry.register(record).unwrap();
    registry.set_team_max_age("team-audit", 3600); // 1 hour

    client
        .heartbeat(HeartbeatRequest {
            agent_id: Some(proto_id),
            credential_token: "sweep-test-token".into(),
            active_runs: 0,
            actions_count: 0,
        })
        .await
        .unwrap();

    // Expect exactly one AgentForceDeregistered audit entry.
    let entry = tokio::time::timeout(std::time::Duration::from_secs(1), audit_rx.recv())
        .await
        .expect("timeout waiting for audit entry")
        .expect("audit channel closed");

    assert_eq!(
        entry.event_type(),
        AuditEventType::AgentForceDeregistered,
        "expected AgentForceDeregistered event"
    );
    assert!(
        entry.payload().contains("age_exceeded"),
        "payload must include reason: {}",
        entry.payload()
    );
}

#[tokio::test]
async fn root_agent_id_when_parent_unknown_returns_invalid_argument() {
    let (addr, _registry) = start_server().await;
    let mut client = AgentLifecycleServiceClient::connect(format!("http://{addr}"))
        .await
        .unwrap();

    let err = register_with_challenge(
        &mut client,
        RegisterRequest {
            agent_id: Some(ProtoAgentId {
                org_id: "unknown-org".into(),
                team_id: "unknown-team".into(),
                agent_id: test_keypair().did_key(),
            }),
            name: "orphan".into(),
            framework: "custom".into(),
            version: "1.0.0".into(),
            risk_tier: 0,
            tool_names: vec![],
            public_key: test_ed25519_public_key_hex(),
            metadata: Default::default(),
            parent_agent_id: Some("does-not-exist".into()),
            ..Default::default()
        },
    )
    .await
    .unwrap_err();

    assert_eq!(err.code(), tonic::Code::InvalidArgument);
    assert!(
        err.message().contains("parent_agent_id not found"),
        "error must name the problem: {}",
        err.message()
    );
}

#[tokio::test]
async fn register_drops_client_supplied_weaker_enforcement_mode() {
    // AAASM-4121 trust boundary: Register is the unauthenticated bootstrap path,
    // so a client-supplied enforcement_mode = OBSERVE (proto value 2) — which
    // would downgrade the agent's own Deny verdicts to audited Allow — must NOT
    // be persisted. It is dropped to None so the server-side default (Enforce)
    // governs. Supersedes the earlier AAASM-1557 storage contract that trusted
    // the client claim. A strengthening Enforce claim is still honored.
    use aa_proto::assembly::common::v1::EnforcementMode as ProtoMode;

    let (addr, registry) = start_server().await;
    let mut client = AgentLifecycleServiceClient::connect(format!("http://{addr}"))
        .await
        .unwrap();

    let proto_id = ProtoAgentId {
        org_id: "org-obs".into(),
        team_id: "team-obs".into(),
        agent_id: test_keypair().did_key(),
    };

    register_with_challenge(
        &mut client,
        RegisterRequest {
            agent_id: Some(proto_id.clone()),
            name: "experimental-agent".into(),
            framework: "custom".into(),
            version: "1.0.0".into(),
            risk_tier: 0,
            tool_names: vec![],
            public_key: test_ed25519_public_key_hex(),
            metadata: Default::default(),
            enforcement_mode: ProtoMode::Observe as i32,
            ..Default::default()
        },
    )
    .await
    .unwrap();

    // The client-supplied Observe downgrade must have been dropped: the record
    // carries no per-agent override, so resolution falls back to Enforce.
    let stored = registry
        .list()
        .into_iter()
        .find(|r| r.name == "experimental-agent")
        .expect("registered agent must be present in registry");
    assert_eq!(
        stored.enforcement_mode, None,
        "client-supplied Observe on self-registration must be dropped (AAASM-4121)"
    );
}

// ── AAASM-3866: server-nonce possession proof ────────────────────────────────
//
// The possession proof must sign a fresh, server-issued, single-use nonce — not
// the public, deterministic agent_id. These tests drive the raw client so they
// can submit stale/replayed/unknown/wrong nonces the `register_with_challenge`
// helper would never produce.

async fn connect(addr: SocketAddr) -> AgentLifecycleServiceClient<Channel> {
    AgentLifecycleServiceClient::connect(format!("http://{addr}"))
        .await
        .unwrap()
}

/// Sign `payload` with the test key and return the raw 64-byte proof.
fn sign(payload: &[u8]) -> Vec<u8> {
    test_keypair().sign(payload).to_vec()
}

#[tokio::test]
async fn register_with_fresh_challenge_response_succeeds() {
    let (addr, _registry) = start_server().await;
    let mut client = connect(addr).await;

    let resp = register_with_challenge(
        &mut client,
        RegisterRequest {
            agent_id: Some(test_agent_id()),
            name: "nonce-ok-agent".into(),
            framework: "custom".into(),
            version: "1.0.0".into(),
            public_key: test_ed25519_public_key_hex(),
            ..Default::default()
        },
    )
    .await
    .expect("a fresh valid challenge-response must mint a credential_token")
    .into_inner();

    assert!(!resp.credential_token.is_empty());
}

#[tokio::test]
async fn register_without_nonce_is_rejected() {
    // No RequestChallenge round-trip. Signing the public agent_id (the old,
    // attacker-derivable challenge) must NOT be accepted any more.
    let (addr, _registry) = start_server().await;
    let mut client = connect(addr).await;
    let agent_id = test_agent_id();

    let status = client
        .register(RegisterRequest {
            agent_id: Some(agent_id.clone()),
            name: "no-nonce-agent".into(),
            framework: "custom".into(),
            version: "1.0.0".into(),
            public_key: test_ed25519_public_key_hex(),
            possession_proof: sign(agent_id.agent_id.as_bytes()),
            registration_nonce: vec![],
            ..Default::default()
        })
        .await
        .unwrap_err();

    assert_eq!(status.code(), tonic::Code::Unauthenticated);
}

#[tokio::test]
async fn register_with_unknown_nonce_is_rejected() {
    // A nonce the server never issued — even with a proof that signs it.
    let (addr, _registry) = start_server().await;
    let mut client = connect(addr).await;
    let bogus = vec![9u8; 32];

    let status = client
        .register(RegisterRequest {
            agent_id: Some(test_agent_id()),
            name: "unknown-nonce-agent".into(),
            framework: "custom".into(),
            version: "1.0.0".into(),
            public_key: test_ed25519_public_key_hex(),
            possession_proof: sign(&bogus),
            registration_nonce: bogus,
            ..Default::default()
        })
        .await
        .unwrap_err();

    assert_eq!(status.code(), tonic::Code::Unauthenticated);
}

#[tokio::test]
async fn register_proof_over_a_different_value_than_the_issued_nonce_is_rejected() {
    // Obtain a real, server-issued nonce but sign something else.
    let (addr, _registry) = start_server().await;
    let mut client = connect(addr).await;
    let agent_id = test_agent_id();
    let public_key = test_ed25519_public_key_hex();

    let challenge = client
        .request_challenge(ChallengeRequest {
            agent_id: Some(agent_id.clone()),
            public_key: public_key.clone(),
        })
        .await
        .unwrap()
        .into_inner();

    let status = client
        .register(RegisterRequest {
            agent_id: Some(agent_id),
            name: "wrong-proof-agent".into(),
            framework: "custom".into(),
            version: "1.0.0".into(),
            public_key,
            // Proof over a value that is NOT the issued nonce.
            possession_proof: sign(b"not-the-issued-nonce"),
            registration_nonce: challenge.nonce,
            ..Default::default()
        })
        .await
        .unwrap_err();

    assert_eq!(status.code(), tonic::Code::Unauthenticated);
}

// ── AAASM-4032: tenanted registration invariant ──────────────────────────────
//
// Under the default Untenanted posture, a team-less agent registers exactly as
// before. Under Tenanted, registration requires a non-empty team_id — a team-
// less agent is rejected with FailedPrecondition, while an agent that carries a
// team registers normally.

/// Build a well-formed RegisterRequest for `agent_id`, leaving the
/// possession-proof fields for `register_with_challenge` to populate.
fn register_req(agent_id: ProtoAgentId, name: &str) -> RegisterRequest {
    RegisterRequest {
        agent_id: Some(agent_id),
        name: name.into(),
        framework: "custom".into(),
        version: "1.0.0".into(),
        risk_tier: 0,
        tool_names: vec![],
        public_key: test_ed25519_public_key_hex(),
        metadata: Default::default(),
        ..Default::default()
    }
}

#[tokio::test]
async fn untenanted_default_accepts_team_less_registration() {
    let (addr, _registry) = start_server_with_tenancy(aa_gateway::service::TenancyMode::Untenanted).await;
    let mut client = connect(addr).await;

    let resp = register_with_challenge(
        &mut client,
        register_req(
            ProtoAgentId {
                org_id: "org-untenanted".into(),
                team_id: String::new(),
                agent_id: test_keypair().did_key(),
            },
            "team-less-untenanted",
        ),
    )
    .await
    .expect("untenanted posture must accept a team-less agent")
    .into_inner();

    assert!(!resp.credential_token.is_empty());
    assert_eq!(resp.team_id, None, "team-less agent normalizes team_id to None");
}

#[tokio::test]
async fn tenanted_rejects_team_less_registration() {
    let (addr, _registry) = start_server_with_tenancy(aa_gateway::service::TenancyMode::Tenanted).await;
    let mut client = connect(addr).await;

    let status = register_with_challenge(
        &mut client,
        register_req(
            ProtoAgentId {
                org_id: "org-tenanted".into(),
                team_id: String::new(),
                agent_id: test_keypair().did_key(),
            },
            "team-less-tenanted",
        ),
    )
    .await
    .unwrap_err();

    assert_eq!(status.code(), tonic::Code::FailedPrecondition);
    assert!(
        status.message().contains("team_id"),
        "error must name the missing team_id: {}",
        status.message()
    );
}

#[tokio::test]
async fn tenanted_accepts_registration_with_team() {
    let (addr, _registry) = start_server_with_tenancy(aa_gateway::service::TenancyMode::Tenanted).await;
    let mut client = connect(addr).await;

    let resp = register_with_challenge(
        &mut client,
        register_req(
            ProtoAgentId {
                org_id: "org-tenanted".into(),
                team_id: "team-alpha".into(),
                agent_id: test_keypair().did_key(),
            },
            "teamed-tenanted",
        ),
    )
    .await
    .expect("tenanted posture must accept an agent that carries a team")
    .into_inner();

    assert!(!resp.credential_token.is_empty());
    assert_eq!(resp.team_id, Some("team-alpha".into()));
}

#[tokio::test]
async fn register_with_a_replayed_nonce_is_rejected() {
    // A nonce is single-use: the first register consumes it; a replay (same
    // nonce + proof) must fail as Unauthenticated, not surface AlreadyExists.
    let (addr, _registry) = start_server().await;
    let mut client = connect(addr).await;
    let agent_id = test_agent_id();
    let public_key = test_ed25519_public_key_hex();

    let challenge = client
        .request_challenge(ChallengeRequest {
            agent_id: Some(agent_id.clone()),
            public_key: public_key.clone(),
        })
        .await
        .unwrap()
        .into_inner();

    let req = RegisterRequest {
        agent_id: Some(agent_id),
        name: "replay-agent".into(),
        framework: "custom".into(),
        version: "1.0.0".into(),
        public_key,
        possession_proof: sign(&challenge.nonce),
        registration_nonce: challenge.nonce,
        ..Default::default()
    };

    client
        .register(req.clone())
        .await
        .expect("first register with a fresh nonce must succeed");

    let status = client.register(req).await.unwrap_err();
    assert_eq!(status.code(), tonic::Code::Unauthenticated);
}
