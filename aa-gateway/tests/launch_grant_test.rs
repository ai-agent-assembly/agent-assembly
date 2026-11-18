//! AAASM-6261 — the launch grant: a short-lived, launch-bound credential that
//! `aa-proxy` can hold INSTEAD of the agent's registration token.
//!
//! What is pinned, each with its paired control:
//!
//! * a grant is accepted by `CheckAction` and `BatchCheck` and binds the check to
//!   the registered agent (`BOUND`); the registration token works there too
//!   (control), and a request with neither is not bound;
//! * a grant is accepted by nothing else: the token interceptor that guards the
//!   approval/audit/topology/secrets services, `Heartbeat` and `Deregister` all
//!   refuse it, while the registration token passes (control);
//! * a forged, expired, revoked (deregistered), wrong-agent, doubled-up or
//!   post-restart grant is REFUSED as an identity failure, never evaluated as an
//!   asserted claim, and its response is never `BOUND`;
//! * minting needs the registration token; a grant cannot mint another grant.
//!
//! `BOUND` here means the holder presented a grant minted for that agent. None of
//! these tests, and nothing in the design, proves which process holds it.

use std::collections::{BTreeMap, VecDeque};
use std::io::Write;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use std::time::Duration;

use aa_core::{AuditEntry, GovernanceLevel};
use aa_gateway::iam::grpc_auth::{auth_interceptor, CREDENTIAL_METADATA_KEY};
use aa_gateway::registry::convert::proto_agent_id_to_key;
use aa_gateway::registry::store::AgentRecord;
use aa_gateway::registry::{AgentRegistry, AgentStatus, OrphanMode};
use aa_gateway::service::{AgentLifecycleServiceImpl, PolicyServiceImpl};
use aa_gateway::PolicyEngine;
use aa_proto::assembly::agent::v1::agent_lifecycle_service_server::AgentLifecycleService;
use aa_proto::assembly::agent::v1::{DeregisterRequest, HeartbeatRequest, MintLaunchGrantRequest};
use aa_proto::assembly::common::v1::{
    ActionType, AgentId as ProtoAgentId, AgentIdentityAssurance as Assurance, Decision,
};
use aa_proto::assembly::policy::v1::policy_service_server::PolicyService;
use aa_proto::assembly::policy::v1::{
    action_context::Action, ActionContext, BatchCheckRequest, CheckActionRequest, CheckActionResponse,
    NetworkCallContext,
};
use chrono::Utc;
use tokio::sync::mpsc;
use tonic::{Code, Request};

const POLICY: &str = "version: \"1\"\nnetwork:\n  allowlist:\n    - allowed.example\n";
const TOKEN_A: &str = "registration-token-a-synthetic";
const TOKEN_B: &str = "registration-token-b-synthetic";

fn triple(label: &str) -> ProtoAgentId {
    ProtoAgentId {
        org_id: String::new(),
        team_id: format!("team-{label}"),
        agent_id: format!("did:key:{label}"),
    }
}

fn record(id: &ProtoAgentId, token: &str) -> AgentRecord {
    AgentRecord {
        agent_id: proto_agent_id_to_key(id),
        name: id.agent_id.clone(),
        framework: "aasm-run".into(),
        version: "1".into(),
        risk_tier: 0,
        tool_names: vec![],
        public_key: "pk".into(),
        credential_token: token.into(),
        metadata: BTreeMap::new(),
        registered_at: Utc::now(),
        last_heartbeat: Utc::now(),
        status: AgentStatus::Active,
        pid: None,
        session_count: 0,
        last_event: None,
        active_sessions: vec![],
        recent_events: VecDeque::new(),
        recent_traces: vec![],
        layer: None,
        governance_level: GovernanceLevel::default(),
        parent_agent_id: None,
        team_id: Some(id.team_id.clone()),
        depth: 0,
        delegation_reason: None,
        spawned_by_tool: None,
        root_agent_id: None,
        children: vec![],
        parent_key: None,
        enforcement_mode: None,
        enforcement_mode_expires_at: None,
        org_id: None,
    }
}

struct Fixture {
    registry: Arc<AgentRegistry>,
    policy: PolicyServiceImpl,
    lifecycle: AgentLifecycleServiceImpl,
    audit: mpsc::Receiver<AuditEntry>,
    a: ProtoAgentId,
    b: ProtoAgentId,
}

fn fixture() -> Fixture {
    let mut file = tempfile::NamedTempFile::new().unwrap();
    write!(file, "{POLICY}").unwrap();
    file.flush().unwrap();
    let (alert_tx, _) = tokio::sync::broadcast::channel::<aa_gateway::budget::BudgetAlert>(64);
    let engine = Arc::new(PolicyEngine::load_from_file(file.path(), alert_tx).unwrap());
    let registry = Arc::new(AgentRegistry::new());
    let (a, b) = (triple("a"), triple("b"));
    registry.register(record(&a, TOKEN_A)).unwrap();
    registry.register(record(&b, TOKEN_B)).unwrap();
    let (audit_tx, audit) = mpsc::channel(4096);
    let policy = PolicyServiceImpl::with_registry(
        engine,
        Arc::clone(&registry),
        audit_tx,
        Arc::new(AtomicU64::new(0)),
        [0u8; 32],
    );
    let lifecycle = AgentLifecycleServiceImpl::new(Arc::clone(&registry));
    Fixture {
        registry,
        policy,
        lifecycle,
        audit,
        a,
        b,
    }
}

async fn mint(f: &Fixture, agent: &ProtoAgentId, token: &str) -> Result<String, tonic::Status> {
    f.lifecycle
        .mint_launch_grant(Request::new(MintLaunchGrantRequest {
            agent_id: Some(agent.clone()),
            credential_token: token.into(),
            launch_id: "launch-1".into(),
            ttl_sec: 0,
        }))
        .await
        .map(|r| r.into_inner().launch_grant)
}

fn network_request(agent: Option<ProtoAgentId>, token: &str, grant: &str, host: &str) -> CheckActionRequest {
    CheckActionRequest {
        agent_id: agent,
        credential_token: token.into(),
        trace_id: String::new(),
        span_id: String::new(),
        action_type: ActionType::NetworkCall as i32,
        context: Some(ActionContext {
            action: Some(Action::NetworkCall(NetworkCallContext {
                host: host.into(),
                port: 443,
                protocol: "https".into(),
                in_allowlist: false,
            })),
        }),
        caller_agent_id: None,
        launch_grant: grant.into(),
    }
}

async fn check(f: &Fixture, req: CheckActionRequest) -> CheckActionResponse {
    f.policy.check_action(Request::new(req)).await.unwrap().into_inner()
}

fn assert_refused_not_bound(r: &CheckActionResponse, what: &str) {
    assert_eq!(r.decision, Decision::Deny as i32, "{what}: {r:?}");
    assert_eq!(r.policy_rule, "a2a_identity_verification", "{what}: {r:?}");
    assert_ne!(
        r.agent_identity_assurance,
        Assurance::Bound as i32,
        "{what}: never bound"
    );
}

/// The grant binds a check to its agent on CheckAction, with a paired allow/deny
/// by policy; the registration token gives the same answer (control).
#[tokio::test]
async fn a_grant_binds_a_check_action_and_the_registration_token_is_the_control() {
    let f = fixture();
    let grant = mint(&f, &f.a, TOKEN_A).await.expect("mint");

    let allowed = check(&f, network_request(Some(f.a.clone()), "", &grant, "allowed.example")).await;
    assert_eq!(allowed.decision, Decision::Allow as i32, "{allowed:?}");
    assert_eq!(allowed.agent_identity_assurance, Assurance::Bound as i32);
    let denied = check(&f, network_request(Some(f.a.clone()), "", &grant, "denied.example")).await;
    assert_eq!(denied.decision, Decision::Deny as i32);
    assert_eq!(denied.agent_identity_assurance, Assurance::Bound as i32);

    let by_token = check(&f, network_request(Some(f.a.clone()), TOKEN_A, "", "allowed.example")).await;
    assert_eq!(by_token.decision, Decision::Allow as i32);
    assert_eq!(by_token.agent_identity_assurance, Assurance::Bound as i32);

    let neither = check(
        &f,
        network_request(Some(ProtoAgentId::default()), "", "", "allowed.example"),
    )
    .await;
    assert_ne!(neither.agent_identity_assurance, Assurance::Bound as i32);
}

#[tokio::test]
async fn a_grant_binds_a_batch_check_entry_and_a_bad_entry_does_not_taint_its_neighbour() {
    let f = fixture();
    let grant = mint(&f, &f.a, TOKEN_A).await.unwrap();
    let batch = BatchCheckRequest {
        requests: vec![
            network_request(Some(f.a.clone()), "", &grant, "allowed.example"),
            network_request(Some(f.a.clone()), "", "forged-grant", "allowed.example"),
            network_request(Some(f.a.clone()), "", &grant, "denied.example"),
        ],
    };
    let responses = f
        .policy
        .batch_check(Request::new(batch))
        .await
        .unwrap()
        .into_inner()
        .responses;
    assert_eq!(responses.len(), 3);
    assert_eq!(responses[0].decision, Decision::Allow as i32);
    assert_eq!(responses[0].agent_identity_assurance, Assurance::Bound as i32);
    assert_refused_not_bound(&responses[1], "forged grant in a batch");
    assert_eq!(responses[2].decision, Decision::Deny as i32);
    assert_eq!(responses[2].agent_identity_assurance, Assurance::Bound as i32);
}

/// Every way a presented grant can be wrong is a refusal. The positive control
/// runs first so a refusal cannot be an artifact of the fixture.
#[tokio::test]
async fn a_wrong_expired_revoked_or_forged_grant_is_refused_and_never_bound() {
    let mut f = fixture();
    let grant_a = mint(&f, &f.a, TOKEN_A).await.unwrap();
    let grant_b = mint(&f, &f.b, TOKEN_B).await.unwrap();
    assert_eq!(
        check(&f, network_request(Some(f.a.clone()), "", &grant_a, "allowed.example"))
            .await
            .agent_identity_assurance,
        Assurance::Bound as i32,
        "positive control"
    );

    assert_refused_not_bound(
        &check(&f, network_request(Some(f.a.clone()), "", &grant_b, "allowed.example")).await,
        "B's grant on A's triple",
    );
    assert_refused_not_bound(
        &check(
            &f,
            network_request(Some(f.a.clone()), "", "guessed-grant", "allowed.example"),
        )
        .await,
        "forged grant",
    );
    assert_refused_not_bound(
        &check(
            &f,
            network_request(Some(f.a.clone()), TOKEN_A, &grant_a, "allowed.example"),
        )
        .await,
        "grant and token together",
    );
    assert_refused_not_bound(
        &check(
            &f,
            network_request(Some(ProtoAgentId::default()), "", &grant_a, "allowed.example"),
        )
        .await,
        "grant with no claimed agent",
    );
    assert_refused_not_bound(
        &check(&f, network_request(Some(f.a.clone()), "", TOKEN_A, "allowed.example")).await,
        "the registration token presented in the grant field",
    );

    // Expiry.
    let (short, _) = f
        .registry
        .mint_launch_grant(&proto_agent_id_to_key(&f.a), "launch-short", Duration::from_millis(200))
        .unwrap();
    tokio::time::sleep(Duration::from_millis(800)).await;
    assert_refused_not_bound(
        &check(&f, network_request(Some(f.a.clone()), "", &short, "allowed.example")).await,
        "expired grant",
    );

    // Revocation by deregistration of the agent.
    let key_b = proto_agent_id_to_key(&f.b);
    f.registry.deregister(&key_b, OrphanMode::Suspend).unwrap();
    assert_refused_not_bound(
        &check(&f, network_request(Some(f.b.clone()), "", &grant_b, "allowed.example")).await,
        "grant of a deregistered agent",
    );

    // Each refusal left impersonation evidence, and the evidence never says bound.
    let mut seen = 0;
    while let Ok(Some(entry)) = tokio::time::timeout(Duration::from_millis(100), f.audit.recv()).await {
        let p: serde_json::Value = serde_json::from_str(entry.payload()).unwrap();
        if entry.event_type() == aa_core::AuditEventType::A2AImpersonationAttempted {
            assert_ne!(p["agent_identity_assurance"], "bound", "{p}");
            assert_eq!(p["launch_grant_present"], true, "{p}");
            seen += 1;
        }
    }
    // Seven refusals, five audited: the second and third benign refusals for the same
    // claimed agent (the registration token in the grant field, and the expired grant)
    // fall inside the benign-refusal throttle window after the forged-grant one.
    assert_eq!(
        seen, 5,
        "non-benign refusals always, benign ones once per agent per window"
    );
}

/// Grants are held in memory only. A restarted gateway has the agent (it
/// re-registers) but not the grant, so the previous process's grant is refused and
/// the proxy holding it denies until the launch is started again. The second
/// fixture is a fresh registry with the same agents re-registered, which is what a
/// restarted gateway's state is; no part of this test claims to restart a process.
#[tokio::test]
async fn a_gateway_instance_that_did_not_mint_a_grant_does_not_recognise_it() {
    let f = fixture();
    let grant = mint(&f, &f.a, TOKEN_A).await.unwrap();
    let restarted = fixture();
    let r = check(
        &restarted,
        network_request(Some(f.a.clone()), "", &grant, "allowed.example"),
    )
    .await;
    assert_refused_not_bound(&r, "grant minted by the previous gateway state");
}

/// A refusal's own answer tells the holder nothing about WHY: a valid grant for a
/// different agent reads exactly like a forged one. The cause is in the audit.
#[tokio::test]
async fn every_grant_refusal_gives_the_caller_the_same_reason() {
    let f = fixture();
    let grant_b = mint(&f, &f.b, TOKEN_B).await.unwrap();
    let wrong_agent = check(&f, network_request(Some(f.a.clone()), "", &grant_b, "allowed.example")).await;
    let forged = check(&f, network_request(Some(f.a.clone()), "", "forged", "allowed.example")).await;
    assert_eq!(wrong_agent.reason, forged.reason);
}

/// A request carrying a valid token AND a valid grant is refused, and the refusal
/// itself is never stamped BOUND in the response.
#[tokio::test]
async fn a_token_and_a_grant_together_are_refused_and_the_refusal_is_not_bound() {
    let f = fixture();
    let grant = mint(&f, &f.a, TOKEN_A).await.unwrap();
    let r = check(
        &f,
        network_request(Some(f.a.clone()), TOKEN_A, &grant, "allowed.example"),
    )
    .await;
    assert_refused_not_bound(&r, "valid token and valid grant");
}

/// The grant is not written into the audit chain.
#[tokio::test]
async fn the_grant_never_appears_in_gateway_audit_entries() {
    let mut f = fixture();
    let grant = mint(&f, &f.a, TOKEN_A).await.unwrap();
    check(&f, network_request(Some(f.a.clone()), "", &grant, "allowed.example")).await;
    check(&f, network_request(Some(f.b.clone()), "", &grant, "allowed.example")).await;
    let mut entries = 0;
    while let Ok(Some(e)) = tokio::time::timeout(Duration::from_millis(150), f.audit.recv()).await {
        assert!(!e.payload().contains(&grant), "the grant is in an audit payload");
        entries += 1;
    }
    assert_eq!(
        entries, 2,
        "control: both the allowed and the refused request were audited"
    );
}

/// Repeated refusals of an expired grant (a launch that outlived it keeps retrying)
/// are audited once per window, not once per request.
#[tokio::test]
async fn repeated_benign_refusals_are_audited_once_per_window() {
    let mut f = fixture();
    for _ in 0..5 {
        let r = check(
            &f,
            network_request(Some(f.a.clone()), "", "expired-or-lost-grant", "allowed.example"),
        )
        .await;
        assert_refused_not_bound(&r, "unknown grant");
    }
    let mut impersonations = 0;
    while let Ok(Some(e)) = tokio::time::timeout(Duration::from_millis(150), f.audit.recv()).await {
        if e.event_type() == aa_core::AuditEventType::A2AImpersonationAttempted {
            impersonations += 1;
        }
    }
    assert_eq!(impersonations, 1, "five identical benign refusals, one audit entry");

    // A non-benign refusal is never throttled.
    let grant_b = mint(&f, &f.b, TOKEN_B).await.unwrap();
    for _ in 0..3 {
        check(&f, network_request(Some(f.a.clone()), "", &grant_b, "allowed.example")).await;
    }
    let mut mismatches = 0;
    while let Ok(Some(e)) = tokio::time::timeout(Duration::from_millis(150), f.audit.recv()).await {
        let p: serde_json::Value = serde_json::from_str(e.payload()).unwrap();
        if p["refusal_detail"] == "launch grant bound to a different agent" {
            mismatches += 1;
        }
    }
    assert_eq!(mismatches, 3, "an agent-mismatch refusal is always audited");
}

/// Minting needs the registration token, and a grant cannot mint a grant.
#[tokio::test]
async fn only_the_registration_token_can_mint_a_grant() {
    let f = fixture();
    let grant = mint(&f, &f.a, TOKEN_A).await.expect("control: the token mints");
    for (what, agent, credential) in [
        ("a grant as the credential", &f.a, grant.as_str()),
        ("B's token for A", &f.a, TOKEN_B),
        ("no credential", &f.a, ""),
    ] {
        let err = mint(&f, agent, credential).await.expect_err(what);
        assert_eq!(err.code(), Code::Unauthenticated, "{what}");
    }
}

/// The grant authenticates to none of the services the registration token does.
/// The control in each case is the registration token passing the same gate.
#[tokio::test]
async fn no_other_service_accepts_a_grant_and_the_registration_token_is_the_control() {
    let f = fixture();
    let grant = mint(&f, &f.a, TOKEN_A).await.unwrap();

    // The interceptor in front of approval, audit, topology and secrets.
    let mut interceptor = auth_interceptor(Arc::clone(&f.registry));
    let with = |value: &str| {
        let mut req = Request::new(());
        req.metadata_mut()
            .insert(CREDENTIAL_METADATA_KEY, value.parse().unwrap());
        req
    };
    assert!(
        interceptor(with(TOKEN_A)).is_ok(),
        "control: the registration token passes"
    );
    assert_eq!(interceptor(with(&grant)).unwrap_err().code(), Code::Unauthenticated);

    // Heartbeat and Deregister authenticate by registration token.
    let beat = |token: &str| HeartbeatRequest {
        agent_id: Some(f.a.clone()),
        credential_token: token.into(),
        ..Default::default()
    };
    assert!(
        f.lifecycle.heartbeat(Request::new(beat(TOKEN_A))).await.is_ok(),
        "control"
    );
    assert_eq!(
        f.lifecycle
            .heartbeat(Request::new(beat(&grant)))
            .await
            .unwrap_err()
            .code(),
        Code::Unauthenticated
    );
    let err = f
        .lifecycle
        .deregister(Request::new(DeregisterRequest {
            agent_id: Some(f.a.clone()),
            credential_token: grant.clone(),
            reason: "a grant must not be able to end the registration".into(),
        }))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::Unauthenticated);
    assert!(
        f.registry.get(&proto_agent_id_to_key(&f.a)).is_some(),
        "the agent is still registered"
    );
}

#[test]
fn the_grant_lifetime_is_clamped() {
    use aa_gateway::service::lifecycle_service::launch_grant_ttl as ttl;
    assert_eq!(ttl(0), Duration::from_secs(8 * 3600));
    assert_eq!(ttl(-5), Duration::from_secs(8 * 3600));
    assert_eq!(ttl(1), Duration::from_secs(10));
    assert_eq!(ttl(60), Duration::from_secs(60));
    assert_eq!(ttl(10_000_000), Duration::from_secs(12 * 3600));
}
