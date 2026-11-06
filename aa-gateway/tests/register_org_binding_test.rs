//! AAASM-6444 — an agent's organization comes from an authenticated binding, not
//! from the `agent_id.org_id` the client sends.
//!
//! Drives the real `AgentLifecycleService.Register` over gRPC with an
//! operator key store holding two org-bound keys and one unbound non-admin key,
//! then reads the result back through the registry and the event audit path.

use std::net::SocketAddr;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;

use aa_auth::api_key::{ApiKey, ApiKeyEntry, ApiKeyStore};
use aa_auth::scope::Scope;
use aa_core::AuditEntry;
use aa_gateway::iam::VerifiedCaller;
use aa_gateway::registry::convert::proto_agent_id_to_key;
use aa_gateway::registry::AgentRegistry;
use aa_gateway::service::org_binding::{OrgBinder, REGISTRATION_KEY_METADATA_KEY};
use aa_gateway::service::{AgentLifecycleServiceImpl, AuditServiceImpl};
use aa_proto::assembly::agent::v1::agent_lifecycle_service_client::AgentLifecycleServiceClient;
use aa_proto::assembly::agent::v1::agent_lifecycle_service_server::AgentLifecycleServiceServer;
use aa_proto::assembly::agent::v1::{ChallengeRequest, RegisterRequest, RegisterResponse};
use aa_proto::assembly::audit::v1::audit_service_server::AuditService;
use aa_proto::assembly::audit::v1::{AuditEvent, ReportEventsRequest};
use aa_proto::assembly::common::v1::AgentId as ProtoAgentId;
use aa_sdk_client::AgentKeypair;
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tonic::transport::{Channel, Server};
use tonic::{Code, Request};

struct Keys {
    acme: String,
    globex: String,
    unbound_plain: String,
}

fn entry(org: Option<&str>, scopes: Vec<Scope>) -> (String, ApiKeyEntry) {
    let key = ApiKey::generate();
    let e = ApiKeyEntry {
        id: uuid::Uuid::new_v4().to_string(),
        key_hash: key.hash().unwrap(),
        scopes,
        created_at: 0,
        expires_at: None,
        label: None,
        team_id: None,
        org_id: org.map(str::to_owned),
        key_lookup: Some(key.lookup()),
    };
    (key.as_str().to_owned(), e)
}

async fn start() -> (SocketAddr, Arc<AgentRegistry>, Keys) {
    let (acme, e1) = entry(Some("acme"), vec![Scope::Read]);
    let (globex, e2) = entry(Some("globex"), vec![Scope::Read]);
    let (unbound_plain, e3) = entry(None, vec![Scope::Read]);
    let binder = OrgBinder::new(Arc::new(ApiKeyStore::from_entries(vec![e1, e2, e3])));

    let registry = Arc::new(AgentRegistry::new());
    let service = AgentLifecycleServiceImpl::new(Arc::clone(&registry)).with_org_binder(binder);
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
    (
        addr,
        registry,
        Keys {
            acme,
            globex,
            unbound_plain,
        },
    )
}

fn identity(name: &str, org: &str) -> (AgentKeypair, ProtoAgentId) {
    let kp = AgentKeypair::derive_transport_key(name);
    let id = ProtoAgentId {
        org_id: org.into(),
        team_id: "team-1".into(),
        agent_id: kp.did_key(),
    };
    (kp, id)
}

async fn register(
    addr: SocketAddr,
    kp: &AgentKeypair,
    id: &ProtoAgentId,
    key: Option<&str>,
) -> Result<RegisterResponse, tonic::Status> {
    let mut client: AgentLifecycleServiceClient<Channel> =
        AgentLifecycleServiceClient::connect(format!("http://{addr}"))
            .await
            .unwrap();
    let challenge = client
        .request_challenge(ChallengeRequest {
            agent_id: Some(id.clone()),
            public_key: kp.public_key_hex(),
        })
        .await?
        .into_inner();
    let req = RegisterRequest {
        agent_id: Some(id.clone()),
        name: "agent".into(),
        framework: "custom".into(),
        version: "1".into(),
        public_key: kp.public_key_hex(),
        possession_proof: kp.sign(&challenge.nonce).to_vec(),
        registration_nonce: challenge.nonce,
        ..Default::default()
    };
    let mut req = Request::new(req);
    if let Some(key) = key {
        req.metadata_mut()
            .insert(REGISTRATION_KEY_METADATA_KEY, key.parse().unwrap());
    }
    client.register(req).await.map(|r| r.into_inner())
}

fn org_of(registry: &AgentRegistry, id: &ProtoAgentId) -> Option<Option<String>> {
    registry.get(&proto_agent_id_to_key(id)).map(|r| r.org_id.clone())
}

/// Missing-org policy row 1: no credential and no org is the legacy org-less
/// registration, unchanged for OSS single-tenant use.
#[tokio::test]
async fn no_credential_and_no_org_registers_org_less() {
    let (addr, registry, _) = start().await;
    let (kp, id) = identity("legacy", "");
    let resp = register(addr, &kp, &id, None).await.expect("org-less registration");
    assert_eq!(resp.org_id, None);
    assert_eq!(org_of(&registry, &id), Some(None));
}

/// Missing-org policy row 2 (positive trace of the old hole): an org claim with
/// no credential used to be accepted verbatim; it is now refused and records nothing.
#[tokio::test]
async fn org_claim_without_credential_is_rejected_and_nothing_is_registered() {
    let (addr, registry, _) = start().await;
    let (kp, id) = identity("squatter", "globex");
    let err = register(addr, &kp, &id, None).await.unwrap_err();
    assert_eq!(err.code(), Code::PermissionDenied);
    assert!(org_of(&registry, &id).is_none());
}

#[tokio::test]
async fn bound_key_derives_org_and_echoes_it_and_the_record_is_keyed_by_it() {
    let (addr, registry, keys) = start().await;
    let (kp, sent) = identity("derived", "");
    let resp = register(addr, &kp, &sent, Some(&keys.acme)).await.expect("derived org");
    assert_eq!(resp.org_id.as_deref(), Some("acme"));

    let authoritative = ProtoAgentId {
        org_id: "acme".into(),
        ..sent.clone()
    };
    assert_eq!(org_of(&registry, &authoritative), Some(Some("acme".into())));
    assert!(
        org_of(&registry, &sent).is_none(),
        "no record under the org-less triple"
    );
}

#[tokio::test]
async fn bound_key_accepts_the_matching_claim() {
    let (addr, registry, keys) = start().await;
    let (kp, id) = identity("matching", "acme");
    let resp = register(addr, &kp, &id, Some(&keys.acme))
        .await
        .expect("matching claim");
    assert_eq!(resp.org_id.as_deref(), Some("acme"));
    assert_eq!(org_of(&registry, &id), Some(Some("acme".into())));
}

/// The spoof: a key bound to acme claiming globex is refused and registers nothing
/// under either org.
#[tokio::test]
async fn spoofed_org_for_a_bound_key_is_rejected() {
    let (addr, registry, keys) = start().await;
    let (kp, id) = identity("spoofer", "globex");
    let err = register(addr, &kp, &id, Some(&keys.acme)).await.unwrap_err();
    assert_eq!(err.code(), Code::PermissionDenied);
    assert!(org_of(&registry, &id).is_none());
    let as_acme = ProtoAgentId {
        org_id: "acme".into(),
        ..id
    };
    assert!(org_of(&registry, &as_acme).is_none());
}

#[tokio::test]
async fn invalid_key_is_unauthenticated_even_without_a_claim() {
    let (addr, _registry, _) = start().await;
    let (kp, id) = identity("bogus", "");
    let err = register(addr, &kp, &id, Some("aa_00000000000000000000000000000000"))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::Unauthenticated);
}

#[tokio::test]
async fn unbound_non_admin_key_cannot_assert_an_org_but_may_register_org_less() {
    let (addr, registry, keys) = start().await;
    let (kp, claiming) = identity("unbound-claim", "acme");
    let err = register(addr, &kp, &claiming, Some(&keys.unbound_plain))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::PermissionDenied);

    let (kp2, plain) = identity("unbound-plain", "");
    register(addr, &kp2, &plain, Some(&keys.unbound_plain))
        .await
        .expect("org-less ok");
    assert_eq!(org_of(&registry, &plain), Some(None));
}

/// team_id is never read as an organization.
#[tokio::test]
async fn team_id_is_not_promoted_to_org() {
    let (addr, registry, _) = start().await;
    let (kp, id) = identity("team-only", "");
    register(addr, &kp, &id, None).await.expect("team-only agent");
    assert_eq!(org_of(&registry, &id), Some(None));
}

/// Two organizations end to end at the gateway: each agent's *event* audit entry
/// carries its own org (the audit write path used to hardcode `org_id: None`),
/// and an org-less agent's entry carries none, so it never matches an org filter.
#[tokio::test]
async fn event_audit_entries_carry_the_bound_org_of_each_agent() {
    let (addr, registry, keys) = start().await;
    let (kp_a, id_a) = identity("audit-a", "");
    let (kp_g, id_g) = identity("audit-g", "");
    let (kp_l, id_l) = identity("audit-legacy", "");
    register(addr, &kp_a, &id_a, Some(&keys.acme)).await.unwrap();
    register(addr, &kp_g, &id_g, Some(&keys.globex)).await.unwrap();
    register(addr, &kp_l, &id_l, None).await.unwrap();

    let authoritative = |id: &ProtoAgentId, org: &str| ProtoAgentId {
        org_id: org.into(),
        ..id.clone()
    };
    let (tx, mut rx) = mpsc::channel::<AuditEntry>(16);
    let audit = AuditServiceImpl::new_with_registry(tx, Arc::new(AtomicU64::new(0)), [0u8; 32], Arc::clone(&registry));

    for (tag, id) in [
        ("acme", authoritative(&id_a, "acme")),
        ("globex", authoritative(&id_g, "globex")),
        ("legacy", id_l.clone()),
    ] {
        let mut req = Request::new(ReportEventsRequest {
            events: vec![AuditEvent {
                event_id: tag.into(),
                agent_id: Some(id.clone()),
                ..Default::default()
            }],
        });
        req.extensions_mut().insert(VerifiedCaller {
            agent_key: proto_agent_id_to_key(&id),
            team_id: Some("team-1".into()),
            org_id: (!id.org_id.is_empty()).then(|| id.org_id.clone()),
        });
        audit.report_events(req).await.expect("report_events");
    }

    let mut got = std::collections::BTreeMap::new();
    for _ in 0..3 {
        let e = rx.recv().await.expect("audit entry");
        let tag = serde_json::from_str::<serde_json::Value>(e.payload()).unwrap()["event_id"]
            .as_str()
            .unwrap()
            .to_owned();
        got.insert(tag, e.org_id().map(str::to_owned));
    }
    assert_eq!(got["acme"].as_deref(), Some("acme"));
    assert_eq!(got["globex"].as_deref(), Some("globex"));
    assert_eq!(got["legacy"], None);
}
