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
    admin_unbound: String,
    revoked: String,
    acme_second: String,
    acme_expired: String,
    acme_team_a: String,
    acme_team_b: String,
    acme_read: String,
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

fn key_store() -> (Arc<ApiKeyStore>, Keys) {
    let (acme, e1) = entry(Some("acme"), vec![Scope::Write]);
    let (globex, e2) = entry(Some("globex"), vec![Scope::Write]);
    let (unbound_plain, e3) = entry(None, vec![Scope::Read]);
    let (admin_unbound, e4) = entry(None, vec![Scope::Admin]);
    let (revoked, e5) = entry(Some("acme"), vec![Scope::Write]);
    let revoked_id = e5.id.clone();
    let (acme_second, e6) = entry(Some("acme"), vec![Scope::Write]);
    let (acme_expired, mut e7) = entry(Some("acme"), vec![Scope::Write]);
    e7.expires_at = Some(1);
    let (acme_team_a, mut e8) = entry(Some("acme"), vec![Scope::Write]);
    e8.team_id = Some("team-a".into());
    let (acme_team_b, mut e9) = entry(Some("acme"), vec![Scope::Write]);
    e9.team_id = Some("team-b".into());
    let (acme_read, e10) = entry(Some("acme"), vec![Scope::Read]);
    let store = ApiKeyStore::from_entries(vec![e1, e2, e3, e4, e5, e6, e7, e8, e9, e10]);
    store.revoke(&revoked_id);
    (
        Arc::new(store),
        Keys {
            acme,
            globex,
            unbound_plain,
            admin_unbound,
            revoked,
            acme_second,
            acme_expired,
            acme_team_a,
            acme_team_b,
            acme_read,
        },
    )
}

/// Serve `Register` over `registry`, authorizing operator keys against `store`.
async fn serve(registry: Arc<AgentRegistry>, store: Arc<ApiKeyStore>) -> SocketAddr {
    let binder = OrgBinder::new(store);
    let service = AgentLifecycleServiceImpl::new(registry).with_org_binder(binder);
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
    addr
}

async fn start() -> (SocketAddr, Arc<AgentRegistry>, Keys) {
    let (store, keys) = key_store();
    let registry = Arc::new(AgentRegistry::new());
    let addr = serve(Arc::clone(&registry), store).await;
    (addr, registry, keys)
}

fn identity(name: &str, org: &str) -> (AgentKeypair, ProtoAgentId) {
    identity_in_team(name, org, "team-1")
}

fn identity_in_team(name: &str, org: &str, team: &str) -> (AgentKeypair, ProtoAgentId) {
    let kp = AgentKeypair::derive_transport_key(name);
    let id = ProtoAgentId {
        org_id: org.into(),
        team_id: team.into(),
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
    register_with_metadata(addr, kp, id, key, Default::default()).await
}

async fn register_with_metadata(
    addr: SocketAddr,
    kp: &AgentKeypair,
    id: &ProtoAgentId,
    key: Option<&str>,
    metadata: std::collections::HashMap<String, String>,
) -> Result<RegisterResponse, tonic::Status> {
    register_full(addr, kp, id, key, metadata, false).await
}

/// A registration from a client whose key is random and held by the agent
/// (`durable_identity_key`), as `aa-sdk-client` sends it. The plain helpers above
/// model a client that predates the flag.
async fn register_durable(
    addr: SocketAddr,
    kp: &AgentKeypair,
    id: &ProtoAgentId,
    key: Option<&str>,
) -> Result<RegisterResponse, tonic::Status> {
    register_full(addr, kp, id, key, Default::default(), true).await
}

async fn register_full(
    addr: SocketAddr,
    kp: &AgentKeypair,
    id: &ProtoAgentId,
    key: Option<&str>,
    metadata: std::collections::HashMap<String, String>,
    durable_identity_key: bool,
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
        metadata,
        durable_identity_key,
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

/// AAASM-6463 / SEC-E1: a key bound to acme at read scope (the `aa-keygen` default) is a
/// read-only REST credential. It is refused at Register whether or not an org is
/// claimed, and registers nothing; the same org at write scope (`keys.acme`) registers.
#[tokio::test]
async fn an_org_bound_read_scope_key_cannot_register_an_agent() {
    let (addr, registry, keys) = start().await;
    for (name, claimed) in [("read-derived", ""), ("read-claiming", "acme")] {
        let (kp, id) = identity(name, claimed);
        let err = register(addr, &kp, &id, Some(&keys.acme_read)).await.unwrap_err();
        assert_eq!(err.code(), Code::PermissionDenied, "{name}");
        let as_acme = ProtoAgentId {
            org_id: "acme".into(),
            ..id.clone()
        };
        assert!(org_of(&registry, &id).is_none(), "{name}");
        assert!(org_of(&registry, &as_acme).is_none(), "{name}");
    }
    let (kp, id) = identity("write-control", "acme");
    register(addr, &kp, &id, Some(&keys.acme))
        .await
        .expect("write scope registers");
    assert_eq!(org_of(&registry, &id), Some(Some("acme".into())));
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

/// AAASM-6444 review: `RegisterRequest.metadata` is client text. An org-less
/// registration that tags itself `org_id: victim` there must stay org-less in the
/// lineage every downstream consumer reads (CheckAction audit stamp, policy
/// cascade, sensitive-data scope).
#[tokio::test]
async fn client_metadata_org_tag_does_not_place_an_org_less_agent_in_an_org() {
    let (addr, registry, keys) = start().await;
    let tag: std::collections::HashMap<String, String> = [("org_id".to_string(), "globex".to_string())].into();

    let (kp, id) = identity("tagger", "");
    register_with_metadata(addr, &kp, &id, None, tag.clone())
        .await
        .expect("org-less registration");
    assert_eq!(registry.lineage(&proto_agent_id_to_key(&id)).unwrap().org_id, None);

    // Unbound non-admin key: still org-less, still untagged.
    let (kp2, id2) = identity("tagger-plain", "");
    register_with_metadata(addr, &kp2, &id2, Some(&keys.unbound_plain), tag.clone())
        .await
        .expect("unbound key, no claim");
    assert_eq!(registry.lineage(&proto_agent_id_to_key(&id2)).unwrap().org_id, None);

    // Positive control: a key-bound registration carries its bound org, whatever the metadata says.
    let (kp3, id3) = identity("tagger-bound", "");
    register_with_metadata(addr, &kp3, &id3, Some(&keys.acme), tag)
        .await
        .expect("bound");
    let bound = ProtoAgentId {
        org_id: "acme".into(),
        ..id3
    };
    assert_eq!(
        registry
            .lineage(&proto_agent_id_to_key(&bound))
            .unwrap()
            .org_id
            .as_deref(),
        Some("acme")
    );
}

/// Operator-authorised assertion end to end: an unbound admin key may register an
/// agent into an org it names; the record carries it.
#[tokio::test]
async fn unbound_admin_key_registers_into_the_org_it_names() {
    let (addr, registry, keys) = start().await;
    let (kp, id) = identity("operator-placed", "initech");
    let resp = register(addr, &kp, &id, Some(&keys.admin_unbound))
        .await
        .expect("admin assertion");
    assert_eq!(resp.org_id.as_deref(), Some("initech"));
    assert_eq!(org_of(&registry, &id), Some(Some("initech".into())));
}

/// A key revoked after boot (here: before the first request) is refused at
/// Register, with or without an org claim, and registers nothing.
#[tokio::test]
async fn revoked_key_is_unauthenticated_end_to_end() {
    let (addr, registry, keys) = start().await;
    for claim in ["", "acme"] {
        let (kp, id) = identity(&format!("revoked-{claim}"), claim);
        let err = register(addr, &kp, &id, Some(&keys.revoked)).await.unwrap_err();
        assert_eq!(err.code(), Code::Unauthenticated, "claim {claim:?}");
        assert!(org_of(&registry, &id).is_none());
    }
}

/// A garbled key header is not "no key": it is refused rather than downgraded to
/// an org-less registration.
#[tokio::test]
async fn blank_registration_key_header_is_refused_not_ignored() {
    let (addr, registry, _) = start().await;
    let (kp, id) = identity("blank-header", "");
    let err = register(addr, &kp, &id, Some("   ")).await.unwrap_err();
    assert_eq!(err.code(), Code::Unauthenticated);
    assert!(org_of(&registry, &id).is_none());
}

// ── AAASM-6447: a later process of an already-registered agent re-binds, and the
// re-bind never inherits, changes or widens an org ─────────────────────────────

/// A second process presenting the same org-bound key re-binds to the same agent:
/// same credential, same org (echoed), one record.
#[tokio::test]
async fn rebind_with_the_same_bound_key_keeps_the_org_and_the_credential() {
    let (addr, registry, keys) = start().await;
    let (kp, id) = identity("rebind-same-key", "");
    let first = register(addr, &kp, &id, Some(&keys.acme)).await.expect("first process");
    let second = register(addr, &kp, &id, Some(&keys.acme))
        .await
        .expect("second process re-binds");

    assert_eq!(second.credential_token, first.credential_token);
    assert_eq!(second.org_id.as_deref(), Some("acme"));
    let bound = ProtoAgentId {
        org_id: "acme".into(),
        ..id
    };
    assert_eq!(org_of(&registry, &bound), Some(Some("acme".into())));
    assert_eq!(registry.list().len(), 1, "one agent, not two");
}

/// The org binding runs before the re-bind: a later process that claims the org but
/// presents no key is refused exactly as in the registration table, and the bound
/// agent is untouched.
#[tokio::test]
async fn rebind_without_a_key_but_with_the_org_claim_is_refused() {
    let (addr, registry, keys) = start().await;
    let (kp, id) = identity("rebind-claim-no-key", "");
    let first = register(addr, &kp, &id, Some(&keys.acme)).await.expect("bound");
    let claimant = ProtoAgentId {
        org_id: "acme".into(),
        ..id.clone()
    };
    let err = register(addr, &kp, &claimant, None).await.unwrap_err();
    assert_eq!(err.code(), Code::PermissionDenied);

    let bound = ProtoAgentId {
        org_id: "acme".into(),
        ..id
    };
    let record = registry.get(&proto_agent_id_to_key(&bound)).expect("still there");
    assert_eq!(record.credential_token, first.credential_token);
    assert_eq!(record.org_id.as_deref(), Some("acme"));
}

/// A later process with no key and no claim, or with another org's key, is a
/// different registry key: it never receives the bound agent's credential or org, and
/// the bound agent keeps its own.
#[tokio::test]
async fn a_rebind_never_inherits_or_widens_an_org() {
    let (addr, registry, keys) = start().await;
    let (kp, id) = identity("rebind-no-widening", "");
    let acme = register(addr, &kp, &id, Some(&keys.acme)).await.expect("acme-bound");

    let org_less = register(addr, &kp, &id, None).await.expect("a separate org-less agent");
    assert_ne!(org_less.credential_token, acme.credential_token);
    assert_eq!(org_less.org_id, None);
    assert_eq!(org_of(&registry, &id), Some(None));

    let globex = register(addr, &kp, &id, Some(&keys.globex))
        .await
        .expect("a separate globex agent");
    assert_ne!(globex.credential_token, acme.credential_token);
    assert_eq!(globex.org_id.as_deref(), Some("globex"));

    let bound = ProtoAgentId {
        org_id: "acme".into(),
        ..id
    };
    let record = registry
        .get(&proto_agent_id_to_key(&bound))
        .expect("acme agent untouched");
    assert_eq!(record.credential_token, acme.credential_token);
    assert_eq!(record.org_id.as_deref(), Some("acme"));
}

// ── AAASM-6447: a re-bind is operator-authorized ──────────────────────────────
//
// A later process re-binds to an existing agent only when a validated operator
// key bound to the record's persisted organization is presented. Possession of
// the agent key proves who the agent is, not that the caller may take over its
// credential. Every refusal below is the same `AlreadyExists` a fresh duplicate
// gets, and none discloses the credential.

fn assert_plain_collision(err: &tonic::Status, existing_token: &str) {
    assert_eq!(err.code(), Code::AlreadyExists, "{err:?}");
    assert!(
        !err.message().contains(existing_token),
        "a refused re-bind must not disclose the credential"
    );
}

/// A second operator key bound to the same org is equally authorized.
#[tokio::test]
async fn rebind_with_another_key_of_the_same_org_returns_the_existing_credential() {
    let (addr, registry, keys) = start().await;
    let (kp, id) = identity("rebind-second-key", "");
    let first = register(addr, &kp, &id, Some(&keys.acme)).await.unwrap();
    let second = register(addr, &kp, &id, Some(&keys.acme_second)).await.unwrap();
    assert_eq!(second.credential_token, first.credential_token);
    assert_eq!(registry.list().len(), 1);
}

/// An identifier-only caller (no key, no claim) lands on the org-less registry
/// key, never the org-bound record: it gets its own agent and none of acme's
/// credential.
#[tokio::test]
async fn an_identifier_only_caller_never_receives_a_bound_agents_credential() {
    let (addr, _registry, keys) = start().await;
    let (kp, id) = identity("rebind-identifier-only", "");
    let acme = register(addr, &kp, &id, Some(&keys.acme)).await.unwrap();
    let bare = register(addr, &kp, &id, None).await.unwrap();
    assert_ne!(bare.credential_token, acme.credential_token);
    assert_eq!(bare.org_id, None);
}

/// Keys that fail validation get the binding's own codes and never reach the
/// registry: invalid, revoked and expired are `Unauthenticated`, another org's key
/// claiming this org is `PermissionDenied`, a claim with no key is
/// `PermissionDenied`.
#[tokio::test]
async fn a_rebind_by_a_missing_invalid_revoked_expired_or_other_org_key_is_refused_by_the_binding() {
    let (addr, registry, keys) = start().await;
    let (kp, id) = identity("rebind-bad-keys", "");
    let first = register(addr, &kp, &id, Some(&keys.acme)).await.unwrap();
    let claim = ProtoAgentId {
        org_id: "acme".into(),
        ..id.clone()
    };

    let cases: [(&str, Option<&str>, Code); 5] = [
        ("garbage key", Some("aa_not_a_real_key"), Code::Unauthenticated),
        ("revoked key", Some(keys.revoked.as_str()), Code::Unauthenticated),
        ("expired key", Some(keys.acme_expired.as_str()), Code::Unauthenticated),
        ("other org's key", Some(keys.globex.as_str()), Code::PermissionDenied),
        ("claim without a key", None, Code::PermissionDenied),
    ];
    for (label, key, code) in cases {
        let err = register(addr, &kp, &claim, key).await.unwrap_err();
        assert_eq!(err.code(), code, "{label}: {err:?}");
        assert!(!err.message().contains(&first.credential_token), "{label}");
    }
    let bound = ProtoAgentId {
        org_id: "acme".into(),
        ..id
    };
    assert_eq!(
        registry.get(&proto_agent_id_to_key(&bound)).unwrap().credential_token,
        first.credential_token
    );
}

/// A record with no organization has no one to authorize a re-bind: any later
/// registration of the same identifier, with or without a key that resolves to no
/// org, is a plain collision.
#[tokio::test]
async fn an_org_less_agent_is_never_rebound() {
    let (addr, registry, keys) = start().await;
    let (kp, id) = identity("rebind-org-less", "");
    let first = register(addr, &kp, &id, None).await.unwrap();

    for (label, key) in [
        ("no key", None),
        ("unbound plain key", Some(keys.unbound_plain.as_str())),
        ("unbound admin key", Some(keys.admin_unbound.as_str())),
    ] {
        let err = register(addr, &kp, &id, key)
            .await
            .expect_err(&format!("{label} must not re-bind an org-less agent"));
        assert_plain_collision(&err, &first.credential_token);
    }
    assert_eq!(registry.list().len(), 1);
}

/// An org claim is not an authorization: an unbound admin key asserting the org of
/// an existing record collides exactly as an org-less duplicate does, with the same
/// message, and an unbound non-admin key is refused by the binding.
#[tokio::test]
async fn an_org_claim_alone_never_authorizes_a_rebind() {
    let (addr, registry, keys) = start().await;
    let (kp, id) = identity("rebind-claim-only", "");
    let acme = register(addr, &kp, &id, Some(&keys.acme)).await.unwrap();
    let claim = ProtoAgentId {
        org_id: "acme".into(),
        ..id.clone()
    };

    let err = register(addr, &kp, &claim, Some(&keys.admin_unbound))
        .await
        .unwrap_err();
    assert_plain_collision(&err, &acme.credential_token);

    let (kp2, id2) = identity("rebind-claim-only-orgless", "");
    let orgless = register(addr, &kp2, &id2, None).await.unwrap();
    let dup = register(addr, &kp2, &id2, None).await.unwrap_err();
    assert_plain_collision(&dup, &orgless.credential_token);
    // The collision message names the registry id (AAASM-6416), so compare the
    // text each refusal is expected to carry, not the two ids to each other.
    let collision = |id: &ProtoAgentId| format!("agent already registered: {}", hex::encode(proto_agent_id_to_key(id)));
    let bound = ProtoAgentId {
        org_id: "acme".into(),
        ..id.clone()
    };
    assert_eq!(
        err.message(),
        collision(&bound),
        "a refused re-bind looks like a fresh collision"
    );
    assert_eq!(dup.message(), collision(&id2));

    let err = register(addr, &kp, &claim, Some(&keys.unbound_plain))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::PermissionDenied);
    let bound = ProtoAgentId {
        org_id: "acme".into(),
        ..id
    };
    assert_eq!(
        registry.get(&proto_agent_id_to_key(&bound)).unwrap().credential_token,
        acme.credential_token
    );
}

/// Concurrent authorized and unauthorized re-binds of one registered agent: every
/// authorized caller gets the one credential, every unauthorized one a plain
/// collision, and nobody gets a second record.
#[tokio::test(flavor = "multi_thread")]
async fn concurrent_rebinds_split_cleanly_by_authorization() {
    let (addr, registry, keys) = start().await;
    let (kp, id) = identity("rebind-parallel", "");
    let first = register(addr, &kp, &id, Some(&keys.acme)).await.unwrap();
    let claim = ProtoAgentId {
        org_id: "acme".into(),
        ..id.clone()
    };
    let kp = Arc::new(kp);

    let mut tasks = Vec::new();
    for i in 0..8 {
        let (kp, id, claim) = (Arc::clone(&kp), id.clone(), claim.clone());
        let (acme, admin) = (keys.acme.clone(), keys.admin_unbound.clone());
        tasks.push(tokio::spawn(async move {
            if i % 2 == 0 {
                (true, register(addr, &kp, &id, Some(&acme)).await)
            } else {
                (false, register(addr, &kp, &claim, Some(&admin)).await)
            }
        }));
    }
    for task in tasks {
        let (authorized, result) = task.await.unwrap();
        if authorized {
            assert_eq!(result.unwrap().credential_token, first.credential_token);
        } else {
            assert_plain_collision(&result.unwrap_err(), &first.credential_token);
        }
    }
    assert_eq!(registry.list().len(), 1);
}

/// Parallel FIRST registrations of one identifier under one bound key: exactly one
/// record results, every success carries its credential, and a caller that lost the
/// race gets either that credential (the winner had committed) or a retryable
/// `AlreadyExists` (it had not) - never a credential for a record that does not
/// exist.
#[tokio::test(flavor = "multi_thread")]
async fn parallel_first_registrations_never_hand_out_an_uncommitted_credential() {
    let (addr, registry, keys) = start().await;
    let (kp, id) = identity("rebind-parallel-first", "");
    let kp = Arc::new(kp);

    let mut tasks = Vec::new();
    for _ in 0..8 {
        let (kp, id, key) = (Arc::clone(&kp), id.clone(), keys.acme.clone());
        tasks.push(tokio::spawn(async move { register(addr, &kp, &id, Some(&key)).await }));
    }
    let mut tokens = std::collections::BTreeSet::new();
    for task in tasks {
        match task.await.unwrap() {
            Ok(resp) => {
                tokens.insert(resp.credential_token);
            }
            Err(status) => assert_eq!(status.code(), Code::AlreadyExists, "{status:?}"),
        }
    }
    let bound = ProtoAgentId {
        org_id: "acme".into(),
        ..id
    };
    let record = registry.get(&proto_agent_id_to_key(&bound)).expect("one record");
    assert_eq!(tokens.len(), 1, "every success shares one credential: {tokens:?}");
    assert!(tokens.contains(&record.credential_token));
    assert_eq!(registry.list().len(), 1);
}

/// AAASM-3139: a key confined to one team is not authorized for another team's
/// agent. Registered by an org-wide key, a team-b record can be re-bound by an
/// org-wide key or a key confined to team-b, never by a key confined to team-a,
/// even though that key sends `team_id = team-b` and so reaches the record.
#[tokio::test]
async fn a_key_confined_to_another_team_cannot_rebind_the_agent() {
    let (addr, registry, keys) = start().await;
    let (kp, id) = identity_in_team("rebind-team-scope", "", "team-b");
    let first = register(addr, &kp, &id, Some(&keys.acme)).await.unwrap();
    let bound = ProtoAgentId {
        org_id: "acme".into(),
        ..id.clone()
    };

    let err = register(addr, &kp, &id, Some(&keys.acme_team_a)).await.unwrap_err();
    assert_plain_collision(&err, &first.credential_token);
    let record = registry.get(&proto_agent_id_to_key(&bound)).expect("untouched");
    assert_eq!(record.credential_token, first.credential_token);
    assert_eq!(record.team_id.as_deref(), Some("team-b"));

    // Positive controls: the refusal above is the team scope, not the agent or the org.
    for (label, key) in [
        ("org-wide key", keys.acme.as_str()),
        ("key confined to the record's team", keys.acme_team_b.as_str()),
    ] {
        let again = register(addr, &kp, &id, Some(key))
            .await
            .unwrap_or_else(|e| panic!("{label} must re-bind: {e:?}"));
        assert_eq!(again.credential_token, first.credential_token, "{label}");
    }
    assert_eq!(registry.list().len(), 1);
}

// ---- AAASM-6447: an org-less agent re-binds by possession of its own key ----------
//
// A record created by a client that declared its key random and held
// (`durable_identity_key`) is re-bound by a later process that proves possession of
// that same key, with no operator key. The marker is read from the STORED record,
// never from the later request, so a record created without it can never be taken
// over by possession, whatever the later request claims.

fn key_of(id: &ProtoAgentId) -> [u8; 16] {
    proto_agent_id_to_key(id)
}

#[tokio::test]
async fn a_keyless_agent_process_restart_rebinds_to_the_same_record() {
    let (addr, registry, _) = start().await;
    let (kp, id) = identity("keyless-restart", "");
    let first = register_durable(addr, &kp, &id, None).await.unwrap();

    let later = register_durable(addr, &kp, &id, None)
        .await
        .expect("a later process holding the same key re-binds");
    assert_eq!(later.credential_token, first.credential_token);
    assert_eq!(later.org_id, None);
    assert_eq!(later.team_id, first.team_id);
    assert_eq!(registry.list().len(), 1, "one record, not a second agent");
    let record = registry.get(&key_of(&id)).unwrap();
    assert_eq!(record.org_id, None, "the record's org is not changed");
    assert_eq!(record.credential_token, first.credential_token);
}

/// Re-binding needs BOTH: the stored record carries the marker, and the later process
/// declares a held key itself. A client that does not (an old one, whose key may be
/// computable) is never re-bound onto a record, so a squatter who registered first
/// with a computable key and the flag set cannot hand it a credential the squatter
/// already holds.
#[tokio::test]
async fn a_later_process_that_does_not_declare_a_durable_key_is_not_rebound() {
    let (addr, registry, _) = start().await;
    let (kp, id) = identity("flag-both-sides", "");
    let first = register_durable(addr, &kp, &id, None).await.unwrap();
    let err = register(addr, &kp, &id, None)
        .await
        .expect_err("a process that does not declare a held key must not be re-bound");
    assert_plain_collision(&err, &first.credential_token);
    assert_eq!(registry.list().len(), 1);
}

/// A process that presents an operator key which resolves to no organization, and
/// claims none, is the same keyless caller: the credential that matters is the key
/// the agent holds, and an unbound key confers nothing at Register.
#[tokio::test]
async fn an_unbound_operator_key_with_no_claim_does_not_block_a_keyless_rebind() {
    let (addr, _, keys) = start().await;
    let (kp, id) = identity("keyless-unbound-key", "");
    let first = register_durable(addr, &kp, &id, None).await.unwrap();
    let later = register_durable(addr, &kp, &id, Some(&keys.unbound_plain))
        .await
        .unwrap();
    assert_eq!(later.credential_token, first.credential_token);
}

/// A record created WITHOUT the flag (a client that predates it, so its key may be
/// computable from a public identifier) is never re-bound by possession, and a later
/// request that carries the flag does not change that.
#[tokio::test]
async fn a_record_created_without_the_flag_is_never_rebound_even_if_a_later_request_claims_it() {
    let (addr, registry, _) = start().await;
    let (kp, id) = identity("unmarked-record", "");
    let first = register(addr, &kp, &id, None).await.unwrap();
    let err = register_durable(addr, &kp, &id, None).await.unwrap_err();
    assert_plain_collision(&err, &first.credential_token);
    assert_eq!(registry.list().len(), 1);
}

/// Knowing the victim's did is not enough: presenting it with the attacker's own
/// public key is refused by the did binding, and nothing about the record changes.
#[tokio::test]
async fn presenting_a_victims_did_with_another_key_obtains_no_credential() {
    let (addr, registry, _) = start().await;
    let (victim_kp, victim_id) = identity("keyless-victim", "");
    let first = register_durable(addr, &victim_kp, &victim_id, None).await.unwrap();
    let (attacker_kp, _) = identity("keyless-attacker", "");

    let err = register_durable(addr, &attacker_kp, &victim_id, None)
        .await
        .expect_err("the attacker does not hold the victim's key");
    assert_eq!(
        err.code(),
        Code::Unauthenticated,
        "the did binding must be what refuses a did presented with another key: {err:?}"
    );
    assert!(!err.message().contains(&first.credential_token), "{err:?}");
    assert_eq!(registry.list().len(), 1);
    assert_eq!(
        registry.get(&key_of(&victim_id)).unwrap().credential_token,
        first.credential_token
    );
}

/// Another key under the same label and team is another did, so it is another agent:
/// it registers on its own and the victim's record and credential are untouched.
#[tokio::test]
async fn another_key_under_the_same_label_is_a_separate_agent() {
    let (addr, registry, _) = start().await;
    let (kp, id) = identity("keyless-original", "");
    let first = register_durable(addr, &kp, &id, None).await.unwrap();
    let (other_kp, other_id) = identity("keyless-other-holder", "");
    let other = register_durable(addr, &other_kp, &other_id, None).await.unwrap();
    assert_ne!(other.credential_token, first.credential_token);
    assert_eq!(registry.list().len(), 2);
    assert_eq!(
        registry.get(&key_of(&id)).unwrap().credential_token,
        first.credential_token
    );
}

/// An organization merely asserted by an unbound admin key never authorizes a
/// re-bind, marked record or not.
#[tokio::test]
async fn an_org_asserted_by_an_unbound_admin_key_never_rebinds_a_marked_record() {
    let (addr, registry, keys) = start().await;
    let (kp, id) = identity("keyless-admin-claim", "");
    let acme = register_durable(addr, &kp, &id, Some(&keys.acme)).await.unwrap();
    let claim = ProtoAgentId {
        org_id: "acme".into(),
        ..id.clone()
    };
    let err = register_durable(addr, &kp, &claim, Some(&keys.admin_unbound))
        .await
        .unwrap_err();
    assert_plain_collision(&err, &acme.credential_token);
    assert_eq!(registry.list().len(), 1);
}

/// A keyless later process of an org-BOUND agent does not reach the bound record:
/// the registry identity includes the organization, so it is a separate org-less agent.
#[tokio::test]
async fn a_keyless_process_never_reaches_an_org_bound_marked_record() {
    let (addr, registry, keys) = start().await;
    let (kp, id) = identity("keyless-vs-bound", "");
    let bound = register_durable(addr, &kp, &id, Some(&keys.acme)).await.unwrap();
    let later = register_durable(addr, &kp, &id, None)
        .await
        .expect("a separate org-less agent registers on its own");
    assert_ne!(later.credential_token, bound.credential_token);
    assert_eq!(later.org_id, None);
    assert_eq!(registry.list().len(), 2);
    let acme_id = ProtoAgentId {
        org_id: "acme".into(),
        ..id.clone()
    };
    assert_eq!(
        registry.get(&key_of(&acme_id)).unwrap().credential_token,
        bound.credential_token
    );
}

/// A marked record that carries no public key, or one that carries an organization,
/// must never be handed out to a keyless caller by possession. (A record with a key
/// but no credential is the restart shape and is re-bound; see the restart tests.)
#[tokio::test]
async fn a_marked_record_without_a_key_or_with_an_org_is_never_rebound() {
    use aa_gateway::registry::OrphanMode;

    let (addr, registry, _) = start().await;
    for (label, strip) in [("no public key", 1u8), ("has an org", 2)] {
        let (kp, id) = identity(&format!("rehydrated-shape-{label}"), "");
        let first = register_durable(addr, &kp, &id, None).await.unwrap();
        let key = key_of(&id);
        let (mut record, _) = registry.deregister(&key, OrphanMode::Suspend).unwrap();
        match strip {
            1 => record.public_key = String::new(),
            _ => record.org_id = Some("acme".into()),
        }
        registry.register(record).unwrap();

        let err = register_durable(addr, &kp, &id, None)
            .await
            .expect_err(&format!("{label}: must not re-bind"));
        assert_plain_collision(&err, &first.credential_token);
    }
}

/// First registrations racing for one key: exactly one record, one credential.
#[tokio::test]
async fn racing_first_registrations_of_a_marked_agent_create_one_record() {
    let (addr, registry, _) = start().await;
    let (kp, id) = identity("keyless-race", "");
    let kp = Arc::new(kp);
    let mut tasks = Vec::new();
    for _ in 0..8 {
        let (kp, id) = (Arc::clone(&kp), id.clone());
        tasks.push(tokio::spawn(
            async move { register_durable(addr, &kp, &id, None).await },
        ));
    }
    let mut tokens = std::collections::HashSet::new();
    for t in tasks {
        match t.await.unwrap() {
            Ok(r) => {
                tokens.insert(r.credential_token);
            }
            Err(e) => assert_eq!(e.code(), Code::AlreadyExists, "{e:?}"),
        }
    }
    assert_eq!(tokens.len(), 1, "every success carries the one credential");
    assert_eq!(registry.list().len(), 1);
}

/// The marker is set only by the typed field: a client cannot plant it through the
/// free-form metadata and so make an unmarked record re-bindable.
#[tokio::test]
async fn the_marker_cannot_be_planted_through_request_metadata() {
    let (addr, registry, _) = start().await;
    let (kp, id) = identity("planted-marker", "");
    let planted = std::collections::HashMap::from([("aa.identity_key".to_string(), "durable/1".to_string())]);
    let first = register_with_metadata(addr, &kp, &id, None, planted).await.unwrap();
    assert_eq!(
        registry.get(&key_of(&id)).unwrap().metadata.get("aa.identity_key"),
        None
    );
    let err = register(addr, &kp, &id, None).await.unwrap_err();
    assert_plain_collision(&err, &first.credential_token);
}

// ---------------------------------------------------------------------------
// AAASM-6451 — re-registration after a gateway restart.
//
// A "restart" here is a second gateway over the same SQLite file: a fresh
// registry that rehydrates from storage, serving the same operator keys. The
// credential is never persisted, so a re-bound agent receives a new one.
// ---------------------------------------------------------------------------

use aa_gateway::registry::token::validate_token;
use aa_gateway::registry::OrphanMode;
use aa_gateway::storage::{open_sqlite_backend, StorageBackend};

async fn boot(db: &std::path::Path, store: &Arc<ApiKeyStore>) -> (SocketAddr, Arc<AgentRegistry>) {
    let storage: Arc<dyn StorageBackend> = open_sqlite_backend(db).await.expect("open storage");
    let registry = Arc::new(AgentRegistry::new().with_storage(storage));
    registry.rehydrate_from_storage().await.expect("rehydrate");
    let addr = serve(Arc::clone(&registry), Arc::clone(store)).await;
    (addr, registry)
}

/// The first gateway of a restart test, with its operator keys.
async fn first_boot(db: &std::path::Path) -> (SocketAddr, Arc<AgentRegistry>, Keys, Arc<ApiKeyStore>) {
    let (store, keys) = key_store();
    let (addr, registry) = boot(db, &store).await;
    (addr, registry, keys, store)
}

#[tokio::test]
async fn a_keyless_agent_rebinds_after_a_gateway_restart_with_a_new_credential() {
    let tmp = tempfile::tempdir().unwrap();
    let db = tmp.path().join("restart.db");
    let (addr1, _r1, _keys, store) = first_boot(&db).await;
    let (kp, id) = identity("restart-keyless", "");
    let first = register_durable(addr1, &kp, &id, None).await.unwrap();

    let (addr2, registry2) = boot(&db, &store).await;
    let record = registry2.get(&key_of(&id)).expect("rehydrated");
    assert_eq!(record.credential_token, "", "the credential is not persisted");
    assert!(
        validate_token(&registry2, &key_of(&id), "").is_err(),
        "a rehydrated record authenticates no token, empty included"
    );

    let again = register_durable(addr2, &kp, &id, None)
        .await
        .expect("the agent re-registers after the restart");
    assert!(!again.credential_token.is_empty());
    assert_ne!(
        again.credential_token, first.credential_token,
        "a new credential, not the old one"
    );
    assert_eq!(registry2.list().len(), 1, "one agent, the same record");
    assert!(validate_token(&registry2, &key_of(&id), &again.credential_token).is_ok());
    assert!(
        validate_token(&registry2, &key_of(&id), &first.credential_token).is_err(),
        "the pre-restart credential is rejected"
    );
    assert_eq!(
        registry2.find_by_credential_token(&again.credential_token),
        Some(key_of(&id)),
        "the new credential is indexed"
    );
}

#[tokio::test]
async fn an_org_bound_agent_rebinds_after_a_restart_with_its_operator_key() {
    let tmp = tempfile::tempdir().unwrap();
    let db = tmp.path().join("restart-org.db");
    let (addr1, _r1, keys, store) = first_boot(&db).await;
    let (kp, id) = identity("restart-acme", "acme");
    register(addr1, &kp, &id, Some(&keys.acme)).await.unwrap();

    let (addr2, registry2) = boot(&db, &store).await;
    assert_eq!(
        org_of(&registry2, &id),
        Some(Some("acme".into())),
        "the org is persisted"
    );

    let again = register(addr2, &kp, &id, Some(&keys.acme_second))
        .await
        .expect("a second acme key re-binds");
    assert_eq!(again.org_id.as_deref(), Some("acme"));
    assert!(!again.credential_token.is_empty());
    assert!(validate_token(&registry2, &key_of(&id), &again.credential_token).is_ok());
}

/// After a restart the same callers are refused as before it: an identifier, another
/// org's key, no key, an unbound admin key and the wrong team's key never re-bind an
/// org-bound record, and a refusal carries no credential and installs none.
#[tokio::test]
async fn unauthorized_callers_cannot_take_over_an_org_bound_record_after_a_restart() {
    let tmp = tempfile::tempdir().unwrap();
    let db = tmp.path().join("restart-org-stranger.db");
    let (addr1, _r1, keys, store) = first_boot(&db).await;
    let (kp, id) = identity_in_team("restart-victim", "acme", "team-a");
    register(addr1, &kp, &id, Some(&keys.acme_team_a)).await.unwrap();

    let (addr2, registry2) = boot(&db, &store).await;
    for (label, key) in [
        ("another org's key", Some(keys.globex.as_str())),
        ("no key", None),
        ("a garbage key", Some("aa_not_a_real_key")),
        ("the wrong team's key", Some(keys.acme_team_b.as_str())),
    ] {
        let err = register(addr2, &kp, &id, key)
            .await
            .expect_err(&format!("{label} must not re-bind the record"));
        assert!(
            matches!(
                err.code(),
                Code::AlreadyExists | Code::PermissionDenied | Code::Unauthenticated
            ),
            "{label}: {err:?}"
        );
        assert_eq!(
            registry2.get(&key_of(&id)).unwrap().credential_token,
            "",
            "{label}: a refusal must install no credential"
        );
    }
    // An unbound admin key only asserts the org: a plain collision, as before the restart.
    let err = register(addr2, &kp, &id, Some(&keys.admin_unbound)).await.unwrap_err();
    assert_eq!(err.code(), Code::AlreadyExists, "{err:?}");
    assert_eq!(registry2.get(&key_of(&id)).unwrap().credential_token, "");
}

#[tokio::test]
async fn a_stranger_cannot_take_over_a_keyless_record_after_a_restart() {
    let tmp = tempfile::tempdir().unwrap();
    let db = tmp.path().join("restart-stranger.db");
    let (addr1, _r1, _keys, store) = first_boot(&db).await;
    let (victim_kp, id) = identity("restart-keyless-victim", "");
    register_durable(addr1, &victim_kp, &id, None).await.unwrap();

    let (addr2, registry2) = boot(&db, &store).await;
    // The victim's identifier with the stranger's own key fails the did binding.
    let stranger_kp = AgentKeypair::derive_transport_key("restart-keyless-stranger-key");
    let err = register_durable(addr2, &stranger_kp, &id, None).await.unwrap_err();
    assert_eq!(err.code(), Code::Unauthenticated, "{err:?}");
    // The stranger's own identity is a separate agent, not the victim's record.
    let (own_kp, own_id) = identity("restart-keyless-stranger", "");
    register_durable(addr2, &own_kp, &own_id, None).await.unwrap();
    assert_eq!(
        registry2.get(&key_of(&id)).unwrap().credential_token,
        "",
        "the victim's record still has no credential"
    );
    assert_eq!(registry2.list().len(), 2);
}

/// A client that did not declare a held key created the record, so its key may be
/// computable: it is never re-bound, before or after a restart.
#[tokio::test]
async fn a_record_created_without_the_declaration_is_not_rebound_after_a_restart() {
    let tmp = tempfile::tempdir().unwrap();
    let db = tmp.path().join("restart-undeclared.db");
    let (addr1, _r1, _keys, store) = first_boot(&db).await;
    let (kp, id) = identity("restart-undeclared", "");
    register(addr1, &kp, &id, None).await.unwrap();

    let (addr2, registry2) = boot(&db, &store).await;
    let err = register_durable(addr2, &kp, &id, None).await.unwrap_err();
    assert_eq!(err.code(), Code::AlreadyExists, "{err:?}");
    assert_eq!(registry2.get(&key_of(&id)).unwrap().credential_token, "");
}

/// A row written before the key was persisted has no key to compare: nothing shows
/// the caller holds the key the record was created with, so it stays refused.
#[tokio::test]
async fn a_row_written_before_the_key_was_persisted_is_not_rebound() {
    use aa_core::identity::AgentId;
    let tmp = tempfile::tempdir().unwrap();
    let db = tmp.path().join("restart-legacy.db");
    let (addr1, _r1, _keys, store) = first_boot(&db).await;
    let (kp, id) = identity("restart-legacy", "");
    register_durable(addr1, &kp, &id, None).await.unwrap();

    // Overwrite the row with the shape the previous release stored: no key, marker kept.
    let storage = open_sqlite_backend(&db).await.unwrap();
    let mut metadata = std::collections::BTreeMap::new();
    metadata.insert("name".to_owned(), "agent".to_owned());
    metadata.insert("aa.identity_key".to_owned(), "durable/1".to_owned());
    storage
        .upsert_agent(aa_gateway::storage::AgentRecord {
            agent_id: AgentId::from_bytes(key_of(&id)),
            team_id: Some("team-1".into()),
            org_id: None,
            metadata,
            registered_at: chrono::Utc::now(),
            last_seen_at: chrono::Utc::now(),
            enforcement_mode: "enforce".into(),
            enforcement_mode_expires_at: None,
        })
        .await
        .unwrap();
    drop(storage);

    let (addr2, registry2) = boot(&db, &store).await;
    assert_eq!(registry2.get(&key_of(&id)).unwrap().public_key, "");
    let err = register_durable(addr2, &kp, &id, None).await.unwrap_err();
    assert_eq!(err.code(), Code::AlreadyExists, "{err:?}");
    assert_eq!(registry2.get(&key_of(&id)).unwrap().credential_token, "");
}

/// Processes of one agent that re-register at once after a restart converge on one
/// credential: the shared-credential model of a live re-bind.
#[tokio::test]
async fn concurrent_rebinds_after_a_restart_share_one_credential() {
    let tmp = tempfile::tempdir().unwrap();
    let db = tmp.path().join("restart-race.db");
    let (addr1, _r1, _keys, store) = first_boot(&db).await;
    let (kp, id) = identity("restart-race", "");
    register_durable(addr1, &kp, &id, None).await.unwrap();

    let (addr2, registry2) = boot(&db, &store).await;
    let kp = Arc::new(kp);
    let mut tasks = Vec::new();
    for _ in 0..8 {
        let (kp, id) = (Arc::clone(&kp), id.clone());
        tasks.push(tokio::spawn(
            async move { register_durable(addr2, &kp, &id, None).await },
        ));
    }
    let mut tokens = std::collections::HashSet::new();
    for t in tasks {
        match t.await.unwrap() {
            Ok(r) => {
                tokens.insert(r.credential_token);
            }
            // A retryable refusal when a concurrent adopt lands between the two reads.
            Err(e) => assert_eq!(e.code(), Code::AlreadyExists, "{e:?}"),
        }
    }
    assert_eq!(tokens.len(), 1, "every success carries the one credential");
    let token = tokens.into_iter().next().unwrap();
    assert!(!token.is_empty());
    assert_eq!(registry2.get(&key_of(&id)).unwrap().credential_token, token);
}

/// An org-bound record that was deregistered does not come back at the next boot:
/// the delete is scoped to the row's org, which used to be stored as NULL.
#[tokio::test]
async fn a_deregistered_org_bound_agent_does_not_return_after_a_restart() {
    let tmp = tempfile::tempdir().unwrap();
    let db = tmp.path().join("restart-deregister.db");
    let (addr1, registry1, keys, store) = first_boot(&db).await;
    let (kp, id) = identity("restart-gone", "acme");
    register(addr1, &kp, &id, Some(&keys.acme)).await.unwrap();
    registry1
        .deregister_persisted(&key_of(&id), OrphanMode::Suspend)
        .await
        .expect("deregister");

    let (_addr2, registry2) = boot(&db, &store).await;
    assert!(registry2.get(&key_of(&id)).is_none(), "the agent must not return");
}
