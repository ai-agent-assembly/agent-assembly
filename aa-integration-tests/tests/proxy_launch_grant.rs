//! AAASM-6261 (J83): a governed launch's network decision is bound to the agent it
//! registered by a launch grant, and the gateway's audit names that same agent.
//!
//! One real `PolicyServiceImpl`, one real `AgentRegistry`, two real registrations
//! (A and B) and real `ProxyServer`s, each holding only a launch grant minted for
//! its own agent. Agent-scoped network rules differ by agent: A may reach `HOST`,
//! B may not. A verdict can therefore differ between the two proxies only if the
//! gateway resolved who each one is, and the gateway's audit entry for each
//! connection is checked against the registry key of the agent that made it.
//!
//! The registration `credential_token` is never given to a proxy in these tests.
//!
//! What these tests prove is **proxy identity**: this proxy is bound to agent X by
//! a gateway-validated grant. They do **not** prove **connection origin**: that the
//! process connecting to the proxy is the governed agent. The last test measures
//! exactly that gap: a second same-user process that reaches A's proxy is
//! attributed to A.
//!
//! Two agents, one broker means two launches against one gateway (ADR 0033 section
//! 6 rejects one shared proxy attributing different agents), so each agent gets
//! its own proxy.

use std::collections::{BTreeMap, VecDeque};
use std::io::Write;
use std::net::SocketAddr;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use std::time::Duration;

use aa_core::{AuditEntry, GovernanceLevel};
use aa_gateway::policy::document::PolicyDocument;
use aa_gateway::policy::scope::PolicyScope;
use aa_gateway::policy::NetworkPolicy;
use aa_gateway::registry::convert::proto_agent_id_to_key;
use aa_gateway::registry::store::AgentRecord;
use aa_gateway::registry::{AgentRegistry, AgentStatus, OrphanMode};
use aa_gateway::service::PolicyServiceImpl;
use aa_gateway::PolicyEngine;
use aa_proto::assembly::common::v1::AgentId as ProtoAgentId;
use aa_proto::assembly::policy::v1::policy_service_client::PolicyServiceClient;
use aa_proto::assembly::policy::v1::policy_service_server::PolicyServiceServer;
use aa_proxy::audit_jsonl::{ProxyAuditDecision, ProxyAuditEntry, RefusalRule};
use aa_proxy::config::{CredentialAction, ProxyConfig};
use aa_proxy::credentials::LaunchGrant;
use aa_proxy::tls::CaStore;
use aa_runtime::pipeline::PipelineEvent;
use chrono::Utc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{broadcast, mpsc};
use tonic::transport::Server;

/// Reachable by agent A's Agent-scoped rule, not by B's.
const HOST: &str = "hooks.example.com";
/// Reachable by agent B's Agent-scoped rule, not by A's.
const OTHER_HOST: &str = "other.example.com";

/// A registered agent: the triple the gateway keys it under, its token, and the
/// registry key the gateway's evidence must carry for it.
#[derive(Clone)]
struct Registered {
    triple: ProtoAgentId,
    token: String,
    key: [u8; 16],
}

fn registered(label: &str, team: &str) -> Registered {
    let triple = ProtoAgentId {
        org_id: String::new(),
        team_id: team.into(),
        agent_id: format!("did:key:{label}"),
    };
    Registered {
        key: proto_agent_id_to_key(&triple),
        token: format!("tok-{label}-synthetic"),
        triple,
    }
}

/// A launch grant the gateway minted for `agent`, as `aasm run` would hand it to
/// the agent's dedicated proxy.
fn grant_for(registry: &AgentRegistry, agent: &Registered) -> LaunchGrant {
    let (grant, _) = registry
        .mint_launch_grant(&agent.key, &agent.token, "launch-1", Duration::from_secs(3600))
        .expect("mint a launch grant");
    LaunchGrant::new(
        agent.triple.org_id.clone(),
        agent.triple.team_id.clone(),
        agent.triple.agent_id.clone(),
        grant,
    )
}

fn register(registry: &AgentRegistry, agent: &Registered) {
    registry
        .register(AgentRecord {
            agent_id: agent.key,
            name: agent.triple.agent_id.clone(),
            framework: "aasm-run".into(),
            version: "1".into(),
            risk_tier: 0,
            tool_names: vec![],
            public_key: "pk".into(),
            credential_token: agent.token.clone(),
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
            team_id: Some(agent.triple.team_id.clone()),
            depth: 0,
            delegation_reason: None,
            spawned_by_tool: None,
            root_agent_id: None,
            children: vec![],
            parent_key: None,
            enforcement_mode: None,
            enforcement_mode_expires_at: None,
            org_id: None,
        })
        .expect("register");
}

fn network_doc(agent: &Registered, allow: &[&str]) -> PolicyDocument {
    PolicyDocument {
        name: None,
        policy_version: None,
        version: None,
        // The engine matches Agent scope on the id derived from the claimed `agent_id`
        // string (the same one the audit entry carries), not the registry key.
        scope: PolicyScope::Agent(aa_core::AgentId::from_bytes(audit_id(agent))),
        network: Some(NetworkPolicy {
            allowlist: allow.iter().map(|h| (*h).to_string()).collect(),
        }),
        schedule: None,
        budget: None,
        data: None,
        approval_timeout_secs: 300,
        approval_policy: None,
        tools: Default::default(),
        capabilities: None,
        filesystem: None,
        syscall_allowlist: None,
        leases: Vec::new(),
        egress: aa_gateway::policy::EgressPosture::NotRequired,
        credentials: aa_gateway::policy::CredentialBrokeragePosture::NotRequired,
    }
}

struct Gateway {
    endpoint: String,
    registry: Arc<AgentRegistry>,
    audit: mpsc::Receiver<AuditEntry>,
}

/// A real gateway with A and B registered and Agent-scoped network rules: A is
/// allowed `HOST`, B is allowed only `OTHER_HOST`.
async fn start_gateway(a: &Registered, b: &Registered) -> Gateway {
    let mut file = tempfile::NamedTempFile::new().unwrap();
    write!(file, "{}", aa_gateway::policy::resolve::ALLOW_ALL_TEMPLATE).unwrap();
    file.flush().unwrap();
    let (alert_tx, _) = broadcast::channel::<aa_gateway::budget::BudgetAlert>(64);
    let mut engine = PolicyEngine::load_from_file(file.path(), alert_tx).unwrap();
    engine.load_policy(network_doc(a, &[HOST]));
    engine.load_policy(network_doc(b, &[OTHER_HOST]));

    let registry = Arc::new(AgentRegistry::new());
    register(&registry, a);
    register(&registry, b);
    let (audit_tx, audit) = mpsc::channel::<AuditEntry>(4096);
    let service = PolicyServiceImpl::with_registry(
        Arc::new(engine),
        Arc::clone(&registry),
        audit_tx,
        Arc::new(AtomicU64::new(0)),
        [0u8; 32],
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _file = file;
        let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);
        Server::builder()
            .add_service(PolicyServiceServer::new(service))
            .serve_with_incoming(incoming)
            .await
            .unwrap();
    });
    tokio::time::sleep(Duration::from_millis(100)).await;
    Gateway {
        endpoint: format!("http://{addr}"),
        registry,
        audit,
    }
}

/// A real proxy for one launch. `grant` is what `aasm run` hands it on stdin; `label` is the old asserted `AA_AGENT_ID`, kept only to prove it is
/// not what the gateway is told.
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
        mitm_hosts: vec![HOST.to_string(), OTHER_HOST.to_string()],
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
        assert!(server.is_governed());
    }
    tokio::spawn(async move {
        let _ = server.run().await;
    });
    tokio::time::sleep(Duration::from_millis(100)).await;
    (addr, audit_rx)
}

/// Send a CONNECT to `host` and return the status line the proxy answered with.
async fn connect_status(proxy: SocketAddr, host: &str) -> String {
    let mut stream = TcpStream::connect(proxy).await.unwrap();
    let connect = format!("CONNECT {host}:443 HTTP/1.1\r\nHost: {host}:443\r\n\r\n");
    stream.write_all(connect.as_bytes()).await.unwrap();
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).await.unwrap();
    line
}

fn allowed(status: &str) -> bool {
    status.contains(" 200")
}

async fn next_gateway_entry(rx: &mut mpsc::Receiver<AuditEntry>) -> AuditEntry {
    tokio::time::timeout(Duration::from_secs(5), rx.recv())
        .await
        .expect("the gateway emitted no audit entry within 5s")
        .expect("the gateway audit channel closed")
}

async fn next_proxy_record(rx: &mut mpsc::Receiver<ProxyAuditEntry>) -> ProxyAuditEntry {
    tokio::time::timeout(Duration::from_secs(5), rx.recv())
        .await
        .expect("the proxy persisted no audit record within 5s")
        .expect("the proxy audit channel closed")
}

fn payload(entry: &AuditEntry) -> serde_json::Value {
    serde_json::from_str(entry.payload()).expect("the audit payload is JSON")
}

/// The id the gateway stamps on an audit entry for `agent`: the existing contract
/// hashes the claimed `agent_id` string (`convert::hash_to_16`), which is NOT the
/// registry key (a hash of the whole org/team/agent triple). Two agents therefore
/// have distinct audit ids exactly when their `agent_id` strings differ.
fn audit_id(agent: &Registered) -> [u8; 16] {
    aa_gateway::service::convert::hash_to_16(&agent.triple.agent_id)
}

fn hex_of(key: &[u8; 16]) -> String {
    key.iter().map(|b| format!("{b:02x}")).collect()
}

/// Drain the gateway audit entries that arrive within `settle`, so a test can
/// assert over every entry two concurrent connections produced.
async fn drain(rx: &mut mpsc::Receiver<AuditEntry>, settle: Duration) -> Vec<AuditEntry> {
    let mut out = Vec::new();
    while let Ok(Some(entry)) = tokio::time::timeout(settle, rx.recv()).await {
        out.push(entry);
    }
    out
}

/// The same CONNECT, opened by a separate OS process (bash `/dev/tcp`) that holds
/// no secret and no label.
async fn connect_status_from_another_process(proxy: SocketAddr, host: &str) -> String {
    let script = format!(
        "exec 3<>/dev/tcp/127.0.0.1/{port}; printf 'CONNECT {host}:443 HTTP/1.1\\r\\nHost: {host}:443\\r\\n\\r\\n' >&3; head -n 1 <&3",
        port = proxy.port()
    );
    let out = tokio::process::Command::new("bash")
        .args(["-c", &script])
        .output()
        .await
        .expect("spawn a second process");
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// The headline: two launches share one gateway, each proxy holds only a grant
/// minted for its own agent, and the verdict, the assurance and the gateway's
/// audit identity all follow the agent that made the connection.
#[tokio::test]
async fn two_concurrent_launches_are_decided_and_audited_as_their_own_registered_agent() {
    let a = registered("agent-a", "team-a");
    let b = registered("agent-b", "team-b");
    let mut gateway = start_gateway(&a, &b).await;
    let (dir_a, dir_b) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    // Labels swapped against the grants: if the gateway were being told the
    // label, the verdicts would follow the label.
    let (grant_a, grant_b) = (grant_for(&gateway.registry, &a), grant_for(&gateway.registry, &b));
    let grant_strings = [grant_a.grant(), grant_b.grant()];
    let (proxy_a, mut proxy_audit_a) =
        start_proxy(&gateway.endpoint, Some(grant_a), Some("label-of-b"), dir_a.path()).await;
    let (proxy_b, mut proxy_audit_b) =
        start_proxy(&gateway.endpoint, Some(grant_b), Some("label-of-a"), dir_b.path()).await;

    let (status_a, status_b) = tokio::join!(connect_status(proxy_a, HOST), connect_status(proxy_b, HOST));
    assert!(allowed(&status_a), "A's rule allows HOST: {status_a:?}");
    assert!(!allowed(&status_b), "B's rule does not allow HOST: {status_b:?}");

    let entries = drain(&mut gateway.audit, Duration::from_millis(600)).await;
    assert_eq!(entries.len(), 2, "one gateway audit entry per connection: {entries:#?}");
    for entry in &entries {
        for grant in &grant_strings {
            assert!(
                !entry.payload().contains(grant),
                "a grant is in the gateway audit payload"
            );
        }
    }
    for entry in &entries {
        let p = payload(entry);
        assert_eq!(p["agent_identity_assurance"], "bound", "{p}");
        let hex = p["agent_id_hex"].as_str().expect("agent_id_hex").to_string();
        assert_eq!(hex_of(entry.agent_id().as_bytes()), hex, "entry and payload agree");
        match hex.as_str() {
            h if h == hex_of(&audit_id(&a)) => {
                assert_eq!(
                    p["decision"],
                    aa_proto::assembly::common::v1::Decision::Allow as i32,
                    "{p}"
                );
                assert_eq!(p["team_id"], "team-a", "{p}");
            }
            h if h == hex_of(&audit_id(&b)) => {
                assert_eq!(
                    p["decision"],
                    aa_proto::assembly::common::v1::Decision::Deny as i32,
                    "{p}"
                );
                assert_eq!(p["team_id"], "team-b", "{p}");
            }
            other => panic!("an audit entry names neither A nor B: {other}"),
        }
    }
    let attributed: std::collections::BTreeSet<_> = entries.iter().map(|e| hex_of(e.agent_id().as_bytes())).collect();
    assert_eq!(
        attributed,
        [hex_of(&audit_id(&a)), hex_of(&audit_id(&b))].into_iter().collect(),
        "each agent appears exactly once: no cross-attribution"
    );
    let refusal = next_proxy_record(&mut proxy_audit_b).await;
    assert_eq!(refusal.decision, ProxyAuditDecision::Blocked);
    assert_eq!(refusal.refusal_rule, Some(RefusalRule::GatewayEgressPolicy));
    let proxy_json = serde_json::to_string(&refusal).unwrap();
    for grant in &grant_strings {
        assert!(!proxy_json.contains(grant), "a grant is in the proxy audit record");
    }
    drop(proxy_audit_a.try_recv());

    // The mirror host proves the verdicts are about the agent, not the proxy.
    let (a2, b2) = tokio::join!(connect_status(proxy_a, OTHER_HOST), connect_status(proxy_b, OTHER_HOST));
    assert!(!allowed(&a2), "A may not reach OTHER_HOST: {a2:?}");
    assert!(allowed(&b2), "B may reach OTHER_HOST: {b2:?}");
}

/// Negative controls: a proxy holding anything but a grant minted for its own
/// agent is refused to a host the agent may reach. The positive control runs
/// first. Each refusal leaves identity evidence that is never `bound`.
#[tokio::test]
async fn a_launch_without_a_grant_minted_for_its_own_agent_is_refused() {
    let a = registered("agent-a", "team-a");
    let b = registered("agent-b", "team-b");
    let mut gateway = start_gateway(&a, &b).await;
    let dir = tempfile::tempdir().unwrap();
    let grant_a = grant_for(&gateway.registry, &a);
    let grant_a_string = grant_a.grant();
    let grant_b = grant_for(&gateway.registry, &b);

    let (own, _audit) = start_proxy(&gateway.endpoint, Some(grant_a), None, dir.path()).await;
    assert!(allowed(&connect_status(own, HOST).await), "positive control");
    assert_eq!(
        payload(&next_gateway_entry(&mut gateway.audit).await)["agent_identity_assurance"],
        "bound"
    );

    let with = |who: &Registered, grant: &str| {
        LaunchGrant::new(
            who.triple.org_id.clone(),
            who.triple.team_id.clone(),
            who.triple.agent_id.clone(),
            grant.to_string(),
        )
    };
    for (name, g) in [
        ("A's triple with B's grant", with(&a, &grant_b.grant())),
        ("B's triple with A's grant", with(&b, &grant_a_string)),
        (
            "A's triple with a guessed grant",
            with(&a, "grant-guessed-by-an-attacker"),
        ),
        // Claims B (not A): a refusal for an unknown grant is a benign one, and the
        // gateway audits at most one benign refusal per claimed agent per window,
        // so A's guessed grant above already used A's slot.
        (
            "B's triple with B's REGISTRATION token as the grant",
            with(&b, &b.token),
        ),
        (
            "a label with A's grant",
            LaunchGrant::new(
                String::new(),
                String::new(),
                "launch-label".into(),
                grant_a_string.clone(),
            ),
        ),
    ] {
        let d = tempfile::tempdir().unwrap();
        let (proxy, _audit) = start_proxy(&gateway.endpoint, Some(g), None, d.path()).await;
        let status = connect_status(proxy, HOST).await;
        assert!(!allowed(&status), "{name}: must be refused, got {status:?}");
        let p = payload(&next_gateway_entry(&mut gateway.audit).await);
        assert_eq!(
            p["decision"],
            aa_proto::assembly::common::v1::Decision::Deny as i32,
            "{name}: {p}"
        );
        assert_ne!(p["agent_identity_assurance"], "bound", "{name}: {p}");
        assert_eq!(p["policy_rule"], "a2a_identity_verification", "{name}: {p}");
    }
}

/// Revocation on deregistration (the end of the launch): the grant dies with the
/// registration, so the proxy that still holds it is refused although the agent's
/// own Agent-scoped rule would have allowed HOST.
#[tokio::test]
async fn a_deregistered_launch_is_refused_although_its_agent_rule_would_have_allowed() {
    let a = registered("agent-a", "team-a");
    let b = registered("agent-b", "team-b");
    let mut gateway = start_gateway(&a, &b).await;
    let dir = tempfile::tempdir().unwrap();
    let grant = grant_for(&gateway.registry, &a);
    let (proxy, mut proxy_audit) = start_proxy(&gateway.endpoint, Some(grant), None, dir.path()).await;

    assert!(
        allowed(&connect_status(proxy, HOST).await),
        "positive control while registered"
    );
    assert_eq!(
        payload(&next_gateway_entry(&mut gateway.audit).await)["agent_identity_assurance"],
        "bound"
    );

    gateway
        .registry
        .deregister(&a.key, OrphanMode::Suspend)
        .expect("deregister A");

    let status = connect_status(proxy, HOST).await;
    assert!(!allowed(&status), "{status:?}");
    let p = payload(&next_gateway_entry(&mut gateway.audit).await);
    assert_eq!(p["policy_rule"], "a2a_identity_verification", "{p}");
    assert_ne!(p["agent_identity_assurance"], "bound", "{p}");
    assert_eq!(
        next_proxy_record(&mut proxy_audit).await.decision,
        ProxyAuditDecision::Blocked
    );
}

/// A proxy with no grant (standalone) is unattributed at the gateway, even with a
/// label.
#[tokio::test]
async fn a_proxy_without_a_grant_is_unattributed_at_the_gateway() {
    let a = registered("agent-a", "team-a");
    let b = registered("agent-b", "team-b");
    let mut gateway = start_gateway(&a, &b).await;
    let dir = tempfile::tempdir().unwrap();
    let (proxy, _audit) = start_proxy(
        &gateway.endpoint,
        None,
        Some("a-label-the-gateway-must-not-see"),
        dir.path(),
    )
    .await;
    let _ = connect_status(proxy, HOST).await;
    let entry = next_gateway_entry(&mut gateway.audit).await;
    let p = payload(&entry);
    assert_eq!(p["agent_identity_assurance"], "unattributed", "{p}");
    assert!(p["agent_id_claimed"].is_null(), "{p}");
}

/// MEASURED, both halves of "a same-user process and the grant":
///
/// * A second process that reaches A's proxy is served and attributed to A
///   (bound, A's registry key). Connection origin is NOT verified.
/// * A second process that does not hold A's grant cannot borrow A's identity at
///   the gateway directly: with A's triple and no grant it is refused, and with a
///   guessed grant it is refused; neither is `bound`.
#[tokio::test]
async fn a_same_user_process_reaching_the_proxy_is_attributed_to_the_launch_but_cannot_use_the_gateway_without_the_grant(
) {
    let a = registered("agent-a", "team-a");
    let b = registered("agent-b", "team-b");
    let mut gateway = start_gateway(&a, &b).await;
    let dir = tempfile::tempdir().unwrap();
    let (proxy, _audit) = start_proxy(
        &gateway.endpoint,
        Some(grant_for(&gateway.registry, &a)),
        None,
        dir.path(),
    )
    .await;

    let status = connect_status_from_another_process(proxy, HOST).await;
    assert!(
        allowed(&status),
        "measured: a second process with no secret is served: {status:?}"
    );
    let entry = next_gateway_entry(&mut gateway.audit).await;
    let p = payload(&entry);
    assert_eq!(p["agent_identity_assurance"], "bound", "{p}");
    assert_eq!(
        hex_of(entry.agent_id().as_bytes()),
        hex_of(&audit_id(&a)),
        "attributed to A"
    );

    // Straight to the gateway, without the grant.
    let mut client = PolicyServiceClient::connect(gateway.endpoint.clone()).await.unwrap();
    for (what, grant) in [
        ("no grant", ""),
        ("a guessed grant", "grant-guessed-by-a-second-process"),
    ] {
        let req = aa_proto::assembly::policy::v1::CheckActionRequest {
            agent_id: Some(a.triple.clone()),
            credential_token: String::new(),
            trace_id: String::new(),
            span_id: String::new(),
            action_type: aa_proto::assembly::common::v1::ActionType::NetworkCall as i32,
            context: Some(aa_proto::assembly::policy::v1::ActionContext {
                action: Some(aa_proto::assembly::policy::v1::action_context::Action::NetworkCall(
                    aa_proto::assembly::policy::v1::NetworkCallContext {
                        host: HOST.into(),
                        port: 443,
                        protocol: "https".into(),
                        in_allowlist: false,
                    },
                )),
            }),
            caller_agent_id: None,
            launch_grant: grant.into(),
        };
        let resp = client.check_action(req).await.unwrap().into_inner();
        assert_eq!(
            resp.decision,
            aa_proto::assembly::common::v1::Decision::Deny as i32,
            "{what}: {resp:?}"
        );
        assert_ne!(
            resp.agent_identity_assurance,
            aa_proto::assembly::common::v1::AgentIdentityAssurance::Bound as i32,
            "{what}"
        );
    }
}
