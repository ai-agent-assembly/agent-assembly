//! AAASM-5665 — the `agentId` a check request claims reaches the gateway, and
//! every piece of evidence says how much is known about it.
//!
//! These tests drive the real gRPC `CheckAction` path against a real
//! `AgentRegistry` and read the `AuditEntry` the service emits onto its audit
//! channel. That entry is the gateway's audit evidence at the point it leaves
//! `PolicyServiceImpl` — it is the production entry, payload and hash chain
//! included, not a test double. It is *not* a persisted record: nothing here
//! claims the write side of the audit pipeline was exercised.
//!
//! The five behaviours pinned:
//!
//! 1. Two different `agentId` values arrive as two different values.
//! 2. Policy evaluation context, decision evidence and audit evidence each
//!    preserve the claimed `agentId`.
//! 3. A denied call preserves it in evidence.
//! 4. An omitted `agentId` is explicitly unattributed, never fabricated.
//! 5. A request that omits the field entirely still deserialises and is
//!    processed.
//!
//! Plus the assurance ladder itself: a registered agent presenting its own
//! token is `BOUND`; a claim the gateway cannot corroborate is `ASSERTED`; a
//! claim that disagrees with the token owner is refused and recorded as
//! `ASSERTED`, never `BOUND`.

use std::collections::{BTreeMap, VecDeque};
use std::io::Write;
use std::net::SocketAddr;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use std::time::Duration;

use aa_core::{AuditEntry, GovernanceLevel};
use aa_gateway::registry::convert::proto_agent_id_to_key;
use aa_gateway::registry::store::AgentRecord;
use aa_gateway::registry::{AgentRegistry, AgentStatus};
use aa_gateway::service::convert::{self, CLAIMED_AGENT_ID_KEY, UNATTRIBUTED_AGENT_ID};
use aa_gateway::service::PolicyServiceImpl;
use aa_gateway::PolicyEngine;
use aa_proto::assembly::common::v1::{
    ActionType, AgentId as ProtoAgentId, AgentIdentityAssurance as ProtoAssurance, Decision,
};
use aa_proto::assembly::policy::v1::policy_service_client::PolicyServiceClient;
use aa_proto::assembly::policy::v1::policy_service_server::PolicyServiceServer;
use aa_proto::assembly::policy::v1::{
    action_context::Action, ActionContext, BatchCheckRequest, CheckActionRequest, CheckActionResponse, ToolCallContext,
};
use chrono::Utc;
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tonic::transport::Server;

const ALLOW_ALL_POLICY: &str = r#"
version: "1"
tools:
  bash:
    allow: true
"#;

const DENY_BASH_POLICY: &str = r#"
version: "1"
tools:
  bash:
    allow: false
"#;

/// Start a gateway carrying a real registry, and hand back the audit receiver
/// so tests read the entries the service actually emitted.
async fn start_server(policy_yaml: &str) -> (SocketAddr, Arc<AgentRegistry>, mpsc::Receiver<AuditEntry>) {
    let mut tmp = tempfile::NamedTempFile::new().unwrap();
    write!(tmp, "{}", policy_yaml).unwrap();
    tmp.flush().unwrap();

    let (alert_tx, _) = tokio::sync::broadcast::channel::<aa_gateway::budget::BudgetAlert>(64);
    let engine = Arc::new(PolicyEngine::load_from_file(tmp.path(), alert_tx).unwrap());
    let registry = Arc::new(AgentRegistry::new());
    let (audit_tx, audit_rx) = mpsc::channel::<AuditEntry>(4096);
    let audit_drops = Arc::new(AtomicU64::new(0));
    let service = PolicyServiceImpl::with_registry(
        Arc::clone(&engine),
        Arc::clone(&registry),
        audit_tx,
        audit_drops,
        [0u8; 32],
    );

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _tmp = tmp;
        let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);
        Server::builder()
            .add_service(PolicyServiceServer::new(service))
            .serve_with_incoming(incoming)
            .await
            .unwrap();
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    (addr, registry, audit_rx)
}

fn register(registry: &AgentRegistry, proto_id: &ProtoAgentId, credential_token: &str) {
    let record = AgentRecord {
        agent_id: proto_agent_id_to_key(proto_id),
        name: proto_id.agent_id.clone(),
        framework: "custom".into(),
        version: "1.0.0".into(),
        risk_tier: 0,
        tool_names: vec![],
        public_key: "pk".into(),
        credential_token: credential_token.into(),
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
        team_id: None,
        depth: 0,
        delegation_reason: None,
        spawned_by_tool: None,
        root_agent_id: None,
        children: vec![],
        parent_key: None,
        enforcement_mode: None,
        enforcement_mode_expires_at: None,
        org_id: None,
    };
    registry.register(record).unwrap();
}

fn proto(agent_id: &str) -> ProtoAgentId {
    ProtoAgentId {
        org_id: "org".into(),
        team_id: "team".into(),
        agent_id: agent_id.into(),
    }
}

/// A bash tool-call check. `agent` is `None` to exercise a client that omits
/// the `agent_id` field entirely.
fn bash_request(agent: Option<ProtoAgentId>, credential_token: &str, trace: &str) -> CheckActionRequest {
    CheckActionRequest {
        agent_id: agent,
        credential_token: credential_token.into(),
        trace_id: trace.into(),
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
    }
}

async fn check(addr: SocketAddr, req: CheckActionRequest) -> CheckActionResponse {
    let mut client = PolicyServiceClient::connect(format!("http://{addr}")).await.unwrap();
    client.check_action(req).await.unwrap().into_inner()
}

/// Take the next audit entry, failing rather than hanging if none was emitted.
async fn next_entry(rx: &mut mpsc::Receiver<AuditEntry>) -> AuditEntry {
    tokio::time::timeout(Duration::from_secs(5), rx.recv())
        .await
        .expect("the gateway emitted no audit entry within 5s")
        .expect("the audit channel closed")
}

fn payload(entry: &AuditEntry) -> serde_json::Value {
    serde_json::from_str(entry.payload()).expect("the audit payload is JSON")
}

// ── 1. Two distinct ids arrive as two distinct values ────────────────────────

#[tokio::test]
async fn two_distinct_agent_ids_reach_the_gateway_as_two_distinct_values() {
    // The defect this pins: a check path that discards `agentId` and reports a
    // single fixture constant for every caller. Two callers, two ids, and the
    // assertion is that the gateway's own evidence distinguishes them.
    let (addr, _registry, mut audit_rx) = start_server(ALLOW_ALL_POLICY).await;

    check(addr, bash_request(Some(proto("agent-alpha")), "", "trace-alpha")).await;
    let alpha = next_entry(&mut audit_rx).await;
    check(addr, bash_request(Some(proto("agent-beta")), "", "trace-beta")).await;
    let beta = next_entry(&mut audit_rx).await;

    assert_eq!(payload(&alpha)["agent_id_claimed"], "agent-alpha");
    assert_eq!(payload(&beta)["agent_id_claimed"], "agent-beta");
    assert_ne!(
        payload(&alpha)["agent_id_claimed"],
        payload(&beta)["agent_id_claimed"],
        "the two claims must not collapse onto one value"
    );
    // The derived identity on the entry must differ too — a payload that
    // distinguishes them while the entry's own agent_id does not would leave
    // every per-agent audit query reading one bucket.
    assert_ne!(alpha.agent_id(), beta.agent_id());
}

// ── 2. Policy evaluation context ─────────────────────────────────────────────

#[test]
fn the_policy_evaluation_context_carries_the_claimed_agent_id() {
    // `AgentContext::agent_id` is a SHA-256 truncation, so the string the caller
    // sent is only in the evaluation context if it is deposited there.
    let (alpha, _) = convert::request_to_core(&bash_request(Some(proto("agent-alpha")), "", "t")).unwrap();
    let (beta, _) = convert::request_to_core(&bash_request(Some(proto("agent-beta")), "", "t")).unwrap();

    assert_eq!(
        alpha.metadata.get(CLAIMED_AGENT_ID_KEY).map(String::as_str),
        Some("agent-alpha")
    );
    assert_eq!(
        beta.metadata.get(CLAIMED_AGENT_ID_KEY).map(String::as_str),
        Some("agent-beta")
    );
    assert_ne!(alpha.agent_id, beta.agent_id);
}

#[test]
fn an_omitted_agent_id_leaves_the_evaluation_context_without_a_claim() {
    let (ctx, _) = convert::request_to_core(&bash_request(None, "", "t")).unwrap();
    assert_eq!(ctx.metadata.get(CLAIMED_AGENT_ID_KEY), None);
    assert_eq!(ctx.agent_id.as_bytes(), &UNATTRIBUTED_AGENT_ID);
    // Not the hash of the empty string — that is a stable value an agent could
    // register under and thereby collect every unattributed action.
    assert_ne!(ctx.agent_id.as_bytes(), &convert::hash_to_16(""));
}

#[test]
fn an_empty_agent_id_string_is_treated_as_no_claim() {
    // The shape a client that always sends the message but leaves the id unset
    // puts on the wire.
    let (ctx, _) = convert::request_to_core(&bash_request(Some(proto("")), "", "t")).unwrap();
    assert_eq!(ctx.metadata.get(CLAIMED_AGENT_ID_KEY), None);
    assert_eq!(ctx.agent_id.as_bytes(), &UNATTRIBUTED_AGENT_ID);
}

// ── 3. A denied call preserves the agentId in evidence ───────────────────────

#[tokio::test]
async fn a_denied_call_preserves_the_agent_id_in_decision_and_audit_evidence() {
    let (addr, _registry, mut audit_rx) = start_server(DENY_BASH_POLICY).await;

    let resp = check(addr, bash_request(Some(proto("agent-denied")), "", "trace-deny")).await;
    assert_eq!(resp.decision, Decision::Deny as i32, "the fixture must actually deny");
    assert_eq!(
        resp.agent_identity_assurance,
        ProtoAssurance::Asserted as i32,
        "an unregistered claim is asserted — the gateway had nothing to bind it to"
    );

    let entry = next_entry(&mut audit_rx).await;
    let p = payload(&entry);
    assert_eq!(p["agent_id_claimed"], "agent-denied");
    assert_eq!(p["agent_identity_assurance"], "asserted");
    assert_eq!(p["decision"], Decision::Deny as i32);
}

// ── 4 + 5. Omitted agentId: unattributed, not fabricated; still processed ────

#[tokio::test]
async fn a_request_with_no_agent_id_field_at_all_is_still_processed() {
    // Backward compatibility. Before AAASM-5665 this path returned
    // `InvalidArgument` from `request_to_core`, which an enforce-posture SDK
    // reads as a deny — an old client was effectively broken by the gateway.
    let (addr, _registry, mut audit_rx) = start_server(ALLOW_ALL_POLICY).await;

    let mut client = PolicyServiceClient::connect(format!("http://{addr}")).await.unwrap();
    let result = client.check_action(bash_request(None, "", "trace-none")).await;
    let resp = result
        .expect("a request that omits agent_id must still be processed")
        .into_inner();

    assert_eq!(resp.decision, Decision::Allow as i32);
    assert_eq!(resp.agent_identity_assurance, ProtoAssurance::Unattributed as i32);

    let entry = next_entry(&mut audit_rx).await;
    let p = payload(&entry);
    assert!(
        p["agent_id_claimed"].is_null(),
        "an absent claim must be recorded as absent, got {}",
        p["agent_id_claimed"]
    );
    assert_eq!(p["agent_identity_assurance"], "unattributed");
    assert_eq!(
        entry.agent_id().as_bytes(),
        &UNATTRIBUTED_AGENT_ID,
        "the entry must carry the reserved unattributed id"
    );
    assert_ne!(
        entry.agent_id().as_bytes(),
        &convert::hash_to_16(""),
        "the empty string must not be hashed into a subject that could be registered"
    );
}

#[tokio::test]
async fn an_omitted_agent_id_is_never_reported_as_bound_even_with_a_valid_token() {
    // A credentialed caller that names no agent must not silently acquire the
    // token owner's identity.
    let (addr, registry, mut audit_rx) = start_server(ALLOW_ALL_POLICY).await;
    register(&registry, &proto("agent-owner"), "token-owner");

    let resp = check(addr, bash_request(None, "token-owner", "trace-tokenless-claim")).await;
    assert_eq!(resp.agent_identity_assurance, ProtoAssurance::Unattributed as i32);

    let p = payload(&next_entry(&mut audit_rx).await);
    assert!(p["agent_id_claimed"].is_null());
    assert_eq!(p["agent_identity_assurance"], "unattributed");
}

// ── The assurance ladder ─────────────────────────────────────────────────────

#[tokio::test]
async fn a_registered_agent_presenting_its_own_token_is_bound() {
    // Positive control. Without it, "asserted" everywhere else could equally be
    // a system that never reports anything but asserted.
    let (addr, registry, mut audit_rx) = start_server(ALLOW_ALL_POLICY).await;
    let agent = proto("agent-owner");
    register(&registry, &agent, "token-owner");

    let resp = check(addr, bash_request(Some(agent), "token-owner", "trace-bound")).await;
    assert_eq!(resp.decision, Decision::Allow as i32);
    assert_eq!(resp.agent_identity_assurance, ProtoAssurance::Bound as i32);

    let p = payload(&next_entry(&mut audit_rx).await);
    assert_eq!(p["agent_id_claimed"], "agent-owner");
    assert_eq!(p["agent_identity_assurance"], "bound");
}

#[tokio::test]
async fn an_uncorroborated_claim_is_asserted_not_bound() {
    // Same shape as the bound case but with no registration behind it, so the
    // only thing that differs is what the gateway could verify.
    let (addr, _registry, mut audit_rx) = start_server(ALLOW_ALL_POLICY).await;

    let resp = check(addr, bash_request(Some(proto("agent-stranger")), "", "trace-asserted")).await;
    assert_eq!(resp.agent_identity_assurance, ProtoAssurance::Asserted as i32);
    assert_ne!(resp.agent_identity_assurance, ProtoAssurance::Bound as i32);

    let p = payload(&next_entry(&mut audit_rx).await);
    assert_eq!(p["agent_id_claimed"], "agent-stranger");
    assert_eq!(p["agent_identity_assurance"], "asserted");
}

#[tokio::test]
async fn a_claim_that_disagrees_with_the_token_owner_is_refused_and_never_bound() {
    // The gateway does have an authoritative identity — the registered owner of
    // the presented credential token — so this case is reachable, not
    // hypothetical. `validate_credential_token` refuses it before evaluation,
    // and the refusal's evidence records the claim as asserted.
    let (addr, registry, mut audit_rx) = start_server(ALLOW_ALL_POLICY).await;
    register(&registry, &proto("agent-owner"), "token-owner");
    register(&registry, &proto("agent-victim"), "token-victim");

    // The owner's token, but the victim's agent_id.
    let resp = check(
        addr,
        bash_request(Some(proto("agent-victim")), "token-owner", "trace-spoof"),
    )
    .await;

    assert_eq!(
        resp.decision,
        Decision::Deny as i32,
        "a mismatched claim must not be evaluated"
    );
    assert_eq!(resp.policy_rule, "a2a_identity_verification");
    assert_eq!(
        resp.agent_identity_assurance,
        ProtoAssurance::Asserted as i32,
        "the claim disagreed with the token owner, so it can never be reported as bound"
    );
    assert_ne!(resp.agent_identity_assurance, ProtoAssurance::Bound as i32);

    let p = payload(&next_entry(&mut audit_rx).await);
    assert_eq!(p["agent_id_claimed"], "agent-victim");
    assert_eq!(p["agent_identity_assurance"], "asserted");
}

// ── F3: the refusal path and the claim predicate must not disagree ───────────

#[tokio::test]
async fn a_blank_subject_with_a_foreign_token_is_refused_and_recorded_as_claiming_nobody() {
    // Reported by review of #2016. `validate_credential_token` gates on the
    // `agent_id` MESSAGE being present; `claimed_agent_id` gates on the STRING
    // being non-empty. This input separates them: a blank subject plus a token
    // registered to a different agent.
    //
    // The refusal must stand — otherwise a token holder blanks `agent_id` to
    // dodge a rule scoped to their own id — while the assurance honestly says
    // no subject was claimed. `identity_claimed` is what makes the row findable,
    // because filtering on the assurance alone would drop it.
    let (addr, registry, mut audit_rx) = start_server(ALLOW_ALL_POLICY).await;
    register(&registry, &proto("agent-owner"), "token-owner");

    let blank_subject = ProtoAgentId {
        org_id: "org".into(),
        team_id: "team".into(),
        agent_id: String::new(),
    };
    let resp = check(
        addr,
        bash_request(Some(blank_subject), "token-owner", "trace-blank-subject"),
    )
    .await;

    assert_eq!(
        resp.decision,
        Decision::Deny as i32,
        "a foreign token must still be refused"
    );
    assert_eq!(resp.policy_rule, "a2a_identity_verification");
    assert_eq!(
        resp.agent_identity_assurance,
        ProtoAssurance::Unattributed as i32,
        "a blank subject claims nobody, so the refusal cannot be ASSERTED"
    );
    assert_ne!(resp.agent_identity_assurance, ProtoAssurance::Bound as i32);

    let p = payload(&next_entry(&mut audit_rx).await);
    assert_eq!(p["agent_identity_assurance"], "unattributed");
    assert_eq!(
        p["identity_claimed"], false,
        "the refusal must record that no subject was claimed, so the row stays findable"
    );
    assert_eq!(p["credential_token_present"], true);
}

#[tokio::test]
async fn a_named_subject_impersonation_is_recorded_as_claiming_someone() {
    // Control for the test above: same refusal, but with a subject named. If
    // `identity_claimed` were hard-coded either way, exactly one of the two
    // would fail.
    let (addr, registry, mut audit_rx) = start_server(ALLOW_ALL_POLICY).await;
    register(&registry, &proto("agent-owner"), "token-owner");
    register(&registry, &proto("agent-victim"), "token-victim");

    let resp = check(
        addr,
        bash_request(Some(proto("agent-victim")), "token-owner", "trace-named-subject"),
    )
    .await;
    assert_eq!(resp.decision, Decision::Deny as i32);
    assert_eq!(resp.agent_identity_assurance, ProtoAssurance::Asserted as i32);

    let p = payload(&next_entry(&mut audit_rx).await);
    assert_eq!(p["identity_claimed"], true);
    assert_eq!(p["agent_id_claimed"], "agent-victim");
}

// ── F4: batch_check stamps the assurance too ────────────────────────────────

#[tokio::test]
async fn batch_check_stamps_the_assurance_on_every_entry() {
    // Reported by review of #2016: nothing constructed a `BatchCheckRequest`,
    // so deleting the stamp from `batch_check` left the suite green. Batch
    // emits both a response and an audit entry per entry, so an unstamped batch
    // is a whole unpinned surface.
    //
    // Two entries with different assurance, in one batch, so the test also
    // catches a stamp applied once to the batch rather than per entry.
    let (addr, registry, mut audit_rx) = start_server(ALLOW_ALL_POLICY).await;
    register(&registry, &proto("agent-owner"), "token-owner");

    let mut client = PolicyServiceClient::connect(format!("http://{addr}")).await.unwrap();
    let batch = BatchCheckRequest {
        requests: vec![
            bash_request(Some(proto("agent-owner")), "token-owner", "trace-batch-bound"),
            bash_request(Some(proto("agent-stranger")), "", "trace-batch-asserted"),
        ],
    };
    let responses = client.batch_check(batch).await.unwrap().into_inner().responses;

    assert_eq!(responses.len(), 2);
    assert_eq!(
        responses[0].agent_identity_assurance,
        ProtoAssurance::Bound as i32,
        "the registered agent presenting its own token is bound"
    );
    assert_eq!(
        responses[1].agent_identity_assurance,
        ProtoAssurance::Asserted as i32,
        "the uncorroborated claim is asserted"
    );
    assert_ne!(
        responses[0].agent_identity_assurance, responses[1].agent_identity_assurance,
        "a stamp applied once per batch instead of per entry would collapse these"
    );

    let first = payload(&next_entry(&mut audit_rx).await);
    let second = payload(&next_entry(&mut audit_rx).await);
    assert_eq!(first["agent_id_claimed"], "agent-owner");
    assert_eq!(first["agent_identity_assurance"], "bound");
    assert_eq!(second["agent_id_claimed"], "agent-stranger");
    assert_eq!(second["agent_identity_assurance"], "asserted");
}
