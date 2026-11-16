//! AAASM-1545 — PolicyService emits a `SecretAlert` broadcast whenever
//! evaluating a `CheckAction` produces non-empty `credential_findings`.
//!
//! Calls `check_action` directly on the trait impl so the test does not
//! need a tonic server / network port — emission happens inside the
//! engine→service path either way.
//!
//! Synthetic secrets only — `AKIAIOSFODNN7EXAMPLE` is a public AWS
//! documentation key, never a live credential.

use std::io::Write;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use std::time::Duration;

use aa_gateway::alerts::SecretAlert;
use aa_gateway::service::PolicyServiceImpl;
use aa_gateway::PolicyEngine;
use aa_proto::assembly::common::v1::{ActionType, AgentId as ProtoAgentId};
use aa_proto::assembly::policy::v1::policy_service_server::PolicyService;
use aa_proto::assembly::policy::v1::{action_context::Action, ActionContext, CheckActionRequest, ToolCallContext};
use aa_security::CredentialKind;
use tonic::Request;

const ALLOW_TEST_TOOL_POLICY: &str = r#"
version: "1"
tools:
  test_tool:
    allow: true
"#;

const FAKE_AWS_ACCESS_KEY: &str = "AKIAIOSFODNN7EXAMPLE";

fn make_service_with_secret_tx() -> (Arc<PolicyServiceImpl>, tokio::sync::broadcast::Receiver<SecretAlert>) {
    let mut tmp = tempfile::NamedTempFile::new().unwrap();
    write!(tmp, "{}", ALLOW_TEST_TOOL_POLICY).unwrap();
    tmp.flush().unwrap();

    let (budget_tx, _) = tokio::sync::broadcast::channel::<aa_gateway::budget::BudgetAlert>(64);
    let engine = PolicyEngine::load_from_file(tmp.path(), budget_tx).unwrap();

    let (audit_tx, _audit_rx) = tokio::sync::mpsc::channel(4096);
    let audit_drops = Arc::new(AtomicU64::new(0));

    let (secret_tx, secret_rx) = tokio::sync::broadcast::channel::<SecretAlert>(16);
    let service =
        PolicyServiceImpl::new(Arc::new(engine), audit_tx, audit_drops, [0u8; 32]).with_secret_alert_tx(secret_tx);

    (Arc::new(service), secret_rx)
}

fn tool_call_request_with_args(args: &str) -> CheckActionRequest {
    CheckActionRequest {
        agent_id: Some(ProtoAgentId {
            org_id: "org".into(),
            team_id: "team-pioneer".into(),
            agent_id: "agent-1".into(),
        }),
        credential_token: "tok".into(),
        trace_id: "trace-secret".into(),
        span_id: "span-1".into(),
        action_type: ActionType::ToolCall as i32,
        context: Some(ActionContext {
            action: Some(Action::ToolCall(ToolCallContext {
                tool_name: "test_tool".into(),
                tool_source: "test".into(),
                args_json: args.as_bytes().to_vec(),
                target_url: String::new(),
            })),
        }),
        caller_agent_id: None,
    }
}

#[tokio::test]
async fn check_action_emits_secret_alert_when_credential_findings_present() {
    let (service, mut rx) = make_service_with_secret_tx();
    let req = tool_call_request_with_args(FAKE_AWS_ACCESS_KEY);

    service
        .check_action(Request::new(req))
        .await
        .expect("check_action should succeed");

    let alert = tokio::time::timeout(Duration::from_secs(1), rx.recv())
        .await
        .expect("alert must arrive within 1s")
        .expect("broadcast channel must yield an alert");

    assert!(alert.kinds.contains(&CredentialKind::AwsAccessKey));
    assert_eq!(alert.team_id.as_deref(), Some("team-pioneer"));
    assert!(alert.finding_count >= 1);
}

#[tokio::test]
async fn check_action_does_not_emit_alert_when_payload_is_clean() {
    let (service, mut rx) = make_service_with_secret_tx();
    let req = tool_call_request_with_args(r#"{"q":"hello"}"#);

    service
        .check_action(Request::new(req))
        .await
        .expect("check_action should succeed");

    // Short wait — no alert should arrive at all.
    let outcome = tokio::time::timeout(Duration::from_millis(150), rx.recv()).await;
    assert!(outcome.is_err(), "no secret alert expected for clean payload");
}

#[tokio::test]
async fn secret_alert_payload_never_contains_raw_secret() {
    let (service, mut rx) = make_service_with_secret_tx();
    let req = tool_call_request_with_args(FAKE_AWS_ACCESS_KEY);

    service
        .check_action(Request::new(req))
        .await
        .expect("check_action should succeed");

    let alert = tokio::time::timeout(Duration::from_secs(1), rx.recv())
        .await
        .expect("alert must arrive within 1s")
        .expect("broadcast channel must yield an alert");

    let serialized = format!("{alert:?}");
    assert!(
        !serialized.contains(FAKE_AWS_ACCESS_KEY),
        "raw secret must never appear in the SecretAlert payload, got: {serialized}"
    );
}

// ── AAASM-6363: who an alert is attributed to ────────────────────────────────

mod attribution {
    use std::collections::{BTreeMap, VecDeque};

    use aa_core::GovernanceLevel;
    use aa_gateway::alerts::UNATTRIBUTED_PROXY_AGENT;
    use aa_gateway::registry::convert::proto_agent_id_to_key;
    use aa_gateway::registry::store::AgentRecord;
    use aa_gateway::registry::{AgentRegistry, AgentStatus};
    use chrono::Utc;

    use super::*;

    const REGISTERED_TOKEN: &str = "tok-registered-6363";

    fn registered_triple() -> ProtoAgentId {
        ProtoAgentId {
            org_id: String::new(),
            team_id: "team-pioneer".into(),
            agent_id: "did:key:registered-6363".into(),
        }
    }

    fn service_with_registered_agent() -> (Arc<PolicyServiceImpl>, tokio::sync::broadcast::Receiver<SecretAlert>) {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        write!(tmp, "{}", ALLOW_TEST_TOOL_POLICY).unwrap();
        tmp.flush().unwrap();
        let (budget_tx, _) = tokio::sync::broadcast::channel::<aa_gateway::budget::BudgetAlert>(64);
        let engine = PolicyEngine::load_from_file(tmp.path(), budget_tx).unwrap();
        let (audit_tx, _audit_rx) = tokio::sync::mpsc::channel(4096);
        let registry = Arc::new(AgentRegistry::new());
        let triple = registered_triple();
        registry
            .register(AgentRecord {
                agent_id: proto_agent_id_to_key(&triple),
                name: triple.agent_id.clone(),
                framework: "aasm-run".into(),
                version: "1".into(),
                risk_tier: 0,
                tool_names: vec![],
                public_key: "pk".into(),
                credential_token: REGISTERED_TOKEN.into(),
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
                team_id: Some(triple.team_id.clone()),
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
            .unwrap();
        let (secret_tx, secret_rx) = tokio::sync::broadcast::channel::<SecretAlert>(16);
        let service = PolicyServiceImpl::with_registry(
            Arc::new(engine),
            registry,
            audit_tx,
            Arc::new(AtomicU64::new(0)),
            [0u8; 32],
        )
        .with_secret_alert_tx(secret_tx);
        (Arc::new(service), secret_rx)
    }

    async fn alert_for(
        service: &PolicyServiceImpl,
        mut req: CheckActionRequest,
        rx: &mut tokio::sync::broadcast::Receiver<SecretAlert>,
        agent: Option<ProtoAgentId>,
        token: &str,
    ) -> Option<SecretAlert> {
        req.agent_id = agent;
        req.credential_token = token.into();
        service.check_action(Request::new(req)).await.expect("check_action");
        tokio::time::timeout(Duration::from_millis(500), rx.recv())
            .await
            .ok()
            .and_then(Result::ok)
    }

    /// A check bound to a registered agent raises its alert under that agent's
    /// registry key, with the registration's team.
    #[tokio::test]
    async fn a_bound_check_raises_the_alert_under_the_registered_agent() {
        let (service, mut rx) = service_with_registered_agent();
        let req = tool_call_request_with_args(FAKE_AWS_ACCESS_KEY);
        let alert = alert_for(&service, req, &mut rx, Some(registered_triple()), REGISTERED_TOKEN)
            .await
            .expect("a bound check with a finding must alert");
        assert_eq!(
            alert.agent_id,
            aa_core::AgentId::from_bytes(proto_agent_id_to_key(&registered_triple()))
        );
        assert_ne!(alert.agent_id, UNATTRIBUTED_PROXY_AGENT);
        assert_eq!(alert.team_id.as_deref(), Some("team-pioneer"));
    }

    /// A check that claims no agent is not dropped: it alerts under the
    /// unattributed sentinel. Both shapes of "no claim" are covered, because an
    /// absent message used to be dropped and a blank one used to be filed under
    /// the hash of an empty triple.
    #[tokio::test]
    async fn a_check_with_no_agent_claim_alerts_as_explicitly_unattributed() {
        let (service, mut rx) = service_with_registered_agent();
        for (label, agent) in [
            ("absent agent_id", None),
            ("blank agent_id", Some(ProtoAgentId::default())),
        ] {
            let req = tool_call_request_with_args(FAKE_AWS_ACCESS_KEY);
            let alert = alert_for(&service, req, &mut rx, agent, "")
                .await
                .unwrap_or_else(|| panic!("{label}: the alert was dropped"));
            assert_eq!(alert.agent_id, UNATTRIBUTED_PROXY_AGENT, "{label}");
            assert_eq!(alert.team_id, None, "{label}");
        }
    }

    /// The SDK's tokenless claim is unchanged: attributed to what it claimed.
    #[tokio::test]
    async fn an_asserted_check_still_alerts_under_the_claimed_key() {
        let (service, mut rx) = service_with_registered_agent();
        let claimed = ProtoAgentId {
            org_id: "org".into(),
            team_id: "team-x".into(),
            agent_id: "sdk-agent".into(),
        };
        let req = tool_call_request_with_args(FAKE_AWS_ACCESS_KEY);
        let alert = alert_for(&service, req, &mut rx, Some(claimed.clone()), "")
            .await
            .expect("an asserted claim must alert");
        assert_eq!(
            alert.agent_id,
            aa_core::AgentId::from_bytes(proto_agent_id_to_key(&claimed))
        );
    }
}
