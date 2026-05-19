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

use aa_core::CredentialKind;
use aa_gateway::alerts::SecretAlert;
use aa_gateway::service::PolicyServiceImpl;
use aa_gateway::PolicyEngine;
use aa_proto::assembly::common::v1::{ActionType, AgentId as ProtoAgentId};
use aa_proto::assembly::policy::v1::policy_service_server::PolicyService;
use aa_proto::assembly::policy::v1::{action_context::Action, ActionContext, CheckActionRequest, ToolCallContext};
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
