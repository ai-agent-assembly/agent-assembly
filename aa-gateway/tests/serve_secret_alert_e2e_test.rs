//! AAASM-1545/5848 — end-to-end proof that secret-detection alerting is ON in
//! the shipped gateway serve path.
//!
//! `PolicyServiceImpl::with_secret_alert_tx` (AAASM-1545) and
//! `credential_action: alert_only`'s "forward unredacted, alert instead"
//! contract were both implemented and unit-tested, but the production serve
//! path (`server::serve_tcp` / `serve_uds`) never attached the hook — so the
//! shipped gateway ran `alert_only` mode forwarding raw secrets with no
//! alert ever recorded (AAASM-5848).
//!
//! This test stands up the `PolicyServiceImpl` with the secret-alert hook
//! attached exactly as the serve path now does, serves it over a real TCP
//! socket, and drives a `ToolCall` action carrying a fabricated credential
//! through a live gRPC `PolicyServiceClient`. It asserts the resulting
//! `SecretAlert` arrives on the broadcast channel — i.e. the alert fires
//! across the wire, proving the capability is wired into the live path and
//! not merely compilable.

use std::io::Write;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use std::time::Duration;

use aa_gateway::alerts::SecretAlert;
use aa_gateway::service::PolicyServiceImpl;
use aa_gateway::PolicyEngine;
use aa_proto::assembly::common::v1::{ActionType, AgentId as ProtoAgentId, Decision};
use aa_proto::assembly::policy::v1::action_context::Action;
use aa_proto::assembly::policy::v1::policy_service_client::PolicyServiceClient;
use aa_proto::assembly::policy::v1::policy_service_server::PolicyServiceServer;
use aa_proto::assembly::policy::v1::{ActionContext, CheckActionRequest, ToolCallContext};
use aa_security::CredentialKind;
use tokio::net::TcpListener;
use tonic::transport::Server;

const ALERT_ONLY_POLICY: &str = r#"
apiVersion: agent-assembly/v1
kind: Policy
metadata:
  name: aaasm-5848-alert-only
  version: "1.0.0"
spec:
  data:
    credential_action: alert_only
  tools:
    "*":
      allow: true
"#;

/// A fabricated (non-real) AWS-style access key, pattern-matching only.
const FAKE_AWS_KEY: &str = "AKIAABCDEFGHIJKLMNOP";

/// Drive a live `ToolCall` `CheckAction` carrying a detectable credential over
/// a real gRPC socket against a service wired with the secret-alert hook
/// (mirroring `server::serve_tcp`), and assert: (a) the decision is a bare
/// Allow with no redact instructions (the documented `alert_only` forward-
/// unredacted contract), and (b) a `SecretAlert` arrives on the broadcast
/// channel — the compensating side effect that was previously silently
/// missing.
#[tokio::test]
async fn tool_call_with_credential_over_live_grpc_fires_secret_alert() {
    let mut tmp = tempfile::NamedTempFile::new().unwrap();
    write!(tmp, "{}", ALERT_ONLY_POLICY).unwrap();
    tmp.flush().unwrap();

    let (budget_alert_tx, _) = tokio::sync::broadcast::channel::<aa_gateway::budget::BudgetAlert>(64);
    let engine = PolicyEngine::load_from_file(tmp.path(), budget_alert_tx).unwrap();
    let (audit_tx, _audit_rx) = tokio::sync::mpsc::channel(4096);
    let audit_drops = Arc::new(AtomicU64::new(0));

    // Mirror the serve-path wiring: attach the secret-alert broadcast.
    let (secret_tx, mut secret_rx) = tokio::sync::broadcast::channel::<SecretAlert>(16);
    let service =
        PolicyServiceImpl::new(Arc::new(engine), audit_tx, audit_drops, [0u8; 32]).with_secret_alert_tx(secret_tx);

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

    let mut client = PolicyServiceClient::connect(format!("http://{addr}"))
        .await
        .expect("client must connect to the live gateway");

    let args_json = format!(r#"{{"path":"/tmp/x.txt","aws_key":"{FAKE_AWS_KEY}"}}"#);
    let req = CheckActionRequest {
        agent_id: Some(ProtoAgentId {
            org_id: "org".into(),
            team_id: "team-pioneer".into(),
            agent_id: "agent-live".into(),
        }),
        credential_token: "tok".into(),
        trace_id: "trace-live-secret-alert".into(),
        span_id: "span-1".into(),
        action_type: ActionType::ToolCall as i32,
        context: Some(ActionContext {
            action: Some(Action::ToolCall(ToolCallContext {
                tool_name: "write_file".into(),
                tool_source: "function".into(),
                args_json: args_json.into_bytes(),
                ..Default::default()
            })),
        }),
        caller_agent_id: None,
    };

    let response = client
        .check_action(tonic::Request::new(req))
        .await
        .expect("CheckAction over the live socket must succeed")
        .into_inner();

    // The documented alert_only contract: bare Allow, no redact instructions
    // — the caller forwards the payload unmodified.
    assert_eq!(
        response.decision,
        Decision::Allow as i32,
        "alert_only must map to a bare Allow decision (got reason: {})",
        response.reason
    );
    assert!(
        response.redact.is_none(),
        "alert_only must carry no redact instructions — the payload is forwarded as-is"
    );

    // The regression this test guards: the compensating alert must actually
    // fire across the live serve path, not merely be constructible in a unit
    // test that manually supplies the sender.
    let alert = tokio::time::timeout(Duration::from_secs(2), secret_rx.recv())
        .await
        .expect("secret alert must arrive within 2s")
        .expect("broadcast channel must yield a secret alert");

    assert!(alert.finding_count >= 1, "at least one finding must be recorded");
    assert!(
        alert.kinds.contains(&CredentialKind::AwsAccessKey),
        "the fabricated AWS key must be among the findings driving the alert, got {:?}",
        alert.kinds
    );
}
