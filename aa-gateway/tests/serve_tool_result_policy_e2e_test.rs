//! AAASM-6355 - live-gRPC proof of what a real gateway answers for a tool
//! RESULT (the evaluation `aa-proxy` now requests on an MCP response).
//!
//! The proxy's own scanner holds built-in patterns only; this shows the gateway
//! applies operator `data.sensitive_patterns` to `ToolResult` bodies, which is
//! why the proxy asks it. Each negative is paired with a clean-body control.

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
use aa_proto::assembly::policy::v1::{ActionContext, CheckActionRequest, CheckActionResponse, ToolResultContext};
use tokio::net::TcpListener;
use tokio::sync::broadcast;
use tonic::transport::{Channel, Server};

/// Fabricated AWS-style access key (pattern-matching only, not a credential).
const FAKE_AWS_KEY: &str = "AKIAABCDEFGHIJKLMNOP";
/// Operator-defined PII-style pattern (`data.sensitive_patterns`) and a value matching it.
const CUSTOM_PATTERN: &str = "PATIENT-[0-9]{6}";
const FAKE_PATIENT_ID: &str = "PATIENT-424242";

fn policy(credential_action: &str, extra_data: &str) -> String {
    format!(
        r#"
apiVersion: agent-assembly/v1
kind: Policy
metadata:
  name: aaasm-6355-{credential_action}
  version: "1.0.0"
spec:
  data:
    credential_action: {credential_action}
{extra_data}
  tools:
    "*":
      allow: true
"#
    )
}

struct LiveGateway {
    client: PolicyServiceClient<Channel>,
    /// Held so the alert broadcast keeps a live receiver, as the serve path does.
    _secret_rx: broadcast::Receiver<SecretAlert>,
}

/// Serve `policy_yaml` over a real TCP socket, wired as `server::serve_tcp` wires
/// the policy service (engine from a policy file, secret-alert hook attached).
async fn serve(policy_yaml: &str) -> LiveGateway {
    let mut tmp = tempfile::NamedTempFile::new().unwrap();
    write!(tmp, "{policy_yaml}").unwrap();
    tmp.flush().unwrap();

    let (budget_alert_tx, _) = broadcast::channel::<aa_gateway::budget::BudgetAlert>(64);
    let engine = PolicyEngine::load_from_file(tmp.path(), budget_alert_tx).unwrap();
    let (audit_tx, _audit_rx) = tokio::sync::mpsc::channel(4096);
    let (secret_tx, secret_rx) = broadcast::channel::<SecretAlert>(16);
    let service = PolicyServiceImpl::new(Arc::new(engine), audit_tx, Arc::new(AtomicU64::new(0)), [0u8; 32])
        .with_secret_alert_tx(secret_tx);

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

    let client = PolicyServiceClient::connect(format!("http://{addr}"))
        .await
        .expect("client must connect to the live gateway");
    LiveGateway {
        client,
        _secret_rx: secret_rx,
    }
}

async fn check_result(gw: &mut LiveGateway, body: &str) -> CheckActionResponse {
    let req = CheckActionRequest {
        agent_id: Some(ProtoAgentId {
            org_id: "org".into(),
            team_id: "team-pioneer".into(),
            agent_id: "agent-live".into(),
        }),
        credential_token: "tok".into(),
        trace_id: "trace-6355".into(),
        span_id: "span-1".into(),
        action_type: ActionType::ToolResult as i32,
        context: Some(ActionContext {
            action: Some(Action::ToolResult(ToolResultContext {
                tool_name: "send_note".into(),
                tool_source: "mcp".into(),
                result_json: body.as_bytes().to_vec(),
                source_url: "https://mcp.example/mcp".into(),
            })),
        }),
        caller_agent_id: None,
    };
    gw.client
        .check_action(tonic::Request::new(req))
        .await
        .expect("CheckAction over the live socket must succeed")
        .into_inner()
}

fn custom_patterns() -> String {
    format!("    sensitive_patterns:\n      - \"{CUSTOM_PATTERN}\"")
}

fn result_with(value: &str) -> String {
    format!(r#"{{"content":[{{"type":"text","text":"note: {value}"}}]}}"#)
}

#[tokio::test]
async fn a_result_with_an_operator_pattern_value_is_redacted_by_the_gateway() {
    let mut gw = serve(&policy("redact_only", &custom_patterns())).await;
    let hit = check_result(&mut gw, &result_with(FAKE_PATIENT_ID)).await;
    assert_eq!(hit.decision, Decision::Redact as i32, "got {hit:?}");
    let control = check_result(&mut gw, &result_with("nothing sensitive")).await;
    assert_eq!(
        control.decision,
        Decision::Allow as i32,
        "control must be allowed, got {control:?}"
    );
}

#[tokio::test]
async fn a_result_with_a_builtin_secret_is_redacted_by_the_gateway() {
    let mut gw = serve(&policy("redact_only", "")).await;
    let hit = check_result(&mut gw, &result_with(FAKE_AWS_KEY)).await;
    assert_eq!(hit.decision, Decision::Redact as i32, "got {hit:?}");
    let control = check_result(&mut gw, &result_with("nothing sensitive")).await;
    assert_eq!(control.decision, Decision::Allow as i32, "got {control:?}");
}

#[tokio::test]
async fn block_mode_denies_a_result_carrying_a_secret() {
    let mut gw = serve(&policy("block", "")).await;
    let hit = check_result(&mut gw, &result_with(FAKE_AWS_KEY)).await;
    assert_eq!(hit.decision, Decision::Deny as i32, "got {hit:?}");
    let control = check_result(&mut gw, &result_with("nothing sensitive")).await;
    assert_eq!(control.decision, Decision::Allow as i32, "got {control:?}");
}
