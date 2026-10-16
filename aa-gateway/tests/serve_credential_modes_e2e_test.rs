//! AAASM-6350 — live-gRPC proof of J27's `credential_action` modes.
//!
//! `serve_secret_alert_e2e_test.rs` proves `alert_only` over a real socket. The
//! other candidate evidence for J27 (`cascade_credential_action_test.rs`,
//! `aa-integration-tests/tests/e2e_mcp_redact.rs`, `e2e_secret_interception.rs`)
//! drives `PolicyEngine` in-process and never crosses the wire, so it cannot
//! show what a gRPC client actually receives. This file does: a real TCP tonic
//! `PolicyService` server wired like `server::serve_tcp` (engine loaded from a
//! policy file, `PolicyServiceImpl` + secret-alert hook), driven by a live
//! `PolicyServiceClient`.
//!
//! Every negative is paired with a control in which the *only* variable is the
//! mode or the presence of the secret, so a Deny/Redact can only come from the
//! policy rejecting the payload, never from a missing backend or a broken
//! request.
//!
//! Wire contract worth knowing: `CheckActionResponse` carries `Decision::Redact`
//! plus `RedactInstructions` (kind-named rules), NOT the redacted payload text —
//! the sanitised string stays inside `EvaluationResult`. The assertions below
//! are therefore "Redact decision, rules present, raw value absent from every
//! byte of the response".

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
use aa_proto::assembly::policy::v1::{ActionContext, CheckActionRequest, CheckActionResponse, ToolCallContext};
use tokio::net::TcpListener;
use tokio::sync::broadcast;
use tonic::transport::{Channel, Server};

/// Fabricated AWS-style access key (pattern-matching only, not a credential).
const FAKE_AWS_KEY: &str = "AKIAABCDEFGHIJKLMNOP";
/// Fabricated US SSN in the `DDD-DD-DDDD` shape the built-in PII scanner flags.
const FAKE_SSN: &str = "123-45-6789";
/// Operator-defined PII-style pattern (`data.sensitive_patterns`) and a value matching it.
const CUSTOM_PATTERN: &str = "PATIENT-[0-9]{6}";
const FAKE_PATIENT_ID: &str = "PATIENT-424242";

fn policy(credential_action: &str, extra_data: &str) -> String {
    format!(
        r#"
apiVersion: agent-assembly/v1
kind: Policy
metadata:
  name: aaasm-6350-{credential_action}
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

async fn check(gw: &mut LiveGateway, args_json: String) -> CheckActionResponse {
    let req = CheckActionRequest {
        agent_id: Some(ProtoAgentId {
            org_id: "org".into(),
            team_id: "team-pioneer".into(),
            agent_id: "agent-live".into(),
        }),
        credential_token: "tok".into(),
        trace_id: "trace-6350".into(),
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
    gw.client
        .check_action(tonic::Request::new(req))
        .await
        .expect("CheckAction over the live socket must succeed")
        .into_inner()
}

fn args_with(field: &str, value: &str) -> String {
    format!(r#"{{"path":"/tmp/x.txt","{field}":"{value}"}}"#)
}

/// The raw value must not appear in any field the client received. The derived
/// `Debug` of the decoded message renders every field (reason, policy_rule,
/// every redact rule), so a leak anywhere in the response shows up here.
fn assert_absent_from_response(resp: &CheckActionResponse, raw: &str) {
    assert!(
        !format!("{resp:?}").contains(raw),
        "raw value leaked into the response: {resp:?}"
    );
}

fn assert_clean_allow(resp: &CheckActionResponse) {
    assert_eq!(
        resp.decision,
        Decision::Allow as i32,
        "clean payload must Allow: {resp:?}"
    );
    assert!(
        resp.redact.is_none(),
        "clean payload must carry no redact rules: {resp:?}"
    );
}

// ---------------------------------------------------------------- redact_only

#[tokio::test]
async fn redact_only_returns_redact_decision_without_the_raw_secret() {
    let mut gw = serve(&policy("redact_only", "")).await;
    let resp = check(&mut gw, args_with("aws_key", FAKE_AWS_KEY)).await;

    assert_eq!(resp.decision, Decision::Redact as i32, "got {resp:?}");
    let rules = &resp.redact.as_ref().expect("Redact must carry instructions").rules;
    assert!(
        rules
            .iter()
            .any(|r| r.field_path.contains("AwsAccessKey") && r.replacement == "[REDACTED]"),
        "a rule must name the detected kind: {rules:?}"
    );
    assert_absent_from_response(&resp, FAKE_AWS_KEY);
}

/// Control: same mode, same request shape, no secret → unredacted Allow.
#[tokio::test]
async fn redact_only_control_without_secret_is_unredacted_allow() {
    let mut gw = serve(&policy("redact_only", "")).await;
    let resp = check(&mut gw, args_with("aws_key", "not-a-credential")).await;
    assert_clean_allow(&resp);
}

// ---------------------------------------------------------------------- block

#[tokio::test]
async fn block_denies_with_credential_reason_and_no_raw_secret() {
    let mut gw = serve(&policy("block", "")).await;
    let resp = check(&mut gw, args_with("aws_key", FAKE_AWS_KEY)).await;

    assert_eq!(resp.decision, Decision::Deny as i32, "got {resp:?}");
    assert_eq!(resp.reason, "credential detected");
    assert!(resp.redact.is_none(), "a Deny must not carry redact instructions");
    assert_absent_from_response(&resp, FAKE_AWS_KEY);
}

/// Control: identical `block` policy, no secret → Allow. Proves the Deny above
/// is the credential policy rejecting, not a blanket deny or missing backend.
#[tokio::test]
async fn block_control_without_secret_is_allow() {
    let mut gw = serve(&policy("block", "")).await;
    let resp = check(&mut gw, args_with("aws_key", "not-a-credential")).await;
    assert_clean_allow(&resp);
}

/// Control: the ONLY variable is the mode — the same secret that `block` denies
/// is merely redacted under `redact_only` (and vice versa above).
#[tokio::test]
async fn same_secret_is_deny_under_block_and_redact_under_redact_only() {
    let mut blocked = serve(&policy("block", "")).await;
    let mut redacted = serve(&policy("redact_only", "")).await;
    let b = check(&mut blocked, args_with("aws_key", FAKE_AWS_KEY)).await;
    let r = check(&mut redacted, args_with("aws_key", FAKE_AWS_KEY)).await;
    assert_eq!(b.decision, Decision::Deny as i32);
    assert_eq!(r.decision, Decision::Redact as i32);
}

// ------------------------------------------------------------------------ PII

#[tokio::test]
async fn pii_ssn_is_redacted_under_redact_only() {
    let mut gw = serve(&policy("redact_only", "")).await;
    let resp = check(&mut gw, args_with("note", &format!("SSN {FAKE_SSN} on file"))).await;

    assert_eq!(resp.decision, Decision::Redact as i32, "got {resp:?}");
    let rules = &resp.redact.as_ref().expect("Redact must carry instructions").rules;
    assert!(
        rules.iter().any(|r| r.field_path.contains("SsnPattern")),
        "a rule must name the SSN kind: {rules:?}"
    );
    assert_absent_from_response(&resp, FAKE_SSN);
}

#[tokio::test]
async fn pii_ssn_is_denied_under_block() {
    let mut gw = serve(&policy("block", "")).await;
    let resp = check(&mut gw, args_with("note", &format!("SSN {FAKE_SSN} on file"))).await;
    assert_eq!(resp.decision, Decision::Deny as i32, "got {resp:?}");
    assert_eq!(resp.reason, "credential detected");
    assert_absent_from_response(&resp, FAKE_SSN);
}

/// Control: same tool, same field, no SSN → unredacted Allow.
#[tokio::test]
async fn pii_control_without_ssn_is_unredacted_allow() {
    let mut gw = serve(&policy("redact_only", "")).await;
    let resp = check(&mut gw, args_with("note", "SSN-free note, order 12345 on file")).await;
    assert_clean_allow(&resp);
}

/// `data.sensitive_patterns` — the operator-defined PII path — is honoured over
/// the wire, in the configured mode.
#[tokio::test]
async fn custom_sensitive_pattern_is_redacted_or_denied_per_mode() {
    let extra = format!("    sensitive_patterns:\n      - \"{CUSTOM_PATTERN}\"");
    let mut redact = serve(&policy("redact_only", &extra)).await;
    let r = check(&mut redact, args_with("note", FAKE_PATIENT_ID)).await;
    assert_eq!(r.decision, Decision::Redact as i32, "got {r:?}");
    assert_absent_from_response(&r, FAKE_PATIENT_ID);

    let mut block = serve(&policy("block", &extra)).await;
    let b = check(&mut block, args_with("note", FAKE_PATIENT_ID)).await;
    assert_eq!(b.decision, Decision::Deny as i32, "got {b:?}");

    // Control: same policy, a value that does not match the pattern.
    let c = check(&mut redact, args_with("note", "PATIENT-ABC")).await;
    assert_clean_allow(&c);
}
