//! Criterion benchmarks for PolicyService CheckAction RPC latency.
//!
//! Measures end-to-end gRPC round-trip (serialize → transport → evaluate → respond)
//! across three representative payload variants:
//! - Minimal: LlmCallContext with no PII
//! - Full: ToolCallContext with ~1KB args_json
//! - Worst-case: NetworkCallContext with long target_url

use std::hint::black_box;
use std::io::Write;
use std::net::SocketAddr;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use tokio::runtime::Runtime;

use aa_gateway::service::PolicyServiceImpl;
use aa_gateway::PolicyEngine;
use aa_proto::assembly::common::v1::{ActionType, AgentId as ProtoAgentId};
use aa_proto::assembly::policy::v1::action_context::Action;
use aa_proto::assembly::policy::v1::policy_service_client::PolicyServiceClient;
use aa_proto::assembly::policy::v1::policy_service_server::PolicyServiceServer;
use aa_proto::assembly::policy::v1::{
    ActionContext, CheckActionRequest, LlmCallContext, NetworkCallContext, ToolCallContext,
};

const POLICY_YAML: &str = r#"
version: "1"
tools:
  web_search:
    allow: true
  llm_call:
    allow: true
"#;

fn agent_id() -> ProtoAgentId {
    ProtoAgentId {
        org_id: "bench-org".into(),
        team_id: "bench-team".into(),
        agent_id: "bench-agent".into(),
    }
}

fn minimal_llm_call() -> CheckActionRequest {
    CheckActionRequest {
        agent_id: Some(agent_id()),
        credential_token: "bench-token".into(),
        trace_id: "trace-bench".into(),
        span_id: "span-bench".into(),
        action_type: ActionType::LlmCall as i32,
        context: Some(ActionContext {
            action: Some(Action::LlmCall(LlmCallContext {
                model: "gpt-4o".into(),
                prompt_tokens: 100,
                contains_pii: false,
            })),
        }),
        caller_agent_id: None,
    }
}

fn full_tool_call() -> CheckActionRequest {
    // ~1KB args_json payload
    let args = serde_json::json!({
        "query": "a]".repeat(200),
        "max_results": 10,
        "filters": {
            "date_range": "last_7_days",
            "language": "en",
            "region": "us-east-1",
        },
        "metadata": {
            "session": "bench-session-id-12345",
            "correlation": "corr-67890",
        }
    });
    CheckActionRequest {
        agent_id: Some(agent_id()),
        credential_token: "bench-token".into(),
        trace_id: "trace-bench".into(),
        span_id: "span-bench".into(),
        action_type: ActionType::ToolCall as i32,
        context: Some(ActionContext {
            action: Some(Action::ToolCall(ToolCallContext {
                tool_name: "web_search".into(),
                tool_source: "mcp".into(),
                args_json: args.to_string().into_bytes(),
                target_url: String::new(),
            })),
        }),
        caller_agent_id: None,
    }
}

fn worst_case_network() -> CheckActionRequest {
    // Long URL with many path segments and query parameters
    let long_url = format!(
        "https://api.example.com/v1/organizations/{}/projects/{}/resources/{}?token={}&session={}&trace={}",
        "org-".to_owned() + &"x".repeat(50),
        "proj-".to_owned() + &"y".repeat(50),
        "res-".to_owned() + &"z".repeat(50),
        "t".repeat(64),
        "s".repeat(64),
        "r".repeat(64),
    );
    CheckActionRequest {
        agent_id: Some(agent_id()),
        credential_token: "bench-token".into(),
        trace_id: "trace-bench".into(),
        span_id: "span-bench".into(),
        action_type: ActionType::NetworkCall as i32,
        context: Some(ActionContext {
            action: Some(Action::NetworkCall(NetworkCallContext {
                host: long_url,
                port: 443,
                protocol: "https".into(),
                in_allowlist: false,
            })),
        }),
        caller_agent_id: None,
    }
}

async fn start_server() -> SocketAddr {
    let mut tmp = tempfile::NamedTempFile::new().unwrap();
    write!(tmp, "{}", POLICY_YAML).unwrap();
    tmp.flush().unwrap();

    let (alert_tx, _) = tokio::sync::broadcast::channel::<aa_gateway::budget::BudgetAlert>(64);
    let engine = PolicyEngine::load_from_file(tmp.path(), alert_tx).unwrap();
    let (audit_tx, _audit_rx) = tokio::sync::mpsc::channel(4096);
    let audit_drops = Arc::new(AtomicU64::new(0));
    let service = PolicyServiceImpl::new(Arc::new(engine), audit_tx, audit_drops, [0u8; 32]);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        let _tmp = tmp;
        let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);
        tonic::transport::Server::builder()
            .add_service(PolicyServiceServer::new(service))
            .serve_with_incoming(incoming)
            .await
            .unwrap();
    });

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    addr
}

fn bench_check_action(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let addr = rt.block_on(start_server());
    let endpoint = format!("http://{addr}");

    let cases: Vec<(&str, CheckActionRequest)> = vec![
        ("minimal_llm_call", minimal_llm_call()),
        ("full_tool_call_1kb", full_tool_call()),
        ("worst_case_network", worst_case_network()),
    ];

    let mut reuse_group = c.benchmark_group("check_action_rpc");
    let client = std::sync::Arc::new(tokio::sync::Mutex::new(
        rt.block_on(PolicyServiceClient::connect(endpoint.clone())).unwrap(),
    ));

    for (name, req) in &cases {
        reuse_group.bench_with_input(BenchmarkId::new("round_trip", name), req, |b, req| {
            b.to_async(&rt).iter(|| {
                let r = req.clone();
                let c = client.clone();
                async move {
                    let resp = c.lock().await.check_action(r).await.unwrap();
                    black_box(resp);
                }
            });
        });
    }

    reuse_group.finish();
}

criterion_group!(benches, bench_check_action);
criterion_main!(benches);
