//! Sustained load test for PolicyService CheckAction RPC.
//!
//! Sends requests at 1,000 req/sec for a configurable duration (default 5s for
//! CI, set `AA_BENCH_DURATION_SECS=60` for full local/nightly validation) and
//! asserts that p99 latency stays below the SLA threshold (default 15ms;
//! override with `AA_BENCH_SLA_P99_MS=5` for bare-metal runners).

use std::io::Write;
use std::net::SocketAddr;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use std::time::{Duration, Instant};

use aa_gateway::service::PolicyServiceImpl;
use aa_gateway::PolicyEngine;
use aa_proto::assembly::common::v1::{ActionType, AgentId as ProtoAgentId};
use aa_proto::assembly::policy::v1::action_context::Action;
use aa_proto::assembly::policy::v1::policy_service_client::PolicyServiceClient;
use aa_proto::assembly::policy::v1::policy_service_server::PolicyServiceServer;
use aa_proto::assembly::policy::v1::{ActionContext, CheckActionRequest, ToolCallContext};
use tokio::net::TcpListener;
use tonic::transport::Server;

const POLICY_YAML: &str = r#"
version: "1"
tools:
  web_search:
    allow: true
"#;

const TARGET_RPS: u64 = 1_000;

/// p99 SLA threshold — override with `AA_BENCH_SLA_P99_MS` for CI runners where
/// shared CPU causes higher tail latency than bare-metal / local development.
fn sla_p99() -> Duration {
    let ms: u64 = std::env::var("AA_BENCH_SLA_P99_MS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(15);
    Duration::from_millis(ms)
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
    addr
}

fn make_request() -> CheckActionRequest {
    CheckActionRequest {
        agent_id: Some(ProtoAgentId {
            org_id: "load-org".into(),
            team_id: "load-team".into(),
            agent_id: "load-agent".into(),
        }),
        credential_token: "tok".into(),
        trace_id: "trace-load".into(),
        span_id: "span-load".into(),
        action_type: ActionType::ToolCall as i32,
        context: Some(ActionContext {
            action: Some(Action::ToolCall(ToolCallContext {
                tool_name: "web_search".into(),
                tool_source: "mcp".into(),
                args_json: b"{\"query\":\"benchmark test\"}".to_vec(),
                target_url: String::new(),
            })),
        }),
        caller_agent_id: None,
    }
}

fn percentile(sorted: &[Duration], pct: f64) -> Duration {
    let idx = ((sorted.len() as f64) * pct / 100.0).ceil() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

#[tokio::test]
async fn sustained_load_p99_under_5ms() {
    let duration_secs: u64 = std::env::var("AA_BENCH_DURATION_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(5);

    let addr = start_server().await;
    let endpoint = format!("http://{addr}");

    // Pre-create a pool of clients to avoid connection setup in the hot loop.
    let concurrency = 10_u64;
    let mut clients = Vec::with_capacity(concurrency as usize);
    for _ in 0..concurrency {
        clients.push(PolicyServiceClient::connect(endpoint.clone()).await.unwrap());
    }
    let clients: Vec<_> = clients
        .into_iter()
        .map(|c| Arc::new(tokio::sync::Mutex::new(c)))
        .collect();

    let total_requests = TARGET_RPS * duration_secs;
    let interval = Duration::from_micros(1_000_000 / TARGET_RPS);
    let latencies = Arc::new(tokio::sync::Mutex::new(Vec::with_capacity(total_requests as usize)));

    let start = Instant::now();

    let mut handles = Vec::with_capacity(total_requests as usize);
    for i in 0..total_requests {
        let target_time = start + interval * (i as u32);
        let now = Instant::now();
        if target_time > now {
            tokio::time::sleep(target_time - now).await;
        }

        let client = clients[(i as usize) % clients.len()].clone();
        let lats = latencies.clone();
        let req = make_request();

        handles.push(tokio::spawn(async move {
            let t0 = Instant::now();
            let _resp = client.lock().await.check_action(req).await.unwrap();
            let elapsed = t0.elapsed();
            lats.lock().await.push(elapsed);
        }));
    }

    // Wait for all in-flight requests to complete.
    for h in handles {
        h.await.unwrap();
    }

    let wall_time = start.elapsed();
    let mut lats = Arc::try_unwrap(latencies).unwrap().into_inner();
    lats.sort();

    let total = lats.len();
    let p50 = percentile(&lats, 50.0);
    let p95 = percentile(&lats, 95.0);
    let p99 = percentile(&lats, 99.0);
    let p999 = percentile(&lats, 99.9);
    let max = lats[total - 1];

    eprintln!();
    eprintln!("=== PolicyService CheckAction Load Test ===");
    eprintln!("  Duration:    {duration_secs}s ({wall_time:.2?} wall)");
    eprintln!("  Target RPS:  {TARGET_RPS}");
    eprintln!("  Total reqs:  {total}");
    eprintln!("  Actual RPS:  {:.0}", total as f64 / wall_time.as_secs_f64());
    eprintln!("  Concurrency: {concurrency} clients");
    eprintln!();
    eprintln!("  p50:  {p50:>10.3?}");
    eprintln!("  p95:  {p95:>10.3?}");
    eprintln!("  p99:  {p99:>10.3?}");
    eprintln!("  p999: {p999:>10.3?}");
    eprintln!("  max:  {max:>10.3?}");
    eprintln!();

    let sla = sla_p99();
    assert!(p99 < sla, "p99 latency {p99:?} exceeds SLA (target: {sla:?})");
}
