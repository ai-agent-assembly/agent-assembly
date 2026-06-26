//! Integration coverage for the `aasm status`, `aasm alerts`, and
//! `aasm approvals` command groups (AAASM-3804).
//!
//! Each command's `run`/`dispatch` builds its own Tokio runtime internally, so
//! every test starts a `wiremock` server on the test runtime and then invokes
//! the command on a separate `std::thread` to avoid a nested-runtime panic.
//! Pure render/format helpers are exercised directly without a server.

use std::process::ExitCode;

use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use aa_cli::output::OutputFormat;

fn make_context(api_url: &str) -> aa_cli::config::ResolvedContext {
    aa_cli::config::ResolvedContext {
        name: None,
        api_url: api_url.to_string(),
        api_key: None,
    }
}

// ── aasm status — full dispatch over the StatusClient (covers client.rs) ──

/// Mount all six endpoints `StatusClient::fetch_all` queries, parametrised by
/// the agent violation count and the storage-health label so the exit-code
/// branches can be exercised independently.
async fn mount_status_endpoints(server: &MockServer, violations: u32, storage_health: &str) {
    Mock::given(method("GET"))
        .and(path("/api/v1/health"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "status": "ok", "version": "0.0.1", "uptime_secs": 3600,
            "active_connections": 2, "pipeline_lag_ms": 0
        })))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path("/healthz"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "mode": "local", "version": "0.0.1", "storage": "sqlite",
            "uptime_secs": 3600, "storage_path": "~/.aasm/local.db"
        })))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v1/admin/status"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "mode": "local", "version": "0.0.1", "uptime_secs": 3600,
            "storage": {
                "backend": "sqlite", "path": "~/.aasm/local.db",
                "health": storage_health, "latency_ms": 1,
                "row_counts": {"audit_events_hot": 47, "agents": 2, "policy_versions": 1}
            }
        })))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v1/agents"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "items": [{
                "id": "a1", "name": "agent-1", "framework": "langgraph",
                "version": "1.0.0", "status": "Running", "tool_names": [],
                "metadata": {}, "session_count": 1,
                "policy_violations_count": violations, "layer": "enforced",
                "last_event": "2026-04-30T08:00:00Z",
                "recent_events": [{"event_type": "tool_call", "summary": "x", "timestamp": "2026-04-30T08:00:00Z"}]
            }],
            "page": 1, "per_page": 100, "total": 1
        })))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v1/approvals"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "items": [{
                "id": "ap-1", "agent_id": "a1", "action": "refund", "reason": "amt",
                "status": "pending", "created_at": "2026-04-30T07:00:00Z",
                "team_id": "", "routing_status": ""
            }],
            "page": 1, "per_page": 100, "total": 1
        })))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v1/costs"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "daily_spend_usd": "8.10", "monthly_spend_usd": "142.50", "date": "2026-04-30",
            "daily_limit_usd": "100.00", "monthly_limit_usd": "2000.00",
            "per_agent": [{"agent_id": "a1", "daily_spend_usd": "4.10"}]
        })))
        .mount(server)
        .await;
}

fn run_status(uri: String, output: OutputFormat, json_flag: bool) -> ExitCode {
    std::thread::spawn(move || {
        let args = aa_cli::commands::status::StatusArgs {
            watch: false,
            json: json_flag,
        };
        aa_cli::commands::status::dispatch(args, &make_context(&uri), output)
    })
    .join()
    .unwrap()
}

#[tokio::test]
async fn status_table_healthy_returns_success() {
    let server = MockServer::start().await;
    mount_status_endpoints(&server, 0, "ok").await;
    assert_eq!(run_status(server.uri(), OutputFormat::Table, false), ExitCode::SUCCESS);
}

#[tokio::test]
async fn status_json_output_returns_success() {
    let server = MockServer::start().await;
    mount_status_endpoints(&server, 0, "ok").await;
    assert_eq!(run_status(server.uri(), OutputFormat::Json, false), ExitCode::SUCCESS);
}

#[tokio::test]
async fn status_yaml_output_returns_success() {
    let server = MockServer::start().await;
    mount_status_endpoints(&server, 0, "ok").await;
    assert_eq!(run_status(server.uri(), OutputFormat::Yaml, false), ExitCode::SUCCESS);
}

#[tokio::test]
async fn status_json_flag_emits_deployment_overview() {
    let server = MockServer::start().await;
    mount_status_endpoints(&server, 0, "ok").await;
    // --json prints only the deployment overview; a healthy snapshot still exits 0.
    assert_eq!(run_status(server.uri(), OutputFormat::Table, true), ExitCode::SUCCESS);
}

#[tokio::test]
async fn status_with_agent_violations_returns_exit_1() {
    let server = MockServer::start().await;
    mount_status_endpoints(&server, 3, "ok").await;
    assert_eq!(run_status(server.uri(), OutputFormat::Table, false), ExitCode::from(1));
}

#[tokio::test]
async fn status_with_storage_unavailable_returns_exit_1() {
    let server = MockServer::start().await;
    mount_status_endpoints(&server, 0, "unavailable").await;
    assert_eq!(run_status(server.uri(), OutputFormat::Table, false), ExitCode::from(1));
}

#[tokio::test]
async fn status_unreachable_gateway_returns_exit_1() {
    // No mocks mounted: every probe 404s and fails to decode, so the gateway
    // is reported unreachable, which collapses to a non-zero exit code.
    let server = MockServer::start().await;
    assert_eq!(run_status(server.uri(), OutputFormat::Table, false), ExitCode::from(1));
}

// ── aasm status — render helpers (covers render.rs branches) ──────────────

use aa_cli::commands::status::models::{
    AdminRowCountsBlock, AdminStorageHealthBlock, AdminTimescaleDbBlock, AgentCostEntry, AgentRow, ApprovalsSummary,
    BudgetRow, DeploymentOverview, RuntimeHealth, StatusSnapshot,
};
use aa_cli::commands::status::render;

fn rich_snapshot() -> StatusSnapshot {
    StatusSnapshot {
        deployment: DeploymentOverview {
            mode: "remote".to_string(),
            gateway_url: "https://cp.internal:7391".to_string(),
            storage_backend: "postgres".to_string(),
            storage_path: None,
            database_url_redacted: Some("postgresql://aasm:***@db:5432/aasm".to_string()),
            version: "0.0.1".to_string(),
            uptime_secs: 90_061,
            health: "ok".to_string(),
        },
        runtime: RuntimeHealth {
            reachable: true,
            status: "ok".to_string(),
            uptime_secs: 90_061,
            active_connections: 4,
            pipeline_lag_ms: 7,
        },
        agents: vec![AgentRow {
            id: "a1".to_string(),
            name: "agent-1".to_string(),
            framework: "langgraph".to_string(),
            status: "Running".to_string(),
            sessions: 2,
            violations_today: 0,
            last_event: "2m ago tool_call".to_string(),
            layer: "enforced".to_string(),
        }],
        approvals: ApprovalsSummary {
            pending_count: 1,
            oldest_pending_age: Some("2h 15m".to_string()),
        },
        budget: BudgetRow {
            // 90/100 → >80% (red bar); monthly 60/100 → 50-80% (yellow bar).
            daily_spend_usd: "90.00".to_string(),
            monthly_spend_usd: Some("60.00".to_string()),
            daily_limit_usd: Some("100.00".to_string()),
            monthly_limit_usd: Some("100.00".to_string()),
            date: "2026-04-30".to_string(),
            per_agent: vec![
                AgentCostEntry {
                    agent_id: "low".to_string(),
                    daily_spend_usd: "1.00".to_string(),
                },
                AgentCostEntry {
                    agent_id: "high".to_string(),
                    daily_spend_usd: "9.00".to_string(),
                },
            ],
        },
        storage_health: Some(AdminStorageHealthBlock {
            backend: "postgres".to_string(),
            path: None,
            database_url: Some("postgresql://aasm:***@db:5432/aasm".to_string()),
            health: "ok".to_string(),
            latency_ms: 3,
            row_counts: AdminRowCountsBlock {
                audit_events_hot: 14_293,
                agents: 8,
                policy_versions: 3,
            },
            timescaledb: Some(AdminTimescaleDbBlock {
                enabled: true,
                total_chunks: 12,
                compressed_chunks: 8,
                compression_ratio: 11.4,
            }),
        }),
    }
}

fn sparse_snapshot() -> StatusSnapshot {
    StatusSnapshot {
        deployment: DeploymentOverview {
            mode: "unknown".to_string(),
            gateway_url: "http://localhost:7391".to_string(),
            storage_backend: "unknown".to_string(),
            storage_path: None,
            database_url_redacted: None,
            version: String::new(),
            uptime_secs: 0,
            health: "unreachable".to_string(),
        },
        runtime: RuntimeHealth {
            reachable: false,
            status: "unreachable".to_string(),
            uptime_secs: 0,
            active_connections: 0,
            pipeline_lag_ms: 0,
        },
        agents: vec![],
        approvals: ApprovalsSummary {
            pending_count: 0,
            oldest_pending_age: None,
        },
        budget: BudgetRow {
            daily_spend_usd: "0.00".to_string(),
            monthly_spend_usd: None,
            daily_limit_usd: None,
            monthly_limit_usd: None,
            date: "--".to_string(),
            per_agent: vec![],
        },
        storage_health: None,
    }
}

#[test]
fn render_all_table_with_rich_snapshot_executes_all_sections() {
    // Exercises render_agents_table (non-empty), render_budget_table
    // (limit + colorize red/yellow + per-agent sort), render_approvals_summary
    // (oldest age branch), render_storage_health, render_runtime_health.
    render::render_all(&rich_snapshot(), OutputFormat::Table);
}

#[test]
fn render_all_table_with_sparse_snapshot_executes_empty_branches() {
    // Empty agents → "(no agents registered)"; no budget limits → "no limit set";
    // no storage_health → storage section omitted; no oldest approval age.
    render::render_all(&sparse_snapshot(), OutputFormat::Table);
}

#[test]
fn render_all_json_and_yaml_arms() {
    render::render_all(&rich_snapshot(), OutputFormat::Json);
    render::render_all(&rich_snapshot(), OutputFormat::Yaml);
}

#[test]
fn render_runtime_and_deployment_helpers_run() {
    render::render_runtime_health(&rich_snapshot().runtime);
    render::render_deployment_overview(&rich_snapshot().deployment);
    render::render_status_json(&rich_snapshot());
    // Direct content assertion on the pure formatter for the unreachable branch.
    let unreachable = render::format_deployment_overview(&sparse_snapshot().deployment);
    assert!(unreachable.contains("unreachable"));
    assert!(!unreachable.contains("Mode:"));
}

// ── aasm alerts ───────────────────────────────────────────────────────────

fn alert_json(id: &str, status: &str) -> serde_json::Value {
    serde_json::json!({
        "id": id, "agent_id": "agent-abc", "severity": "critical",
        "category": "budget", "message": "Budget exceeded", "status": status,
        "created_at": "2026-04-30T10:00:00Z", "updated_at": null, "context": null
    })
}

#[tokio::test]
async fn alerts_list_table_success() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/alerts"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "items": [alert_json("alert-1", "unresolved")], "page": 1, "per_page": 20, "total": 1
        })))
        .mount(&server)
        .await;
    let uri = server.uri();
    let result = std::thread::spawn(move || {
        let args = aa_cli::commands::alerts::list::ListArgs {
            agent: None,
            severity: None,
            status: None,
        };
        aa_cli::commands::alerts::list::run(args, &make_context(&uri), OutputFormat::Table)
    })
    .join()
    .unwrap();
    assert_eq!(result, ExitCode::SUCCESS);
}

#[tokio::test]
async fn alerts_list_empty_prints_no_alerts() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/alerts"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "items": [], "page": 1, "per_page": 20, "total": 0
        })))
        .mount(&server)
        .await;
    let uri = server.uri();
    let result = std::thread::spawn(move || {
        let args = aa_cli::commands::alerts::list::ListArgs {
            agent: None,
            severity: None,
            status: None,
        };
        aa_cli::commands::alerts::list::run(args, &make_context(&uri), OutputFormat::Json)
    })
    .join()
    .unwrap();
    assert_eq!(result, ExitCode::SUCCESS);
}

#[tokio::test]
async fn alerts_list_error_returns_failure() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/alerts"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;
    let uri = server.uri();
    let result = std::thread::spawn(move || {
        let args = aa_cli::commands::alerts::list::ListArgs {
            agent: None,
            severity: None,
            status: None,
        };
        aa_cli::commands::alerts::list::run(args, &make_context(&uri), OutputFormat::Table)
    })
    .join()
    .unwrap();
    assert_eq!(result, ExitCode::FAILURE);
}

#[tokio::test]
async fn alerts_get_table_success() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/alerts/alert-1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(alert_json("alert-1", "unresolved")))
        .mount(&server)
        .await;
    let uri = server.uri();
    let result = std::thread::spawn(move || {
        let args = aa_cli::commands::alerts::get::GetArgs {
            alert_id: "alert-1".to_string(),
        };
        aa_cli::commands::alerts::get::run(args, &make_context(&uri), OutputFormat::Json)
    })
    .join()
    .unwrap();
    assert_eq!(result, ExitCode::SUCCESS);
}

#[tokio::test]
async fn alerts_get_not_found_returns_failure() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/alerts/missing"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;
    let uri = server.uri();
    let result = std::thread::spawn(move || {
        let args = aa_cli::commands::alerts::get::GetArgs {
            alert_id: "missing".to_string(),
        };
        aa_cli::commands::alerts::get::run(args, &make_context(&uri), OutputFormat::Table)
    })
    .join()
    .unwrap();
    assert_eq!(result, ExitCode::FAILURE);
}

#[tokio::test]
async fn alerts_resolve_force_success() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/alerts/alert-1/resolve"))
        .respond_with(ResponseTemplate::new(200).set_body_json(alert_json("alert-1", "resolved")))
        .mount(&server)
        .await;
    let uri = server.uri();
    let result = std::thread::spawn(move || {
        let args = aa_cli::commands::alerts::resolve::ResolveArgs {
            alert_id: "alert-1".to_string(),
            reason: Some("handled".to_string()),
            force: true,
        };
        aa_cli::commands::alerts::resolve::run(args, &make_context(&uri), OutputFormat::Table)
    })
    .join()
    .unwrap();
    assert_eq!(result, ExitCode::SUCCESS);
}

#[tokio::test]
async fn alerts_resolve_error_returns_failure() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/alerts/alert-1/resolve"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;
    let uri = server.uri();
    let result = std::thread::spawn(move || {
        let args = aa_cli::commands::alerts::resolve::ResolveArgs {
            alert_id: "alert-1".to_string(),
            reason: None,
            force: true,
        };
        aa_cli::commands::alerts::resolve::run(args, &make_context(&uri), OutputFormat::Json)
    })
    .join()
    .unwrap();
    assert_eq!(result, ExitCode::FAILURE);
}

// ── aasm approvals (skips `watch` — WebSocket streaming) ──────────────────

fn approval_json(id: &str, status: &str) -> serde_json::Value {
    serde_json::json!({
        "id": id, "agent_id": "support-agent", "action": "process_refund",
        "reason": "amount > $100", "status": status, "created_at": "2026-04-30T10:00:00Z"
    })
}

#[tokio::test]
async fn approvals_list_table_success() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/approvals"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "items": [approval_json("ap-1", "pending")], "page": 1, "per_page": 20, "total": 1
        })))
        .mount(&server)
        .await;
    let uri = server.uri();
    let result = std::thread::spawn(move || {
        let args = aa_cli::commands::approvals::list::ListArgs {
            output: None,
            status: None,
            agent: None,
        };
        aa_cli::commands::approvals::list::run_list(args, &make_context(&uri), OutputFormat::Table)
    })
    .join()
    .unwrap();
    assert_eq!(result, ExitCode::SUCCESS);
}

#[tokio::test]
async fn approvals_list_json_with_status_filter_success() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/approvals"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "items": [approval_json("ap-2", "approved")], "page": 1, "per_page": 20, "total": 1
        })))
        .mount(&server)
        .await;
    let uri = server.uri();
    let result = std::thread::spawn(move || {
        let args = aa_cli::commands::approvals::list::ListArgs {
            output: Some(OutputFormat::Json),
            status: Some(aa_cli::commands::approvals::list::ApprovalStatusFilter::Approved),
            agent: Some("support-agent".to_string()),
        };
        aa_cli::commands::approvals::list::run_list(args, &make_context(&uri), OutputFormat::Table)
    })
    .join()
    .unwrap();
    assert_eq!(result, ExitCode::SUCCESS);
}

#[tokio::test]
async fn approvals_list_error_returns_failure() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/approvals"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;
    let uri = server.uri();
    let result = std::thread::spawn(move || {
        let args = aa_cli::commands::approvals::list::ListArgs {
            output: None,
            status: None,
            agent: None,
        };
        aa_cli::commands::approvals::list::run_list(args, &make_context(&uri), OutputFormat::Table)
    })
    .join()
    .unwrap();
    assert_eq!(result, ExitCode::FAILURE);
}

#[tokio::test]
async fn approvals_get_table_success() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/approvals/ap-1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(approval_json("ap-1", "pending")))
        .mount(&server)
        .await;
    let uri = server.uri();
    let result = std::thread::spawn(move || {
        let args = aa_cli::commands::approvals::get::GetArgs {
            id: "ap-1".to_string(),
            output: None,
        };
        aa_cli::commands::approvals::get::run_get(args, &make_context(&uri), OutputFormat::Table)
    })
    .join()
    .unwrap();
    assert_eq!(result, ExitCode::SUCCESS);
}

#[tokio::test]
async fn approvals_get_json_success() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/approvals/ap-1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(approval_json("ap-1", "pending")))
        .mount(&server)
        .await;
    let uri = server.uri();
    let result = std::thread::spawn(move || {
        let args = aa_cli::commands::approvals::get::GetArgs {
            id: "ap-1".to_string(),
            output: Some(OutputFormat::Json),
        };
        aa_cli::commands::approvals::get::run_get(args, &make_context(&uri), OutputFormat::Table)
    })
    .join()
    .unwrap();
    assert_eq!(result, ExitCode::SUCCESS);
}

#[tokio::test]
async fn approvals_get_not_found_returns_failure() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/approvals/missing"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;
    let uri = server.uri();
    let result = std::thread::spawn(move || {
        let args = aa_cli::commands::approvals::get::GetArgs {
            id: "missing".to_string(),
            output: None,
        };
        aa_cli::commands::approvals::get::run_get(args, &make_context(&uri), OutputFormat::Table)
    })
    .join()
    .unwrap();
    assert_eq!(result, ExitCode::FAILURE);
}

#[tokio::test]
async fn approvals_approve_success() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/approvals/ap-1/approve"))
        .respond_with(ResponseTemplate::new(200).set_body_json(approval_json("ap-1", "approved")))
        .mount(&server)
        .await;
    let uri = server.uri();
    // A non-empty --reason short-circuits stdin resolution, keeping the test
    // deterministic (no stdin read).
    let result = std::thread::spawn(move || {
        let args = aa_cli::commands::approvals::approve::ApproveArgs {
            id: "ap-1".to_string(),
            reason: Some("looks good".to_string()),
        };
        aa_cli::commands::approvals::approve::run_approve(args, &make_context(&uri))
    })
    .join()
    .unwrap();
    assert_eq!(result, ExitCode::SUCCESS);
}

#[tokio::test]
async fn approvals_approve_error_returns_failure() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/approvals/ap-1/approve"))
        .respond_with(ResponseTemplate::new(409))
        .mount(&server)
        .await;
    let uri = server.uri();
    let result = std::thread::spawn(move || {
        let args = aa_cli::commands::approvals::approve::ApproveArgs {
            id: "ap-1".to_string(),
            reason: Some("looks good".to_string()),
        };
        aa_cli::commands::approvals::approve::run_approve(args, &make_context(&uri))
    })
    .join()
    .unwrap();
    assert_eq!(result, ExitCode::FAILURE);
}

#[tokio::test]
async fn approvals_reject_success() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/approvals/ap-1/reject"))
        .respond_with(ResponseTemplate::new(200).set_body_json(approval_json("ap-1", "rejected")))
        .mount(&server)
        .await;
    let uri = server.uri();
    let result = std::thread::spawn(move || {
        let args = aa_cli::commands::approvals::reject::RejectArgs {
            id: "ap-1".to_string(),
            reason: Some("not authorized".to_string()),
        };
        aa_cli::commands::approvals::reject::run_reject(args, &make_context(&uri))
    })
    .join()
    .unwrap();
    assert_eq!(result, ExitCode::SUCCESS);
}

#[tokio::test]
async fn approvals_reject_error_returns_failure() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/approvals/ap-1/reject"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;
    let uri = server.uri();
    let result = std::thread::spawn(move || {
        let args = aa_cli::commands::approvals::reject::RejectArgs {
            id: "ap-1".to_string(),
            reason: Some("not authorized".to_string()),
        };
        aa_cli::commands::approvals::reject::run_reject(args, &make_context(&uri))
    })
    .join()
    .unwrap();
    assert_eq!(result, ExitCode::FAILURE);
}
