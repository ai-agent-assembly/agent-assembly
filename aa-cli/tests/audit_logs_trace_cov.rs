//! Coverage-focused integration tests for `aasm audit`, `aasm logs`, and
//! `aasm trace` (AAASM-3804). These exercise the still-uncovered branches of
//! the command `run()`/`dispatch()` paths that the existing
//! `audit_list_export.rs` / `logs_follow.rs` suites don't reach: YAML output,
//! transport/parse error arms, JSONL export, the compliance-export error path,
//! the `trace` dispatch across every output format, and its client error arm.
//!
//! Harness note: every command builds its own runtime (or uses
//! `reqwest::blocking`), so each `run()`/`dispatch()` is invoked on a dedicated
//! `std::thread` to avoid blocking/nesting the test's tokio runtime.

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

/// An api_url whose port is not listening, so `reqwest` fails to connect — used
/// to drive the "failed to connect" error arms deterministically.
const UNREACHABLE: &str = "http://127.0.0.1:1";

fn audit_log_body() -> serde_json::Value {
    serde_json::json!({
        "items": [
            {
                "seq": 0,
                "timestamp": "2026-04-30T10:00:00Z",
                "agent_id": "aa001",
                "session_id": "sess001",
                "event_type": "ToolCallIntercepted",
                "payload": "{\"tool\":\"bash\",\"result\":\"allow\",\"policy\":\"default\"}"
            },
            {
                "seq": 1,
                "timestamp": "2026-04-30T10:01:00Z",
                "agent_id": "aa002",
                "session_id": "sess002",
                "event_type": "PolicyViolation",
                "payload": "{\"tool\":\"rm\",\"result\":\"deny\",\"policy\":\"deny-rm\"}"
            }
        ],
        "page": 1,
        "per_page": 50,
        "total": 2
    })
}

fn list_args() -> aa_cli::commands::audit::list::ListArgs {
    aa_cli::commands::audit::list::ListArgs {
        agent: None,
        action: None,
        result: None,
        since: None,
        until: None,
        limit: 50,
        dry_run_only: false,
    }
}

// ── audit list ────────────────────────────────────────────────────────────

#[tokio::test]
async fn audit_list_yaml_output_succeeds() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/logs"))
        .respond_with(ResponseTemplate::new(200).set_body_json(audit_log_body()))
        .mount(&server)
        .await;
    let uri = server.uri();
    let result = std::thread::spawn(move || {
        aa_cli::commands::audit::list::run(list_args(), &make_context(&uri), OutputFormat::Yaml)
    })
    .join()
    .unwrap();
    assert_eq!(result, ExitCode::SUCCESS);
}

#[tokio::test]
async fn audit_list_empty_result_renders_empty_table() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/logs"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "items": [], "page": 1, "per_page": 50, "total": 0
        })))
        .mount(&server)
        .await;
    let uri = server.uri();
    let result = std::thread::spawn(move || {
        aa_cli::commands::audit::list::run(list_args(), &make_context(&uri), OutputFormat::Table)
    })
    .join()
    .unwrap();
    assert_eq!(result, ExitCode::SUCCESS);
}

#[tokio::test]
async fn audit_list_connection_failure_returns_failure() {
    // No server — connect refused exercises the transport-error arm.
    let result = std::thread::spawn(|| {
        aa_cli::commands::audit::list::run(list_args(), &make_context(UNREACHABLE), OutputFormat::Table)
    })
    .join()
    .unwrap();
    assert_eq!(result, ExitCode::FAILURE);
}

#[tokio::test]
async fn audit_list_unparseable_body_returns_failure() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/logs"))
        .respond_with(ResponseTemplate::new(200).set_body_string("not json"))
        .mount(&server)
        .await;
    let uri = server.uri();
    let result = std::thread::spawn(move || {
        aa_cli::commands::audit::list::run(list_args(), &make_context(&uri), OutputFormat::Table)
    })
    .join()
    .unwrap();
    assert_eq!(result, ExitCode::FAILURE);
}

// ── audit export ──────────────────────────────────────────────────────────

#[tokio::test]
async fn audit_export_jsonl_to_file_writes_one_line_per_entry() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/logs"))
        .respond_with(ResponseTemplate::new(200).set_body_json(audit_log_body()))
        .mount(&server)
        .await;
    let uri = server.uri();
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let tmp_path = tmp.path().to_string_lossy().to_string();
    let result = std::thread::spawn(move || {
        let args = aa_cli::commands::audit::export::ExportArgs {
            format: aa_cli::commands::audit::models::ExportFormat::Jsonl,
            compliance: None,
            output_file: Some(tmp_path),
            agent: None,
            action: None,
            result: None,
            since: None,
            until: None,
            limit: 1000,
        };
        aa_cli::commands::audit::export::run(args, &make_context(&uri))
    })
    .join()
    .unwrap();
    assert_eq!(result, ExitCode::SUCCESS);
    let contents = std::fs::read_to_string(tmp.path()).unwrap();
    let lines: Vec<&str> = contents.lines().filter(|l| !l.trim().is_empty()).collect();
    assert_eq!(lines.len(), 2, "one JSONL record per audit entry");
    for line in lines {
        let _: aa_cli::commands::audit::models::AuditEntry = serde_json::from_str(line).unwrap();
    }
}

#[tokio::test]
async fn audit_export_json_to_stdout_succeeds() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/logs"))
        .respond_with(ResponseTemplate::new(200).set_body_json(audit_log_body()))
        .mount(&server)
        .await;
    let uri = server.uri();
    let result = std::thread::spawn(move || {
        let args = aa_cli::commands::audit::export::ExportArgs {
            format: aa_cli::commands::audit::models::ExportFormat::Json,
            compliance: None,
            output_file: None, // stdout path
            agent: None,
            action: None,
            result: None,
            since: None,
            until: None,
            limit: 1000,
        };
        aa_cli::commands::audit::export::run(args, &make_context(&uri))
    })
    .join()
    .unwrap();
    assert_eq!(result, ExitCode::SUCCESS);
}

#[tokio::test]
async fn audit_export_connection_failure_returns_failure() {
    let result = std::thread::spawn(|| {
        let args = aa_cli::commands::audit::export::ExportArgs {
            format: aa_cli::commands::audit::models::ExportFormat::Csv,
            compliance: None,
            output_file: None,
            agent: None,
            action: None,
            result: None,
            since: None,
            until: None,
            limit: 1000,
        };
        aa_cli::commands::audit::export::run(args, &make_context(UNREACHABLE))
    })
    .join()
    .unwrap();
    assert_eq!(result, ExitCode::FAILURE);
}

#[tokio::test]
async fn audit_export_server_error_returns_failure() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/logs"))
        .respond_with(ResponseTemplate::new(503))
        .mount(&server)
        .await;
    let uri = server.uri();
    let result = std::thread::spawn(move || {
        let args = aa_cli::commands::audit::export::ExportArgs {
            format: aa_cli::commands::audit::models::ExportFormat::Csv,
            compliance: None,
            output_file: None,
            agent: None,
            action: None,
            result: None,
            since: None,
            until: None,
            limit: 1000,
        };
        aa_cli::commands::audit::export::run(args, &make_context(&uri))
    })
    .join()
    .unwrap();
    assert_eq!(result, ExitCode::FAILURE);
}

#[tokio::test]
async fn audit_export_uncreatable_output_file_returns_failure() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/logs"))
        .respond_with(ResponseTemplate::new(200).set_body_json(audit_log_body()))
        .mount(&server)
        .await;
    let uri = server.uri();
    let result = std::thread::spawn(move || {
        let args = aa_cli::commands::audit::export::ExportArgs {
            format: aa_cli::commands::audit::models::ExportFormat::Csv,
            compliance: None,
            // Parent directory does not exist → File::create fails.
            output_file: Some("/nonexistent-dir-aaasm-3804/out.csv".to_string()),
            agent: None,
            action: None,
            result: None,
            since: None,
            until: None,
            limit: 1000,
        };
        aa_cli::commands::audit::export::run(args, &make_context(&uri))
    })
    .join()
    .unwrap();
    assert_eq!(result, ExitCode::FAILURE);
}

// ── audit compliance-export ─────────────────────────────────────────────────

#[test]
fn audit_compliance_export_missing_input_returns_failure() {
    let args = aa_cli::commands::audit::compliance::ComplianceExportArgs {
        input: std::path::PathBuf::from("/nonexistent-aaasm-3804/audit.jsonl"),
        format: aa_cli::commands::audit::models::ExportFormat::Jsonl,
        compliance: None,
        output_file: None,
        agent: None,
        event_type: None,
        since: None,
        until: None,
    };
    assert_eq!(aa_cli::commands::audit::compliance::run(args), ExitCode::FAILURE);
}

// ── logs (fetch / non-follow dispatch) ──────────────────────────────────────

fn logs_args() -> aa_cli::commands::logs::LogsArgs {
    aa_cli::commands::logs::LogsArgs {
        follow: false,
        agent: None,
        r#type: None,
        since: None,
        until: None,
        limit: 50,
        no_color: false,
        output: None,
    }
}

#[tokio::test]
async fn logs_fetch_table_with_color_succeeds() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/logs"))
        .respond_with(ResponseTemplate::new(200).set_body_json(audit_log_body()))
        .mount(&server)
        .await;
    let uri = server.uri();
    let result = std::thread::spawn(move || aa_cli::commands::logs::dispatch(logs_args(), &make_context(&uri)))
        .join()
        .unwrap();
    assert_eq!(result, ExitCode::SUCCESS);
}

#[tokio::test]
async fn logs_fetch_json_output_succeeds() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/logs"))
        .respond_with(ResponseTemplate::new(200).set_body_json(audit_log_body()))
        .mount(&server)
        .await;
    let uri = server.uri();
    let result = std::thread::spawn(move || {
        let mut args = logs_args();
        args.output = Some(OutputFormat::Json);
        args.no_color = true;
        aa_cli::commands::logs::dispatch(args, &make_context(&uri))
    })
    .join()
    .unwrap();
    assert_eq!(result, ExitCode::SUCCESS);
}

#[tokio::test]
async fn logs_fetch_multiple_type_filter_applies_client_side() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/logs"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "items": [
                {"seq":0,"timestamp":"2026-04-30T10:00:00Z","agent_id":"a","session_id":"s","event_type":"violation","payload":"x"},
                {"seq":1,"timestamp":"2026-04-30T10:01:00Z","agent_id":"a","session_id":"s","event_type":"budget","payload":"y"},
                {"seq":2,"timestamp":"2026-04-30T10:02:00Z","agent_id":"a","session_id":"s","event_type":"approval","payload":"z"}
            ],
            "page":1,"per_page":50,"total":3
        })))
        .mount(&server)
        .await;
    let uri = server.uri();
    let result = std::thread::spawn(move || {
        use aa_cli::commands::logs::types::LogEventType;
        let mut args = logs_args();
        // Two types → server filter omitted, client-side filter keeps these two.
        args.r#type = Some(vec![LogEventType::Violation, LogEventType::Budget]);
        aa_cli::commands::logs::dispatch(args, &make_context(&uri))
    })
    .join()
    .unwrap();
    assert_eq!(result, ExitCode::SUCCESS);
}

#[tokio::test]
async fn logs_fetch_since_until_window_filters_entries() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/logs"))
        .respond_with(ResponseTemplate::new(200).set_body_json(audit_log_body()))
        .mount(&server)
        .await;
    let uri = server.uri();
    let result = std::thread::spawn(move || {
        let mut args = logs_args();
        args.since = Some("2026-04-30T09:00:00Z".to_string());
        args.until = Some("2026-04-30T11:00:00Z".to_string());
        aa_cli::commands::logs::dispatch(args, &make_context(&uri))
    })
    .join()
    .unwrap();
    assert_eq!(result, ExitCode::SUCCESS);
}

#[tokio::test]
async fn logs_fetch_connection_failure_returns_failure() {
    let result = std::thread::spawn(|| aa_cli::commands::logs::dispatch(logs_args(), &make_context(UNREACHABLE)))
        .join()
        .unwrap();
    assert_eq!(result, ExitCode::FAILURE);
}

#[tokio::test]
async fn logs_fetch_server_error_returns_failure() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/logs"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;
    let uri = server.uri();
    let result = std::thread::spawn(move || aa_cli::commands::logs::dispatch(logs_args(), &make_context(&uri)))
        .join()
        .unwrap();
    assert_eq!(result, ExitCode::FAILURE);
}

#[tokio::test]
async fn logs_fetch_unparseable_body_returns_failure() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/logs"))
        .respond_with(ResponseTemplate::new(200).set_body_string("<<<not json>>>"))
        .mount(&server)
        .await;
    let uri = server.uri();
    let result = std::thread::spawn(move || aa_cli::commands::logs::dispatch(logs_args(), &make_context(&uri)))
        .join()
        .unwrap();
    assert_eq!(result, ExitCode::FAILURE);
}

// ── trace ───────────────────────────────────────────────────────────────────

fn trace_wire_body(session_id: &str) -> serde_json::Value {
    serde_json::json!({
        "session_id": session_id,
        "agent_id": "aabbccdd00112233aabbccdd00112233",
        "spans": [
            {
                "span_id": "root",
                "parent_span_id": null,
                "operation": "llm_call",
                "decision": "allow",
                "start_time": "2026-01-01T00:00:00Z",
                "end_time": "2026-01-01T00:00:00.800Z"
            },
            {
                "span_id": "child",
                "parent_span_id": "root",
                "operation": "tool_call",
                "decision": "allow",
                "start_time": "2026-01-01T00:00:00.100Z",
                "end_time": "2026-01-01T00:00:00.250Z"
            }
        ]
    })
}

fn trace_args(session_id: &str, format: aa_cli::commands::trace::TraceFormat) -> aa_cli::commands::trace::TraceArgs {
    aa_cli::commands::trace::TraceArgs {
        session_id: session_id.to_string(),
        format,
    }
}

#[tokio::test]
async fn trace_tree_table_succeeds() {
    let server = MockServer::start().await;
    let sid = "sess-001";
    Mock::given(method("GET"))
        .and(path(format!("/api/v1/traces/{sid}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(trace_wire_body(sid)))
        .mount(&server)
        .await;
    let uri = server.uri();
    let result = std::thread::spawn(move || {
        aa_cli::commands::trace::dispatch(
            trace_args(sid, aa_cli::commands::trace::TraceFormat::Tree),
            &make_context(&uri),
            OutputFormat::Table,
        )
    })
    .join()
    .unwrap();
    assert_eq!(result, ExitCode::SUCCESS);
}

#[tokio::test]
async fn trace_timeline_table_succeeds() {
    let server = MockServer::start().await;
    let sid = "sess-002";
    Mock::given(method("GET"))
        .and(path(format!("/api/v1/traces/{sid}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(trace_wire_body(sid)))
        .mount(&server)
        .await;
    let uri = server.uri();
    let result = std::thread::spawn(move || {
        aa_cli::commands::trace::dispatch(
            trace_args(sid, aa_cli::commands::trace::TraceFormat::Timeline),
            &make_context(&uri),
            OutputFormat::Table,
        )
    })
    .join()
    .unwrap();
    assert_eq!(result, ExitCode::SUCCESS);
}

#[tokio::test]
async fn trace_json_output_succeeds() {
    let server = MockServer::start().await;
    let sid = "sess-003";
    Mock::given(method("GET"))
        .and(path(format!("/api/v1/traces/{sid}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(trace_wire_body(sid)))
        .mount(&server)
        .await;
    let uri = server.uri();
    let result = std::thread::spawn(move || {
        aa_cli::commands::trace::dispatch(
            trace_args(sid, aa_cli::commands::trace::TraceFormat::Tree),
            &make_context(&uri),
            OutputFormat::Json,
        )
    })
    .join()
    .unwrap();
    assert_eq!(result, ExitCode::SUCCESS);
}

#[tokio::test]
async fn trace_yaml_output_succeeds() {
    let server = MockServer::start().await;
    let sid = "sess-004";
    Mock::given(method("GET"))
        .and(path(format!("/api/v1/traces/{sid}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(trace_wire_body(sid)))
        .mount(&server)
        .await;
    let uri = server.uri();
    let result = std::thread::spawn(move || {
        aa_cli::commands::trace::dispatch(
            trace_args(sid, aa_cli::commands::trace::TraceFormat::Tree),
            &make_context(&uri),
            OutputFormat::Yaml,
        )
    })
    .join()
    .unwrap();
    assert_eq!(result, ExitCode::SUCCESS);
}

#[tokio::test]
async fn trace_not_found_returns_failure() {
    let server = MockServer::start().await;
    let sid = "missing";
    Mock::given(method("GET"))
        .and(path(format!("/api/v1/traces/{sid}")))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;
    let uri = server.uri();
    let result = std::thread::spawn(move || {
        aa_cli::commands::trace::dispatch(
            trace_args(sid, aa_cli::commands::trace::TraceFormat::Tree),
            &make_context(&uri),
            OutputFormat::Table,
        )
    })
    .join()
    .unwrap();
    assert_eq!(result, ExitCode::FAILURE);
}

#[test]
fn trace_build_url_trims_trailing_slash() {
    let ctx = make_context("http://localhost:8080/");
    let url = aa_cli::commands::trace::client::build_trace_url(&ctx, "sess-xyz");
    assert_eq!(url, "http://localhost:8080/api/v1/traces/sess-xyz");
}
