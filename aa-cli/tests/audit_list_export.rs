//! Integration tests for `aasm audit list` and `aasm audit export` via mock HTTP server.

use std::process::ExitCode;

use wiremock::matchers::{method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn make_context(api_url: &str) -> aa_cli::config::ResolvedContext {
    aa_cli::config::ResolvedContext {
        name: None,
        api_url: api_url.to_string(),
        api_key: None,
    }
}

fn sample_response() -> serde_json::Value {
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

#[tokio::test]
async fn audit_list_returns_success_with_mock_data() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/api/v1/logs"))
        .respond_with(ResponseTemplate::new(200).set_body_json(sample_response()))
        .expect(1)
        .mount(&server)
        .await;

    let uri = server.uri();

    let result = std::thread::spawn(move || {
        let args = aa_cli::commands::audit::list::ListArgs {
            agent: None,
            action: None,
            result: None,
            since: None,
            until: None,
            limit: 50,
        };
        let ctx = make_context(&uri);
        aa_cli::commands::audit::list::run(args, &ctx, aa_cli::output::OutputFormat::Table)
    })
    .join()
    .unwrap();

    assert_eq!(result, ExitCode::SUCCESS);
}

#[tokio::test]
async fn audit_list_with_agent_filter_sends_query_param() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/api/v1/logs"))
        .and(query_param("agent_id", "aa001"))
        .respond_with(ResponseTemplate::new(200).set_body_json(sample_response()))
        .expect(1)
        .mount(&server)
        .await;

    let uri = server.uri();

    let result = std::thread::spawn(move || {
        let args = aa_cli::commands::audit::list::ListArgs {
            agent: Some("aa001".to_string()),
            action: None,
            result: None,
            since: None,
            until: None,
            limit: 50,
        };
        let ctx = make_context(&uri);
        aa_cli::commands::audit::list::run(args, &ctx, aa_cli::output::OutputFormat::Json)
    })
    .join()
    .unwrap();

    assert_eq!(result, ExitCode::SUCCESS);
}

#[tokio::test]
async fn audit_list_fails_on_server_error() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/api/v1/logs"))
        .respond_with(ResponseTemplate::new(500))
        .expect(1)
        .mount(&server)
        .await;

    let uri = server.uri();

    let result = std::thread::spawn(move || {
        let args = aa_cli::commands::audit::list::ListArgs {
            agent: None,
            action: None,
            result: None,
            since: None,
            until: None,
            limit: 50,
        };
        let ctx = make_context(&uri);
        aa_cli::commands::audit::list::run(args, &ctx, aa_cli::output::OutputFormat::Table)
    })
    .join()
    .unwrap();

    assert_eq!(result, ExitCode::FAILURE);
}

#[tokio::test]
async fn audit_export_csv_returns_success() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/api/v1/logs"))
        .respond_with(ResponseTemplate::new(200).set_body_json(sample_response()))
        .expect(1)
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
        let ctx = make_context(&uri);
        aa_cli::commands::audit::export::run(args, &ctx)
    })
    .join()
    .unwrap();

    assert_eq!(result, ExitCode::SUCCESS);
}

#[tokio::test]
async fn audit_export_json_to_file_creates_output() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/api/v1/logs"))
        .respond_with(ResponseTemplate::new(200).set_body_json(sample_response()))
        .expect(1)
        .mount(&server)
        .await;

    let uri = server.uri();
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let tmp_path = tmp.path().to_string_lossy().to_string();

    let result = std::thread::spawn(move || {
        let args = aa_cli::commands::audit::export::ExportArgs {
            format: aa_cli::commands::audit::models::ExportFormat::Json,
            compliance: None,
            output_file: Some(tmp_path),
            agent: None,
            action: None,
            result: None,
            since: None,
            until: None,
            limit: 1000,
        };
        let ctx = make_context(&uri);
        aa_cli::commands::audit::export::run(args, &ctx)
    })
    .join()
    .unwrap();

    assert_eq!(result, ExitCode::SUCCESS);

    // Verify the file contains valid JSON.
    let contents = std::fs::read_to_string(tmp.path()).unwrap();
    let entries: Vec<aa_cli::commands::audit::models::AuditEntry> = serde_json::from_str(&contents).unwrap();
    assert_eq!(entries.len(), 2);
}

#[tokio::test]
async fn audit_export_csv_with_compliance_header() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/api/v1/logs"))
        .respond_with(ResponseTemplate::new(200).set_body_json(sample_response()))
        .expect(1)
        .mount(&server)
        .await;

    let uri = server.uri();
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let tmp_path = tmp.path().to_string_lossy().to_string();

    let result = std::thread::spawn(move || {
        let args = aa_cli::commands::audit::export::ExportArgs {
            format: aa_cli::commands::audit::models::ExportFormat::Csv,
            compliance: Some(aa_cli::commands::audit::models::ComplianceFormat::EuAiAct),
            output_file: Some(tmp_path),
            agent: None,
            action: None,
            result: None,
            since: None,
            until: None,
            limit: 1000,
        };
        let ctx = make_context(&uri);
        aa_cli::commands::audit::export::run(args, &ctx)
    })
    .join()
    .unwrap();

    assert_eq!(result, ExitCode::SUCCESS);

    let contents = std::fs::read_to_string(tmp.path()).unwrap();
    assert!(contents.contains("EU AI Act"));
    assert!(contents.contains("timestamp,agent_id"));
}
