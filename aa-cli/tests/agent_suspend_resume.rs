//! Integration tests for `aasm agent suspend` and `aasm agent resume` via mock HTTP server.

use std::process::ExitCode;

use wiremock::matchers::{body_partial_json, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn make_context(api_url: &str) -> aa_cli::config::ResolvedContext {
    aa_cli::config::ResolvedContext {
        name: None,
        api_url: api_url.to_string(),
        api_key: None,
    }
}

#[tokio::test]
async fn suspend_sends_post_and_returns_success() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/api/v1/agents/aabbccdd00112233/suspend"))
        .and(body_partial_json(serde_json::json!({
            "reason": "anomaly spike"
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "agent_id": "aabbccdd00112233",
            "previous_status": "Active",
            "new_status": "Suspended(Manual)"
        })))
        .expect(1)
        .mount(&server)
        .await;

    let uri = server.uri();

    let result = std::thread::spawn(move || {
        let args = aa_cli::commands::agent::suspend::SuspendArgs {
            agent_id: "aabbccdd00112233".to_string(),
            reason: "anomaly spike".to_string(),
            force: true,
        };
        let ctx = make_context(&uri);
        aa_cli::commands::agent::suspend::run(args, &ctx, aa_cli::output::OutputFormat::Json)
    })
    .join()
    .unwrap();

    assert_eq!(result, ExitCode::SUCCESS);
}

#[tokio::test]
async fn suspend_returns_failure_on_404() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/api/v1/agents/0000000000000000/suspend"))
        .respond_with(ResponseTemplate::new(404).set_body_json(serde_json::json!({
            "status": 404,
            "title": "Not Found",
            "detail": "Agent not found"
        })))
        .expect(1)
        .mount(&server)
        .await;

    let uri = server.uri();

    let result = std::thread::spawn(move || {
        let args = aa_cli::commands::agent::suspend::SuspendArgs {
            agent_id: "0000000000000000".to_string(),
            reason: "test".to_string(),
            force: true,
        };
        let ctx = make_context(&uri);
        aa_cli::commands::agent::suspend::run(args, &ctx, aa_cli::output::OutputFormat::Table)
    })
    .join()
    .unwrap();

    assert_eq!(result, ExitCode::FAILURE);
}

#[tokio::test]
async fn resume_sends_post_and_returns_success() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/api/v1/agents/aabbccdd00112233/resume"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "agent_id": "aabbccdd00112233",
            "previous_status": "Suspended(Manual)",
            "new_status": "Active"
        })))
        .expect(1)
        .mount(&server)
        .await;

    let uri = server.uri();

    let result = std::thread::spawn(move || {
        let args = aa_cli::commands::agent::resume::ResumeArgs {
            agent_id: "aabbccdd00112233".to_string(),
        };
        let ctx = make_context(&uri);
        aa_cli::commands::agent::resume::run(args, &ctx, aa_cli::output::OutputFormat::Json)
    })
    .join()
    .unwrap();

    assert_eq!(result, ExitCode::SUCCESS);
}

#[tokio::test]
async fn resume_returns_failure_on_404() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/api/v1/agents/0000000000000000/resume"))
        .respond_with(ResponseTemplate::new(404).set_body_json(serde_json::json!({
            "status": 404,
            "title": "Not Found",
            "detail": "Agent not found"
        })))
        .expect(1)
        .mount(&server)
        .await;

    let uri = server.uri();

    let result = std::thread::spawn(move || {
        let args = aa_cli::commands::agent::resume::ResumeArgs {
            agent_id: "0000000000000000".to_string(),
        };
        let ctx = make_context(&uri);
        aa_cli::commands::agent::resume::run(args, &ctx, aa_cli::output::OutputFormat::Table)
    })
    .join()
    .unwrap();

    assert_eq!(result, ExitCode::FAILURE);
}

// ── render-format coverage (AAASM-3812) ───────────────────────────────
//
// The success tests above only render in `Json`; the `Table` and `Yaml`
// success-render arms of `suspend`/`resume` were never exercised.

async fn suspend_ok(uri: String, fmt: aa_cli::output::OutputFormat) -> ExitCode {
    std::thread::spawn(move || {
        let args = aa_cli::commands::agent::suspend::SuspendArgs {
            agent_id: "aabbccdd00112233".to_string(),
            reason: "drift".to_string(),
            force: true,
        };
        aa_cli::commands::agent::suspend::run(args, &make_context(&uri), fmt)
    })
    .join()
    .unwrap()
}

async fn mount_suspend_ok(server: &MockServer) {
    Mock::given(method("POST"))
        .and(path("/api/v1/agents/aabbccdd00112233/suspend"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "agent_id": "aabbccdd00112233",
            "previous_status": "Active",
            "new_status": "Suspended(Manual)"
        })))
        .mount(server)
        .await;
}

#[tokio::test]
async fn suspend_table_success_renders() {
    let server = MockServer::start().await;
    mount_suspend_ok(&server).await;
    assert_eq!(
        suspend_ok(server.uri(), aa_cli::output::OutputFormat::Table).await,
        ExitCode::SUCCESS
    );
}

#[tokio::test]
async fn suspend_yaml_success_renders() {
    let server = MockServer::start().await;
    mount_suspend_ok(&server).await;
    assert_eq!(
        suspend_ok(server.uri(), aa_cli::output::OutputFormat::Yaml).await,
        ExitCode::SUCCESS
    );
}

#[tokio::test]
async fn resume_yaml_success_renders() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/agents/aabbccdd00112233/resume"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "agent_id": "aabbccdd00112233",
            "previous_status": "Suspended(Manual)",
            "new_status": "Active"
        })))
        .mount(&server)
        .await;
    let uri = server.uri();
    let result = std::thread::spawn(move || {
        let args = aa_cli::commands::agent::resume::ResumeArgs {
            agent_id: "aabbccdd00112233".to_string(),
        };
        aa_cli::commands::agent::resume::run(args, &make_context(&uri), aa_cli::output::OutputFormat::Yaml)
    })
    .join()
    .unwrap();
    assert_eq!(result, ExitCode::SUCCESS);
}
