//! End-to-end test for `aasm admin run-retention` — Epic 18 Story S-I.5
//! (AAASM-1872).
//!
//! The subcommand POSTs to `/api/v1/admin/retention-policy/run` on the
//! configured gateway and prints the returned `RetentionRunStatsDto`.
//! These tests drive that path against a wiremock server so the wire
//! contract — endpoint, request body, response shape, exit codes — is
//! pinned independently of any running aa-api binary.

use std::process::ExitCode;

use wiremock::matchers::{body_json, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use aa_cli::commands::admin::retention::{dispatch, RunRetentionArgs};
use aa_cli::config::ResolvedContext;
use aa_cli::output::OutputFormat;

fn make_context(api_url: &str) -> ResolvedContext {
    ResolvedContext {
        name: None,
        api_url: api_url.to_string(),
        api_key: None,
    }
}

fn sample_stats_json() -> serde_json::Value {
    serde_json::json!({
        "ran_at": "2026-05-23T12:34:56Z",
        "hot_rows": 100,
        "compressed_rows": 20,
        "archived_rows": 5,
        "dropped_rows": 3,
        "freed_bytes": 4096,
        "dry_run": false
    })
}

/// Default invocation (no `--dry-run`) POSTs `{"dry_run": false}` and
/// exits SUCCESS when the gateway returns a valid stats JSON.
#[tokio::test]
async fn run_retention_default_posts_dry_run_false_and_succeeds() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/api/v1/admin/retention-policy/run"))
        .and(body_json(serde_json::json!({"dry_run": false})))
        .respond_with(ResponseTemplate::new(200).set_body_json(sample_stats_json()))
        .expect(1)
        .mount(&server)
        .await;

    let uri = server.uri();
    let result = std::thread::spawn(move || {
        let ctx = make_context(&uri);
        dispatch(RunRetentionArgs { dry_run: false }, &ctx, OutputFormat::Table)
    })
    .join()
    .unwrap();

    assert_eq!(result, ExitCode::SUCCESS);
}

/// `--dry-run` puts `{"dry_run": true}` on the wire.
#[tokio::test]
async fn run_retention_dry_run_flag_flows_to_request_body() {
    let server = MockServer::start().await;

    let mut dry_run_stats = sample_stats_json();
    dry_run_stats["dry_run"] = serde_json::Value::Bool(true);

    Mock::given(method("POST"))
        .and(path("/api/v1/admin/retention-policy/run"))
        .and(body_json(serde_json::json!({"dry_run": true})))
        .respond_with(ResponseTemplate::new(200).set_body_json(dry_run_stats))
        .expect(1)
        .mount(&server)
        .await;

    let uri = server.uri();
    let result = std::thread::spawn(move || {
        let ctx = make_context(&uri);
        dispatch(RunRetentionArgs { dry_run: true }, &ctx, OutputFormat::Json)
    })
    .join()
    .unwrap();

    assert_eq!(result, ExitCode::SUCCESS);
}

/// Connect-refused (unreachable gateway) surfaces as `ExitCode::FAILURE`.
/// Points the CLI at a port that has no listener — the request errors
/// out at connection time and the dispatcher must NOT silently exit 0.
#[tokio::test]
async fn run_retention_unreachable_gateway_returns_failure() {
    // Bind ourselves to grab a free port, then drop the listener so the
    // port is definitively closed before the CLI dials.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral");
    let port = listener.local_addr().unwrap().port();
    drop(listener);

    let uri = format!("http://127.0.0.1:{port}");
    let result = std::thread::spawn(move || {
        let ctx = make_context(&uri);
        dispatch(RunRetentionArgs { dry_run: false }, &ctx, OutputFormat::Table)
    })
    .join()
    .unwrap();

    assert_eq!(
        result,
        ExitCode::FAILURE,
        "connect-refused must surface as ExitCode::FAILURE, not silent success"
    );
}

/// `--output yaml` renders the response as YAML; the wire contract is
/// unchanged.
#[tokio::test]
async fn run_retention_respects_yaml_output_selector() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/api/v1/admin/retention-policy/run"))
        .respond_with(ResponseTemplate::new(200).set_body_json(sample_stats_json()))
        .expect(1)
        .mount(&server)
        .await;

    let uri = server.uri();
    let result = std::thread::spawn(move || {
        let ctx = make_context(&uri);
        dispatch(RunRetentionArgs { dry_run: false }, &ctx, OutputFormat::Yaml)
    })
    .join()
    .unwrap();

    assert_eq!(result, ExitCode::SUCCESS);
}
