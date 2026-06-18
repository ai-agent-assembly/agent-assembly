//! Integration tests for `aasm policy apply` via REST API.

use std::io::Write;
use std::path::PathBuf;
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
async fn apply_sends_post_to_api_and_prints_response() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/api/v1/policies"))
        .and(body_partial_json(serde_json::json!({
            "policy_yaml": "apiVersion: agent-assembly.dev/v1alpha1\nkind: GovernancePolicy\nmetadata:\n  name: test-policy\n  version: \"1.0.0\"\nspec:\n  budget:\n    daily_limit_usd: 1000.0\n"
        })))
        .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
            "name": "abc123def456",
            "version": "2026-04-30T12:00:00Z",
            "active": true,
            "rule_count": 0
        })))
        .expect(1)
        .mount(&server)
        .await;

    let mut tmp = tempfile::NamedTempFile::new().unwrap();
    tmp.write_all(b"apiVersion: agent-assembly.dev/v1alpha1\nkind: GovernancePolicy\nmetadata:\n  name: test-policy\n  version: \"1.0.0\"\nspec:\n  budget:\n    daily_limit_usd: 1000.0\n").unwrap();

    let file_path = tmp.path().to_path_buf();
    let uri = server.uri();

    // run_apply creates its own tokio runtime via block_on, so run it
    // on a separate thread to avoid nesting inside the #[tokio::test] runtime.
    let result = std::thread::spawn(move || {
        let args = aa_cli::commands::policy::history::ApplyArgs {
            file: file_path,
            applied_by: None,
        };
        let ctx = make_context(&uri);
        aa_cli::commands::policy::history::run_apply(args, &ctx)
    })
    .join()
    .unwrap();

    assert_eq!(result, ExitCode::SUCCESS);
}

#[tokio::test]
async fn apply_fails_fast_on_invalid_yaml_without_api_call() {
    let server = MockServer::start().await;

    // No mock mounted — any API call would cause an unmatched request error.

    let mut tmp = tempfile::NamedTempFile::new().unwrap();
    tmp.write_all(b"this is not valid yaml: [").unwrap();

    let file_path = tmp.path().to_path_buf();
    let uri = server.uri();

    let result = std::thread::spawn(move || {
        let args = aa_cli::commands::policy::history::ApplyArgs {
            file: file_path,
            applied_by: None,
        };
        let ctx = make_context(&uri);
        aa_cli::commands::policy::history::run_apply(args, &ctx)
    })
    .join()
    .unwrap();

    assert_eq!(result, ExitCode::FAILURE);
}

#[test]
fn apply_fails_on_missing_file() {
    let args = aa_cli::commands::policy::history::ApplyArgs {
        file: PathBuf::from("/tmp/nonexistent-policy-file-aaasm179.yaml"),
        applied_by: None,
    };
    let ctx = make_context("http://localhost:9999");

    let result = aa_cli::commands::policy::history::run_apply(args, &ctx);
    assert_eq!(result, ExitCode::FAILURE);
}
