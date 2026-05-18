//! AAASM-1495 / F122 ST-N — live-gateway integration tests for `GET /api/v1/tools`.
//!
//! ## Endpoint under test
//!
//! `GET /api/v1/tools` — returns `Vec<DevToolInfo>` from the gateway's
//! `DiscoveryService`. Runs all registered `DevToolAdapter`s concurrently
//! via `spawn_blocking` and returns only the detected ones.
//!
//! ## Divergences from the ticket AC
//!
//! | Ticket expectation | Actual behaviour |
//! |---|---|
//! | Filter params: `category`, `enabled`, `team_id` | No query params accepted; handler calls `discover_all()` directly |
//! | Response shape `{tools:[…], total:N}` | Plain `Vec<DevToolInfo>` JSON array |
//! | Fields: `id`, `name`, `description`, `category`, `enabled` | Actual fields: `kind`, `version`, `install_path`, `governance_level`, `supports_mcp`, `supports_managed_settings` |
//! | Harness baseline non-empty | Default harness wires `DiscoveryService::with_adapters(vec![])` → always `[]` |
//!
//! Tests that require non-empty results use `TopologyTestEnv::start_with_discovery`
//! with local stub adapters. Tests with the default env confirm empty-baseline behaviour.

mod common;

use std::path::PathBuf;

use aa_core::policy::PolicyDocument;
use aa_core::{AdapterError, DevToolAdapter, DevToolInfo, DevToolKind, GovernanceLevel, McpServerInfo};
use async_trait::async_trait;
use common::TopologyTestEnv;

// ── Stub adapters ────────────────────────────────────────────────────────────

struct AlwaysDetectsClaudeCode;

#[async_trait]
impl DevToolAdapter for AlwaysDetectsClaudeCode {
    fn detect(&self) -> Option<DevToolInfo> {
        Some(DevToolInfo {
            kind: DevToolKind::ClaudeCode,
            version: Some("1.0.0".into()),
            install_path: PathBuf::from("/usr/local/bin/claude"),
            governance_level: GovernanceLevel::L3Native,
            supports_mcp: true,
            supports_managed_settings: true,
        })
    }
    async fn generate_managed_settings(&self, _: &PolicyDocument) -> Result<String, AdapterError> {
        Err(AdapterError::SettingsGenerationFailed("stub".into()))
    }
    async fn apply_settings(&self, _: &str) -> Result<(), AdapterError> {
        Err(AdapterError::SettingsApplyFailed(std::io::Error::other("stub")))
    }
    fn build_launch_command(
        &self,
        _: &[String],
        _: &str,
        _: Option<&str>,
        _: Option<&str>,
    ) -> Result<std::process::Command, AdapterError> {
        Err(AdapterError::LaunchFailed("stub".into()))
    }
    async fn list_mcp_servers(&self) -> Result<Vec<McpServerInfo>, AdapterError> {
        Ok(vec![])
    }
    async fn apply_mcp_governance(&self, _: &[String], _: &[String]) -> Result<(), AdapterError> {
        Ok(())
    }
    fn governance_level(&self) -> GovernanceLevel {
        GovernanceLevel::L3Native
    }
}

struct AlwaysDetectsCodex;

#[async_trait]
impl DevToolAdapter for AlwaysDetectsCodex {
    fn detect(&self) -> Option<DevToolInfo> {
        Some(DevToolInfo {
            kind: DevToolKind::Codex,
            version: None,
            install_path: PathBuf::from("/usr/local/bin/codex"),
            governance_level: GovernanceLevel::L2Enforce,
            supports_mcp: false,
            supports_managed_settings: false,
        })
    }
    async fn generate_managed_settings(&self, _: &PolicyDocument) -> Result<String, AdapterError> {
        Err(AdapterError::SettingsGenerationFailed("stub".into()))
    }
    async fn apply_settings(&self, _: &str) -> Result<(), AdapterError> {
        Err(AdapterError::SettingsApplyFailed(std::io::Error::other("stub")))
    }
    fn build_launch_command(
        &self,
        _: &[String],
        _: &str,
        _: Option<&str>,
        _: Option<&str>,
    ) -> Result<std::process::Command, AdapterError> {
        Err(AdapterError::LaunchFailed("stub".into()))
    }
    async fn list_mcp_servers(&self) -> Result<Vec<McpServerInfo>, AdapterError> {
        Ok(vec![])
    }
    async fn apply_mcp_governance(&self, _: &[String], _: &[String]) -> Result<(), AdapterError> {
        Ok(())
    }
    fn governance_level(&self) -> GovernanceLevel {
        GovernanceLevel::L2Enforce
    }
}

struct PanickingAdapter;

#[async_trait]
impl DevToolAdapter for PanickingAdapter {
    fn detect(&self) -> Option<DevToolInfo> {
        panic!("intentional panic for test")
    }
    async fn generate_managed_settings(&self, _: &PolicyDocument) -> Result<String, AdapterError> {
        Err(AdapterError::SettingsGenerationFailed("stub".into()))
    }
    async fn apply_settings(&self, _: &str) -> Result<(), AdapterError> {
        Err(AdapterError::SettingsApplyFailed(std::io::Error::other("stub")))
    }
    fn build_launch_command(
        &self,
        _: &[String],
        _: &str,
        _: Option<&str>,
        _: Option<&str>,
    ) -> Result<std::process::Command, AdapterError> {
        Err(AdapterError::LaunchFailed("stub".into()))
    }
    async fn list_mcp_servers(&self) -> Result<Vec<McpServerInfo>, AdapterError> {
        Ok(vec![])
    }
    async fn apply_mcp_governance(&self, _: &[String], _: &[String]) -> Result<(), AdapterError> {
        Ok(())
    }
    fn governance_level(&self) -> GovernanceLevel {
        GovernanceLevel::L0Discover
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

/// Default harness wires empty adapters → response must be `[]`.
#[tokio::test(flavor = "multi_thread")]
async fn tools_list_empty_returns_200_and_empty_array() {
    let env = TopologyTestEnv::start().await.expect("harness should start");
    let url = format!("{}/api/v1/tools", env.base_url());

    let resp = reqwest::get(&url).await.expect("GET /api/v1/tools should succeed");
    assert_eq!(resp.status(), reqwest::StatusCode::OK, "expected 200");

    let body: serde_json::Value = resp.json().await.expect("body should be valid JSON");
    assert_eq!(
        body,
        serde_json::json!([]),
        "expected empty array with no adapters registered"
    );
}

/// One stub adapter → response must contain exactly one entry.
#[tokio::test(flavor = "multi_thread")]
async fn tools_list_with_one_adapter_returns_one_entry() {
    let env = TopologyTestEnv::start_with_discovery(vec![Box::new(AlwaysDetectsClaudeCode)])
        .await
        .expect("harness should start");
    let url = format!("{}/api/v1/tools", env.base_url());

    let resp = reqwest::get(&url).await.expect("GET /api/v1/tools should succeed");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);

    let body: serde_json::Value = resp.json().await.unwrap();
    let arr = body.as_array().expect("response should be an array");
    assert_eq!(arr.len(), 1, "expected exactly one tool entry");
}

/// Entry must contain the six `DevToolInfo` fields (actual schema, not the ticket's assumed schema).
#[tokio::test(flavor = "multi_thread")]
async fn tools_list_entry_has_expected_fields() {
    let env = TopologyTestEnv::start_with_discovery(vec![Box::new(AlwaysDetectsClaudeCode)])
        .await
        .expect("harness should start");
    let url = format!("{}/api/v1/tools", env.base_url());

    let resp = reqwest::get(&url).await.unwrap();
    let body: serde_json::Value = resp.json().await.unwrap();
    let entry = &body[0];

    assert!(!entry["kind"].is_null(), "entry must have 'kind'");
    assert!(!entry["install_path"].is_null(), "entry must have 'install_path'");
    assert!(
        !entry["governance_level"].is_null(),
        "entry must have 'governance_level'"
    );
    assert!(!entry["supports_mcp"].is_null(), "entry must have 'supports_mcp'");
    assert!(
        !entry["supports_managed_settings"].is_null(),
        "entry must have 'supports_managed_settings'"
    );

    assert_eq!(entry["kind"], "ClaudeCode", "kind should match stub adapter");
    assert_eq!(entry["version"], "1.0.0", "version should match stub adapter");
    assert_eq!(entry["governance_level"], "L3Native");
    assert_eq!(entry["supports_mcp"], true);
    assert_eq!(entry["supports_managed_settings"], true);
}

/// Two different adapters → response must contain exactly two entries.
#[tokio::test(flavor = "multi_thread")]
async fn tools_list_multiple_adapters_all_detected() {
    let env =
        TopologyTestEnv::start_with_discovery(vec![Box::new(AlwaysDetectsClaudeCode), Box::new(AlwaysDetectsCodex)])
            .await
            .expect("harness should start");
    let url = format!("{}/api/v1/tools", env.base_url());

    let resp = reqwest::get(&url).await.unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);

    let body: serde_json::Value = resp.json().await.unwrap();
    let arr = body.as_array().expect("should be array");
    assert_eq!(arr.len(), 2, "both adapters should be detected");

    let kinds: Vec<&str> = arr.iter().map(|e| e["kind"].as_str().unwrap_or("")).collect();
    assert!(kinds.contains(&"ClaudeCode"), "ClaudeCode entry should be present");
    assert!(kinds.contains(&"Codex"), "Codex entry should be present");
}

/// A panicking adapter must not crash the gateway — the other adapter's result is still returned.
#[tokio::test(flavor = "multi_thread")]
async fn tools_list_panicking_adapter_is_skipped() {
    let env =
        TopologyTestEnv::start_with_discovery(vec![Box::new(PanickingAdapter), Box::new(AlwaysDetectsClaudeCode)])
            .await
            .expect("harness should start");
    let url = format!("{}/api/v1/tools", env.base_url());

    let resp = reqwest::get(&url)
        .await
        .expect("request should succeed even with a panicking adapter");
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::OK,
        "panic in adapter must not propagate to HTTP layer"
    );

    let body: serde_json::Value = resp.json().await.unwrap();
    let arr = body.as_array().expect("should be array");
    assert_eq!(arr.len(), 1, "only the non-panicking adapter's result should appear");
    assert_eq!(arr[0]["kind"], "ClaudeCode");
}

/// Two sequential GET calls must return byte-identical JSON (no spurious mutation).
#[tokio::test(flavor = "multi_thread")]
async fn tools_list_is_consistent_across_calls() {
    let env = TopologyTestEnv::start_with_discovery(vec![Box::new(AlwaysDetectsClaudeCode)])
        .await
        .expect("harness should start");
    let url = format!("{}/api/v1/tools", env.base_url());
    let client = reqwest::Client::new();

    let r1: serde_json::Value = client.get(&url).send().await.unwrap().json().await.unwrap();
    let r2: serde_json::Value = client.get(&url).send().await.unwrap().json().await.unwrap();
    assert_eq!(r1, r2, "two sequential calls should return identical responses");
}

/// Extra / unknown query params must be silently ignored (handler accepts no params).
///
/// Documents live behaviour: Axum does not reject unknown query params when the
/// handler has no `Query` extractor, so `?nonsense=foo` is tolerated and the
/// full tool list is returned unchanged.
#[tokio::test(flavor = "multi_thread")]
async fn tools_list_unknown_query_param_is_ignored() {
    let env = TopologyTestEnv::start_with_discovery(vec![Box::new(AlwaysDetectsClaudeCode)])
        .await
        .expect("harness should start");

    let url_plain = format!("{}/api/v1/tools", env.base_url());
    let url_with_param = format!("{}/api/v1/tools?nonsense=foo", env.base_url());
    let client = reqwest::Client::new();

    let plain: serde_json::Value = client.get(&url_plain).send().await.unwrap().json().await.unwrap();
    let with_param: serde_json::Value = client.get(&url_with_param).send().await.unwrap().json().await.unwrap();

    assert_eq!(
        plain, with_param,
        "unknown query param should be ignored; response should be identical to plain GET"
    );
}

/// Response must carry `Content-Type: application/json`.
#[tokio::test(flavor = "multi_thread")]
async fn tools_list_content_type_is_application_json() {
    let env = TopologyTestEnv::start().await.expect("harness should start");
    let url = format!("{}/api/v1/tools", env.base_url());

    let resp = reqwest::get(&url).await.expect("GET /api/v1/tools should succeed");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);

    let content_type = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        content_type.contains("application/json"),
        "Content-Type should be application/json, got: {content_type}"
    );
}
