//! Live-gateway integration tests for `/api/v1/policies/*` (AAASM-1484).
//!
//! All 7 tests run against a real in-process Axum server (no mocking).
//! Pagination uses `per_page` (not `limit`) per `PaginationParams`.
//! Inactive versions are hidden by default; pass `include_archived=true`
//! to retrieve the full version history.

mod common;

use common::TopologyTestEnv;
use reqwest::StatusCode;
use serde_json::Value;

// ── Shared policy YAML fixtures ─────────────────────────────────────────────

const TOPOLOGY_IT_YAML: &str = r#"
apiVersion: agent-assembly.dev/v1alpha1
kind: GovernancePolicy
metadata:
  name: topology-it-policy
  version: "0.1.0"
spec:
  rules: []
"#;

const ANOTHER_YAML: &str = r#"
apiVersion: agent-assembly.dev/v1alpha1
kind: GovernancePolicy
metadata:
  name: another-policy
  version: "1.0.0"
spec:
  rules: []
"#;

// ── Helpers ─────────────────────────────────────────────────────────────────

async fn post_policy(client: &reqwest::Client, base_url: &str, yaml: &str) -> Value {
    let resp = client
        .post(format!("{base_url}/api/v1/policies"))
        .header("content-type", "application/json")
        .json(&serde_json::json!({"policy_yaml": yaml}))
        .send()
        .await
        .expect("POST /api/v1/policies");
    assert_eq!(resp.status(), StatusCode::CREATED, "expected 201 from POST /policies");
    resp.json::<Value>().await.expect("201 body json")
}

// ── Active policy tests ──────────────────────────────────────────────────────

/// Clean fixture; active endpoint returns the harness-seeded topology-it-policy.
#[tokio::test(flavor = "multi_thread")]
async fn policies_active_returns_default_seeded_policy() {
    let env = TopologyTestEnv::start().await.expect("harness start");
    let client = reqwest::Client::new();

    let resp = client
        .get(format!("{}/api/v1/policies/active", env.base_url()))
        .send()
        .await
        .expect("GET /api/v1/policies/active");

    assert_eq!(resp.status(), StatusCode::OK);
    let body: Value = resp.json().await.expect("json body");

    assert_eq!(body["name"], "topology-it-policy", "policy name from engine metadata");
    assert_eq!(body["version"], "0.1.0", "policy version from engine metadata");
    assert_eq!(body["active"], true);
    assert_eq!(body["rule_count"], 0, "harness policy has zero rules");
}

/// Active-policy response contains populated metadata fields.
#[tokio::test(flavor = "multi_thread")]
async fn policies_active_includes_metadata_fields() {
    let env = TopologyTestEnv::start().await.expect("harness start");
    let client = reqwest::Client::new();

    let resp = client
        .get(format!("{}/api/v1/policies/active", env.base_url()))
        .send()
        .await
        .expect("GET /api/v1/policies/active");

    assert_eq!(resp.status(), StatusCode::OK);
    let body: Value = resp.json().await.expect("json body");

    assert!(
        body["name"].as_str().map(|s| !s.is_empty()).unwrap_or(false),
        "name must be a non-empty string"
    );
    assert!(
        body["version"].as_str().map(|s| !s.is_empty()).unwrap_or(false),
        "version must be a non-empty string"
    );
    assert_eq!(body["active"], true, "active field must be true");
    assert!(body["rule_count"].is_number(), "rule_count must be a number");
    assert!(body["policy_yaml"].is_string(), "policy_yaml must be present as string");
}

/// When no named policy is loaded the active endpoint returns HTTP 404.
#[tokio::test(flavor = "multi_thread")]
async fn policies_active_when_no_policy_loaded_returns_404() {
    let env = TopologyTestEnv::start_empty_policy()
        .await
        .expect("nameless-policy harness");
    let client = reqwest::Client::new();

    let resp = client
        .get(format!("{}/api/v1/policies/active", env.base_url()))
        .send()
        .await
        .expect("GET /api/v1/policies/active on empty-policy harness");

    assert_eq!(resp.status(), StatusCode::NOT_FOUND, "no named policy → 404");
}

// ── List tests ───────────────────────────────────────────────────────────────

/// After seeding one policy version the list returns exactly that one entry.
#[tokio::test(flavor = "multi_thread")]
async fn policies_list_includes_active_only_when_seeded() {
    let env = TopologyTestEnv::start().await.expect("harness start");
    let client = reqwest::Client::new();

    // Seed the default topology-it-policy YAML into history via the API.
    post_policy(&client, &env.base_url(), TOPOLOGY_IT_YAML).await;

    let resp = client
        .get(format!("{}/api/v1/policies", env.base_url()))
        .send()
        .await
        .expect("GET /api/v1/policies");

    assert_eq!(resp.status(), StatusCode::OK);
    let body: Value = resp.json().await.expect("json body");

    let items = body["items"].as_array().expect("items array");
    assert_eq!(items.len(), 1, "exactly one active policy without include_archived");
    assert_eq!(items[0]["active"], true, "the returned entry is active");
    assert_eq!(body["total"], 1, "total reflects the single active entry");
}

/// per_page pagination param is respected and metadata fields are present.
///
/// Pagination uses `per_page` (not `limit`). The `total` field reports the
/// count of the filtered set; `per_page` echoes the requested page size.
#[tokio::test(flavor = "multi_thread")]
async fn policies_list_pagination_param_respected() {
    let env = TopologyTestEnv::start().await.expect("harness start");
    let client = reqwest::Client::new();

    // Seed 5 policy versions with distinct content so they get unique SHA256 entries.
    for i in 1..=5u32 {
        let yaml = format!(
            "apiVersion: agent-assembly.dev/v1alpha1\nkind: GovernancePolicy\nmetadata:\n  name: pagination-policy\n  version: \"{i}.0.0\"\nspec:\n  rules: []\n"
        );
        post_policy(&client, &env.base_url(), &yaml).await;
    }

    // Request page 1, 2 items, with include_archived=true to see full history.
    let resp = client
        .get(format!(
            "{}/api/v1/policies?per_page=2&include_archived=true",
            env.base_url()
        ))
        .send()
        .await
        .expect("GET /api/v1/policies with pagination");

    assert_eq!(resp.status(), StatusCode::OK);
    let body: Value = resp.json().await.expect("json body");

    let items = body["items"].as_array().expect("items array");
    assert_eq!(items.len(), 2, "per_page=2 returns at most 2 items");
    assert_eq!(body["total"], 5, "total reflects all 5 seeded versions");
    assert_eq!(body["per_page"], 2, "per_page echoes the requested value");
    assert_eq!(body["page"], 1, "page defaults to 1 when not specified");
}

/// Without include_archived only the active version is listed; with it all
/// previous versions appear too.
#[tokio::test(flavor = "multi_thread")]
async fn policies_list_includes_archived_when_flag_set() {
    let env = TopologyTestEnv::start().await.expect("harness start");
    let client = reqwest::Client::new();

    // Seed two versions: first becomes inactive once the second is applied.
    post_policy(&client, &env.base_url(), TOPOLOGY_IT_YAML).await;
    post_policy(&client, &env.base_url(), ANOTHER_YAML).await;

    // Without include_archived: only the active (most-recent) version.
    let resp = client
        .get(format!("{}/api/v1/policies", env.base_url()))
        .send()
        .await
        .expect("GET /api/v1/policies (no flag)");
    let body: Value = resp.json().await.expect("json body");
    assert_eq!(body["total"], 1, "only active version without include_archived");

    // With include_archived=true: both versions visible.
    let resp = client
        .get(format!("{}/api/v1/policies?include_archived=true", env.base_url()))
        .send()
        .await
        .expect("GET /api/v1/policies?include_archived=true");
    let body: Value = resp.json().await.expect("json body");
    assert_eq!(body["total"], 2, "all versions visible with include_archived=true");
}

// ── Schema validation ────────────────────────────────────────────────────────

/// Active-policy response body validates against the PolicyResponse schema in
/// openapi/v1.yaml. This is a shape sanity-check for the policies module;
/// full OpenAPI conformance is covered by the ST-Q test.
#[tokio::test(flavor = "multi_thread")]
async fn policies_active_response_matches_openapi_schema() {
    let env = TopologyTestEnv::start().await.expect("harness start");
    let client = reqwest::Client::new();

    let resp = client
        .get(format!("{}/api/v1/policies/active", env.base_url()))
        .send()
        .await
        .expect("GET /api/v1/policies/active");
    assert_eq!(resp.status(), StatusCode::OK);
    let body: Value = resp.json().await.expect("json body");

    // Load the generated OpenAPI spec and extract the PolicyResponse schema.
    let spec_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../openapi/v1.yaml");
    let spec_str =
        std::fs::read_to_string(&spec_path).unwrap_or_else(|e| panic!("failed to read {}: {e}", spec_path.display()));
    let spec: Value = serde_yaml::from_str(&spec_str).expect("parse openapi spec yaml");

    let schema = spec
        .pointer("/components/schemas/PolicyResponse")
        .expect("PolicyResponse not found in openapi/v1.yaml components/schemas")
        .clone();

    assert!(
        jsonschema::is_valid(&schema, &body),
        "GET /api/v1/policies/active response does not match PolicyResponse schema: {body}"
    );
}
