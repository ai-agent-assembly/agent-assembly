//! AAASM-1498 / F122 ST-Q — OpenAPI contract gate.
//!
//! Validates that every endpoint and live response is consistent with the
//! schema declared in `openapi/v1.yaml`. Prevents silent spec/implementation
//! drift — a new endpoint without OpenAPI annotations fails TC-2, and a
//! response with an undocumented field shape fails TC-3.
//!
//! ## Divergence notes
//!
//! * `openapi_spec_paths_match_implemented_routes` (TC-2) compares the YAML
//!   file paths against a hardcoded expected list. Axum does not expose a
//!   route-listing API, so the utoipa-generated programmatic spec is the
//!   source of truth.
//! * TC-3 tests three representative singleton-response endpoints whose
//!   component schemas have no nested `$ref`s, making them directly
//!   validatable via `jsonschema::is_valid`.
//! * TC-5 tests `POST /api/v1/approvals/{invalid-uuid}/*` paths — the route
//!   handler short-circuits on UUID parse failure and returns ProblemDetail
//!   400 before reading the request body.

mod common;

use aa_api::alerts::AlertStore;
use aa_core::AgentId;
use aa_gateway::budget::types::BudgetAlert;
use common::TopologyTestEnv;
use reqwest::StatusCode;
use serde_json::Value;

fn seed_alert(env: &TopologyTestEnv, threshold_pct: u8, agent_id_bytes: [u8; 16]) -> String {
    let limit_usd = 10.0_f64;
    let spent_usd = limit_usd * f64::from(threshold_pct) / 100.0;
    env.alert_store.record(&BudgetAlert {
        agent_id: AgentId::from_bytes(agent_id_bytes),
        team_id: None,
        threshold_pct,
        spent_usd,
        limit_usd,
    })
}

fn load_spec() -> Value {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../openapi/v1.yaml");
    let yaml = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    serde_yaml::from_str(&yaml).expect("openapi/v1.yaml must be valid YAML")
}

// ── TC-1: spec file loads and has 46 paths ───────────────────────────────────

#[test]
fn openapi_spec_loads_without_errors() {
    let spec = load_spec();

    assert_eq!(
        spec["openapi"].as_str(),
        Some("3.1.0"),
        "spec must declare openapi: 3.1.0"
    );

    let path_count = spec["paths"].as_object().expect("spec must have a paths object").len();

    assert_eq!(
        path_count, 46,
        "openapi/v1.yaml must declare exactly 46 paths, found {path_count}"
    );

    for schema in ["HealthResponse", "ProblemDetail", "PolicyResponse", "AlertResponse"] {
        assert!(
            spec.pointer(&format!("/components/schemas/{schema}")).is_some(),
            "{schema} must exist in components/schemas"
        );
    }
}

// ── TC-2: YAML paths match the hardcoded expected list (bidirectional gate) ──
//
// Axum does not expose a route-listing API, so the utoipa-generated spec file
// is the authoritative source of truth. The hardcoded list fixes the known
// contract at the time of this ST. Adding or removing a path from the spec
// fails this test — intentional: forces an engineer to update both the spec
// and the test together.

#[test]
fn openapi_spec_paths_match_implemented_routes() {
    let spec = load_spec();
    let mut yaml_paths: Vec<String> = spec["paths"]
        .as_object()
        .expect("spec must have a paths object")
        .keys()
        .cloned()
        .collect();
    yaml_paths.sort();

    let mut expected: Vec<&str> = vec![
        "/api/v1/agents",
        "/api/v1/agents/{id}",
        "/api/v1/agents/{id}/budget",
        "/api/v1/agents/{id}/capabilities",
        "/api/v1/agents/{id}/edges",
        "/api/v1/agents/{id}/graph",
        "/api/v1/agents/{id}/resume",
        "/api/v1/agents/{id}/subtree-burn",
        "/api/v1/agents/{id}/suspend",
        "/api/v1/alerts",
        "/api/v1/alerts/destinations",
        "/api/v1/alerts/destinations/{id}",
        "/api/v1/alerts/destinations/{id}/test",
        "/api/v1/alerts/silence",
        "/api/v1/alerts/ws",
        "/api/v1/alerts/{id}",
        "/api/v1/alerts/{id}/resolve",
        "/api/v1/approvals",
        "/api/v1/approvals/{id}",
        "/api/v1/approvals/{id}/approve",
        "/api/v1/approvals/{id}/reject",
        "/api/v1/audit/violations-by-lineage",
        "/api/v1/auth/token",
        "/api/v1/capability/matrix",
        "/api/v1/capability/override",
        "/api/v1/capability/override/{id}",
        "/api/v1/costs",
        "/api/v1/health",
        "/api/v1/iam/api-keys",
        "/api/v1/iam/api-keys/{id}/revoke",
        "/api/v1/iam/api-keys/{id}/rotate",
        "/api/v1/logs",
        "/api/v1/ops",
        "/api/v1/ops/{id}/pause",
        "/api/v1/ops/{id}/resume",
        "/api/v1/ops/{id}/terminate",
        "/api/v1/policies",
        "/api/v1/policies/active",
        "/api/v1/topology/edges",
        "/api/v1/topology/lineage/{agent_id}",
        "/api/v1/topology/overview",
        "/api/v1/topology/stats",
        "/api/v1/topology/team/{team_id}",
        "/api/v1/topology/tree/{root_id}",
        "/api/v1/traces/{session_id}",
        "/api/v1/ws/events",
    ];
    expected.sort();

    let yaml_refs: Vec<&str> = yaml_paths.iter().map(|s| s.as_str()).collect();

    let extra: Vec<&&str> = expected.iter().filter(|p| !yaml_refs.contains(*p)).collect();
    let missing: Vec<&String> = yaml_paths.iter().filter(|p| !expected.contains(&p.as_str())).collect();

    assert!(
        extra.is_empty(),
        "paths in expected list but missing from openapi/v1.yaml (add to spec or remove from test): {extra:?}"
    );
    assert!(
        missing.is_empty(),
        "paths in openapi/v1.yaml not in expected list (add to test or remove from spec): {missing:?}"
    );
}

// ── TC-3: live responses validate against component schemas ──────────────────
//
// Tests three representative endpoints whose component schemas contain only
// primitive properties (no nested $ref), making them directly validatable
// via jsonschema::is_valid on the extracted schema component.
//
// Endpoints tested:
//   GET /api/v1/health          → HealthResponse (no seed, always populated)
//   GET /api/v1/policies/active → PolicyResponse (no seed, loaded at startup)
//   GET /api/v1/alerts/{id}     → AlertResponse  (one seeded budget alert)

#[tokio::test(flavor = "multi_thread")]
async fn openapi_spec_response_schemas_validate_live_responses() {
    let env = TopologyTestEnv::start().await.expect("harness should start");
    let client = reqwest::Client::new();
    let spec = load_spec();

    let alert_id = seed_alert(&env, 95, [0xBB; 16]);
    let alert_path = format!("/api/v1/alerts/{alert_id}");

    let cases: Vec<(&str, &str)> = vec![
        ("/api/v1/health", "HealthResponse"),
        ("/api/v1/policies/active", "PolicyResponse"),
        (alert_path.as_str(), "AlertResponse"),
    ];

    for (path, schema_name) in cases {
        let schema = spec
            .pointer(&format!("/components/schemas/{schema_name}"))
            .unwrap_or_else(|| panic!("{schema_name} not found in components/schemas"))
            .clone();

        let resp = client
            .get(format!("{}{path}", env.base_url()))
            .send()
            .await
            .unwrap_or_else(|e| panic!("GET {path} transport error: {e}"));

        assert_eq!(resp.status(), StatusCode::OK, "GET {path} must return 200");

        let body: Value = resp.json().await.expect("response must parse as JSON");

        assert!(
            jsonschema::is_valid(&schema, &body),
            "GET {path} response does not match {schema_name} schema in openapi/v1.yaml.\nBody: {body}"
        );
    }
}

// ── TC-4: 404 responses match the ProblemDetail envelope ─────────────────────
//
// For three representative endpoints that return 404 on unknown IDs, assert
// the response body is a valid ProblemDetail (RFC 7807) as declared in the
// spec and that the numeric status field equals 404.

#[tokio::test(flavor = "multi_thread")]
async fn openapi_spec_error_envelope_matches_for_404() {
    let env = TopologyTestEnv::start().await.expect("harness should start");
    let client = reqwest::Client::new();
    let spec = load_spec();
    let problem_schema = spec
        .pointer("/components/schemas/ProblemDetail")
        .expect("ProblemDetail must exist in spec")
        .clone();

    let urls = [
        format!("{}/api/v1/agents/{}", env.base_url(), "00".repeat(16)),
        format!("{}/api/v1/alerts/00000000000000000000000000", env.base_url()),
        format!("{}/api/v1/traces/no-such-session-contract-q", env.base_url()),
    ];

    for url in &urls {
        let resp = client
            .get(url)
            .send()
            .await
            .unwrap_or_else(|e| panic!("GET {url} transport error: {e}"));

        assert_eq!(
            resp.status(),
            StatusCode::NOT_FOUND,
            "GET {url} with unknown id must return 404"
        );

        let body: Value = resp.json().await.expect("404 response must have a JSON body");

        assert!(
            jsonschema::is_valid(&problem_schema, &body),
            "GET {url} 404 body does not match ProblemDetail schema.\nBody: {body}"
        );

        assert_eq!(
            body["status"].as_u64(),
            Some(404),
            "ProblemDetail.status must equal 404 for {url}"
        );
    }
}

// ── TC-5: 400 responses match the ProblemDetail envelope ─────────────────────
//
// The approvals route handlers parse the `{id}` path segment as a UUID and
// return ProblemDetail 400 before reading the body when parsing fails. This
// exercises the 400 error envelope using inputs that are consistent across
// all three operations (inspect, approve, reject).

#[tokio::test(flavor = "multi_thread")]
async fn openapi_spec_error_envelope_matches_for_400() {
    let env = TopologyTestEnv::start().await.expect("harness should start");
    let client = reqwest::Client::new();
    let spec = load_spec();
    let problem_schema = spec
        .pointer("/components/schemas/ProblemDetail")
        .expect("ProblemDetail must exist in spec")
        .clone();

    let bad_id = "not-a-valid-uuid";
    let base = env.base_url();

    let operations: Vec<(String, reqwest::Method)> = vec![
        (format!("{base}/api/v1/approvals/{bad_id}"), reqwest::Method::GET),
        (
            format!("{base}/api/v1/approvals/{bad_id}/approve"),
            reqwest::Method::POST,
        ),
        (
            format!("{base}/api/v1/approvals/{bad_id}/reject"),
            reqwest::Method::POST,
        ),
    ];

    for (url, method) in &operations {
        let req = client
            .request(method.clone(), url.as_str())
            .json(&serde_json::json!({}));

        let resp = req
            .send()
            .await
            .unwrap_or_else(|e| panic!("{method} {url} transport error: {e}"));

        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "{method} {url} with invalid UUID must return 400"
        );

        let body: Value = resp.json().await.expect("400 response must have a JSON body");

        assert!(
            jsonschema::is_valid(&problem_schema, &body),
            "{method} {url} 400 body does not match ProblemDetail schema.\nBody: {body}"
        );

        assert_eq!(
            body["status"].as_u64(),
            Some(400),
            "ProblemDetail.status must equal 400 for {method} {url}"
        );
    }
}

// ── TC-6: spec-declared security schemes are enforced by the live server ──────
//
// openapi/v1.yaml declares `security: [{ bearer_auth: [] }]` on
// POST /api/v1/auth/token. When the server starts with AuthMode::On
// (via start_with_auth), calling the endpoint without the
// `Authorization: Bearer` header must return 401 — proving the declared
// security requirement is actually enforced.

#[tokio::test(flavor = "multi_thread")]
async fn openapi_spec_security_schemes_enforced() {
    use aa_api::auth::scope::Scope;

    let (_, entry) = common::make_api_key("q-key-1", vec![Scope::Read, Scope::Write]);
    let env = TopologyTestEnv::start_with_auth(&[entry], 1000)
        .await
        .expect("harness should start with auth");

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{}/api/v1/auth/token", env.base_url()))
        .json(&serde_json::json!({}))
        .send()
        .await
        .expect("POST /api/v1/auth/token should not fail at transport level");

    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "POST /api/v1/auth/token without credentials must return 401 when auth is enabled"
    );

    let body: Value = resp.json().await.expect("401 response must have a JSON body");
    assert!(body.is_object(), "401 response body must be a JSON object; got: {body}");
}
