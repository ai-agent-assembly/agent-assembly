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

use serde_json::Value;

fn load_spec() -> Value {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../openapi/v1.yaml");
    let yaml = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    serde_yaml::from_str(&yaml).expect("openapi/v1.yaml must be valid YAML")
}

// ── TC-1: spec file loads and has 39 paths ───────────────────────────────────

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
        path_count, 39,
        "openapi/v1.yaml must declare exactly 39 paths, found {path_count}"
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
        "/api/v1/costs",
        "/api/v1/health",
        "/api/v1/iam/api-keys",
        "/api/v1/iam/api-keys/{id}/revoke",
        "/api/v1/iam/api-keys/{id}/rotate",
        "/api/v1/logs",
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
