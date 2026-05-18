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
