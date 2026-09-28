//! Tests that the generated OpenAPI spec is structurally correct.

use utoipa::OpenApi;

#[test]
fn spec_version_is_3_1_0() {
    let spec = aa_api::ApiDoc::openapi();
    assert_eq!(spec.info.version, "0.0.1");
    // utoipa 5.x generates OpenAPI 3.1.0
    let yaml = serde_yaml::to_string(&spec).unwrap();
    assert!(yaml.starts_with("openapi: 3.1.0"));
}

#[test]
fn health_path_exists() {
    let spec = aa_api::ApiDoc::openapi();
    let paths = &spec.paths;
    assert!(
        paths.paths.contains_key("/api/v1/health"),
        "expected /api/v1/health in paths, got: {:?}",
        paths.paths.keys().collect::<Vec<_>>()
    );
}

#[test]
fn health_response_schema_exists() {
    let spec = aa_api::ApiDoc::openapi();
    let schemas = &spec.components.as_ref().expect("components should exist").schemas;
    assert!(schemas.contains_key("HealthResponse"), "HealthResponse schema missing");
    assert!(schemas.contains_key("ProblemDetail"), "ProblemDetail schema missing");
}

#[test]
fn schemas_have_descriptions() {
    let spec = aa_api::ApiDoc::openapi();
    let yaml = serde_yaml::to_string(&spec).unwrap();
    // Doc comments from Rust structs should appear as descriptions
    assert!(
        yaml.contains("Response body for the health endpoint"),
        "HealthResponse description missing from spec"
    );
    assert!(
        yaml.contains("RFC 7807 Problem Details JSON body"),
        "ProblemDetail description missing from spec"
    );
}

#[test]
fn health_get_has_operation_id() {
    let spec = aa_api::ApiDoc::openapi();
    let yaml = serde_yaml::to_string(&spec).unwrap();
    assert!(
        yaml.contains("operationId: health"),
        "health operationId missing from spec"
    );
}

#[test]
fn ws_events_path_exists() {
    let spec = aa_api::ApiDoc::openapi();
    let paths = &spec.paths;
    assert!(
        paths.paths.contains_key("/api/v1/ws/events"),
        "expected /api/v1/ws/events in paths, got: {:?}",
        paths.paths.keys().collect::<Vec<_>>()
    );
}

#[test]
fn ws_events_has_query_params() {
    let spec = aa_api::ApiDoc::openapi();
    let yaml = serde_yaml::to_string(&spec).unwrap();
    // WsQueryParams fields should appear as query parameters
    assert!(
        yaml.contains("operationId: ws_events_handler"),
        "ws operationId missing"
    );
    assert!(yaml.contains("name: types"), "types query param missing");
    assert!(yaml.contains("name: agent_id"), "agent_id query param missing");
    assert!(yaml.contains("name: since"), "since query param missing");
}

#[test]
fn governance_event_schema_exists() {
    let spec = aa_api::ApiDoc::openapi();
    let schemas = &spec.components.as_ref().expect("components should exist").schemas;
    assert!(
        schemas.contains_key("GovernanceEvent"),
        "GovernanceEvent schema missing"
    );
    assert!(schemas.contains_key("EventType"), "EventType schema missing");
    assert!(
        schemas.contains_key("ViolationPayload"),
        "ViolationPayload schema missing"
    );
    assert!(
        schemas.contains_key("ApprovalPayload"),
        "ApprovalPayload schema missing"
    );
    assert!(
        schemas.contains_key("BudgetAlertPayload"),
        "BudgetAlertPayload schema missing"
    );
    assert!(schemas.contains_key("EventPayload"), "EventPayload schema missing");
}

#[test]
fn event_type_enum_variants() {
    let spec = aa_api::ApiDoc::openapi();
    let yaml = serde_yaml::to_string(&spec).unwrap();
    // EventType enum should list all three variants in snake_case
    assert!(yaml.contains("violation"), "violation variant missing from EventType");
    assert!(yaml.contains("approval"), "approval variant missing from EventType");
    assert!(yaml.contains("budget"), "budget variant missing from EventType");
}

/// AAASM-6216: the published spec must not claim alert delivery that the
/// code does not perform.
///
/// Ten descriptions used to assert, in the present tense, that alerts are
/// routed to their destinations, that `routing_log` records real delivery
/// attempts, and that a destination's `enabled` flag gates dispatch. None
/// of that is wired up: the only production caller of the connector
/// framework is the manual test-fire endpoint, the rule evaluator seeds an
/// empty `routing_log` that nothing appends to, and no code reads
/// `enabled`.
///
/// This test guards both directions, so a regeneration cannot silently
/// restore the false text and a well-meant reword cannot drop the
/// qualification.
#[test]
fn spec_makes_no_unearned_alert_delivery_claim() {
    // Serialize as JSON rather than YAML: JSON escapes the newlines that
    // doc-comment wrapping introduces, so a needle spanning two source
    // lines is still findable after normalization.
    let json = serde_json::to_string(&aa_api::ApiDoc::openapi()).unwrap();
    let spec = json
        .replace("\\n", " ")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");

    // --- Claims that must be gone -----------------------------------
    for false_claim in [
        "Destinations the alert is routed to",
        "Destinations the rule routes to",
        "Connector-framework delivery log",
        "One delivery attempt by the connector framework for a routed alert",
        "Identifier of the destination the alert was routed to",
        "Whether dispatch is allowed",
        "Whether dispatch is enabled on creation",
        "supplying just `enabled` toggles dispatch",
        "suppress further routing",
    ] {
        assert!(
            !spec.contains(false_claim),
            "AAASM-6216: the spec claims alert delivery that no code performs: {false_claim:?}"
        );
    }

    // --- Qualifications that must be present -------------------------
    // Each is the load-bearing half of a corrected description; losing one
    // puts the spec back to overclaiming even if the old wording is gone.
    for qualification in [
        // AlertRule::destination_ids
        "Destinations bound to this rule",
        "Outbound delivery is not wired up yet",
        // AlertDetailResponse::destination_ids and ::routing_log
        "Destinations bound to the originating rule",
        "nothing is delivered to them",
        "always empty today",
        // RoutingLogEntry
        "The shape reserved for one delivery attempt",
        "no production code constructs this type",
        // Silence
        "what a silence does *not* do is hold back outbound notifications",
        // Destination::enabled and its two request bodies
        "no code path consults it",
        "recorded only",
        "not consulted by any dispatch path",
    ] {
        assert!(
            spec.contains(qualification),
            "AAASM-6216: a corrected description lost its qualification: {qualification:?}"
        );
    }

    // The approval router is real and its routing claims are accurate —
    // they must survive this sweep untouched (AAASM-6216 AC 3).
    for kept in [
        "Team the approval was routed to, if known",
        "Team the request was routed to, if known",
    ] {
        assert!(
            spec.contains(kept),
            "AAASM-6216: an accurate approval-routing description was collateral damage: {kept:?}"
        );
    }
}
