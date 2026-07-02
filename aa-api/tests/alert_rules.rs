//! Integration tests for `/api/v1/alerts/rules` (AAASM-1386).

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::json;
use tower::ServiceExt;

fn valid_rule_body() -> serde_json::Value {
    json!({
        "name": "Budget > 90%",
        "description": "Fire CRITICAL when budget spend exceeds 90%",
        "metric": "budget_spent_pct",
        "operator": ">",
        "threshold": 90,
        "evaluationWindowSeconds": 300,
        "severity": "CRITICAL",
        "destinationIds": ["slack-ops"],
        "dedupWindowSeconds": 600,
        "enabled": true
    })
}

async fn read_json(response: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

fn post(uri: &str, body: serde_json::Value) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

fn put(uri: &str, body: serde_json::Value) -> Request<Body> {
    Request::builder()
        .method("PUT")
        .uri(uri)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

fn delete(uri: &str) -> Request<Body> {
    Request::builder()
        .method("DELETE")
        .uri(uri)
        .body(Body::empty())
        .unwrap()
}

fn get(uri: &str) -> Request<Body> {
    Request::builder().uri(uri).body(Body::empty()).unwrap()
}

#[tokio::test]
async fn full_crud_round_trip() {
    let app = common::test_app();

    // POST → 201 + assigned id/timestamps
    let response = app
        .clone()
        .oneshot(post("/api/v1/alerts/rules", valid_rule_body()))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let created = read_json(response).await;
    let id = created["id"].as_str().expect("id assigned").to_string();
    assert!(!id.is_empty());
    assert!(!created["createdAt"].as_str().unwrap().is_empty());
    let original_created_at = created["createdAt"].as_str().unwrap().to_string();

    // GET list contains the rule (bare array, matching dashboard hooks
    // from AAASM-1075)
    let response = app.clone().oneshot(get("/api/v1/alerts/rules")).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let list = read_json(response).await;
    let arr = list.as_array().expect("list response must be a JSON array");
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["id"], id);

    // GET by id → 200
    let response = app
        .clone()
        .oneshot(get(&format!("/api/v1/alerts/rules/{id}")))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // PUT → 200 with bumped updatedAt + preserved createdAt
    // sleep a tick so updatedAt is observably different
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    let mut updated_body = valid_rule_body();
    updated_body["threshold"] = json!(95);
    let response = app
        .clone()
        .oneshot(put(&format!("/api/v1/alerts/rules/{id}"), updated_body))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let updated = read_json(response).await;
    assert_eq!(updated["id"], id);
    assert_eq!(updated["createdAt"], original_created_at);
    assert_ne!(updated["updatedAt"], original_created_at);
    assert_eq!(updated["threshold"], 95.0);

    // DELETE → 204
    let response = app
        .clone()
        .oneshot(delete(&format!("/api/v1/alerts/rules/{id}")))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    // GET after delete → 404
    let response = app
        .clone()
        .oneshot(get(&format!("/api/v1/alerts/rules/{id}")))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let problem = read_json(response).await;
    assert_eq!(problem["error_code"], "rule_not_found");
}

#[tokio::test]
async fn create_with_unknown_metric_returns_invalid_metric() {
    let app = common::test_app();
    let mut body = valid_rule_body();
    body["metric"] = json!("not_a_real_metric");
    let response = app.oneshot(post("/api/v1/alerts/rules", body)).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let problem = read_json(response).await;
    assert_eq!(problem["error_code"], "invalid_metric");
}

#[tokio::test]
async fn create_with_out_of_range_threshold_returns_invalid_threshold() {
    let app = common::test_app();
    let mut body = valid_rule_body();
    body["threshold"] = json!(200);
    let response = app.oneshot(post("/api/v1/alerts/rules", body)).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let problem = read_json(response).await;
    assert_eq!(problem["error_code"], "invalid_threshold");
}

#[tokio::test]
async fn create_with_unknown_destination_returns_destination_unknown() {
    let app = common::test_app();
    let mut body = valid_rule_body();
    body["destinationIds"] = json!(["does-not-exist"]);
    let response = app.oneshot(post("/api/v1/alerts/rules", body)).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let problem = read_json(response).await;
    assert_eq!(problem["error_code"], "destination_unknown");
}

#[tokio::test]
async fn get_unknown_id_returns_rule_not_found() {
    let app = common::test_app();
    let response = app.oneshot(get("/api/v1/alerts/rules/no-such-id")).await.unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let problem = read_json(response).await;
    assert_eq!(problem["error_code"], "rule_not_found");
}

#[tokio::test]
async fn create_with_duplicate_name_returns_rule_name_conflict() {
    let app = common::test_app();
    let response = app
        .clone()
        .oneshot(post("/api/v1/alerts/rules", valid_rule_body()))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    let response = app
        .oneshot(post("/api/v1/alerts/rules", valid_rule_body()))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);
    let problem = read_json(response).await;
    assert_eq!(problem["error_code"], "rule_name_conflict");
}

#[tokio::test]
async fn list_filters_by_enabled_query() {
    let app = common::test_app();

    let mut a = valid_rule_body();
    a["name"] = json!("on");
    app.clone().oneshot(post("/api/v1/alerts/rules", a)).await.unwrap();

    let mut b = valid_rule_body();
    b["name"] = json!("off");
    b["enabled"] = json!(false);
    app.clone().oneshot(post("/api/v1/alerts/rules", b)).await.unwrap();

    let response = app
        .clone()
        .oneshot(get("/api/v1/alerts/rules?enabled=true"))
        .await
        .unwrap();
    let list = read_json(response).await;
    let arr = list.as_array().expect("list response must be a JSON array");
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["name"], "on");

    let response = app.oneshot(get("/api/v1/alerts/rules?enabled=false")).await.unwrap();
    let list = read_json(response).await;
    let arr = list.as_array().expect("list response must be a JSON array");
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["name"], "off");
}

// ── AAASM-1658 — DELETE rule preserves snapshot on already-recorded alerts ──

#[tokio::test]
async fn delete_rule_preserves_snapshot_on_already_recorded_alerts() {
    use aa_api::alerts::detail::{RoutingLogEntry, RuleSnapshot};
    use aa_api::alerts::rules::types::{AlertRule, RuleMetric, RuleOperator, RuleSeverity};
    use aa_api::alerts::RuleAlertSeed;
    use std::sync::Arc;

    let state = common::test_state();
    // Hold a handle to alert_store so we can seed a rule alert *after*
    // POSTing the rule (the route handler will assign the rule id).
    let alert_store = Arc::clone(&state.alert_store);
    let app = aa_api::server::build_app(state);

    // 1) Create a rule via the public API.
    let response = app
        .clone()
        .oneshot(post("/api/v1/alerts/rules", valid_rule_body()))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let created = read_json(response).await;
    let rule_id = created["id"].as_str().expect("id assigned").to_string();
    let rule_name = created["name"].as_str().unwrap().to_string();

    // 2) Record a rule-derived alert carrying the full AlertRule snapshot
    //    — what the live evaluator does once a metric source fires.
    let snapshot_rule = AlertRule {
        id: rule_id.clone(),
        name: rule_name.clone(),
        description: "Fire CRITICAL when budget spend exceeds 90%".to_string(),
        metric: RuleMetric::BudgetSpentPct,
        operator: RuleOperator::Gt,
        threshold: 90.0,
        evaluation_window_seconds: 300,
        severity: RuleSeverity::Critical,
        destination_ids: vec!["slack-ops".to_string()],
        dedup_window_seconds: 600,
        suppression_labels: std::collections::HashMap::new(),
        enabled: true,
        created_at: "2026-05-13T09:00:00Z".to_string(),
        updated_at: "2026-05-13T09:00:00Z".to_string(),
        team_id: None,
        org_id: None,
    };
    let alert_id = alert_store.record_rule_alert(&RuleAlertSeed {
        agent_id: None,
        team_id: None,
        rule_id: rule_id.clone(),
        rule_name: rule_name.clone(),
        rule_snapshot: RuleSnapshot {
            metric: "budget_spent_pct".to_string(),
            operator: ">".to_string(),
            threshold: 90.0,
            evaluation_window_seconds: 300,
            severity: "CRITICAL".to_string(),
            dedup_window_seconds: 600,
            suppression_labels: std::collections::BTreeMap::new(),
        },
        destination_ids: vec!["slack-ops".to_string()],
        event_payload: serde_json::json!({ "metric_value": 92.3 }),
        routing_log: vec![RoutingLogEntry {
            destination_id: "slack-ops".to_string(),
            delivered_at: "2026-05-20T09:00:01Z".to_string(),
            status: "ok".to_string(),
        }],
        alert_rule: Some(snapshot_rule),
    });

    // 3) DELETE the rule out of the registry.
    let response = app
        .clone()
        .oneshot(delete(&format!("/api/v1/alerts/rules/{rule_id}")))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    let response = app
        .clone()
        .oneshot(get(&format!("/api/v1/alerts/rules/{rule_id}")))
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::NOT_FOUND,
        "rule must be gone after DELETE",
    );

    // 4) The already-recorded alert's ruleSnapshot must still carry the
    //    full original AlertRule, so the dashboard detail view can render.
    let response = app.oneshot(get(&format!("/api/v1/alerts/{alert_id}"))).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = read_json(response).await;
    assert_eq!(body["ruleSnapshot"]["id"], rule_id);
    assert_eq!(body["ruleSnapshot"]["name"], rule_name);
    assert_eq!(body["ruleSnapshot"]["threshold"], 90.0);
    assert_eq!(body["ruleSnapshot"]["metric"], "budget_spent_pct");
}

// ── AAASM-3911: tenant isolation ────────────────────────────────────────────

/// Attach a Bearer JWT to a request builder body-less GET.
fn get_as(uri: &str, token: &str) -> Request<Body> {
    Request::builder()
        .uri(uri)
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap()
}

fn post_as(uri: &str, token: &str, body: serde_json::Value) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::from(body.to_string()))
        .unwrap()
}

fn put_as(uri: &str, token: &str, body: serde_json::Value) -> Request<Body> {
    Request::builder()
        .method("PUT")
        .uri(uri)
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::from(body.to_string()))
        .unwrap()
}

fn delete_as(uri: &str, token: &str) -> Request<Body> {
    Request::builder()
        .method("DELETE")
        .uri(uri)
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap()
}

fn named_rule_body(name: &str) -> serde_json::Value {
    let mut body = valid_rule_body();
    body["name"] = json!(name);
    body
}

/// A tenant-confined Write key manages ONLY its own tenant's alert rules: it
/// cannot list, read, update, or delete another tenant's rules, while an admin
/// key retains cross-tenant access. Reverts the AAASM-3894 admin-gate stopgap.
#[tokio::test]
async fn write_key_is_confined_to_its_own_tenant_alert_rules() {
    let app = common::test_app_with_auth(&[], 1000);

    let write = &[Scope::Read, Scope::Write];
    let token_a = common::generate_test_jwt_for_team("key-a", write, "team-a");
    let token_b = common::generate_test_jwt_for_team("key-b", write, "team-b");
    let token_admin = common::generate_test_jwt("key-admin", &[Scope::Admin]);

    // Team A (Write) creates a rule → 201.
    let response = app
        .clone()
        .oneshot(post_as("/api/v1/alerts/rules", &token_a, named_rule_body("rule-a")))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED, "team-A Write key can create");
    let rule_a_id = read_json(response).await["id"].as_str().unwrap().to_string();

    // Team B (Write) creates its own rule → 201.
    let response = app
        .clone()
        .oneshot(post_as("/api/v1/alerts/rules", &token_b, named_rule_body("rule-b")))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let rule_b_id = read_json(response).await["id"].as_str().unwrap().to_string();

    // Team B's list must contain only its own rule — never team-A's.
    let response = app
        .clone()
        .oneshot(get_as("/api/v1/alerts/rules", &token_b))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let arr = read_json(response).await;
    let arr = arr.as_array().unwrap();
    assert_eq!(arr.len(), 1, "team-B sees only its own rule");
    assert_eq!(arr[0]["id"], rule_b_id);

    // Team B cannot read team-A's rule.
    let response = app
        .clone()
        .oneshot(get_as(&format!("/api/v1/alerts/rules/{rule_a_id}"), &token_b))
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "team-B cannot read team-A's rule"
    );

    // Team B cannot update team-A's rule.
    let response = app
        .clone()
        .oneshot(put_as(
            &format!("/api/v1/alerts/rules/{rule_a_id}"),
            &token_b,
            named_rule_body("rule-a-hijack"),
        ))
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "team-B cannot update team-A's rule"
    );

    // Team B cannot delete team-A's rule.
    let response = app
        .clone()
        .oneshot(delete_as(&format!("/api/v1/alerts/rules/{rule_a_id}"), &token_b))
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "team-B cannot delete team-A's rule"
    );

    // Team A still sees and can read its own rule (untouched by B's attempts).
    let response = app
        .clone()
        .oneshot(get_as("/api/v1/alerts/rules", &token_a))
        .await
        .unwrap();
    let arr = read_json(response).await;
    let arr = arr.as_array().unwrap();
    assert_eq!(arr.len(), 1, "team-A sees only its own rule");
    assert_eq!(arr[0]["id"], rule_a_id);

    // Admin sees every tenant's rules and can act cross-tenant.
    let response = app
        .clone()
        .oneshot(get_as("/api/v1/alerts/rules", &token_admin))
        .await
        .unwrap();
    let arr = read_json(response).await;
    assert_eq!(arr.as_array().unwrap().len(), 2, "admin sees both tenants' rules");

    let response = app
        .clone()
        .oneshot(get_as(&format!("/api/v1/alerts/rules/{rule_a_id}"), &token_admin))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK, "admin reads any tenant's rule");

    let response = app
        .oneshot(delete_as(&format!("/api/v1/alerts/rules/{rule_a_id}"), &token_admin))
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::NO_CONTENT,
        "admin deletes any tenant's rule"
    );
}

#[tokio::test]
async fn create_accepts_every_operator_variant() {
    let app = common::test_app();
    for (i, op) in [">", ">=", "<", "="].iter().enumerate() {
        let mut body = valid_rule_body();
        body["name"] = json!(format!("op-rule-{i}"));
        body["operator"] = json!(op);
        // "<"/"=" against budget_spent_pct with threshold 90 is still in range.
        let resp = app.clone().oneshot(post("/api/v1/alerts/rules", body)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED, "operator {op} must be accepted");
    }
}

#[tokio::test]
async fn create_accepts_every_severity_variant() {
    let app = common::test_app();
    for (i, sev) in ["CRITICAL", "HIGH", "MEDIUM", "LOW"].iter().enumerate() {
        let mut body = valid_rule_body();
        body["name"] = json!(format!("sev-rule-{i}"));
        body["severity"] = json!(sev);
        let resp = app.clone().oneshot(post("/api/v1/alerts/rules", body)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED, "severity {sev} must be accepted");
    }
}

#[tokio::test]
async fn create_with_unknown_operator_returns_invalid_operator() {
    let app = common::test_app();
    let mut body = valid_rule_body();
    body["operator"] = json!("≈");
    let resp = app.oneshot(post("/api/v1/alerts/rules", body)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let json = read_json(resp).await;
    assert_eq!(json["error_code"], "invalid_operator");
}

#[tokio::test]
async fn create_with_unknown_severity_returns_invalid_severity() {
    let app = common::test_app();
    let mut body = valid_rule_body();
    body["severity"] = json!("FATAL");
    let resp = app.oneshot(post("/api/v1/alerts/rules", body)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let json = read_json(resp).await;
    assert_eq!(json["error_code"], "invalid_severity");
}

// ── AAASM-3911 — alert-rule mutations are tenant-scoped Write ─────────────────
//
// AAASM-3894 gated alert-rule mutations on admin scope as a stopgap because
// rules carried no tenant. Now each rule is stamped with (and confined to) its
// creating tenant, so mutations revert to Write scope — see
// `write_key_is_confined_to_its_own_tenant_alert_rules` above for the full
// isolation contract. An admin caller still creates rules cross-tenant.

use aa_api::auth::config::AuthMode;
use aa_api::auth::scope::Scope;

fn bearer(method: &str, uri: &str, token: &str, body: Option<serde_json::Value>) -> Request<Body> {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("authorization", format!("Bearer {token}"));
    match body {
        Some(b) => {
            builder = builder.header("content-type", "application/json");
            builder.body(Body::from(b.to_string())).unwrap()
        }
        None => builder.body(Body::empty()).unwrap(),
    }
}

/// A tenant-confined Write key cannot mutate another tenant's rule: PUT / DELETE
/// against a rule the caller's tenant does not own is refused. (Creation and the
/// full isolation contract are covered by
/// `write_key_is_confined_to_its_own_tenant_alert_rules`.)
#[tokio::test]
async fn write_key_cannot_mutate_another_tenants_rule() {
    let state = common::test_state_with_auth(AuthMode::On, &[], 1000);
    let app = aa_api::build_app(state);
    let write = &[Scope::Read, Scope::Write];
    let token_a = common::generate_test_jwt_for_team("key-a", write, "team-a");
    let token_b = common::generate_test_jwt_for_team("key-b", write, "team-b");

    // Team A creates a rule.
    let resp = app
        .clone()
        .oneshot(bearer(
            "POST",
            "/api/v1/alerts/rules",
            &token_a,
            Some(valid_rule_body()),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let id = read_json(resp).await["id"].as_str().unwrap().to_string();

    // Team B cannot update or delete it.
    let resp = app
        .clone()
        .oneshot(bearer(
            "PUT",
            &format!("/api/v1/alerts/rules/{id}"),
            &token_b,
            Some(valid_rule_body()),
        ))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "team-B cannot update team-A's rule"
    );

    let resp = app
        .oneshot(bearer("DELETE", &format!("/api/v1/alerts/rules/{id}"), &token_b, None))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "team-B cannot delete team-A's rule"
    );
}

#[tokio::test]
async fn create_rule_admin_token_is_allowed() {
    let state = common::test_state_with_auth(AuthMode::On, &[], 1000);
    let app = aa_api::build_app(state);
    let token = common::generate_test_jwt("admin", &[Scope::Admin]);
    let resp = app
        .oneshot(bearer("POST", "/api/v1/alerts/rules", &token, Some(valid_rule_body())))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::CREATED,
        "an admin caller must be able to create an alert rule"
    );
}
