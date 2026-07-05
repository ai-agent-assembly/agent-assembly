//! Integration tests for the `/api/v1/analytics/*` endpoints (AAASM-4141).
//!
//! Each endpoint is covered by two cases: a happy-path request against the
//! auth-disabled app asserting the response deserialises to the shape the
//! dashboard hooks expect, and an auth-enabled request without a credential
//! asserting the deny-by-default gate returns 401.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

use aa_api::auth::scope::Scope;

/// GET `uri` against `app`, assert 200, and return the parsed JSON body.
async fn get_ok_json(app: axum::Router, uri: &str) -> serde_json::Value {
    let res = app
        .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK, "expected 200 for {uri}");
    let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&body).unwrap()
}

/// Assert that GET `uri` on an auth-enabled app without a bearer credential is
/// rejected with 401 by the `require_authentication` gate.
async fn assert_requires_auth(uri: &str) {
    let (_plaintext, entry) = common::generate_test_api_key("analytics-key", vec![Scope::Read]);
    let app = common::test_app_with_auth(&[entry], 1000);
    let res = app
        .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(
        res.status(),
        StatusCode::UNAUTHORIZED,
        "expected 401 without a credential for {uri}"
    );
}

// --- kpis -----------------------------------------------------------------

#[tokio::test]
async fn kpis_returns_kpi_shape() {
    let json = get_ok_json(common::test_app(), "/api/v1/analytics/kpis?metric=agents&range=7d").await;
    assert_eq!(json["metric"], "agents");
    assert!(json["value"].is_number(), "value must be a number");
    assert!(json["delta"].is_number(), "delta must be a number");
}

#[tokio::test]
async fn kpis_cost_metric_reports_usd_unit() {
    let json = get_ok_json(common::test_app(), "/api/v1/analytics/kpis?metric=cost").await;
    assert_eq!(json["metric"], "cost");
    assert_eq!(json["unit"], "USD");
}

#[tokio::test]
async fn kpis_requires_authentication() {
    assert_requires_auth("/api/v1/analytics/kpis?metric=agents").await;
}

// --- cost-breakdown -------------------------------------------------------

#[tokio::test]
async fn cost_breakdown_returns_buckets_array() {
    let json = get_ok_json(
        common::test_app(),
        "/api/v1/analytics/cost-breakdown?groupBy=agent&range=30d",
    )
    .await;
    assert!(json["buckets"].is_array(), "buckets must be an array");
}

#[tokio::test]
async fn cost_breakdown_model_grouping_is_empty() {
    // No per-model spend source exists — the model grouping returns no buckets.
    let json = get_ok_json(common::test_app(), "/api/v1/analytics/cost-breakdown?groupBy=model").await;
    assert_eq!(json["buckets"].as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn cost_breakdown_requires_authentication() {
    assert_requires_auth("/api/v1/analytics/cost-breakdown?groupBy=agent").await;
}

// --- action-volume --------------------------------------------------------

#[tokio::test]
async fn action_volume_returns_series_array() {
    let json = get_ok_json(common::test_app(), "/api/v1/analytics/action-volume?range=24h").await;
    assert!(json["series"].is_array(), "series must be an array");
}

#[tokio::test]
async fn action_volume_requires_authentication() {
    assert_requires_auth("/api/v1/analytics/action-volume").await;
}

// --- tool-usage -----------------------------------------------------------

#[tokio::test]
async fn tool_usage_returns_tools_array() {
    let json = get_ok_json(common::test_app(), "/api/v1/analytics/tool-usage?range=7d").await;
    assert!(json["tools"].is_array(), "tools must be an array");
}

#[tokio::test]
async fn tool_usage_requires_authentication() {
    assert_requires_auth("/api/v1/analytics/tool-usage").await;
}

// --- approvals ------------------------------------------------------------

#[tokio::test]
async fn approvals_returns_analytics_shape() {
    let json = get_ok_json(common::test_app(), "/api/v1/analytics/approvals?range=30d").await;
    assert!(json["volume"].is_number(), "volume must be a number");
    assert!(json["medianTta"].is_number(), "medianTta must be a number");
    assert!(json["approvalRate"].is_number(), "approvalRate must be a number");
    assert!(
        json["byOutcome"]["approved"].is_number(),
        "byOutcome.approved must be a number"
    );
    assert!(
        json["byOutcome"]["rejected"].is_number(),
        "byOutcome.rejected must be a number"
    );
    assert!(
        json["byOutcome"]["expired"].is_number(),
        "byOutcome.expired must be a number"
    );
}

#[tokio::test]
async fn approvals_requires_authentication() {
    assert_requires_auth("/api/v1/analytics/approvals").await;
}

// --- policy-effectiveness -------------------------------------------------

#[tokio::test]
async fn policy_effectiveness_returns_rules_array() {
    let json = get_ok_json(common::test_app(), "/api/v1/analytics/policy-effectiveness?range=7d").await;
    assert!(json["rules"].is_array(), "rules must be an array");
}

#[tokio::test]
async fn policy_effectiveness_requires_authentication() {
    assert_requires_auth("/api/v1/analytics/policy-effectiveness").await;
}

// --- fleet-health ---------------------------------------------------------

#[tokio::test]
async fn fleet_health_returns_agents_array() {
    let json = get_ok_json(common::test_app(), "/api/v1/analytics/fleet-health?range=24h").await;
    assert!(json["agents"].is_array(), "agents must be an array");
}

#[tokio::test]
async fn fleet_health_requires_authentication() {
    assert_requires_auth("/api/v1/analytics/fleet-health").await;
}
