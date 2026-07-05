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
