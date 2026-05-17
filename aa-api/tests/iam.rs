//! Integration tests for the IAM API key endpoints (AAASM-1397).

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::json;
use tower::ServiceExt;

use aa_api::auth::scope::Scope;

fn get_request(uri: &str, token: Option<&str>) -> Request<Body> {
    let mut builder = Request::builder().method("GET").uri(uri);
    if let Some(t) = token {
        builder = builder.header("authorization", format!("Bearer {t}"));
    }
    builder.body(Body::empty()).unwrap()
}

fn post_json_request(uri: &str, body: serde_json::Value, token: Option<&str>) -> Request<Body> {
    let mut builder = Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json");
    if let Some(t) = token {
        builder = builder.header("authorization", format!("Bearer {t}"));
    }
    builder.body(Body::from(serde_json::to_vec(&body).unwrap())).unwrap()
}

fn post_empty_request(uri: &str, token: Option<&str>) -> Request<Body> {
    let mut builder = Request::builder().method("POST").uri(uri);
    if let Some(t) = token {
        builder = builder.header("authorization", format!("Bearer {t}"));
    }
    builder.body(Body::empty()).unwrap()
}

#[tokio::test]
async fn list_api_keys_returns_seeded_entries_newest_first() {
    let app = common::test_app();

    let response = app.oneshot(get_request("/api/v1/iam/api-keys", None)).await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let keys = json.as_array().expect("array");
    assert_eq!(keys.len(), 3, "seed mirrors the dashboard's three-entry fixture");

    // Newest-first ordering: key-2 (2026-05-02) before key-1 (2026-04-30) before key-3 (2026-03-14).
    assert_eq!(keys[0]["id"], "key-2");
    assert_eq!(keys[1]["id"], "key-1");
    assert_eq!(keys[2]["id"], "key-3");

    // Shape contract — snake_case fields matching dashboard's TS ApiKey interface.
    assert!(keys[0]["created_at"].is_string());
    assert!(keys[0]["scopes"].is_array());
    assert!(keys[0]["recent_activity"].is_array());
    assert!(keys[0]["assigned_policies"].is_array());
    assert_eq!(keys[2]["status"], "revoked");
}

#[tokio::test]
async fn generate_api_key_returns_one_shot_secret_and_persists_entry() {
    let app = common::test_app();

    let body = json!({ "label": "ci-bot", "scopes": ["read:audit"] });
    let response = app
        .clone()
        .oneshot(post_json_request("/api/v1/iam/api-keys", body, None))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let json: serde_json::Value =
        serde_json::from_slice(&axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap()).unwrap();
    assert!(json["id"].is_string(), "generated id present");
    assert!(json["prefix"].as_str().unwrap().starts_with("aa_live_"));
    let secret = json["secret"].as_str().expect("secret reveal present");
    assert!(secret.contains(json["prefix"].as_str().unwrap()));

    // The new entry must now show up in list().
    let list_resp = app.oneshot(get_request("/api/v1/iam/api-keys", None)).await.unwrap();
    let list_body = axum::body::to_bytes(list_resp.into_body(), usize::MAX).await.unwrap();
    let list_json: serde_json::Value = serde_json::from_slice(&list_body).unwrap();
    let labels: Vec<&str> = list_json
        .as_array()
        .unwrap()
        .iter()
        .map(|k| k["label"].as_str().unwrap())
        .collect();
    assert!(labels.contains(&"ci-bot"));
}

#[tokio::test]
async fn revoke_api_key_marks_entry_revoked() {
    let app = common::test_app();

    let response = app
        .clone()
        .oneshot(post_empty_request("/api/v1/iam/api-keys/key-1/revoke", None))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    // After revoke, the entry must report status: revoked.
    let list_resp = app.oneshot(get_request("/api/v1/iam/api-keys", None)).await.unwrap();
    let body = axum::body::to_bytes(list_resp.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let key1 = json
        .as_array()
        .unwrap()
        .iter()
        .find(|k| k["id"] == "key-1")
        .expect("key-1 still present");
    assert_eq!(key1["status"], "revoked");
}

#[tokio::test]
async fn revoke_unknown_id_returns_404() {
    let app = common::test_app();

    let response = app
        .oneshot(post_empty_request("/api/v1/iam/api-keys/nope/revoke", None))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let detail = json["detail"].as_str().unwrap_or("");
    assert!(
        detail.contains("nope"),
        "ProblemDetail names the offending id; got: {detail}"
    );
}

#[tokio::test]
async fn revoke_already_revoked_returns_409() {
    let app = common::test_app();

    // key-3 is seeded as already revoked.
    let response = app
        .oneshot(post_empty_request("/api/v1/iam/api-keys/key-3/revoke", None))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn rotate_api_key_returns_new_secret_and_revokes_old() {
    let app = common::test_app();

    let response = app
        .clone()
        .oneshot(post_empty_request("/api/v1/iam/api-keys/key-1/rotate", None))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let new_id = json["id"].as_str().expect("new id present");
    assert_ne!(new_id, "key-1", "replacement carries a distinct id");
    assert!(json["secret"].as_str().unwrap().starts_with("aa_live_"));

    // The list must now have key-1 marked revoked and the new entry present
    // with the same label / scopes as key-1.
    let list_resp = app.oneshot(get_request("/api/v1/iam/api-keys", None)).await.unwrap();
    let list_body = axum::body::to_bytes(list_resp.into_body(), usize::MAX).await.unwrap();
    let list: serde_json::Value = serde_json::from_slice(&list_body).unwrap();

    let old = list.as_array().unwrap().iter().find(|k| k["id"] == "key-1").unwrap();
    assert_eq!(old["status"], "revoked");

    let new_entry = list.as_array().unwrap().iter().find(|k| k["id"] == new_id).unwrap();
    assert_eq!(new_entry["label"], "gateway-ci");
    assert_eq!(new_entry["scopes"], json!(["read:members", "read:policies"]));
    assert_eq!(new_entry["status"], "active");
}

#[tokio::test]
async fn rotate_unknown_id_returns_404() {
    let app = common::test_app();

    let response = app
        .oneshot(post_empty_request("/api/v1/iam/api-keys/nope/rotate", None))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn rotate_already_revoked_returns_409() {
    let app = common::test_app();

    let response = app
        .oneshot(post_empty_request("/api/v1/iam/api-keys/key-3/rotate", None))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn generate_with_read_only_scope_is_forbidden() {
    let (token, entry) = common::generate_test_api_key("viewer-key", vec![Scope::Read]);
    let app = common::test_app_with_auth(&[entry], 1000);

    let response = app
        .oneshot(post_json_request(
            "/api/v1/iam/api-keys",
            json!({ "label": "x", "scopes": ["admin"] }),
            Some(&token),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn rotate_with_read_only_scope_is_forbidden() {
    let (token, entry) = common::generate_test_api_key("viewer-key", vec![Scope::Read]);
    let app = common::test_app_with_auth(&[entry], 1000);

    let response = app
        .oneshot(post_empty_request("/api/v1/iam/api-keys/key-1/rotate", Some(&token)))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}
