//! Live-gateway HTTP integration tests for the `/api/v1/iam/api-keys/*` surface.
//! AAASM-1492 / F122 ST-K
//!
//! Covers:
//! - `POST /api/v1/iam/api-keys`              — create (3 tests)
//! - `GET  /api/v1/iam/api-keys`              — list + shape (3 tests)
//! - `POST /api/v1/iam/api-keys/{id}/revoke`  — revoke (3 tests)
//! - `POST /api/v1/iam/api-keys/{id}/rotate`  — rotate (3 tests)
//!
//! ## Setup pattern
//!
//! Each test boots a fresh `TopologyTestEnv` (independent TCP port + in-memory
//! stores). The harness pre-seeds `IamApiKeyStore` via `seeded_iam_store()`:
//! - `key-1`: "gateway-ci", active, scopes: `["read:members","read:policies"]`,
//!   created 2026-04-30
//! - `key-2`: "observability-exporter", active, scopes: `["read:audit"]`,
//!   created 2026-05-02 (newest)
//! - `key-3`: "retired-runner", revoked, scopes: `["admin"]`,
//!   created 2026-03-14 (oldest)
//!
//! No additional direct seeding is required; all tests operate through HTTP.
//!
//! ## Observed live behaviours (documented per ticket AAASM-1492 AC)
//!
//! * **Auth bypass**: the harness runs `AuthMode::Off`. `AuthenticatedCaller`
//!   returns a synthetic `__bypass__` caller with `[Read, Write, Admin]` scopes
//!   → `OrgAdmin` role → all IAM mutation endpoints (`generate`, `revoke`,
//!   `rotate`) pass `PolicyWriteAuth::check_mutation` without credentials.
//!
//! * **Create returns 200** (not 201): `generate_api_key` uses
//!   `StatusCode::OK`, matching the utoipa annotation in `routes/iam.rs`.
//!
//! * **Only 4 handlers**: no `GET /api/v1/iam/api-keys/{id}` inspect endpoint
//!   exists. The ticket spec guessed a 5th handler; source inspection confirms
//!   only list / generate / revoke / rotate. Shape inspection is done via list.
//!
//! * **List returns ALL keys** (active + revoked, newest-first by `created_at`).
//!   The dashboard filters by status client-side. No `?status=` server filter.
//!
//! * **Revoke is NOT idempotent**: `POST /revoke` on an already-revoked key
//!   returns 409 CONFLICT (`RevokeError::AlreadyRevoked`). The ticket guessed
//!   idempotent 200 — the live store returns an explicit conflict error.
//!
//! * **Secret absent from list**: `ApiKeyEntry` in `IamApiKeyStore` never
//!   holds the raw secret. `GeneratedApiKey` (one-shot reveal) is returned
//!   only by `generate` and `rotate`. `ApiKeyResponse` (list shape) has no
//!   `secret` field.
//!
//! * **Rotate on revoked → 409**: `RotateError::AlreadyRevoked` maps to 409.
//!
//! * **Invalid scope → 422**: Axum's `Json<T>` extractor returns
//!   `JsonRejection::JsonDataError` (422) when serde fails to match an
//!   `ApiKeyScopeResponse` enum variant.

mod common;

use common::TopologyTestEnv;

// =============================================================================
// POST /api/v1/iam/api-keys — create
// =============================================================================

/// `POST /api/v1/iam/api-keys` returns 200 (not 201) with `{id, prefix, secret}`.
/// The secret embeds the prefix: `secret.starts_with(prefix)`.
/// Auth bypass (AuthMode::Off) grants OrgAdmin so PolicyWriteAuth passes.
#[tokio::test(flavor = "multi_thread")]
async fn iam_create_api_key_returns_200_with_key_and_secret() {
    let env = TopologyTestEnv::start().await.expect("harness should start");
    let client = reqwest::Client::new();

    let resp = client
        .post(format!("{}/api/v1/iam/api-keys", env.base_url()))
        .json(&serde_json::json!({"label": "ci-bot", "scopes": ["read:audit"]}))
        .send()
        .await
        .expect("POST /iam/api-keys should succeed");

    // Live contract: 200, not 201.
    assert_eq!(resp.status(), reqwest::StatusCode::OK, "create must return 200");

    let body: serde_json::Value = resp.json().await.expect("response should parse as JSON");
    assert!(body["id"].is_string(), "`id` must be present");
    let prefix = body["prefix"].as_str().expect("`prefix` must be present");
    assert!(prefix.starts_with("aa_live_"), "prefix must start with 'aa_live_'");
    let secret = body["secret"].as_str().expect("`secret` must be present on creation");
    assert!(
        secret.starts_with(prefix),
        "secret must embed the public prefix; prefix={prefix}, secret={secret}",
    );
}

/// Sending an unrecognised scope string results in 422 Unprocessable Entity.
/// Axum's `Json<T>` extractor returns `JsonDataError` (422) when serde fails
/// to deserialize an unknown `ApiKeyScopeResponse` enum variant.
#[tokio::test(flavor = "multi_thread")]
async fn iam_create_with_invalid_scope_returns_422() {
    let env = TopologyTestEnv::start().await.expect("harness should start");
    let client = reqwest::Client::new();

    let resp = client
        .post(format!("{}/api/v1/iam/api-keys", env.base_url()))
        .json(&serde_json::json!({"label": "bad-scope-key", "scopes": ["read:agents"]}))
        .send()
        .await
        .expect("POST with invalid scope should reach the server");

    assert_eq!(
        resp.status(),
        reqwest::StatusCode::UNPROCESSABLE_ENTITY,
        "unknown scope string must yield 422 (serde enum variant mismatch)"
    );
}

/// A key created via POST appears in the subsequent GET list.
/// The list entry must NOT carry a `secret` field — the one-shot reveal is only
/// returned by the create response; `IamApiKeyStore` never persists the secret.
#[tokio::test(flavor = "multi_thread")]
async fn iam_create_key_appears_in_list_without_secret() {
    let env = TopologyTestEnv::start().await.expect("harness should start");
    let client = reqwest::Client::new();

    let create_resp = client
        .post(format!("{}/api/v1/iam/api-keys", env.base_url()))
        .json(&serde_json::json!({"label": "list-check-bot", "scopes": ["read:policies"]}))
        .send()
        .await
        .expect("POST /iam/api-keys should succeed");
    assert_eq!(create_resp.status(), reqwest::StatusCode::OK);
    let created: serde_json::Value = create_resp.json().await.expect("create response should parse");
    let new_id = created["id"].as_str().expect("id must be present");

    let list_resp = client
        .get(format!("{}/api/v1/iam/api-keys", env.base_url()))
        .send()
        .await
        .expect("GET /iam/api-keys should succeed");
    assert_eq!(list_resp.status(), reqwest::StatusCode::OK);
    let keys: Vec<serde_json::Value> = list_resp.json().await.expect("list should parse as JSON array");

    let entry = keys
        .iter()
        .find(|k| k["id"].as_str() == Some(new_id))
        .expect("newly created key must appear in list");
    assert_eq!(entry["label"].as_str(), Some("list-check-bot"));
    assert!(
        entry.get("secret").is_none() || entry["secret"].is_null(),
        "list entry must NOT expose the secret"
    );
}

// =============================================================================
// GET /api/v1/iam/api-keys — list + shape
// =============================================================================

/// `GET /api/v1/iam/api-keys` returns all 3 seeded entries newest-first
/// (`created_at` descending): key-2 (2026-05-02) → key-1 (2026-04-30) →
/// key-3 (2026-03-14). Verifies array shape fields are present.
#[tokio::test(flavor = "multi_thread")]
async fn iam_list_returns_seeded_keys_newest_first() {
    let env = TopologyTestEnv::start().await.expect("harness should start");
    let client = reqwest::Client::new();

    let resp = client
        .get(format!("{}/api/v1/iam/api-keys", env.base_url()))
        .send()
        .await
        .expect("GET /iam/api-keys should succeed");

    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let keys: Vec<serde_json::Value> = resp.json().await.expect("list should parse as JSON array");

    assert_eq!(keys.len(), 3, "seeded store has 3 entries");
    // Newest-first ordering by created_at.
    assert_eq!(
        keys[0]["id"].as_str(),
        Some("key-2"),
        "key-2 (2026-05-02) must be first"
    );
    assert_eq!(
        keys[1]["id"].as_str(),
        Some("key-1"),
        "key-1 (2026-04-30) must be second"
    );
    assert_eq!(keys[2]["id"].as_str(), Some("key-3"), "key-3 (2026-03-14) must be last");

    // Shape contract.
    assert!(keys[0]["scopes"].is_array(), "`scopes` must be an array");
    assert!(
        keys[0]["recent_activity"].is_array(),
        "`recent_activity` must be an array"
    );
    assert!(
        keys[0]["assigned_policies"].is_array(),
        "`assigned_policies` must be an array"
    );
    assert!(keys[0]["created_at"].is_string(), "`created_at` must be set");
}

/// `GET /api/v1/iam/api-keys` includes both active and revoked keys.
/// Live contract: list always returns ALL entries; dashboard filters client-side.
/// key-3 ("retired-runner") is seeded as revoked; key-1 and key-2 are active.
#[tokio::test(flavor = "multi_thread")]
async fn iam_list_includes_both_active_and_revoked() {
    let env = TopologyTestEnv::start().await.expect("harness should start");
    let client = reqwest::Client::new();

    let resp = client
        .get(format!("{}/api/v1/iam/api-keys", env.base_url()))
        .send()
        .await
        .expect("GET /iam/api-keys should succeed");

    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let keys: Vec<serde_json::Value> = resp.json().await.expect("list should parse as JSON array");

    let active_count = keys.iter().filter(|k| k["status"].as_str() == Some("active")).count();
    let revoked_count = keys.iter().filter(|k| k["status"].as_str() == Some("revoked")).count();
    // Live contract: no server-side status filter — both statuses present.
    assert_eq!(active_count, 2, "2 seeded active keys (key-1, key-2)");
    assert_eq!(revoked_count, 1, "1 seeded revoked key (key-3)");
}

/// No entry returned by `GET /api/v1/iam/api-keys` contains a `secret` field.
/// `IamApiKeyStore` never stores the raw secret; `ApiKeyResponse` has no
/// `secret` field; the one-shot reveal only appears in `GeneratedApiKeyResponse`
/// from create / rotate calls.
#[tokio::test(flavor = "multi_thread")]
async fn iam_list_entries_have_no_secret_field() {
    let env = TopologyTestEnv::start().await.expect("harness should start");
    let client = reqwest::Client::new();

    let resp = client
        .get(format!("{}/api/v1/iam/api-keys", env.base_url()))
        .send()
        .await
        .expect("GET /iam/api-keys should succeed");

    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let keys: Vec<serde_json::Value> = resp.json().await.expect("list should parse as JSON array");

    for key in &keys {
        assert!(
            key.get("secret").is_none() || key["secret"].is_null(),
            "list entry id={} must not expose `secret`",
            key["id"].as_str().unwrap_or("?")
        );
    }
}

// =============================================================================
// POST /api/v1/iam/api-keys/{id}/revoke — revoke
// =============================================================================

/// Revoking an active key returns 204 No Content. A subsequent GET list
/// shows the key's `status` changed to `"revoked"`.
#[tokio::test(flavor = "multi_thread")]
async fn iam_revoke_active_key_returns_204_and_status_becomes_revoked() {
    let env = TopologyTestEnv::start().await.expect("harness should start");
    let client = reqwest::Client::new();

    let revoke_resp = client
        .post(format!("{}/api/v1/iam/api-keys/key-1/revoke", env.base_url()))
        .send()
        .await
        .expect("POST /iam/api-keys/key-1/revoke should succeed");

    assert_eq!(
        revoke_resp.status(),
        reqwest::StatusCode::NO_CONTENT,
        "revoke must return 204"
    );

    // Confirm state via list.
    let list_resp = client
        .get(format!("{}/api/v1/iam/api-keys", env.base_url()))
        .send()
        .await
        .expect("follow-up GET should succeed");
    let keys: Vec<serde_json::Value> = list_resp.json().await.expect("list should parse");
    let key1 = keys
        .iter()
        .find(|k| k["id"].as_str() == Some("key-1"))
        .expect("key-1 must still appear in list after revoke");
    assert_eq!(
        key1["status"].as_str(),
        Some("revoked"),
        "key-1 status must be 'revoked' after POST /revoke"
    );
}

/// `POST /revoke` on an already-revoked key returns 409 CONFLICT.
/// Live contract: `IamApiKeyStore::revoke` returns `RevokeError::AlreadyRevoked`
/// which the handler maps to 409 — NOT idempotent 200.
/// key-3 ("retired-runner") is pre-seeded as revoked.
#[tokio::test(flavor = "multi_thread")]
async fn iam_revoke_already_revoked_returns_409() {
    let env = TopologyTestEnv::start().await.expect("harness should start");
    let client = reqwest::Client::new();

    let resp = client
        .post(format!("{}/api/v1/iam/api-keys/key-3/revoke", env.base_url()))
        .send()
        .await
        .expect("POST /revoke on revoked key should reach the server");

    assert_eq!(
        resp.status(),
        reqwest::StatusCode::CONFLICT,
        "revoke on already-revoked key must return 409, not idempotent 200"
    );
}

/// `POST /revoke` on a nonexistent key id returns 404 Not Found.
/// The `ProblemDetail` body includes the unknown id in its `detail` field.
#[tokio::test(flavor = "multi_thread")]
async fn iam_revoke_unknown_id_returns_404() {
    let env = TopologyTestEnv::start().await.expect("harness should start");
    let client = reqwest::Client::new();

    let resp = client
        .post(format!("{}/api/v1/iam/api-keys/nonexistent-key/revoke", env.base_url()))
        .send()
        .await
        .expect("POST /revoke on unknown id should reach the server");

    assert_eq!(
        resp.status(),
        reqwest::StatusCode::NOT_FOUND,
        "unknown id must return 404"
    );
    let body: serde_json::Value = resp.json().await.expect("error body should parse as JSON");
    let detail = body["detail"].as_str().unwrap_or("");
    assert!(
        detail.contains("nonexistent-key"),
        "ProblemDetail must name the offending id; got: {detail}"
    );
}

// =============================================================================
// POST /api/v1/iam/api-keys/{id}/rotate — rotate
// =============================================================================

/// Rotating an active key returns 200 with a new `{id, prefix, secret}`.
/// The new id differs from the original; the old key's status becomes "revoked";
/// the new entry inherits the same label and status "active".
#[tokio::test(flavor = "multi_thread")]
async fn iam_rotate_active_key_returns_new_secret_and_revokes_old() {
    let env = TopologyTestEnv::start().await.expect("harness should start");
    let client = reqwest::Client::new();

    let rotate_resp = client
        .post(format!("{}/api/v1/iam/api-keys/key-2/rotate", env.base_url()))
        .send()
        .await
        .expect("POST /rotate should succeed");

    assert_eq!(rotate_resp.status(), reqwest::StatusCode::OK, "rotate must return 200");
    let rotated: serde_json::Value = rotate_resp.json().await.expect("rotate response should parse");

    let new_id = rotated["id"].as_str().expect("`id` must be present");
    assert_ne!(new_id, "key-2", "replacement must carry a distinct id");
    let new_prefix = rotated["prefix"].as_str().expect("`prefix` must be present");
    let new_secret = rotated["secret"].as_str().expect("`secret` must be present");
    assert!(
        new_secret.starts_with(new_prefix),
        "secret must embed the new prefix; prefix={new_prefix}"
    );

    // List must show key-2 revoked and the new entry active with same label.
    let list_resp = client
        .get(format!("{}/api/v1/iam/api-keys", env.base_url()))
        .send()
        .await
        .expect("follow-up GET should succeed");
    let keys: Vec<serde_json::Value> = list_resp.json().await.expect("list should parse");

    let old = keys
        .iter()
        .find(|k| k["id"].as_str() == Some("key-2"))
        .expect("original key-2 must still appear in list");
    assert_eq!(
        old["status"].as_str(),
        Some("revoked"),
        "original key must be revoked after rotate"
    );

    let new_entry = keys
        .iter()
        .find(|k| k["id"].as_str() == Some(new_id))
        .expect("replacement key must appear in list");
    assert_eq!(
        new_entry["status"].as_str(),
        Some("active"),
        "replacement must be active"
    );
    assert_eq!(
        new_entry["label"].as_str(),
        Some("observability-exporter"),
        "replacement must inherit the original label"
    );
}

/// `POST /rotate` on an already-revoked key returns 409 CONFLICT.
/// `IamApiKeyStore::rotate` returns `RotateError::AlreadyRevoked` mapped to 409.
/// key-3 is pre-seeded as revoked.
#[tokio::test(flavor = "multi_thread")]
async fn iam_rotate_revoked_key_returns_409() {
    let env = TopologyTestEnv::start().await.expect("harness should start");
    let client = reqwest::Client::new();

    let resp = client
        .post(format!("{}/api/v1/iam/api-keys/key-3/rotate", env.base_url()))
        .send()
        .await
        .expect("POST /rotate on revoked key should reach the server");

    assert_eq!(
        resp.status(),
        reqwest::StatusCode::CONFLICT,
        "rotate on revoked key must return 409"
    );
}

/// `POST /rotate` on a nonexistent key id returns 404 Not Found.
#[tokio::test(flavor = "multi_thread")]
async fn iam_rotate_unknown_id_returns_404() {
    let env = TopologyTestEnv::start().await.expect("harness should start");
    let client = reqwest::Client::new();

    let resp = client
        .post(format!("{}/api/v1/iam/api-keys/nonexistent-key/rotate", env.base_url()))
        .send()
        .await
        .expect("POST /rotate on unknown id should reach the server");

    assert_eq!(
        resp.status(),
        reqwest::StatusCode::NOT_FOUND,
        "unknown id must return 404"
    );
}
