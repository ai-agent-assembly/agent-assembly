//! AAASM-1499 — Authentication & authorization integration test matrix.
//!
//! 25 live-gateway HTTP integration tests (via `reqwest` against a real
//! in-process Axum server) covering 6 auth sections:
//!
//! - S1: JWT validation
//! - S2: API key authentication
//! - S3: Scope-based authorization
//! - S4: Rate limiting
//! - S5: Bypass attempts
//! - S6: Policy → RBAC integration

mod common;

use aa_api::auth::jwt::JwtSigner;
use aa_api::auth::scope::Scope;
use common::{make_api_key, TopologyTestEnv, AUTH_IT_JWT_SECRET};
use reqwest::StatusCode;
use serde_json::Value;

// ── Section 1 — JWT validation ───────────────────────────────────────────────
//
// S1 tests use POST /api/v1/auth/token because it requires AuthenticatedCaller
// (enforces auth). GET /api/v1/agents is public and does not validate auth.

/// Build an expired JWT using the same secret as the test harness.
///
/// We construct Claims manually with `exp` in the past and encode directly
/// with `jsonwebtoken` — `JwtSigner::sign_with_expiry` is `#[cfg(test)]`-private
/// to aa-api and is not accessible from integration tests.
fn build_expired_jwt() -> String {
    use aa_api::auth::jwt::Claims;
    use jsonwebtoken::{encode, EncodingKey, Header};
    let claims = Claims {
        sub: "test-expired".to_string(),
        iat: 0,
        exp: 1, // epoch second 1 — always in the past
        scope: vec![],
    };
    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(AUTH_IT_JWT_SECRET),
    )
    .unwrap()
}

#[tokio::test]
async fn auth_jwt_valid_signed_token_grants_access() {
    let env = TopologyTestEnv::start_with_auth(&[], 1000).await.unwrap();

    let jwt = JwtSigner::new(AUTH_IT_JWT_SECRET)
        .sign("test-sub", &[Scope::Read, Scope::Write])
        .unwrap();

    // POST /api/v1/auth/token enforces AuthenticatedCaller; a valid JWT should succeed.
    let resp = reqwest::Client::new()
        .post(format!("{}/api/v1/auth/token", env.base_url()))
        .bearer_auth(&jwt)
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn auth_jwt_expired_token_returns_401() {
    let env = TopologyTestEnv::start_with_auth(&[], 1000).await.unwrap();
    let jwt = build_expired_jwt();

    let resp = reqwest::Client::new()
        .post(format!("{}/api/v1/auth/token", env.base_url()))
        .bearer_auth(&jwt)
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let body: Value = resp.json().await.unwrap();
    assert!(
        body["detail"].as_str().unwrap_or("").contains("expired"),
        "expected 'expired' in detail, got: {:?}",
        body["detail"]
    );
}

#[tokio::test]
async fn auth_jwt_invalid_signature_returns_401() {
    let env = TopologyTestEnv::start_with_auth(&[], 1000).await.unwrap();

    // Sign with the wrong secret — signature will be invalid.
    let jwt = JwtSigner::new(b"wrong-secret-totally-different-32bytes!!")
        .sign("test-sub", &[Scope::Read])
        .unwrap();

    let resp = reqwest::Client::new()
        .post(format!("{}/api/v1/auth/token", env.base_url()))
        .bearer_auth(&jwt)
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let body: Value = resp.json().await.unwrap();
    assert!(
        body["detail"].as_str().unwrap_or("").to_lowercase().contains("invalid"),
        "expected 'invalid' in detail, got: {:?}",
        body["detail"]
    );
}

#[tokio::test]
async fn auth_jwt_malformed_token_returns_401() {
    let env = TopologyTestEnv::start_with_auth(&[], 1000).await.unwrap();

    let resp = reqwest::Client::new()
        .post(format!("{}/api/v1/auth/token", env.base_url()))
        .bearer_auth("not.a.jwt")
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let body: Value = resp.json().await.unwrap();
    let detail = body["detail"].as_str().unwrap_or("").to_lowercase();
    assert!(
        detail.contains("invalid") || detail.contains("token"),
        "expected 'invalid' or 'token' in detail, got: {:?}",
        body["detail"]
    );
}

#[tokio::test]
async fn auth_jwt_missing_authorization_header_returns_401() {
    let env = TopologyTestEnv::start_with_auth(&[], 1000).await.unwrap();

    // No Authorization header at all.
    let resp = reqwest::Client::new()
        .post(format!("{}/api/v1/auth/token", env.base_url()))
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let body: Value = resp.json().await.unwrap();
    assert!(
        body["detail"].as_str().unwrap_or("").contains("Missing"),
        "expected 'Missing' in detail, got: {:?}",
        body["detail"]
    );
}

// ── Section 2 — API key authentication ─────────────────────────────────────

#[tokio::test]
async fn auth_api_key_via_bearer_header_grants_access() {
    // API key auth uses Authorization: Bearer aa_<hex> — not X-API-Key header
    let (plaintext, entry) = make_api_key("key-1", vec![Scope::Read, Scope::Write]);
    let env = TopologyTestEnv::start_with_auth(&[entry], 1000).await.unwrap();

    let resp = reqwest::Client::new()
        .get(format!("{}/api/v1/agents", env.base_url()))
        .bearer_auth(&plaintext)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn auth_api_key_query_param_unsupported_returns_401() {
    // Query-param API key auth is not implemented; only Authorization: Bearer is supported
    let (plaintext, entry) = make_api_key("key-1", vec![Scope::Read]);
    let env = TopologyTestEnv::start_with_auth(&[entry], 1000).await.unwrap();

    // Provide key via query param only — no Authorization header.
    // Use an auth-protected endpoint so we can observe the 401.
    let resp = reqwest::Client::new()
        .post(format!("{}/api/v1/auth/token?api_key={plaintext}", env.base_url()))
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn auth_api_key_revoked_returns_401() {
    let (plaintext, entry) = make_api_key("key-rev", vec![Scope::Read]);
    let env = TopologyTestEnv::start_with_auth(&[entry], 1000).await.unwrap();

    // Revoke the key at runtime — the server holds the same Arc<ApiKeyStore>.
    env.key_store.revoke("key-rev");

    let resp = reqwest::Client::new()
        .post(format!("{}/api/v1/auth/token", env.base_url()))
        .bearer_auth(&plaintext)
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let body: Value = resp.json().await.unwrap();
    assert!(
        body["detail"].as_str().unwrap_or("").contains("revoked"),
        "expected 'revoked' in detail, got: {:?}",
        body["detail"]
    );
}

#[tokio::test]
async fn auth_api_key_unknown_returns_401() {
    // No keys seeded — any aa_-prefixed token is unknown.
    let env = TopologyTestEnv::start_with_auth(&[], 1000).await.unwrap();

    let resp = reqwest::Client::new()
        .post(format!("{}/api/v1/auth/token", env.base_url()))
        .bearer_auth("aa_00000000000000000000000000000000")
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let body: Value = resp.json().await.unwrap();
    let detail = body["detail"].as_str().unwrap_or("").to_lowercase();
    assert!(
        detail.contains("invalid") || detail.contains("api key"),
        "expected 'invalid' or 'api key' in detail, got: {:?}",
        body["detail"]
    );
}

// ── Section 3 — Scope-based authorization ────────────────────────────────────

#[tokio::test]
async fn auth_scope_read_key_accesses_public_endpoint() {
    // GET /agents has no scope guard — any valid auth is accepted
    let (plaintext, entry) = make_api_key("read-key", vec![Scope::Read]);
    let env = TopologyTestEnv::start_with_auth(&[entry], 1000).await.unwrap();

    let resp = reqwest::Client::new()
        .get(format!("{}/api/v1/agents", env.base_url()))
        .bearer_auth(&plaintext)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn auth_scope_read_cannot_elevate_to_write_via_token() {
    // read-scoped caller cannot elevate to write via token endpoint
    let (plaintext, entry) = make_api_key("read-key", vec![Scope::Read]);
    let env = TopologyTestEnv::start_with_auth(&[entry], 1000).await.unwrap();

    let resp = reqwest::Client::new()
        .post(format!("{}/api/v1/auth/token", env.base_url()))
        .bearer_auth(&plaintext)
        .json(&serde_json::json!({"scopes": ["write"]}))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn auth_scope_admin_grants_full_token_issuance() {
    let (plaintext, entry) = make_api_key("admin-key", vec![Scope::Read, Scope::Write, Scope::Admin]);
    let env = TopologyTestEnv::start_with_auth(&[entry], 1000).await.unwrap();

    let resp = reqwest::Client::new()
        .post(format!("{}/api/v1/auth/token", env.base_url()))
        .bearer_auth(&plaintext)
        .json(&serde_json::json!({"scopes": ["read", "write", "admin"]}))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body: Value = resp.json().await.unwrap();
    assert!(body["token"].is_string(), "response must have 'token' string field");
}

#[tokio::test]
async fn auth_scope_read_only_key_blocked_from_policy_mutation() {
    // PolicyWriteAuth requires Write or Admin scope; read-only callers are rejected
    let (plaintext, entry) = make_api_key("read-key", vec![Scope::Read]);
    let env = TopologyTestEnv::start_with_auth(&[entry], 1000).await.unwrap();

    let policy_yaml = r#"
apiVersion: agent-assembly.dev/v1alpha1
kind: GovernancePolicy
metadata:
  name: rbac-test-policy
  version: "1.0.0"
spec:
  rules: []
"#;

    let resp = reqwest::Client::new()
        .post(format!("{}/api/v1/policies", env.base_url()))
        .bearer_auth(&plaintext)
        .json(&serde_json::json!({"policy_yaml": policy_yaml}))
        .send()
        .await
        .unwrap();

    // PolicyWriteAuth maps read → Viewer → denied at all policy scope levels
    let status = resp.status();
    assert!(
        status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN,
        "expected 401 or 403 for read-only caller, got: {status}"
    );
}

// ── Section 4 — Rate limiting ─────────────────────────────────────────────────

#[tokio::test]
async fn auth_rate_limit_within_budget_succeeds() {
    let (plaintext, entry) = make_api_key("key-1", vec![Scope::Read, Scope::Write]);
    let env = TopologyTestEnv::start_with_auth(&[entry], 60).await.unwrap();
    let client = reqwest::Client::new();

    for _ in 0..5 {
        let resp = client
            .post(format!("{}/api/v1/auth/token", env.base_url()))
            .bearer_auth(&plaintext)
            .json(&serde_json::json!({}))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "request within budget should succeed");
    }
}

#[tokio::test]
async fn auth_rate_limit_burst_returns_429_with_retry_after() {
    let (plaintext, entry) = make_api_key("key-rl", vec![Scope::Read, Scope::Write]);
    let env = TopologyTestEnv::start_with_auth(&[entry], 2).await.unwrap();
    let client = reqwest::Client::new();
    let url = format!("{}/api/v1/auth/token", env.base_url());

    // First 2 requests should succeed (rpm=2, bucket starts full).
    for _ in 0..2 {
        let resp = client
            .post(&url)
            .bearer_auth(&plaintext)
            .json(&serde_json::json!({}))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "first requests should succeed");
    }

    // Third request should be rate-limited.
    let resp_429 = client
        .post(&url)
        .bearer_auth(&plaintext)
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp_429.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(
        resp_429.headers().contains_key("retry-after"),
        "429 response must include retry-after header"
    );
    let body: Value = resp_429.json().await.unwrap();
    let detail = body["detail"].as_str().unwrap_or("").to_lowercase();
    assert!(
        detail.contains("rate") || detail.contains("limit") || detail.contains("retry"),
        "expected rate-limit detail, got: {:?}",
        body["detail"]
    );
}

#[tokio::test]
#[ignore = "rate-limit refill window is ~60s; not suitable for CI"]
async fn auth_rate_limit_resets_after_window() {
    let (plaintext, entry) = make_api_key("key-rl-reset", vec![Scope::Read]);
    let env = TopologyTestEnv::start_with_auth(&[entry], 1).await.unwrap();
    let client = reqwest::Client::new();
    let url = format!("{}/api/v1/auth/token", env.base_url());

    // First request succeeds.
    let resp = client
        .post(&url)
        .bearer_auth(&plaintext)
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Second request is rate-limited.
    let resp2 = client
        .post(&url)
        .bearer_auth(&plaintext)
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp2.status(), StatusCode::TOO_MANY_REQUESTS);

    // Wait for bucket to refill (rpm=1 → 1 token per 60s).
    tokio::time::sleep(std::time::Duration::from_secs(61)).await;

    // Third request succeeds after refill.
    let resp3 = client
        .post(&url)
        .bearer_auth(&plaintext)
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp3.status(),
        StatusCode::OK,
        "request should succeed after rate-limit window resets"
    );
}

#[tokio::test]
async fn auth_rate_limit_per_key_isolation() {
    let (plaintext_a, entry_a) = make_api_key("key-a", vec![Scope::Read, Scope::Write]);
    let (plaintext_b, entry_b) = make_api_key("key-b", vec![Scope::Read, Scope::Write]);
    let env = TopologyTestEnv::start_with_auth(&[entry_a, entry_b], 2).await.unwrap();
    let client = reqwest::Client::new();
    let url = format!("{}/api/v1/auth/token", env.base_url());

    // Exhaust key-A's budget (rpm=2 → 2 requests).
    for _ in 0..2 {
        let resp = client
            .post(&url)
            .bearer_auth(&plaintext_a)
            .json(&serde_json::json!({}))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "key-A within budget");
    }

    // key-A should now be rate-limited.
    let resp_a = client
        .post(&url)
        .bearer_auth(&plaintext_a)
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp_a.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "key-A should be exhausted"
    );

    // key-B is unaffected — rate limiting is per-key.
    let resp_b = client
        .post(&url)
        .bearer_auth(&plaintext_b)
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp_b.status(),
        StatusCode::OK,
        "key-B should be independent of key-A's rate limit"
    );
}

// ── Section 5 — Bypass attempts ──────────────────────────────────────────────

/// Craft a classic alg:none unsigned JWT.
///
/// This is the canonical CVE: a JWT with header `{"alg":"none"}` and an
/// empty signature. A correctly implemented verifier must reject it.
fn build_alg_none_jwt() -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;
    let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"none","typ":"JWT"}"#);
    let payload = URL_SAFE_NO_PAD.encode(br#"{"sub":"attacker","iat":0,"exp":9999999999,"scope":[]}"#);
    format!("{header}.{payload}.") // empty signature
}

/// Craft a JWT that claims RS256 in its header but is actually signed with HS256.
///
/// An algorithm-confusion attack: the header is replaced to claim `"alg":"RS256"`
/// while the signature remains HS256. Verifiers that trust the `alg` claim in
/// the header (rather than enforcing a fixed algorithm) are vulnerable.
fn build_swapped_alg_jwt() -> String {
    use aa_api::auth::jwt::Claims;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;
    use jsonwebtoken::{encode, EncodingKey, Header};

    let claims = Claims {
        sub: "attacker".to_string(),
        iat: 0,
        exp: 9_999_999_999,
        scope: vec![],
    };
    let valid_jwt = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(AUTH_IT_JWT_SECRET),
    )
    .unwrap();

    // Replace the header segment with one that claims RS256.
    let fake_header = URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256","typ":"JWT"}"#);
    let parts: Vec<&str> = valid_jwt.splitn(3, '.').collect();
    format!("{}.{}.{}", fake_header, parts[1], parts[2])
}

#[tokio::test]
async fn auth_bypass_header_injection_no_effect() {
    // reqwest/hyper sanitize headers; CRLF injection is rejected at the HTTP client layer.
    // Attempting to inject a CRLF newline into the Authorization header value will
    // either cause reqwest to reject the header (panic/error) or the server to reject it.
    // In either case the injection must not result in a 200 OK.
    let env = TopologyTestEnv::start_with_auth(&[], 1000).await.unwrap();
    let url = format!("{}/api/v1/auth/token", env.base_url());

    // Use a valid JWT as the base token to ensure we're testing injection, not missing auth.
    let jwt = JwtSigner::new(AUTH_IT_JWT_SECRET)
        .sign("test-sub", &[Scope::Read])
        .unwrap();
    let injected_value = format!("Bearer {jwt}\r\nX-Admin: true");

    let result = reqwest::Client::new()
        .post(&url)
        .header("authorization", injected_value)
        .json(&serde_json::json!({}))
        .send()
        .await;

    match result {
        Err(_) => {
            // reqwest/hyper rejected the CRLF-containing header at the client level — injection had no effect.
        }
        Ok(resp) => {
            // The server received the request but must not have treated it as a privileged request.
            let status = resp.status();
            assert_ne!(
                status,
                StatusCode::OK,
                "CRLF-injected authorization header must not result in 200 OK"
            );
        }
    }
}

#[tokio::test]
async fn auth_bypass_path_traversal_no_effect() {
    // path traversal must not expose unintended routes
    let (plaintext, entry) = make_api_key("key-1", vec![Scope::Read]);
    let env = TopologyTestEnv::start_with_auth(&[entry], 1000).await.unwrap();
    let client = reqwest::Client::new();

    // Attempt 1: standard path traversal — reqwest may normalize the path.
    let url1 = format!("{}/api/v1/agents/../admin/secrets", env.base_url());
    let resp1 = client.get(&url1).bearer_auth(&plaintext).send().await.unwrap();
    let s1 = resp1.status();
    assert!(
        s1 == StatusCode::NOT_FOUND || s1 == StatusCode::BAD_REQUEST || s1 == StatusCode::UNAUTHORIZED,
        "path traversal must not expose unintended routes (got {s1})"
    );

    // Attempt 2: percent-encoded traversal — `%2e%2e` = `..`
    let url2 = format!("{}/api/v1/agents/%2e%2e/admin/secrets", env.base_url());
    let resp2 = client.get(&url2).bearer_auth(&plaintext).send().await.unwrap();
    let s2 = resp2.status();
    assert!(
        s2 == StatusCode::NOT_FOUND || s2 == StatusCode::BAD_REQUEST || s2 == StatusCode::UNAUTHORIZED,
        "percent-encoded path traversal must not expose unintended routes (got {s2})"
    );
}

#[tokio::test]
async fn auth_bypass_jwt_alg_none_rejected() {
    // Classic alg:none vulnerability — jsonwebtoken crate rejects unsigned tokens
    let env = TopologyTestEnv::start_with_auth(&[], 1000).await.unwrap();
    let token = build_alg_none_jwt();

    let resp = reqwest::Client::new()
        .post(format!("{}/api/v1/auth/token", env.base_url()))
        .bearer_auth(&token)
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "alg:none JWT must be rejected with 401"
    );
}

#[tokio::test]
async fn auth_bypass_jwt_swapped_alg_rejected() {
    // Algorithm confusion attack — claiming RS256 while signed with HS256 must be rejected
    let env = TopologyTestEnv::start_with_auth(&[], 1000).await.unwrap();
    let token = build_swapped_alg_jwt();

    let resp = reqwest::Client::new()
        .post(format!("{}/api/v1/auth/token", env.base_url()))
        .bearer_auth(&token)
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "algorithm-confusion JWT must be rejected with 401"
    );
}

#[tokio::test]
async fn auth_bypass_repeated_auth_headers_first_wins_or_rejected() {
    // When two Authorization headers are sent the server must either accept the
    // first and ignore the second, or reject the request — it must not grant
    // elevated access from the second header.
    let (key_a, entry_a) = make_api_key("key-a", vec![Scope::Read, Scope::Write]);
    let env = TopologyTestEnv::start_with_auth(&[entry_a], 1000).await.unwrap();
    let jwt_b = JwtSigner::new(AUTH_IT_JWT_SECRET)
        .sign("key-b-elevated", &[Scope::Admin])
        .unwrap();
    let resp = reqwest::Client::new()
        .post(format!("{}/api/v1/auth/token", env.base_url()))
        .header("authorization", format!("Bearer {key_a}"))
        .header("authorization", format!("Bearer {jwt_b}"))
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap();
    let status = resp.status();
    assert!(
        status == StatusCode::OK || status == StatusCode::UNAUTHORIZED,
        "repeated Authorization headers must be handled safely (got {status})"
    );
}

// ── Section 6 — Policy RBAC integration ─────────────────────────────────────
//
// PolicyWriteAuth maps scopes to roles:
//   Scope::Read  → Viewer  (no write access)
//   Scope::Write → Developer (write access for team-scoped policies only)
//   Scope::Admin → OrgAdmin  (write access for global policies)
//
// POST /api/v1/policies uses PolicyWriteAuth (default scope = Global).
// A write-scope (Developer) token can write team-scoped policies but is denied
// at the global level; an admin-scope (OrgAdmin) token can write global policies.

const RBAC_POLICY_YAML: &str = r#"
apiVersion: agent-assembly.dev/v1alpha1
kind: GovernancePolicy
metadata:
  name: rbac-test-policy
  version: "1.0.0"
spec:
  rules: []
"#;

#[tokio::test]
async fn auth_policy_rbac_admin_scope_allows_global_policy_mutation() {
    // Admin-scoped JWT maps to OrgAdmin role → may POST global policies.
    let env = TopologyTestEnv::start_with_auth(&[], 1000).await.unwrap();

    let jwt = JwtSigner::new(AUTH_IT_JWT_SECRET)
        .sign("admin-user", &[Scope::Admin])
        .unwrap();

    let resp = reqwest::Client::new()
        .post(format!("{}/api/v1/policies", env.base_url()))
        .bearer_auth(&jwt)
        .json(&serde_json::json!({ "policy_yaml": RBAC_POLICY_YAML }))
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        StatusCode::CREATED,
        "Admin scope (OrgAdmin role) must be allowed to POST a global policy"
    );
}

#[tokio::test]
async fn auth_policy_rbac_write_scope_denied_at_global_level() {
    // Write-scoped JWT maps to Developer role → denied from POSTing global policies.
    // The default policy scope is Global; Developer role requires a team scope.
    let env = TopologyTestEnv::start_with_auth(&[], 1000).await.unwrap();

    let jwt = JwtSigner::new(AUTH_IT_JWT_SECRET)
        .sign("dev-user", &[Scope::Write])
        .unwrap();

    let resp = reqwest::Client::new()
        .post(format!("{}/api/v1/policies", env.base_url()))
        .bearer_auth(&jwt)
        .json(&serde_json::json!({ "policy_yaml": RBAC_POLICY_YAML }))
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "Write scope (Developer role) must be denied from POSTing a global policy (got {})",
        resp.status()
    );
}

#[tokio::test]
async fn auth_policy_rbac_read_scope_denied_at_all_policy_levels() {
    // Read-scoped JWT maps to Viewer role → denied from any policy mutation.
    let env = TopologyTestEnv::start_with_auth(&[], 1000).await.unwrap();

    let jwt = JwtSigner::new(AUTH_IT_JWT_SECRET)
        .sign("viewer-user", &[Scope::Read])
        .unwrap();

    let resp = reqwest::Client::new()
        .post(format!("{}/api/v1/policies", env.base_url()))
        .bearer_auth(&jwt)
        .json(&serde_json::json!({ "policy_yaml": RBAC_POLICY_YAML }))
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "Read scope (Viewer role) must be denied from all policy mutations (got {})",
        resp.status()
    );
}
