//! Native email/password authentication endpoints (AAASM-5305, ADR 0031).
//!
//! These are the human-operator account endpoints that coexist with the retained
//! API-key path (`routes::auth::issue_token`, deliberately untouched). They are
//! **Postgres-gated** (ADR 0031 D2): every handler that touches an account first
//! resolves the [`AppState::auth_store`], and when it is absent (the in-memory
//! deployment) responds `503 Service Unavailable` so the surface degrades
//! honestly. `GET /auth/methods` advertises whether the password path is even
//! available so the frontend never offers a form the backend cannot serve.
//!
//! Both this login path and `/auth/token` mint the **same** scoped JWT shape
//! (via [`JwtSigner`]), differing only in lifetime, so every downstream RBAC gate
//! reads either credential source unchanged.
//!
//! Security posture (ADR 0031 §"Security considerations", development rule 7):
//! - Login is enumeration-safe: a uniform `401` for unknown-email OR bad-password,
//!   and an unknown email still runs an argon2 verify against a dummy hash so the
//!   response time does not leak whether the account exists.
//! - Lockout is Postgres-backed (never in memory) → `423` + `retry-after`.
//! - The refresh token is opaque, hashed-at-rest, delivered as an
//!   `HttpOnly; Secure; SameSite=Strict` cookie, rotated on every refresh, and
//!   revocable (logout).
//! - Register bootstrap is advisory-locked so two concurrent registrations can
//!   never both claim `owner`.
//! - Passwords, tokens, and hashes are never logged and never returned on the wire.

use std::sync::Arc;
use std::sync::OnceLock;

use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use utoipa::ToSchema;
use uuid::Uuid;

use aa_auth::jwt::JwtSigner;
use aa_auth::password::{hash_password, verify_password};
use aa_auth::role::Role;
use aa_auth::scope::Scope;
use aa_auth::AuthenticatedCaller;
use aa_storage_postgres::{BootstrapOutcome, NewInvite, NewUser, PgUserStore, UserRecord, UserRole, UserStatus};

use crate::error::ProblemDetail;
use crate::native_auth::NativeAuthConfig;
use crate::state::AppState;

/// The cookie name carrying the opaque refresh token.
const REFRESH_COOKIE: &str = "aa_refresh";

/// The cookie `Path`. Scoped to the auth surface so the refresh token is only
/// ever sent to the endpoints that consume it (refresh / logout), not attached
/// to every API call.
const REFRESH_COOKIE_PATH: &str = "/api/v1/auth";

// ── Request / response bodies ────────────────────────────────────────────────

/// Request body for `POST /auth/login`.
#[derive(Debug, Deserialize, ToSchema)]
pub struct LoginRequest {
    /// The account email (case-insensitive).
    pub email: String,
    /// The account password.
    pub password: String,
    /// When true, the refresh session is issued with an extended lifetime.
    #[serde(default)]
    pub remember_me: bool,
}

/// Response body carrying a freshly minted access token (login / refresh /
/// invite-accept). The refresh token is NOT in the body — it rides in the
/// HttpOnly cookie.
#[derive(Debug, Serialize, ToSchema)]
pub struct AccessTokenResponse {
    /// The short-lived access JWT to present as `Authorization: Bearer`.
    pub access_token: String,
    /// Access-token lifetime in seconds.
    pub expires_in: u64,
}

/// Request body for `POST /auth/register`.
#[derive(Debug, Deserialize, ToSchema)]
pub struct RegisterRequest {
    /// The new account email (case-insensitive). OSS is single-workspace, so no
    /// `tenant_name` is accepted (ADR 0031 §4).
    pub email: String,
    /// The new account password (must clear the minimum-length floor).
    pub password: String,
}

/// Response body for a successful `POST /auth/register`.
#[derive(Debug, Serialize, ToSchema)]
pub struct RegisterResponse {
    /// The id of the newly created account (UUID string).
    pub user_id: String,
    /// The short-lived access JWT for the bootstrap owner (the refresh token is
    /// delivered as the HttpOnly cookie alongside).
    pub access_token: String,
    /// Access-token lifetime in seconds.
    pub expires_in: u64,
}

/// Request body for `POST /auth/invite` (admin only).
#[derive(Debug, Deserialize, ToSchema)]
pub struct InviteRequest {
    /// The email to invite.
    pub email: String,
    /// The role the invited account will receive on accept.
    pub role: Role,
}

/// Response body for `POST /auth/invite`. The raw invite token is returned once
/// to the inviting admin to deliver out of band; only its hash is stored.
#[derive(Debug, Serialize, ToSchema)]
pub struct InviteResponse {
    /// The created invite id (UUID string).
    pub invite_id: String,
    /// The single-use, expiring raw invite token. Returned exactly once, here;
    /// the server stores only its SHA-256 hash and can never surface it again.
    pub token: String,
}

/// Request body for `POST /auth/invite/accept`.
#[derive(Debug, Deserialize, ToSchema)]
pub struct InviteAcceptRequest {
    /// The raw invite token delivered to the invitee.
    pub token: String,
    /// The initial password to set on the account (must clear the floor).
    pub password: String,
}

/// Response body for `GET /auth/methods` (ADR 0031 §Q5). Advertises which
/// credential paths this deployment can serve so the frontend degrades honestly.
#[derive(Debug, Serialize, ToSchema)]
pub struct AuthMethodsResponse {
    /// `["api_key"]` on an in-memory deployment; `["api_key","password"]` when a
    /// Postgres store backs native accounts.
    pub methods: Vec<String>,
}

// ── Endpoints ────────────────────────────────────────────────────────────────

/// Advertise the credential methods this deployment supports (ADR 0031 §Q5).
///
/// Public: the login page reads this before rendering, so it never offers a
/// password form on an in-memory (API-key-only) backend. Always lists `api_key`;
/// adds `password` only when a Postgres-backed account store is configured.
#[utoipa::path(
    get,
    path = "/api/v1/auth/methods",
    responses((status = 200, description = "Available auth methods", body = AuthMethodsResponse)),
    tag = "auth"
)]
pub async fn auth_methods(Extension(state): Extension<AppState>) -> Json<AuthMethodsResponse> {
    let mut methods = vec!["api_key".to_string()];
    if state.auth_store.is_some() {
        methods.push("password".to_string());
    }
    Json(AuthMethodsResponse { methods })
}

/// Authenticate with email + password, returning an access token and setting the
/// refresh cookie (ADR 0031 §3).
///
/// Enumeration-safe: an unknown email and a wrong password both return a uniform
/// `401`, and an unknown email still runs an argon2 verify against a dummy hash
/// so the timing does not distinguish the two. A locked account returns `423`
/// with `retry-after` regardless of whether the password is correct.
#[utoipa::path(
    post,
    path = "/api/v1/auth/login",
    request_body = LoginRequest,
    responses(
        (status = 200, description = "Authenticated", body = AccessTokenResponse),
        (status = 401, description = "Invalid credentials", body = ProblemDetail),
        (status = 423, description = "Account locked", body = ProblemDetail),
        (status = 503, description = "Native auth not available (no Postgres)", body = ProblemDetail),
    ),
    tag = "auth"
)]
pub async fn login(
    Extension(state): Extension<AppState>,
    Extension(jwt_signer): Extension<Arc<JwtSigner>>,
    Json(body): Json<LoginRequest>,
) -> Response {
    let store = match require_store(&state) {
        Ok(s) => s,
        Err(e) => return e.into_response(),
    };
    let cfg = &state.native_auth;
    let org = cfg.default_org_id;

    let user = match store.find_by_email(org, &body.email).await {
        Ok(u) => u,
        Err(_) => return internal_error().into_response(),
    };

    // Enumeration-safe timing: verify against a dummy hash when the account is
    // absent so the response time does not reveal whether the email exists.
    let Some(user) = user else {
        let _ = verify_password(dummy_hash(), &body.password);
        return unauthorized().into_response();
    };

    // Lockout is checked BEFORE the password verify so a locked account is
    // refused even with correct credentials (and the correct-password path does
    // not silently reset the lock).
    match store.lockout_state(org, user.id).await {
        Ok(state_) => {
            if let Some(retry_after) = state_.retry_after_secs(now()) {
                return locked(retry_after).into_response();
            }
        }
        Err(_) => return internal_error().into_response(),
    }

    // Always run the argon2 verify — even for a disabled/invited account and even
    // when we already know the status is non-Active — so the response time does
    // not distinguish "active wrong password" from "non-active account" (a
    // short-circuit here would leak a status oracle by timing). The password_ok
    // and status_ok checks are then combined without a boolean short-circuit.
    let password_ok = verify_password(&user.password_hash, &body.password);
    let credentials_ok = password_ok & (user.status == UserStatus::Active);
    if !credentials_ok {
        // Record the failure and, if this attempt crossed the lockout threshold,
        // return 423 + retry-after immediately (rather than a plain 401 that
        // silently hides the just-applied lock until the next attempt). A
        // non-active account has nothing to lock — it still returns a uniform 401.
        if user.status == UserStatus::Active {
            if let Ok(state_) = store
                .record_login_failure(org, user.id, cfg.lockout_threshold, cfg.lockout_window_secs)
                .await
            {
                if let Some(retry_after) = state_.retry_after_secs(now()) {
                    return locked(retry_after).into_response();
                }
            }
        }
        return unauthorized().into_response();
    }

    // Success: clear the failed-attempt counter and issue tokens.
    if store.clear_login_failures(org, user.id).await.is_err() {
        return internal_error().into_response();
    }

    issue_session(&store, jwt_signer.as_ref(), cfg, &user, body.remember_me)
        .await
        .map(|(json, cookie)| with_cookie(StatusCode::OK, json, cookie))
        .unwrap_or_else(|e| e.into_response())
}

/// Register the first account (bootstrap owner) or a self-registered account when
/// open registration is enabled (ADR 0031 §4 / §Q3).
///
/// The first account on a fresh instance becomes `owner` under an advisory lock
/// so two concurrent registrations cannot both claim owner. Once a user exists,
/// registration is closed (`403`) unless `AA_AUTH_OPEN_REGISTRATION` is set, in
/// which case a subsequent registration creates a `developer` account.
#[utoipa::path(
    post,
    path = "/api/v1/auth/register",
    request_body = RegisterRequest,
    responses(
        (status = 200, description = "Registered", body = RegisterResponse),
        (status = 403, description = "Registration closed", body = ProblemDetail),
        (status = 409, description = "Email already exists", body = ProblemDetail),
        (status = 422, description = "Weak password", body = ProblemDetail),
        (status = 503, description = "Native auth not available (no Postgres)", body = ProblemDetail),
    ),
    tag = "auth"
)]
pub async fn register(
    Extension(state): Extension<AppState>,
    Extension(jwt_signer): Extension<Arc<JwtSigner>>,
    Json(body): Json<RegisterRequest>,
) -> Response {
    let store = match require_store(&state) {
        Ok(s) => s,
        Err(e) => return e.into_response(),
    };
    let cfg = &state.native_auth;
    let org = cfg.default_org_id;

    if !cfg.password_is_strong_enough(&body.password) {
        return weak_password(cfg.min_password_len).into_response();
    }

    let password_hash = match hash_password(&body.password) {
        Ok(h) => h,
        Err(_) => return internal_error().into_response(),
    };

    let new_id = Uuid::new_v4();
    let outcome = match store
        .bootstrap_first_user(org, cfg.default_org_name, new_id, &body.email, &password_hash)
        .await
    {
        Ok(o) => o,
        // A unique-index violation here means the email already exists in the
        // bootstrap path (a genuine concurrent duplicate) → 409.
        Err(_) => return email_conflict().into_response(),
    };

    let user = match outcome {
        BootstrapOutcome::CreatedOwner { .. } => UserRecord {
            id: new_id,
            email: body.email.clone(),
            password_hash,
            org_id: org,
            role: UserRole::Owner,
            status: UserStatus::Active,
            created_at: now(),
            updated_at: now(),
            last_login_at: None,
        },
        BootstrapOutcome::AlreadyBootstrapped { .. } => {
            // Not the first user. Closed unless open registration is enabled.
            if !cfg.open_registration {
                return registration_closed().into_response();
            }
            // Reject a duplicate email up front (register legitimately reveals
            // existence via 409 per ADR 0031 §3 — this is not the login surface).
            match store.find_by_email(org, &body.email).await {
                Ok(Some(_)) => return email_conflict().into_response(),
                Ok(None) => {}
                Err(_) => return internal_error().into_response(),
            }
            let new_user = NewUser {
                id: new_id,
                email: body.email.clone(),
                password_hash: password_hash.clone(),
                role: UserRole::Developer,
                status: UserStatus::Active,
            };
            if store.create_user(org, &new_user).await.is_err() {
                // Most likely a race lost to the unique index → 409.
                return email_conflict().into_response();
            }
            UserRecord {
                id: new_id,
                email: body.email.clone(),
                password_hash,
                org_id: org,
                role: UserRole::Developer,
                status: UserStatus::Active,
                created_at: now(),
                updated_at: now(),
                last_login_at: None,
            }
        }
    };

    // A registered account is logged straight in (bootstrap admin / self-signup),
    // returning tokens + the refresh cookie.
    match issue_session(&store, jwt_signer.as_ref(), cfg, &user, false).await {
        Ok((json, cookie)) => {
            let resp = RegisterResponse {
                user_id: user.id.to_string(),
                access_token: json.access_token,
                expires_in: json.expires_in,
            };
            with_cookie(StatusCode::OK, resp, cookie)
        }
        Err(e) => e.into_response(),
    }
}

/// Create a single-use, expiring invite for a new account (admin scope only)
/// (ADR 0031 §3). The raw token is returned once here; only its hash is stored.
#[utoipa::path(
    post,
    path = "/api/v1/auth/invite",
    request_body = InviteRequest,
    responses(
        (status = 200, description = "Invite created", body = InviteResponse),
        (status = 403, description = "Caller is not an admin", body = ProblemDetail),
        (status = 503, description = "Native auth not available (no Postgres)", body = ProblemDetail),
    ),
    security(("bearer_auth" = [])),
    tag = "auth"
)]
pub async fn invite(
    Extension(state): Extension<AppState>,
    caller: AuthenticatedCaller,
    Json(body): Json<InviteRequest>,
) -> Result<Json<InviteResponse>, ProblemDetail> {
    let store = require_store(&state)?;
    let cfg = &state.native_auth;

    if !Scope::Admin.is_satisfied_by(&caller.scopes) {
        return Err(
            ProblemDetail::from_status(StatusCode::FORBIDDEN).with_detail("Creating an invite requires admin scope")
        );
    }

    let org = cfg.default_org_id;

    // Create the invited (password-less) account row FIRST, so a token is only
    // ever handed out for a fresh, activatable account. It is created `invited`
    // with a placeholder hash that never verifies, so it cannot authenticate
    // until accept sets a real password. If the email already exists (any
    // status), the create fails on the unique index → 409, and no dead invite
    // token is issued. This is the admin surface (not the login surface), so
    // revealing existence via 409 is acceptable and matches register.
    let invited_user = NewUser {
        id: Uuid::new_v4(),
        email: body.email.clone(),
        password_hash: unset_password_hash().to_string(),
        role: role_to_user_role(body.role),
        status: UserStatus::Invited,
    };
    if store.create_user(org, &invited_user).await.is_err() {
        return Err(email_conflict());
    }

    // The raw token is opaque and single-use; only its hash is persisted. Bind
    // the invite to the account just created (invited_by = the account row) so
    // one token maps to exactly one account.
    let raw_token = generate_opaque_token();
    let token_hash = sha256_hex(&raw_token);
    let invite_id = Uuid::new_v4();

    let new_invite = NewInvite {
        id: invite_id,
        token_hash,
        email: body.email.clone(),
        role: role_to_user_role(body.role),
        expires_at: now() + chrono::Duration::days(7),
        invited_by: Uuid::parse_str(&caller.key_id).ok(),
    };
    store
        .create_invite(org, &new_invite)
        .await
        .map_err(|_| internal_error())?;

    Ok(Json(InviteResponse {
        invite_id: invite_id.to_string(),
        token: raw_token,
    }))
}

/// Accept an invite: consume the single-use token and set the initial password,
/// activating the account (ADR 0031 §3). Public: the invitee is not yet
/// authenticated.
#[utoipa::path(
    post,
    path = "/api/v1/auth/invite/accept",
    request_body = InviteAcceptRequest,
    responses(
        (status = 200, description = "Invite accepted", body = AccessTokenResponse),
        (status = 422, description = "Token expired/used or weak password", body = ProblemDetail),
        (status = 503, description = "Native auth not available (no Postgres)", body = ProblemDetail),
    ),
    tag = "auth"
)]
pub async fn invite_accept(
    Extension(state): Extension<AppState>,
    Extension(jwt_signer): Extension<Arc<JwtSigner>>,
    Json(body): Json<InviteAcceptRequest>,
) -> Response {
    let store = match require_store(&state) {
        Ok(s) => s,
        Err(e) => return e.into_response(),
    };
    let cfg = &state.native_auth;
    let org = cfg.default_org_id;

    if !cfg.password_is_strong_enough(&body.password) {
        return weak_password(cfg.min_password_len).into_response();
    }

    // Hash the new password BEFORE consuming the single-use token, so a hashing
    // failure cannot burn the invite and leave the invitee permanently unable to
    // accept it (the token is spent but the account was never activated).
    let password_hash = match hash_password(&body.password) {
        Ok(h) => h,
        Err(_) => return internal_error().into_response(),
    };

    let token_hash = sha256_hex(&body.token);
    let invite = match store.consume_invite(org, &token_hash).await {
        Ok(Some(inv)) => inv,
        Ok(None) => return invalid_invite().into_response(),
        Err(_) => return internal_error().into_response(),
    };

    // Find the invited account by email and activate it.
    let user = match store.find_by_email(org, &invite.email).await {
        Ok(Some(u)) => u,
        Ok(None) => return invalid_invite().into_response(),
        Err(_) => return internal_error().into_response(),
    };
    match store.activate_invited_user(org, user.id, &password_hash).await {
        Ok(true) => {}
        // Already active (or gone): the invite was consumed but the account
        // cannot be activated — treat as an invalid/spent invite.
        Ok(false) => return invalid_invite().into_response(),
        Err(_) => return internal_error().into_response(),
    }

    let activated = UserRecord {
        password_hash,
        status: UserStatus::Active,
        ..user
    };
    issue_session(&store, jwt_signer.as_ref(), cfg, &activated, false)
        .await
        .map(|(json, cookie)| with_cookie(StatusCode::OK, json, cookie))
        .unwrap_or_else(|e| e.into_response())
}

/// Exchange a valid refresh cookie for a new access token, rotating the refresh
/// token (ADR 0031 §5). Public (the cookie is the credential).
#[utoipa::path(
    post,
    path = "/api/v1/auth/refresh",
    responses(
        (status = 200, description = "Refreshed", body = AccessTokenResponse),
        (status = 401, description = "Missing / revoked / expired refresh token", body = ProblemDetail),
        (status = 503, description = "Native auth not available (no Postgres)", body = ProblemDetail),
    ),
    tag = "auth"
)]
pub async fn refresh(
    Extension(state): Extension<AppState>,
    Extension(jwt_signer): Extension<Arc<JwtSigner>>,
    headers: HeaderMap,
) -> Response {
    let store = match require_store(&state) {
        Ok(s) => s,
        Err(e) => return e.into_response(),
    };
    let cfg = &state.native_auth;
    let org = cfg.default_org_id;

    let Some(raw) = read_refresh_cookie(&headers) else {
        return unauthorized().into_response();
    };
    let token_hash = sha256_hex(&raw);

    // Read the session to recover its owner and check expiry. Liveness here is
    // advisory only — the authoritative single-use gate is the atomic revoke
    // below, which is what makes rotation race-safe.
    let record = match store.find_refresh_token(org, &token_hash).await {
        Ok(Some(r)) if r.is_live(now()) => r,
        Ok(_) => return unauthorized().into_response(),
        Err(_) => return internal_error().into_response(),
    };

    // Rotate: atomically revoke the presented token BEFORE issuing the
    // replacement. `revoke_refresh_token` flips `revoked_at` only `WHERE
    // revoked_at IS NULL`, so it is a compare-and-set: exactly one caller gets
    // `true`. A concurrent replay of the same cookie (or a re-submitted request)
    // loses the race, gets `false`, and is rejected — so one cookie can never
    // mint two live sessions.
    match store.revoke_refresh_token(org, &token_hash).await {
        Ok(true) => {}
        Ok(false) => return unauthorized().into_response(),
        Err(_) => return internal_error().into_response(),
    }

    let user = match store.find_by_id(org, record.user_id).await {
        Ok(Some(u)) if u.status == UserStatus::Active => u,
        Ok(_) => return unauthorized().into_response(),
        Err(_) => return internal_error().into_response(),
    };

    // Preserve the presented refresh lifetime shape: a rotated session keeps the
    // default (non-remembered) lifetime; a longer-lived remembered session is
    // re-established on the next explicit login.
    issue_session(&store, jwt_signer.as_ref(), cfg, &user, false)
        .await
        .map(|(json, cookie)| with_cookie(StatusCode::OK, json, cookie))
        .unwrap_or_else(|e| e.into_response())
}

/// Revoke the refresh session and clear the cookie (ADR 0031 §5). Requires an
/// authenticated caller; always returns `204`.
#[utoipa::path(
    post,
    path = "/api/v1/auth/logout",
    responses(
        (status = 204, description = "Logged out (refresh revoked)"),
        (status = 401, description = "Not authenticated", body = ProblemDetail),
    ),
    security(("bearer_auth" = [])),
    tag = "auth"
)]
pub async fn logout(
    Extension(state): Extension<AppState>,
    _caller: AuthenticatedCaller,
    headers: HeaderMap,
) -> Response {
    // Best-effort revoke: if a Postgres store and a cookie are present, revoke the
    // presented refresh token. The response is 204 regardless so logout is
    // idempotent and never leaks whether a session existed.
    if let Some(store) = state.auth_store.as_ref() {
        if let Some(raw) = read_refresh_cookie(&headers) {
            let _ = store
                .revoke_refresh_token(state.native_auth.default_org_id, &sha256_hex(&raw))
                .await;
        }
    }

    let mut resp = StatusCode::NO_CONTENT.into_response();
    resp.headers_mut().insert(header::SET_COOKIE, cleared_refresh_cookie());
    resp
}

// ── Shared helpers ───────────────────────────────────────────────────────────

/// Resolve the Postgres account store, or a `503` when native auth is not
/// available (in-memory deployment, ADR 0031 D2).
fn require_store(state: &AppState) -> Result<Arc<PgUserStore>, ProblemDetail> {
    state.auth_store.clone().ok_or_else(|| {
        ProblemDetail::from_status(StatusCode::SERVICE_UNAVAILABLE)
            .with_detail("Native email/password auth requires a Postgres-backed deployment")
    })
}

/// Mint an access token + a fresh refresh session for `user`, returning the
/// response body and the `Set-Cookie` value carrying the refresh token.
async fn issue_session(
    store: &PgUserStore,
    jwt_signer: &JwtSigner,
    cfg: &NativeAuthConfig,
    user: &UserRecord,
    remember_me: bool,
) -> Result<(AccessTokenResponse, HeaderValue), ProblemDetail> {
    let scopes = user_role_to_role(user.role).scopes();
    // Same JWT shape as /auth/token: subject + scope + tenant org; short TTL.
    let access_token = jwt_signer
        .sign_with_ttl(
            &user.id.to_string(),
            &scopes,
            None,
            Some(user.org_id.to_string()),
            cfg.access_ttl_secs,
        )
        .map_err(|_| internal_error())?;

    let refresh_ttl = cfg.refresh_ttl_for(remember_me);
    let raw_refresh = generate_opaque_token();
    let refresh_hash = sha256_hex(&raw_refresh);
    let expires_at = now() + chrono::Duration::seconds(refresh_ttl as i64);
    store
        .store_refresh_token(user.org_id, Uuid::new_v4(), &refresh_hash, user.id, expires_at)
        .await
        .map_err(|_| internal_error())?;

    let cookie = refresh_cookie(&raw_refresh, refresh_ttl);
    Ok((
        AccessTokenResponse {
            access_token,
            expires_in: cfg.access_ttl_secs,
        },
        cookie,
    ))
}

/// Build a JSON `Response` with the refresh `Set-Cookie` header attached.
fn with_cookie<T: Serialize>(status: StatusCode, body: T, cookie: HeaderValue) -> Response {
    let mut resp = (status, Json(body)).into_response();
    resp.headers_mut().insert(header::SET_COOKIE, cookie);
    resp
}

/// Build the refresh-token `Set-Cookie` value:
/// `HttpOnly; Secure; SameSite=Strict`, path-scoped to the auth surface, with a
/// `Max-Age` matching the refresh lifetime (ADR 0031 §5).
fn refresh_cookie(token: &str, max_age_secs: u64) -> HeaderValue {
    let raw = format!(
        "{REFRESH_COOKIE}={token}; Max-Age={max_age_secs}; Path={REFRESH_COOKIE_PATH}; \
         HttpOnly; Secure; SameSite=Strict"
    );
    HeaderValue::from_str(&raw).expect("refresh cookie is a valid header value")
}

/// Build a `Set-Cookie` that immediately expires the refresh cookie (logout).
fn cleared_refresh_cookie() -> HeaderValue {
    let raw = format!("{REFRESH_COOKIE}=; Max-Age=0; Path={REFRESH_COOKIE_PATH}; HttpOnly; Secure; SameSite=Strict");
    HeaderValue::from_str(&raw).expect("cleared refresh cookie is a valid header value")
}

/// Read the raw refresh token from the request `Cookie` header, if present.
fn read_refresh_cookie(headers: &HeaderMap) -> Option<String> {
    let cookie_header = headers.get(header::COOKIE)?.to_str().ok()?;
    for pair in cookie_header.split(';') {
        let pair = pair.trim();
        if let Some(value) = pair.strip_prefix(&format!("{REFRESH_COOKIE}=")) {
            if !value.is_empty() {
                return Some(value.to_string());
            }
        }
    }
    None
}

/// Generate a 256-bit opaque token as lowercase hex (refresh / invite tokens).
///
/// Uses the same CSPRNG (`rand::rng`) as API-key / WS-ticket generation. 256 bits
/// of entropy makes the token unguessable; it is meaningless without the
/// server-side hash store.
fn generate_opaque_token() -> String {
    use rand::RngExt;
    let mut rng = rand::rng();
    let mut bytes = [0u8; 32];
    rng.fill(&mut bytes);
    hex::encode(bytes)
}

/// SHA-256 of an opaque token, lowercase hex — the at-rest representation.
fn sha256_hex(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hasher.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

/// A password-hash placeholder for a not-yet-accepted invited account. It is a
/// syntactically invalid PHC string, so [`verify_password`] can never accept any
/// candidate against it — the account is unauthenticatable until accept sets a
/// real hash.
fn unset_password_hash() -> &'static str {
    "invited-no-password-set"
}

/// A dummy argon2 hash used to equalise login timing on an unknown email. Minted
/// once from a random password so an unknown-email login still pays the argon2
/// verify cost without ever matching a real password.
fn dummy_hash() -> &'static str {
    static DUMMY: OnceLock<String> = OnceLock::new();
    DUMMY.get_or_init(|| {
        let secret = generate_opaque_token();
        hash_password(&secret).expect("dummy hash mints")
    })
}

/// Map the storage-layer role to the auth-layer role (same lowercase labels).
fn user_role_to_role(role: UserRole) -> Role {
    match role {
        UserRole::Owner => Role::Owner,
        UserRole::Admin => Role::Admin,
        UserRole::Developer => Role::Developer,
        UserRole::Viewer => Role::Viewer,
    }
}

/// Map the auth-layer role to the storage-layer role (same lowercase labels).
fn role_to_user_role(role: Role) -> UserRole {
    match role {
        Role::Owner => UserRole::Owner,
        Role::Admin => UserRole::Admin,
        Role::Developer => UserRole::Developer,
        Role::Viewer => UserRole::Viewer,
    }
}

/// Current wall-clock time.
fn now() -> chrono::DateTime<chrono::Utc> {
    chrono::Utc::now()
}

// ── Error constructors (uniform, leak-free) ──────────────────────────────────

fn unauthorized() -> ProblemDetail {
    // Uniform for unknown-email OR bad-password (enumeration-safe).
    ProblemDetail::from_status(StatusCode::UNAUTHORIZED).with_detail("Invalid email or password")
}

fn locked(retry_after_secs: u64) -> Response {
    let problem = ProblemDetail::from_status(StatusCode::LOCKED)
        .with_detail("Account locked due to too many failed login attempts");
    let mut resp = problem.into_response();
    resp.headers_mut().insert(
        header::RETRY_AFTER,
        HeaderValue::from_str(&retry_after_secs.to_string()).expect("integer is a valid header value"),
    );
    resp
}

fn registration_closed() -> ProblemDetail {
    ProblemDetail::from_status(StatusCode::FORBIDDEN)
        .with_detail("Registration is closed; new accounts are created by invite")
}

fn email_conflict() -> ProblemDetail {
    ProblemDetail::from_status(StatusCode::CONFLICT).with_detail("An account with that email already exists")
}

fn weak_password(min_len: usize) -> ProblemDetail {
    ProblemDetail::from_status(StatusCode::UNPROCESSABLE_ENTITY)
        .with_detail(format!("Password must be at least {min_len} characters"))
}

fn invalid_invite() -> ProblemDetail {
    ProblemDetail::from_status(StatusCode::UNPROCESSABLE_ENTITY)
        .with_detail("Invite token is invalid, expired, or already used")
}

fn internal_error() -> ProblemDetail {
    // Deliberately generic: never surfaces a password, token, hash, or DB detail.
    ProblemDetail::from_status(StatusCode::INTERNAL_SERVER_ERROR).with_detail("Authentication service error")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refresh_cookie_carries_all_security_attributes() {
        let cookie = refresh_cookie("opaque-token-value", 3600);
        let s = cookie.to_str().unwrap();
        assert!(s.contains("aa_refresh=opaque-token-value"));
        assert!(s.contains("HttpOnly"), "cookie must be HttpOnly: {s}");
        assert!(s.contains("Secure"), "cookie must be Secure: {s}");
        assert!(s.contains("SameSite=Strict"), "cookie must be SameSite=Strict: {s}");
        assert!(s.contains("Max-Age=3600"));
        assert!(s.contains("Path=/api/v1/auth"));
    }

    #[test]
    fn cleared_cookie_expires_immediately() {
        let s = cleared_refresh_cookie();
        let s = s.to_str().unwrap();
        assert!(s.contains("Max-Age=0"), "logout cookie must expire now: {s}");
        assert!(s.contains("HttpOnly") && s.contains("Secure") && s.contains("SameSite=Strict"));
    }

    #[test]
    fn read_refresh_cookie_extracts_the_named_value() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            HeaderValue::from_static("other=x; aa_refresh=the-token; another=y"),
        );
        assert_eq!(read_refresh_cookie(&headers).as_deref(), Some("the-token"));
    }

    #[test]
    fn read_refresh_cookie_absent_or_empty_is_none() {
        let empty = HeaderMap::new();
        assert!(read_refresh_cookie(&empty).is_none());

        let mut headers = HeaderMap::new();
        headers.insert(header::COOKIE, HeaderValue::from_static("aa_refresh=; other=z"));
        assert!(read_refresh_cookie(&headers).is_none(), "empty cookie value is None");
    }

    #[test]
    fn opaque_tokens_are_unpredictable_and_hex() {
        let a = generate_opaque_token();
        let b = generate_opaque_token();
        assert_ne!(a, b, "two tokens must differ");
        assert_eq!(a.len(), 64, "32 bytes -> 64 hex chars");
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn sha256_hex_is_stable_and_not_the_input() {
        let token = "some-opaque-token";
        let h = sha256_hex(token);
        assert_eq!(h, sha256_hex(token), "hashing is deterministic");
        assert_ne!(h, token, "the stored hash is not the raw token");
        assert_eq!(h.len(), 64);
    }

    #[test]
    fn dummy_hash_is_a_real_argon2_hash_that_never_matches() {
        let h = dummy_hash();
        assert!(
            h.starts_with("$argon2id$"),
            "must be a real PHC hash for constant-time verify"
        );
        // It must not verify against a guessed password (it was minted from a
        // random secret the caller never sees).
        assert!(!verify_password(h, "password"));
        assert!(!verify_password(h, ""));
    }

    #[test]
    fn role_mapping_roundtrips_between_layers() {
        for role in [Role::Owner, Role::Admin, Role::Developer, Role::Viewer] {
            assert_eq!(user_role_to_role(role_to_user_role(role)), role);
        }
    }

    #[test]
    fn unset_invite_password_placeholder_never_verifies() {
        // An invited-but-not-accepted account carries a placeholder that can never
        // authenticate, so a login attempt before accept is always rejected.
        assert!(!verify_password(unset_password_hash(), "anything"));
    }
}
