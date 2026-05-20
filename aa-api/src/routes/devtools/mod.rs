//! Dev tool governance endpoints.
//!
//! Currently exposes one endpoint:
//! - `POST /devtools/saas/{provider}/events` — ingests signed audit webhook
//!   events from SaaS coding-agent providers (AAASM-924).
//!
//! # Webhook pipeline
//!
//! 1. **Parse provider** — the `{provider}` path segment is parsed into
//!    [`aa_devtool_saas::provider::SaasProvider`]. Unknown values return 404.
//! 2. **Resolve secret** — the per-provider secret reference is looked up
//!    through [`secret_cache::SecretCache`], which caches resolved bytes for
//!    [`secret_cache::SECRET_CACHE_TTL`] (5 minutes). The default resolver
//!    reads from an environment variable; the Vault backend swaps in via the
//!    [`secret_cache::SecretResolver`] trait. Returns 401 if absent.
//! 3. **Verify signature** — [`aa_devtool_saas::signature::verify`] runs the
//!    per-provider scheme (Anthropic, OpenAI, or Cursor) using a constant-time
//!    HMAC-SHA256 compare. Returns 401 on missing header or mismatch BEFORE
//!    parsing the body.
//! 4. **Parse body** — [`aa_devtool_saas::parser::parse`] decodes the
//!    provider-specific JSON into a single
//!    [`aa_devtool_saas::event::SaasAuditEvent`]. Returns 400 on malformed JSON
//!    or missing required field.
//! 5. **Persist to audit pipeline** —
//!    [`audit_mapping::to_audit_entry`] builds an [`aa_core::AuditEntry`] tagged
//!    with `Lineage::spawned_by_tool = "saas:<provider>"`, then
//!    `try_send`s it onto [`crate::state::AppState::audit_sender`]. The send
//!    is non-blocking: 503 on `Full`, 503 on `Closed`, 503 if the sender is
//!    `None` (pipeline unconnected). Success returns 202.
//!
//! # Status code summary
//!
//! | Code | Meaning |
//! | --- | --- |
//! | 202 | Signed, parsed, queued. |
//! | 400 | Body failed provider-specific parse. |
//! | 401 | Signature header missing, secret unresolved, or HMAC mismatch. |
//! | 404 | `{provider}` not in `{claude-ai, chatgpt, cursor-cloud}`. |
//! | 503 | Audit pipeline disconnected or at capacity. |

pub mod audit_mapping;
pub mod secret_cache;

use axum::body::Bytes;
use axum::extract::Path;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::Extension;
use tokio::sync::mpsc::error::TrySendError;

use aa_devtool_saas::parser;
use aa_devtool_saas::provider::SaasProvider;
use aa_devtool_saas::signature::{self, SignatureError};

use crate::error::ProblemDetail;
use crate::state::AppState;

/// Parse a URL path segment into a [`SaasProvider`].
///
/// Returns `None` for any value not in the known set. Callers translate
/// that into HTTP 404 (AAASM-924 AC).
fn parse_provider(s: &str) -> Option<SaasProvider> {
    match s {
        "claude-ai" => Some(SaasProvider::ClaudeAi),
        "chatgpt" => Some(SaasProvider::ChatGpt),
        "cursor-cloud" => Some(SaasProvider::CursorCloud),
        _ => None,
    }
}

/// Derive the per-provider HMAC secret reference used to look up the key
/// via the [`secret_cache::SecretCache`].
///
/// Today the reference doubles as the environment variable name
/// (`AA_SAAS_<PROVIDER>_HMAC_SECRET`) because the default backend is
/// [`secret_cache::EnvVarResolver`]. When the Vault-backed resolver is
/// wired (see secret_cache module rustdoc), this function will return a
/// `vault:secret/...` reference fetched from `SaasProviderConfig`.
fn secret_ref_for(provider_str: &str) -> String {
    format!("AA_SAAS_{}_HMAC_SECRET", provider_str.replace('-', "_").to_uppercase())
}

/// `POST /api/v1/devtools/saas/{provider}/events`
///
/// Ingest a signed audit-webhook event from a SaaS coding-agent provider.
///
/// # Flow
/// 1. Parse `{provider}` to a [`SaasProvider`] (404 on unknown value).
/// 2. Resolve the HMAC secret via the cached resolver (401 if absent).
/// 3. Verify the HMAC signature (401 on missing header or mismatch).
/// 4. Decode the body into a [`SaasAuditEvent`] (400 on malformed body).
/// 5. Push an [`AuditEntry`] onto the audit pipeline (503 on backpressure
///    or when no pipeline is connected).
///
/// # Response codes
///
/// | Code | When |
/// | --- | --- |
/// | `202 Accepted` | Event signed, parsed, and queued. |
/// | `400 Bad Request` | Body failed to parse for this provider. |
/// | `401 Unauthorized` | HMAC signature missing or invalid. |
/// | `404 Not Found` | `{provider}` is not a known SaaS provider. |
/// | `503 Service Unavailable` | Audit-pipeline queue is full or unconnected. |
///
/// [`SaasAuditEvent`]: aa_devtool_saas::event::SaasAuditEvent
/// [`AuditEntry`]: aa_core::AuditEntry
pub async fn saas_webhook(
    Path(provider_str): Path<String>,
    headers: HeaderMap,
    Extension(state): Extension<AppState>,
    body: Bytes,
) -> impl IntoResponse {
    // 1. Parse provider — 404 on unknown.
    let Some(provider) = parse_provider(&provider_str) else {
        return (
            StatusCode::NOT_FOUND,
            ProblemDetail::from_status(StatusCode::NOT_FOUND)
                .with_detail(format!("Unknown SaaS provider: {provider_str}")),
        )
            .into_response();
    };

    // 2. Resolve HMAC secret via the cached resolver.
    let secret_ref = secret_ref_for(&provider_str);
    let Some(secret) = state.saas_secret_cache.get(&secret_ref).await else {
        return (
            StatusCode::UNAUTHORIZED,
            ProblemDetail::from_status(StatusCode::UNAUTHORIZED)
                .with_detail("HMAC secret not configured for this provider"),
        )
            .into_response();
    };

    // 3. Verify HMAC signature BEFORE parsing the body (AAASM-924 AC).
    if let Err(e) = signature::verify(&provider, &headers, &body, &secret) {
        let detail = match e {
            SignatureError::MissingHeader => "Missing webhook signature header",
            SignatureError::InvalidSignature => "Webhook signature verification failed",
        };
        return (
            StatusCode::UNAUTHORIZED,
            ProblemDetail::from_status(StatusCode::UNAUTHORIZED).with_detail(detail),
        )
            .into_response();
    }

    // 4. Decode the provider-specific body into the normalized event.
    let event = match parser::parse(&provider, &body) {
        Ok(e) => e,
        Err(err) => {
            return (
                StatusCode::BAD_REQUEST,
                ProblemDetail::from_status(StatusCode::BAD_REQUEST).with_detail(err.to_string()),
            )
                .into_response();
        }
    };

    // 5. Push to the audit pipeline. Non-blocking — backpressure is 503.
    let Some(sender) = state.audit_sender.as_ref() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            ProblemDetail::from_status(StatusCode::SERVICE_UNAVAILABLE).with_detail("Audit pipeline is not connected"),
        )
            .into_response();
    };
    let entry = audit_mapping::to_audit_entry(&event);
    match sender.try_send(entry) {
        Ok(()) => StatusCode::ACCEPTED.into_response(),
        Err(TrySendError::Full(_)) => (
            StatusCode::SERVICE_UNAVAILABLE,
            ProblemDetail::from_status(StatusCode::SERVICE_UNAVAILABLE)
                .with_detail("Audit pipeline at capacity; retry shortly"),
        )
            .into_response(),
        Err(TrySendError::Closed(_)) => (
            StatusCode::SERVICE_UNAVAILABLE,
            ProblemDetail::from_status(StatusCode::SERVICE_UNAVAILABLE).with_detail("Audit pipeline is shutting down"),
        )
            .into_response(),
    }
}

// Expose config type for future registry integration.
pub use aa_devtool_saas::provider::SaasProviderConfig as SaasProviderCfg;
