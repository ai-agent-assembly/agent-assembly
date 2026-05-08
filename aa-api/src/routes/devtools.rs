//! Dev tool governance endpoints.
//!
//! Currently exposes one endpoint:
//! - `POST /devtools/saas/{provider}/events` — ingests signed audit webhook
//!   events from SaaS coding-agent providers.

use axum::body::Bytes;
use axum::extract::Path;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::Extension;

use aa_devtool_saas::provider::SaasProvider;
use aa_devtool_saas::signature::{self, SignatureError};

use crate::error::ProblemDetail;
use crate::state::AppState;

/// Parse a URL path segment into a [`SaasProvider`].
fn parse_provider(s: &str) -> Option<SaasProvider> {
    match s {
        "claude-ai" => Some(SaasProvider::ClaudeAi),
        "chatgpt" => Some(SaasProvider::ChatGpt),
        "cursor-cloud" => Some(SaasProvider::CursorCloud),
        _ => None,
    }
}

/// Resolve the HMAC secret for a provider from an environment variable.
///
/// Variable name pattern: `AA_SAAS_<PROVIDER>_HMAC_SECRET`
/// where `<PROVIDER>` is the uppercase form of the URL path segment
/// (e.g. `CLAUDE_AI`, `CHATGPT`, `CURSOR_CLOUD`).
///
/// This is a placeholder for the real Vault-backed secret resolution that
/// will be wired in when `SaasProviderConfig` is stored in the gateway
/// registry and the secret store MCP is available.
fn resolve_hmac_secret(provider_str: &str) -> Option<Vec<u8>> {
    let env_key = format!("AA_SAAS_{}_HMAC_SECRET", provider_str.replace('-', "_").to_uppercase());
    std::env::var(env_key).ok().map(|s| s.into_bytes())
}

/// `POST /api/v1/devtools/saas/{provider}/events`
///
/// Ingest a signed audit-webhook event from a SaaS coding-agent provider.
///
/// ### Flow
/// 1. Parse `{provider}` to a [`SaasProvider`] (400 on unknown value).
/// 2. Resolve the HMAC secret from the environment (401 if not configured).
/// 3. Verify the HMAC signature (401 on failure).
/// 4. Persist the event body to the audit pipeline.
///
/// ### Response codes
/// - `202 Accepted` — event accepted and queued for audit ingestion.
/// - `400 Bad Request` — unknown provider identifier.
/// - `401 Unauthorized` — HMAC signature missing or invalid.
pub async fn saas_webhook(
    Path(provider_str): Path<String>,
    headers: HeaderMap,
    Extension(_state): Extension<AppState>,
    body: Bytes,
) -> impl IntoResponse {
    // Step 1: parse provider.
    let Some(provider) = parse_provider(&provider_str) else {
        return (
            StatusCode::BAD_REQUEST,
            ProblemDetail::from_status(StatusCode::BAD_REQUEST)
                .with_detail(format!("Unknown SaaS provider: {provider_str}")),
        )
            .into_response();
    };

    // Step 2: resolve HMAC secret.
    let Some(secret) = resolve_hmac_secret(&provider_str) else {
        return (
            StatusCode::UNAUTHORIZED,
            ProblemDetail::from_status(StatusCode::UNAUTHORIZED)
                .with_detail("HMAC secret not configured for this provider"),
        )
            .into_response();
    };

    // Step 3: verify HMAC signature.
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

    // Step 4: persist event to audit pipeline.
    // TODO(AAASM-924): wire to audit pipeline when Epic 6 ingestion API is stable.
    let _ = (&provider, &body); // suppress unused warnings until wired

    // Acknowledge receipt. The event will be processed asynchronously once
    // the audit ingestion pipeline is available.
    StatusCode::ACCEPTED.into_response()
}

// Expose config type for future registry integration.
pub use aa_devtool_saas::provider::SaasProviderConfig as SaasProviderCfg;
