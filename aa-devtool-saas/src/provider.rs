//! SaaS provider identity types for the coding-agent observability adapter.

/// Identifies the SaaS coding-agent provider being governed.
///
/// Each variant maps to a distinct webhook scheme, HMAC header, and
/// governance overlay. Adding a new provider requires a matching arm in
/// [`crate::signature::verify`] and a new overlay module.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum SaasProvider {
    /// Anthropic Claude.ai (workspace-managed coding agent).
    ClaudeAi,
    /// OpenAI ChatGPT Enterprise / Custom GPTs.
    ChatGpt,
    /// Cursor cloud (audit-webhook only).
    CursorCloud,
}

/// Configuration for a SaaS provider integration.
///
/// All sensitive credentials are represented as Vault-style opaque reference
/// strings — never plaintext keys. The caller is responsible for resolving
/// the reference to an actual secret before performing HMAC verification.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SaasProviderConfig {
    /// Which SaaS coding-agent provider this config targets.
    pub provider: SaasProvider,
    /// Base URL of the SaaS provider's API (e.g. `"https://api.anthropic.com"`).
    pub api_url: String,
    /// Vault secret reference for the HMAC webhook signing key.
    ///
    /// This field holds an opaque reference string such as
    /// `"vault:secret/saas/claude-ai/hmac"`. It must never contain a
    /// plaintext key. The adapter reads this field during webhook validation
    /// to locate the key in the secret store — the actual resolution step
    /// is performed by the caller.
    pub api_key_secret_ref: String,
}
