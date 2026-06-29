//! Credential token generation and validation for registered agents.
//!
//! Tokens are issued at registration and must be presented on every subsequent
//! RPC (heartbeat, deregister, control stream). The current implementation uses
//! UUID v4 random tokens; a future iteration may switch to HMAC-SHA256 signed tokens.

use subtle::ConstantTimeEq;

use super::store::AgentRegistry;

/// Errors returned by token validation.
#[derive(Debug, thiserror::Error)]
pub enum TokenError {
    /// The agent ID is not present in the registry.
    #[error("agent not found: {0:?}")]
    AgentNotFound([u8; 16]),
    /// The provided token does not match the stored credential.
    #[error("invalid credential token")]
    InvalidToken,
}

/// Generate a new random credential token (UUID v4 hex string).
pub fn generate_credential_token() -> String {
    uuid::Uuid::new_v4().to_string()
}

/// Validate that `token` matches the credential stored for `agent_id` in the registry.
///
/// The comparison is constant-time (AAASM-3922): a plain `String ==` short-circuits
/// on the first differing byte, leaking a timing side-channel. Tokens are 122-bit
/// random so this is not practically exploitable, but a constant-time compare
/// removes the side-channel as defence-in-depth.
pub fn validate_token(registry: &AgentRegistry, agent_id: &[u8; 16], token: &str) -> Result<(), TokenError> {
    let record = registry.get(agent_id).ok_or(TokenError::AgentNotFound(*agent_id))?;

    if bool::from(record.credential_token.as_bytes().ct_eq(token.as_bytes())) {
        Ok(())
    } else {
        Err(TokenError::InvalidToken)
    }
}
