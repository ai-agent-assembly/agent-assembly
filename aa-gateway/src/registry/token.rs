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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::store::AgentRecord;
    use crate::registry::AgentStatus;

    fn record_with_token(id: [u8; 16], token: &str) -> AgentRecord {
        AgentRecord {
            agent_id: id,
            name: "test".into(),
            framework: "test".into(),
            version: "0.0.1".into(),
            risk_tier: 0,
            tool_names: vec![],
            public_key: "deadbeef".into(),
            credential_token: token.into(),
            metadata: Default::default(),
            registered_at: chrono::Utc::now(),
            last_heartbeat: chrono::Utc::now(),
            status: AgentStatus::Active,
            pid: None,
            session_count: 0,
            last_event: None,
            policy_violations_count: 0,
            active_sessions: vec![],
            recent_events: Default::default(),
            recent_traces: vec![],
            layer: None,
            governance_level: aa_core::GovernanceLevel::default(),
            parent_agent_id: None,
            team_id: None,
            depth: 0,
            delegation_reason: None,
            spawned_by_tool: None,
            root_agent_id: None,
            children: vec![],
            parent_key: None,
            enforcement_mode: None,
            org_id: None,
        }
    }

    #[test]
    fn accepts_matching_token() {
        // The constant-time compare must still accept the genuine token.
        let reg = AgentRegistry::new();
        let id = [7u8; 16];
        let token = generate_credential_token();
        reg.register(record_with_token(id, &token)).unwrap();
        assert!(validate_token(&reg, &id, &token).is_ok());
    }

    #[test]
    fn rejects_wrong_token_of_same_length() {
        // A same-length but differing token is rejected — the compare returns
        // false on mismatch just like `==` did, only without the timing leak.
        let reg = AgentRegistry::new();
        let id = [7u8; 16];
        let token = generate_credential_token();
        reg.register(record_with_token(id, &token)).unwrap();
        let mut wrong = token.clone();
        let last = wrong.pop().unwrap();
        wrong.push(if last == 'a' { 'b' } else { 'a' });
        assert!(matches!(
            validate_token(&reg, &id, &wrong),
            Err(TokenError::InvalidToken)
        ));
    }

    #[test]
    fn rejects_prefix_of_real_token() {
        // `ConstantTimeEq::ct_eq` reports false for differing lengths, so a
        // truncated prefix of the real token must not be accepted.
        let reg = AgentRegistry::new();
        let id = [7u8; 16];
        let token = generate_credential_token();
        reg.register(record_with_token(id, &token)).unwrap();
        let prefix = &token[..token.len() - 1];
        assert!(matches!(
            validate_token(&reg, &id, prefix),
            Err(TokenError::InvalidToken)
        ));
    }

    #[test]
    fn unknown_agent_is_not_found() {
        let reg = AgentRegistry::new();
        assert!(matches!(
            validate_token(&reg, &[9u8; 16], "anything"),
            Err(TokenError::AgentNotFound(_))
        ));
    }
}
