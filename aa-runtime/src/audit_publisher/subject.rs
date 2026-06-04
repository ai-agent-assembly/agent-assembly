//! Derivation of the NATS subject an audit entry is published to.

use aa_core::storage::AuditEntry;

/// Subject prefix shared by every audit event.
const SUBJECT_PREFIX: &str = "assembly.audit";

/// Token used when a tenant identifier is unavailable on the entry.
const UNKNOWN_TENANT: &str = "default";

/// Build the NATS subject `assembly.audit.<tenant>.<agent>` for `entry`.
///
/// `<tenant>` is the entry's org id, falling back to its team id, then to
/// `default`. `<agent>` is the agent id rendered as a hyphenated UUID. The
/// tenant token is sanitized so the subject contains only subject-safe
/// characters — NATS forbids whitespace and reserves `.`, `*`, and `>`.
pub fn subject_for(entry: &AuditEntry) -> String {
    let tenant = entry
        .org_id()
        .or_else(|| entry.team_id())
        .map(sanitize_token)
        .filter(|token| !token.is_empty())
        .unwrap_or_else(|| UNKNOWN_TENANT.to_string());
    let agent = uuid::Uuid::from_bytes(*entry.agent_id().as_bytes());
    format!("{SUBJECT_PREFIX}.{tenant}.{agent}")
}

/// Replace every character outside `[A-Za-z0-9_-]` with `_` so the result is a
/// single valid NATS subject token.
fn sanitize_token(raw: &str) -> String {
    raw.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use aa_core::audit::{AuditEventType, Lineage};
    use aa_core::{AgentId, SessionId};

    const AGENT_BYTES: [u8; 16] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];

    /// Build an audit entry carrying the given optional org/team lineage.
    fn entry_with(org: Option<&str>, team: Option<&str>) -> AuditEntry {
        let lineage = Lineage {
            org_id: org.map(str::to_string),
            team_id: team.map(str::to_string),
            ..Lineage::default()
        };
        AuditEntry::new_with_lineage(
            1,
            0,
            AuditEventType::ToolCallIntercepted,
            AgentId::from_bytes(AGENT_BYTES),
            SessionId::from_bytes(AGENT_BYTES),
            "{}".to_string(),
            [0u8; 32],
            lineage,
        )
    }

    #[test]
    fn defaults_tenant_and_renders_agent_uuid() {
        let entry = entry_with(None, None);
        let expected_agent = uuid::Uuid::from_bytes(AGENT_BYTES);
        assert_eq!(subject_for(&entry), format!("assembly.audit.default.{expected_agent}"));
    }
}
