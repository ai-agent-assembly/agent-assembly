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
