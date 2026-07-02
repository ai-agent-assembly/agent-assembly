//! Tenant authorization for the WebSocket event and alert streams (AAASM-3980).
//!
//! The live event / alert channels are shared across all tenants, so the
//! dispatch loops must gate every frame — live *and* replayed — against the
//! connecting caller's tenant before forwarding it. This mirrors the
//! per-tenant REST surface (`routes::agents` / `routes::alerts`), which
//! authorizes each row via [`AuthenticatedCaller::can_access_team`] /
//! [`AuthenticatedCaller::can_access_org`].
//!
//! The gate is **fail-closed**: an event whose owning tenant cannot be
//! resolved is visible only to admins. A non-admin caller therefore never
//! receives cross-tenant data, even for events that carry no tenant tag.

use aa_gateway::registry::AgentRegistry;

use crate::auth::scope::Scope;
use crate::auth::AuthenticatedCaller;

/// Whether `caller` is entitled to see an event owned by the given tenant.
///
/// Admins (including the bypass-mode synthetic caller) see every tenant's
/// events. Any other caller must be entitled to the event's owning `team_id`
/// or `org_id`. Fail-closed: when the event carries neither a resolvable team
/// nor org, only admins pass — a tenant-scoped caller sees nothing rather than
/// risk cross-tenant disclosure.
pub(crate) fn caller_can_view(caller: &AuthenticatedCaller, team_id: Option<&str>, org_id: Option<&str>) -> bool {
    if caller.scopes.contains(&Scope::Admin) {
        return true;
    }
    if let Some(team) = team_id {
        if caller.can_access_team(team) {
            return true;
        }
    }
    if let Some(org) = org_id {
        if caller.can_access_org(org) {
            return true;
        }
    }
    false
}

/// Resolve the owning `(team_id, org_id)` for an event.
///
/// Prefers the tenant carried on the event itself (`explicit_team`); falls
/// back to the agent-registry lineage when a resolvable agent id is available.
/// The org tier is only ever known via lineage, since the live event payloads
/// don't carry it. Returns `(None, None)` when nothing can be resolved — the
/// [`caller_can_view`] gate then treats the event as admin-only.
pub(crate) fn resolve_event_tenant(
    registry: &AgentRegistry,
    explicit_team: Option<String>,
    agent_id: Option<[u8; 16]>,
) -> (Option<String>, Option<String>) {
    let lineage = agent_id.and_then(|bytes| registry.lineage(&bytes));
    let team = explicit_team
        .filter(|t| !t.is_empty())
        .or_else(|| lineage.as_ref().and_then(|l| l.team_id.clone()));
    let org = lineage.and_then(|l| l.org_id);
    (team, org)
}

/// Parse a 32-char hex agent id into its 16 raw bytes, or `None` when the
/// string isn't a well-formed hex agent id (e.g. `"system:ebpf"`, a human
/// label, or an empty string). Used to key the registry lineage lookup for
/// events whose agent id travels as a display string.
pub(crate) fn agent_id_to_bytes(id: &str) -> Option<[u8; 16]> {
    if id.len() != 32 {
        return None;
    }
    let mut out = [0u8; 16];
    for (i, slot) in out.iter_mut().enumerate() {
        *slot = u8::from_str_radix(id.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}
