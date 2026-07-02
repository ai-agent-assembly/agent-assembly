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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::Tenant;
    use aa_gateway::registry::{AgentRecord, AgentStatus};

    fn caller(scopes: &[Scope], team: Option<&str>, org: Option<&str>) -> AuthenticatedCaller {
        AuthenticatedCaller {
            key_id: "k".into(),
            scopes: scopes.to_vec(),
            tenant: Tenant {
                team_id: team.map(str::to_string),
                org_id: org.map(str::to_string),
            },
        }
    }

    // ── caller_can_view ──────────────────────────────────────────────────────

    #[test]
    fn admin_sees_every_tenant_including_untagged_events() {
        let admin = caller(&[Scope::Read, Scope::Admin], None, None);
        assert!(caller_can_view(&admin, Some("team-a"), None));
        assert!(caller_can_view(&admin, Some("team-b"), Some("org-z")));
        // Fail-open only for admins: an event with no owning tenant is still visible.
        assert!(caller_can_view(&admin, None, None));
    }

    #[test]
    fn team_scoped_caller_sees_only_its_own_team() {
        let a = caller(&[Scope::Read], Some("team-a"), None);
        assert!(caller_can_view(&a, Some("team-a"), None), "same team is visible");
        assert!(
            !caller_can_view(&a, Some("team-b"), None),
            "cross-tenant team must be blocked"
        );
    }

    #[test]
    fn team_scoped_caller_never_sees_untagged_events() {
        // Fail-closed: an event with no resolvable owning tenant is admin-only.
        let a = caller(&[Scope::Read], Some("team-a"), None);
        assert!(!caller_can_view(&a, None, None));
    }

    #[test]
    fn org_scoped_caller_sees_its_own_org() {
        let o = caller(&[Scope::Read], None, Some("org-z"));
        assert!(
            caller_can_view(&o, Some("team-a"), Some("org-z")),
            "same org is visible"
        );
        assert!(
            !caller_can_view(&o, Some("team-a"), Some("org-y")),
            "cross-tenant org must be blocked"
        );
    }

    #[test]
    fn caller_with_no_tenant_and_no_admin_sees_nothing() {
        let none = caller(&[Scope::Read], None, None);
        assert!(!caller_can_view(&none, Some("team-a"), None));
        assert!(!caller_can_view(&none, None, Some("org-z")));
        assert!(!caller_can_view(&none, None, None));
    }

    // ── agent_id_to_bytes ────────────────────────────────────────────────────

    #[test]
    fn agent_id_to_bytes_parses_valid_hex() {
        let hex = "000102030405060708090a0b0c0d0e0f";
        assert_eq!(
            agent_id_to_bytes(hex),
            Some([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15])
        );
    }

    #[test]
    fn agent_id_to_bytes_rejects_non_hex_ids() {
        assert_eq!(agent_id_to_bytes("system:ebpf"), None);
        assert_eq!(agent_id_to_bytes(""), None);
        assert_eq!(agent_id_to_bytes("support-agent"), None);
        // Right length, but not hex.
        assert_eq!(agent_id_to_bytes(&"z".repeat(32)), None);
    }

    // ── resolve_event_tenant ─────────────────────────────────────────────────

    fn record_with_tenant(id: [u8; 16], team: Option<&str>, org: Option<&str>) -> AgentRecord {
        AgentRecord {
            agent_id: id,
            name: "test".into(),
            framework: "test".into(),
            version: "0.0.1".into(),
            risk_tier: 0,
            tool_names: vec![],
            public_key: "deadbeef".into(),
            credential_token: "tok".into(),
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
            team_id: team.map(str::to_string),
            depth: 0,
            delegation_reason: None,
            spawned_by_tool: None,
            root_agent_id: None,
            children: vec![],
            parent_key: None,
            enforcement_mode: None,
            org_id: org.map(str::to_string),
        }
    }

    #[test]
    fn explicit_team_is_used_verbatim_when_present() {
        let reg = AgentRegistry::new();
        let (team, org) = resolve_event_tenant(&reg, Some("team-a".into()), None);
        assert_eq!(team.as_deref(), Some("team-a"));
        assert_eq!(org, None, "org is only known via lineage");
    }

    #[test]
    fn unresolvable_event_yields_no_tenant() {
        // Empty explicit team + an agent id absent from the registry → nothing
        // resolves, so the gate treats the event as admin-only.
        let reg = AgentRegistry::new();
        let (team, org) = resolve_event_tenant(&reg, None, Some([9u8; 16]));
        assert_eq!(team, None);
        assert_eq!(org, None);
        // An empty explicit team string is also treated as absent.
        let (team, _) = resolve_event_tenant(&reg, Some(String::new()), None);
        assert_eq!(team, None);
    }

    #[test]
    fn lineage_fills_team_and_org_for_tagless_events() {
        // Mirrors the ops-change path: the event carries only an agent id, and
        // the owning team + org are recovered from the agent-registry lineage.
        let reg = AgentRegistry::new();
        let id = [7u8; 16];
        reg.register(record_with_tenant(id, Some("team-a"), Some("org-z")))
            .unwrap();

        let (team, org) = resolve_event_tenant(&reg, None, Some(id));
        assert_eq!(team.as_deref(), Some("team-a"));
        assert_eq!(org.as_deref(), Some("org-z"));
    }

    #[test]
    fn explicit_team_wins_but_org_still_from_lineage() {
        let reg = AgentRegistry::new();
        let id = [7u8; 16];
        reg.register(record_with_tenant(id, Some("team-a"), Some("org-z")))
            .unwrap();

        // The event tags team-a explicitly; org is not on the event, so it is
        // still pulled from lineage.
        let (team, org) = resolve_event_tenant(&reg, Some("team-a".into()), Some(id));
        assert_eq!(team.as_deref(), Some("team-a"));
        assert_eq!(org.as_deref(), Some("org-z"));
    }
}
