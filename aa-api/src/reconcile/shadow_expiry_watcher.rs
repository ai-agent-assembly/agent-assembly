//! Background reconciler that auto-reverts expired shadow enforcement windows.
//!
//! When the enforcement-mode endpoint (AAASM-5338) weakens an agent to
//! `Observe`, it stores a mandatory `enforcement_mode_expires_at` deadline
//! (≤72h per ADR 0021). This watcher runs every [`TICK_INTERVAL`] and, on each
//! tick, finds agents whose shadow window has expired (Observe + past deadline)
//! and reverts them to `Enforce`, clearing the expiry via the durable
//! [`set_enforcement_mode_persisted`](aa_gateway::registry::AgentRegistry::set_enforcement_mode_persisted)
//! write primitive so the storage row is cleaned too.
//!
//! Each auto-revert emits a [`GovernanceMutationAudit`] attributed to a fixed
//! **system** principal ([`SYSTEM_ACTOR`]) — never a request-supplied actor,
//! because this is a reconciliation action performed by the server itself. The
//! audit's tenant is taken from the agent's own record (org / team) so existing
//! audit-log tenant scoping applies.
//!
//! Restart-safety (AAASM-5288 / AAASM-5339): the expiry is persisted, so an
//! already-expired shadow window rehydrates on startup as Observe + past
//! deadline. Because [`tick`] queries the persisted fields, the first tick
//! catches and reverts it — no special startup path is needed.

use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use tokio::sync::mpsc;

use aa_core::audit::{AuditEntry, GovernanceMutationAudit};
use aa_core::{AgentId, EnforcementMode, SessionId};
use aa_gateway::registry::AgentRegistry;

/// Cadence of the shadow-expiry reconciler. Shadow windows are bounded at 72h
/// (ADR 0021), so a coarse tick is sufficient — latency between a window's
/// deadline and its auto-revert is bounded by this interval. 60 s trades a
/// small revert latency for negligible background-task cost.
pub const TICK_INTERVAL: Duration = Duration::from_secs(60);

/// Fixed system principal recorded as the `actor` on an auto-revert audit.
/// This is NOT a request-supplied identity — the reconciler acts on the
/// server's own behalf, so the audit must attribute the mutation to the
/// system, not to whichever operator originally weakened the agent.
pub const SYSTEM_ACTOR: &str = "system:shadow-reconciler";

/// Fixed justification for an auto-revert. Mirrors the mandatory-reason
/// requirement of [`GovernanceMutationAudit::new`] (ADR 0021).
const REVERT_REASON: &str = "shadow window expired — auto-reverted to enforce";

/// Governance action label, matching the enforcement-mode endpoint's audits.
const REVERT_ACTION: &str = "enforcement_mode";

/// One pass of the reconciliation loop — reverts every agent whose shadow
/// (Observe) window has expired at `now` back to `Enforce`, clearing the
/// expiry, and emits one system-attributed audit per revert.
///
/// Pure with respect to timing (modulo registry mutation and audit emission)
/// so tests can drive it directly with a fixed `now` instead of sleeping.
///
/// Returns the number of agents reverted this tick.
pub async fn tick(
    registry: &AgentRegistry,
    audit_sender: Option<&mpsc::Sender<AuditEntry>>,
    now: DateTime<Utc>,
) -> usize {
    let expired = registry.agents_with_expired_shadow(now);
    let mut reverted = 0;
    for agent_id in expired {
        // Snapshot the agent's tenant before the revert so the audit records
        // the agent's own org/team. Skip if the agent vanished between the
        // query and here (deregistered) — nothing to revert.
        let Some(record) = registry.get(&agent_id) else {
            continue;
        };
        let org = record.org_id.clone();
        let team = record.team_id.clone();

        // Durable revert: Enforce with no expiry. Uses the write-through
        // primitive (with rollback-on-failure) so the storage row is cleaned
        // and won't resurrect the expired window on a subsequent restart.
        match registry
            .set_enforcement_mode_persisted(&agent_id, Some(EnforcementMode::Enforce), None)
            .await
        {
            Ok(()) => {
                reverted += 1;
                emit_revert_audit(audit_sender, &agent_id, org, team);
            }
            Err(err) => {
                // A failed persist rolls the in-memory mutation back, so the
                // agent stays Observe and the next tick retries. Log and move
                // on rather than aborting the whole pass.
                tracing::warn!(
                    agent_id = %hex_agent_id(&agent_id),
                    error = %err,
                    "shadow-expiry reconciler failed to revert agent; will retry next tick",
                );
            }
        }
    }
    reverted
}

/// Emit a system-attributed [`GovernanceMutationAudit`] for one auto-revert.
///
/// Best-effort onto the audit channel, matching the dispatch path in
/// `routes::agents`: a full or absent channel drops the entry rather than
/// failing the revert the reconciler already performed. `seq` / `previous_hash`
/// are zero because the audit sink re-sequences and re-chains as it persists.
///
/// The `actor` is the fixed [`SYSTEM_ACTOR`], never a request identity; the
/// tenant is the agent's own org / team.
fn emit_revert_audit(
    audit_sender: Option<&mpsc::Sender<AuditEntry>>,
    agent_id: &[u8; 16],
    org: Option<String>,
    team: Option<String>,
) {
    let Some(sender) = audit_sender else {
        return;
    };
    let record = match GovernanceMutationAudit::new(
        AgentId::from_bytes(*agent_id),
        SYSTEM_ACTOR,
        org,
        team,
        REVERT_ACTION,
        REVERT_REASON,
        EnforcementMode::Observe.as_wire(),
        EnforcementMode::Enforce.as_wire(),
    ) {
        Ok(r) => r,
        Err(e) => {
            // REVERT_REASON is a non-empty constant, so this cannot happen; the
            // branch keeps the emission total. Log and skip.
            tracing::error!(error = %e, "shadow-revert audit not emitted");
            return;
        }
    };
    let entry = record.to_audit_entry(0, unix_now_ns(), SessionId::from_bytes([0u8; 16]), [0u8; 32]);
    let _ = sender.try_send(entry);
}

/// Current Unix timestamp in nanoseconds. Mirrors the dispatch-path helper so
/// audit entries carry a real wall-clock time.
fn unix_now_ns() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

/// Hex-encode a raw agent id for log output.
fn hex_agent_id(agent_id: &[u8; 16]) -> String {
    agent_id.iter().map(|b| format!("{b:02x}")).collect()
}

/// Spawn the shadow-expiry reconciler as a tokio task.
///
/// The task loops forever, sleeping [`TICK_INTERVAL`] between passes and calling
/// [`tick`] with the current wall-clock time. It holds a clone of the registry
/// handle and the audit sender, so it runs until process shutdown.
pub fn spawn_shadow_expiry_watcher(
    registry: Arc<AgentRegistry>,
    audit_sender: Option<mpsc::Sender<AuditEntry>>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(TICK_INTERVAL).await;
            tick(registry.as_ref(), audit_sender.as_ref(), Utc::now()).await;
        }
    })
}

#[cfg(test)]
mod tests {
    use aa_gateway::registry::{AgentRecord, AgentStatus};
    use chrono::Duration as ChronoDuration;

    use super::*;

    /// Build a minimal registered `AgentRecord` with an optional shadow window.
    fn make_record(id: [u8; 16], mode: Option<EnforcementMode>, expires_at: Option<DateTime<Utc>>) -> AgentRecord {
        AgentRecord {
            agent_id: id,
            name: "test".into(),
            framework: "test".into(),
            version: "0.0.1".into(),
            risk_tier: 0,
            tool_names: vec![],
            public_key: "deadbeef".into(),
            credential_token: String::new(),
            metadata: Default::default(),
            registered_at: Utc::now(),
            last_heartbeat: Utc::now(),
            status: AgentStatus::Active,
            pid: None,
            session_count: 0,
            last_event: None,
            active_sessions: vec![],
            recent_events: Default::default(),
            recent_traces: vec![],
            layer: None,
            governance_level: aa_core::GovernanceLevel::default(),
            parent_agent_id: None,
            team_id: Some("teamA".to_string()),
            depth: 0,
            delegation_reason: None,
            spawned_by_tool: None,
            root_agent_id: None,
            children: vec![],
            parent_key: None,
            enforcement_mode: mode,
            enforcement_mode_expires_at: expires_at,
            org_id: Some("orgA".to_string()),
        }
    }

    #[tokio::test]
    async fn tick_reverts_expired_shadow_to_enforce() {
        let reg = AgentRegistry::new();
        let id = [1u8; 16];
        let past = Utc::now() - ChronoDuration::hours(1);
        reg.register(make_record(id, Some(EnforcementMode::Observe), Some(past)))
            .unwrap();

        let reverted = tick(&reg, None, Utc::now()).await;
        assert_eq!(reverted, 1);

        let rec = reg.get(&id).unwrap();
        assert_eq!(rec.enforcement_mode, Some(EnforcementMode::Enforce));
        assert!(rec.enforcement_mode_expires_at.is_none(), "expiry must be cleared");
    }

    #[tokio::test]
    async fn tick_leaves_future_shadow_untouched() {
        let reg = AgentRegistry::new();
        let id = [2u8; 16];
        let future = Utc::now() + ChronoDuration::hours(1);
        reg.register(make_record(id, Some(EnforcementMode::Observe), Some(future)))
            .unwrap();

        let reverted = tick(&reg, None, Utc::now()).await;
        assert_eq!(reverted, 0);

        let rec = reg.get(&id).unwrap();
        assert_eq!(rec.enforcement_mode, Some(EnforcementMode::Observe));
        assert_eq!(rec.enforcement_mode_expires_at, Some(future));
    }

    #[tokio::test]
    async fn tick_leaves_enforce_agent_untouched() {
        let reg = AgentRegistry::new();
        let id = [3u8; 16];
        // No override, no expiry — the enforce default.
        reg.register(make_record(id, None, None)).unwrap();

        let reverted = tick(&reg, None, Utc::now()).await;
        assert_eq!(reverted, 0);

        let rec = reg.get(&id).unwrap();
        assert_eq!(rec.enforcement_mode, None);
        assert!(rec.enforcement_mode_expires_at.is_none());
    }

    #[tokio::test]
    async fn revert_emits_system_attributed_audit() {
        let reg = AgentRegistry::new();
        let id = [4u8; 16];
        let past = Utc::now() - ChronoDuration::minutes(5);
        reg.register(make_record(id, Some(EnforcementMode::Observe), Some(past)))
            .unwrap();

        let (tx, mut rx) = mpsc::channel::<AuditEntry>(16);
        let reverted = tick(&reg, Some(&tx), Utc::now()).await;
        assert_eq!(reverted, 1);

        let entry = rx.try_recv().expect("an audit entry must be emitted");
        assert_eq!(entry.event_type(), aa_core::AuditEventType::GovernanceMutation);
        // Actor + before/after live in the JSON payload.
        let payload: serde_json::Value = serde_json::from_str(entry.payload()).unwrap();
        assert_eq!(payload["actor"], SYSTEM_ACTOR);
        assert_eq!(payload["after"], "enforce");
        assert_eq!(payload["before"], "observe");
        assert_eq!(payload["action"], REVERT_ACTION);
        // Tenant is carried on the entry's lineage from the agent's own record.
        assert_eq!(entry.org_id(), Some("orgA"));
        assert_eq!(entry.team_id(), Some("teamA"));

        // Only one revert → only one audit.
        assert!(rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn restart_expired_window_reverts_and_does_not_resurrect() {
        // Simulate a restart: the registry is rehydrated with an agent already
        // in Observe + past-expiry (AAASM-5288 round-trips both columns).
        let reg = AgentRegistry::new();
        let id = [5u8; 16];
        let past = Utc::now() - ChronoDuration::hours(2);
        reg.register(make_record(id, Some(EnforcementMode::Observe), Some(past)))
            .unwrap();

        // First tick after "startup" catches and reverts it.
        let reverted = tick(&reg, None, Utc::now()).await;
        assert_eq!(reverted, 1);
        let rec = reg.get(&id).unwrap();
        assert_eq!(rec.enforcement_mode, Some(EnforcementMode::Enforce));
        assert!(rec.enforcement_mode_expires_at.is_none());

        // A subsequent tick finds nothing to do — the window does not resurrect.
        let reverted_again = tick(&reg, None, Utc::now()).await;
        assert_eq!(reverted_again, 0);
        let rec = reg.get(&id).unwrap();
        assert_eq!(rec.enforcement_mode, Some(EnforcementMode::Enforce));
    }
}
