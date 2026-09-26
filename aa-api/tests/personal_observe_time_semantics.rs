//! HORO-1375 AC-4 — >72h virtual-time test. Two distinct behaviours, driven
//! with an injected `now` against `shadow_expiry_watcher::tick` (already
//! `now`-parameterised — no sleeping, no clock-mocking crate).
//!
//! T1: personal-observe (a `None` record) never expires, at any horizon.
//! T2: an enterprise shadow window (`Some(Observe)` + `expires_at`) still
//!     reverts at exactly 72h, and personal-observe does NOT re-shadow the
//!     reverted agent afterward.

use std::collections::VecDeque;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;

use aa_api::reconcile::shadow_expiry_watcher::tick;
use aa_core::EnforcementMode;
use aa_gateway::audit::AuditChain;
use aa_gateway::engine::{resolve_enforcement_mode, PolicyDefaultMode};
use aa_gateway::registry::{AgentRecord, AgentRegistry, AgentStatus};
use chrono::{Duration as ChronoDuration, Utc};

fn personal_observe_default() -> PolicyDefaultMode {
    let mut cfg = aa_core::config::GatewayConfig::default();
    cfg.observation.profile = aa_core::config::ObservationProfile::PersonalObserve;
    let dep = aa_core::observation::PersonalObserveDeployment {
        config: &cfg,
        bind_addr: "127.0.0.1:7700".parse().unwrap(),
        auth_is_off: false,
    };
    match aa_core::observation::authorize_personal_observe(dep, |_| None).expect("gate must grant") {
        aa_core::observation::PersonalObserveOutcome::Granted(grant) => PolicyDefaultMode::personal_observe(&grant),
        aa_core::observation::PersonalObserveOutcome::NotRequested => panic!("expected Granted"),
    }
}

fn make_record(id: [u8; 16], mode: Option<EnforcementMode>, expires_at: Option<chrono::DateTime<Utc>>) -> AgentRecord {
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
        recent_events: VecDeque::new(),
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

/// T1 — personal-observe does NOT expire, at any horizon.
#[tokio::test]
async fn t1_personal_observe_does_not_expire_across_every_horizon() {
    let reg = AgentRegistry::new();
    let id = [0x10u8; 16];
    // No per-agent override — the only shape personal-observe affects.
    reg.register(make_record(id, None, None)).unwrap();

    let now = Utc::now();
    let personal_observe = personal_observe_default();

    for horizon in [
        ChronoDuration::hours(1),
        ChronoDuration::hours(71),
        ChronoDuration::hours(73),
        ChronoDuration::days(30),
    ] {
        let reverted = tick(&reg, None, now + horizon).await;
        assert_eq!(
            reverted, 0,
            "personal-observe must never be reverted by the shadow-expiry tick"
        );

        let rec = reg.get(&id).unwrap();
        assert_eq!(rec.enforcement_mode, None, "still no override after tick at +{horizon}");
        assert_eq!(
            resolve_enforcement_mode(rec.enforcement_mode, personal_observe).get(),
            EnforcementMode::Observe,
            "effective mode must remain Observe at +{horizon}"
        );
    }
}

/// T2 — an enterprise shadow window still reverts at exactly 72h, even with
/// personal-observe ALSO active; personal-observe does not re-shadow the
/// reverted agent afterward.
#[tokio::test]
async fn t2_enterprise_shadow_still_reverts_at_72h_despite_personal_observe() {
    let reg = AgentRegistry::new();
    let id = [0x11u8; 16];
    let now = Utc::now();
    let deadline = now + ChronoDuration::hours(72);
    reg.register(make_record(id, Some(EnforcementMode::Observe), Some(deadline)))
        .unwrap();

    let (tx, mut rx) = tokio::sync::mpsc::channel::<aa_core::AuditEntry>(16);
    let chain = Arc::new(AuditChain::new(tx, Arc::new(AtomicU64::new(0)), [0u8; 32], 0));

    // At 71h: not yet due.
    let reverted = tick(&reg, Some(&chain), now + ChronoDuration::hours(71)).await;
    assert_eq!(reverted, 0);
    let rec = reg.get(&id).unwrap();
    assert_eq!(rec.enforcement_mode, Some(EnforcementMode::Observe));

    // At exactly 72h: reverts. Inclusive boundary, matching the reconciler's
    // documented convention.
    let reverted = tick(&reg, Some(&chain), now + ChronoDuration::hours(72)).await;
    assert_eq!(reverted, 1, "the 72h shadow window must revert at its exact deadline");
    let rec = reg.get(&id).unwrap();
    assert_eq!(rec.enforcement_mode, Some(EnforcementMode::Enforce));
    assert_eq!(rec.enforcement_mode_expires_at, None);

    // A GovernanceMutationAudit was emitted, attributed to the system actor.
    let entry = rx.try_recv().expect("an audit entry must be emitted for the revert");
    assert_eq!(entry.event_type(), aa_core::AuditEventType::GovernanceMutation);
    let payload: serde_json::Value = serde_json::from_str(entry.payload()).unwrap();
    assert_eq!(payload["actor"], "system:shadow-reconciler");
    assert_eq!(payload["before"], "observe");
    assert_eq!(payload["after"], "enforce");

    // personal-observe does NOT re-shadow the reverted agent: resolving
    // through the real resolver with a personal-observe default still
    // yields Enforce, because the agent NOW carries an explicit Enforce
    // override (the revert wrote one) — not None.
    let personal_observe = personal_observe_default();
    assert_eq!(
        resolve_enforcement_mode(rec.enforcement_mode, personal_observe).get(),
        EnforcementMode::Enforce,
        "a reverted agent must not be silently re-shadowed by personal-observe"
    );
}
