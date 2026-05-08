//! Unit tests for `AgentRegistry` CRUD operations and control stream infrastructure.

use std::collections::{BTreeMap, VecDeque};

use chrono::Utc;

use aa_gateway::registry::store::AgentRecord;
use aa_gateway::registry::{AgentRegistry, AgentStatus, OrphanMode};

/// Build a minimal `AgentRecord` with the given 16-byte key.
fn make_record(key: [u8; 16]) -> AgentRecord {
    AgentRecord {
        agent_id: key,
        name: "test-agent".into(),
        framework: "custom".into(),
        version: "0.1.0".into(),
        risk_tier: 0,
        tool_names: vec!["tool_a".into()],
        public_key: "pk_placeholder".into(),
        credential_token: "tok_placeholder".into(),
        metadata: BTreeMap::new(),
        registered_at: Utc::now(),
        last_heartbeat: Utc::now(),
        status: AgentStatus::Active,
        pid: None,
        session_count: 0,
        last_event: None,
        policy_violations_count: 0,
        active_sessions: Vec::new(),
        recent_events: VecDeque::new(),
        recent_traces: Vec::new(),
        layer: None,
        governance_level: aa_core::GovernanceLevel::default(),
        parent_agent_id: None,
        team_id: None,
        depth: 0,
        delegation_reason: None,
        spawned_by_tool: None,
        root_agent_id: None,
        children: Vec::new(),
        parent_key: None,
    }
}

fn key(n: u8) -> [u8; 16] {
    let mut k = [0u8; 16];
    k[0] = n;
    k
}

// ── Register ────────────────────────────────────────────────────────────────

#[test]
fn register_inserts_agent() {
    let reg = AgentRegistry::new();
    let record = make_record(key(1));
    reg.register(record).unwrap();

    let got = reg.get(&key(1)).expect("agent should exist");
    assert_eq!(got.name, "test-agent");
    assert_eq!(got.framework, "custom");
}

#[test]
fn register_duplicate_returns_error() {
    let reg = AgentRegistry::new();
    reg.register(make_record(key(1))).unwrap();

    let err = reg.register(make_record(key(1)));
    assert!(err.is_err());
    assert!(err.unwrap_err().to_string().contains("already registered"));
}

// ── Get ─────────────────────────────────────────────────────────────────────

#[test]
fn get_returns_none_for_missing_agent() {
    let reg = AgentRegistry::new();
    assert!(reg.get(&key(99)).is_none());
}

// ── Deregister ──────────────────────────────────────────────────────────────

#[test]
fn deregister_removes_agent() {
    let reg = AgentRegistry::new();
    reg.register(make_record(key(1))).unwrap();

    let (removed, _effects) = reg.deregister(&key(1), OrphanMode::Suspend).unwrap();
    assert_eq!(removed.name, "test-agent");
    assert!(reg.get(&key(1)).is_none());
}

#[test]
fn deregister_missing_returns_error() {
    let reg = AgentRegistry::new();
    let err = reg.deregister(&key(1), OrphanMode::Suspend);
    assert!(err.is_err());
    assert!(err.unwrap_err().to_string().contains("not found"));
}

// ── Heartbeat ───────────────────────────────────────────────────────────────

#[test]
fn update_heartbeat_updates_timestamp() {
    let reg = AgentRegistry::new();
    let mut record = make_record(key(1));
    let old_ts = Utc::now() - chrono::Duration::hours(1);
    record.last_heartbeat = old_ts;
    reg.register(record).unwrap();

    reg.update_heartbeat(&key(1)).unwrap();

    let got = reg.get(&key(1)).unwrap();
    assert!(got.last_heartbeat > old_ts);
}

#[test]
fn update_heartbeat_missing_returns_error() {
    let reg = AgentRegistry::new();
    assert!(reg.update_heartbeat(&key(99)).is_err());
}

// ── List ────────────────────────────────────────────────────────────────────

#[test]
fn list_returns_all_agents() {
    let reg = AgentRegistry::new();
    reg.register(make_record(key(1))).unwrap();
    reg.register(make_record(key(2))).unwrap();
    reg.register(make_record(key(3))).unwrap();

    let agents = reg.list();
    assert_eq!(agents.len(), 3);
}

#[test]
fn list_empty_registry() {
    let reg = AgentRegistry::new();
    assert!(reg.list().is_empty());
}

// ── Control stream ──────────────────────────────────────────────────────────

#[tokio::test]
async fn open_control_stream_for_registered_agent() {
    let reg = AgentRegistry::new();
    reg.register(make_record(key(1))).unwrap();

    let _rx = reg.open_control_stream(&key(1)).expect("should open stream");
}

#[test]
fn open_control_stream_for_missing_agent_returns_error() {
    let reg = AgentRegistry::new();
    assert!(reg.open_control_stream(&key(99)).is_err());
}

#[tokio::test]
async fn send_command_delivers_to_stream() {
    use aa_proto::assembly::agent::v1::control_command::Command;
    use aa_proto::assembly::agent::v1::{ControlCommand, SuspendCommand};

    let reg = AgentRegistry::new();
    reg.register(make_record(key(1))).unwrap();
    let mut rx = reg.open_control_stream(&key(1)).unwrap();

    let cmd = ControlCommand {
        command: Some(Command::Suspend(SuspendCommand {
            reason: "test suspend".into(),
        })),
    };
    reg.send_command(&key(1), cmd).await.unwrap();

    let received = rx.recv().await.unwrap().unwrap();
    match received.command {
        Some(Command::Suspend(s)) => assert_eq!(s.reason, "test suspend"),
        other => panic!("expected Suspend command, got {other:?}"),
    }
}

#[tokio::test]
async fn deregister_cleans_up_control_sender() {
    use aa_proto::assembly::agent::v1::control_command::Command;
    use aa_proto::assembly::agent::v1::{ControlCommand, SuspendCommand};

    let reg = AgentRegistry::new();
    reg.register(make_record(key(1))).unwrap();
    let _rx = reg.open_control_stream(&key(1)).unwrap();

    reg.deregister(&key(1), OrphanMode::Suspend).unwrap();

    // send_command should fail since sender was removed
    let cmd = ControlCommand {
        command: Some(Command::Suspend(SuspendCommand { reason: "noop".into() })),
    };
    assert!(reg.send_command(&key(1), cmd).await.is_err());
}

// ── Concurrent registration ────────────────────────────────────────────────

#[tokio::test]
async fn concurrent_registration_of_100_agents() {
    use std::sync::Arc;

    let reg = Arc::new(AgentRegistry::new());
    let mut handles = Vec::new();

    for i in 0u8..100 {
        let reg = Arc::clone(&reg);
        handles.push(tokio::spawn(async move {
            let mut k = [0u8; 16];
            k[0] = i;
            k[1] = (i as u16 >> 8) as u8;
            // Use i as a unique discriminator across the full byte
            let record = AgentRecord {
                agent_id: k,
                name: format!("agent-{i}"),
                framework: "custom".into(),
                version: "0.1.0".into(),
                risk_tier: 0,
                tool_names: vec![],
                public_key: format!("pk_{i}"),
                credential_token: format!("tok_{i}"),
                metadata: BTreeMap::new(),
                registered_at: Utc::now(),
                last_heartbeat: Utc::now(),
                status: AgentStatus::Active,
                pid: None,
                session_count: 0,
                last_event: None,
                policy_violations_count: 0,
                active_sessions: Vec::new(),
                recent_events: VecDeque::new(),
                recent_traces: Vec::new(),
                layer: None,
                governance_level: aa_core::GovernanceLevel::default(),
                parent_agent_id: None,
                team_id: None,
                depth: 0,
                delegation_reason: None,
                spawned_by_tool: None,
                root_agent_id: None,
                children: Vec::new(),
                parent_key: None,
            };
            reg.register(record).unwrap();
        }));
    }

    for h in handles {
        h.await.unwrap();
    }

    assert_eq!(reg.list().len(), 100);
}

// ── Suspend / Resume / Status ─────────────���───────────────────────────────

#[test]
fn suspend_agent_sets_status_to_suspended() {
    use aa_gateway::registry::SuspendReason;

    let reg = AgentRegistry::new();
    reg.register(make_record(key(1))).unwrap();

    reg.suspend_agent(&key(1), SuspendReason::BudgetExceeded).unwrap();

    let status = reg.agent_status(&key(1)).unwrap();
    assert_eq!(status, AgentStatus::Suspended(SuspendReason::BudgetExceeded));
}

#[test]
fn resume_agent_sets_status_to_active() {
    use aa_gateway::registry::SuspendReason;

    let reg = AgentRegistry::new();
    reg.register(make_record(key(1))).unwrap();

    reg.suspend_agent(&key(1), SuspendReason::BudgetExceeded).unwrap();
    reg.resume_agent(&key(1)).unwrap();

    let status = reg.agent_status(&key(1)).unwrap();
    assert_eq!(status, AgentStatus::Active);
}

#[test]
fn suspend_agent_not_found_returns_error() {
    use aa_gateway::registry::SuspendReason;

    let reg = AgentRegistry::new();
    let result = reg.suspend_agent(&key(99), SuspendReason::Manual);
    assert!(result.is_err());
}

#[tokio::test]
async fn suspend_and_notify_sends_command_on_control_stream() {
    use aa_gateway::registry::SuspendReason;
    use aa_proto::assembly::agent::v1::control_command::Command;

    let reg = AgentRegistry::new();
    reg.register(make_record(key(1))).unwrap();
    let mut rx = reg.open_control_stream(&key(1)).unwrap();

    reg.suspend_and_notify(&key(1), SuspendReason::BudgetExceeded, "budget limit exceeded")
        .await
        .unwrap();

    // Status should be Suspended
    let status = reg.agent_status(&key(1)).unwrap();
    assert_eq!(status, AgentStatus::Suspended(SuspendReason::BudgetExceeded));

    // SuspendCommand should have been delivered
    let received = rx.recv().await.unwrap().unwrap();
    match received.command {
        Some(Command::Suspend(s)) => assert_eq!(s.reason, "budget limit exceeded"),
        other => panic!("expected Suspend command, got {other:?}"),
    }
}

#[test]
fn new_fields_default_values_on_registration() {
    let reg = AgentRegistry::new();
    reg.register(make_record(key(1))).unwrap();

    let record = reg.get(&key(1)).unwrap();
    assert!(record.pid.is_none());
    assert_eq!(record.session_count, 0);
    assert!(record.last_event.is_none());
    assert_eq!(record.policy_violations_count, 0);
    assert!(record.active_sessions.is_empty());
    assert!(record.recent_events.is_empty());
}

#[test]
fn new_fields_survive_clone_and_retrieval() {
    let reg = AgentRegistry::new();
    let mut record = make_record(key(2));
    record.pid = Some(5678);
    record.session_count = 10;
    record.last_event = Some(Utc::now());
    record.policy_violations_count = 3;
    reg.register(record).unwrap();

    let retrieved = reg.get(&key(2)).unwrap();
    assert_eq!(retrieved.pid, Some(5678));
    assert_eq!(retrieved.session_count, 10);
    assert!(retrieved.last_event.is_some());
    assert_eq!(retrieved.policy_violations_count, 3);
}

#[test]
fn active_sessions_and_recent_events_survive_retrieval() {
    use aa_gateway::registry::{ActiveSession, RecentEvent};

    let reg = AgentRegistry::new();
    let mut record = make_record(key(3));
    record.active_sessions = vec![ActiveSession {
        session_id: "aabb".into(),
        started_at: Utc::now(),
        status: "running".into(),
    }];
    record.recent_events.push_back(RecentEvent {
        event_type: "violation".into(),
        summary: "unauthorized tool call".into(),
        timestamp: Utc::now(),
    });
    reg.register(record).unwrap();

    let retrieved = reg.get(&key(3)).unwrap();
    assert_eq!(retrieved.active_sessions.len(), 1);
    assert_eq!(retrieved.active_sessions[0].session_id, "aabb");
    assert_eq!(retrieved.active_sessions[0].status, "running");
    assert_eq!(retrieved.recent_events.len(), 1);
    assert_eq!(retrieved.recent_events[0].event_type, "violation");
    assert_eq!(retrieved.recent_events[0].summary, "unauthorized tool call");
}

#[test]
fn agent_record_defaults_governance_level_to_l0_discover() {
    // Records constructed via the standard test builder (which mirrors the
    // production lifecycle path) start at the safest level — discover-only.
    let record = make_record(key(0));
    assert_eq!(record.governance_level, aa_core::GovernanceLevel::L0Discover);
}

#[test]
fn agent_record_governance_level_round_trips_through_registry() {
    let reg = AgentRegistry::new();
    let mut record = make_record(key(1));
    record.governance_level = aa_core::GovernanceLevel::L2Enforce;
    reg.register(record).unwrap();

    let retrieved = reg.get(&key(1)).unwrap();
    assert_eq!(retrieved.governance_level, aa_core::GovernanceLevel::L2Enforce);
}

// ── Topology fields ──────────────────────────────────────────────────────────

#[test]
fn sub_agent_topology_fields_survive_registration() {
    let reg = AgentRegistry::new();
    let mut record = make_record(key(1));
    record.parent_agent_id = Some("parent-agent-uuid".into());
    record.team_id = Some("team-alpha".into());
    record.depth = 2;
    record.delegation_reason = Some("handle data extraction".into());
    record.spawned_by_tool = Some("langgraph.subgraph".into());
    reg.register(record).unwrap();

    let retrieved = reg.get(&key(1)).unwrap();
    assert_eq!(retrieved.parent_agent_id.as_deref(), Some("parent-agent-uuid"));
    assert_eq!(retrieved.team_id.as_deref(), Some("team-alpha"));
    assert_eq!(retrieved.depth, 2);
    assert_eq!(retrieved.delegation_reason.as_deref(), Some("handle data extraction"));
    assert_eq!(retrieved.spawned_by_tool.as_deref(), Some("langgraph.subgraph"));
}

#[test]
fn root_agent_topology_fields_default_to_none_and_zero() {
    let reg = AgentRegistry::new();
    reg.register(make_record(key(2))).unwrap();

    let retrieved = reg.get(&key(2)).unwrap();
    assert!(retrieved.parent_agent_id.is_none());
    assert!(retrieved.team_id.is_none());
    assert_eq!(retrieved.depth, 0);
    assert!(retrieved.delegation_reason.is_none());
    assert!(retrieved.spawned_by_tool.is_none());
}

#[test]
fn root_agent_id_field_round_trips_through_registry() {
    let reg = AgentRegistry::new();
    let mut record = make_record(key(5));
    record.root_agent_id = Some([0xAA; 16]);
    reg.register(record).unwrap();

    let retrieved = reg.get(&key(5)).unwrap();
    assert_eq!(retrieved.root_agent_id, Some([0xAA; 16]));
}
