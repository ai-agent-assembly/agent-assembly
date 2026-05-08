//! Integration tests for PolicyEngine::collect_cascade (AAASM-957).

use std::collections::BTreeMap;
use std::collections::HashMap;
use std::sync::Arc;

use aa_core::identity::AgentId;
use aa_gateway::engine::PolicyEngine;
use aa_gateway::policy::document::PolicyDocument;
use aa_gateway::policy::scope::PolicyScope;
use aa_gateway::registry::{AgentRecord, AgentRegistry, AgentStatus};
use chrono::Utc;

fn make_registry() -> Arc<AgentRegistry> {
    Arc::new(AgentRegistry::new())
}

fn make_engine() -> PolicyEngine {
    use std::io::Write;
    let mut tmp = tempfile::NamedTempFile::new().unwrap();
    writeln!(tmp, "version: \"1\"").unwrap();
    tmp.flush().unwrap();
    let (alert_tx, _) = tokio::sync::broadcast::channel::<aa_gateway::budget::BudgetAlert>(64);
    PolicyEngine::load_from_file(tmp.path(), alert_tx).unwrap()
}

fn doc_for_scope(scope: PolicyScope) -> PolicyDocument {
    PolicyDocument {
        name: None,
        policy_version: None,
        version: None,
        scope,
        network: None,
        schedule: None,
        budget: None,
        data: None,
        approval_timeout_secs: 300,
        tools: HashMap::new(),
    }
}

fn register_agent(registry: &AgentRegistry, agent_id: AgentId, org_id: Option<&str>, team_id: Option<&str>) {
    let mut metadata = BTreeMap::new();
    if let Some(org) = org_id {
        metadata.insert("org_id".to_string(), org.to_string());
    }
    if let Some(team) = team_id {
        metadata.insert("team_id".to_string(), team.to_string());
    }
    registry
        .register(AgentRecord {
            agent_id: *agent_id.as_bytes(),
            name: "test-agent".into(),
            framework: "test".into(),
            version: "0.0.1".into(),
            risk_tier: 0,
            tool_names: vec![],
            public_key: String::new(),
            credential_token: String::new(),
            metadata,
            registered_at: Utc::now(),
            last_heartbeat: Utc::now(),
            status: AgentStatus::Active,
            pid: None,
            session_count: 0,
            last_event: None,
            policy_violations_count: 0,
            active_sessions: vec![],
            recent_events: Default::default(),
            recent_traces: vec![],
            layer: None,
            governance_level: Default::default(),
            parent_agent_id: None,
            team_id: None,
            depth: 0,
            delegation_reason: None,
            spawned_by_tool: None,
            root_agent_id: None,
            children: Vec::new(),
            parent_key: None,
        })
        .unwrap();
}

#[test]
fn full_lineage_returns_global_org_team_agent_in_order() {
    let agent_id = AgentId::from_bytes([1u8; 16]);
    let registry = make_registry();
    register_agent(&registry, agent_id, Some("acme"), Some("platform"));

    let mut engine = make_engine().with_registry(Arc::clone(&registry));

    engine.load_policy(doc_for_scope(PolicyScope::Global));
    engine.load_policy(doc_for_scope(PolicyScope::Org("acme".into())));
    engine.load_policy(doc_for_scope(PolicyScope::Team("platform".into())));
    engine.load_policy(doc_for_scope(PolicyScope::Agent(agent_id)));

    let cascade = engine.collect_cascade(&agent_id);

    assert_eq!(cascade.len(), 4, "expected 4 policies in full lineage");
    assert_eq!(cascade[0].scope, PolicyScope::Global);
    assert_eq!(cascade[1].scope, PolicyScope::Org("acme".into()));
    assert_eq!(cascade[2].scope, PolicyScope::Team("platform".into()));
    assert_eq!(cascade[3].scope, PolicyScope::Agent(agent_id));
}

#[test]
fn agent_without_team_returns_global_org_agent() {
    let agent_id = AgentId::from_bytes([2u8; 16]);
    let registry = make_registry();
    register_agent(&registry, agent_id, Some("acme"), None);

    let mut engine = make_engine().with_registry(Arc::clone(&registry));
    engine.load_policy(doc_for_scope(PolicyScope::Global));
    engine.load_policy(doc_for_scope(PolicyScope::Org("acme".into())));
    engine.load_policy(doc_for_scope(PolicyScope::Team("platform".into()))); // not applicable
    engine.load_policy(doc_for_scope(PolicyScope::Agent(agent_id)));

    let cascade = engine.collect_cascade(&agent_id);

    assert_eq!(cascade.len(), 3);
    assert_eq!(cascade[0].scope, PolicyScope::Global);
    assert_eq!(cascade[1].scope, PolicyScope::Org("acme".into()));
    assert_eq!(cascade[2].scope, PolicyScope::Agent(agent_id));
}

#[test]
fn top_level_agent_no_lineage_returns_global_and_agent() {
    let agent_id = AgentId::from_bytes([3u8; 16]);
    let registry = make_registry();
    register_agent(&registry, agent_id, None, None);

    let mut engine = make_engine().with_registry(Arc::clone(&registry));
    engine.load_policy(doc_for_scope(PolicyScope::Global));
    engine.load_policy(doc_for_scope(PolicyScope::Agent(agent_id)));

    let cascade = engine.collect_cascade(&agent_id);

    assert_eq!(cascade.len(), 2);
    assert_eq!(cascade[0].scope, PolicyScope::Global);
    assert_eq!(cascade[1].scope, PolicyScope::Agent(agent_id));
}

#[test]
fn agent_not_in_registry_returns_only_global_and_agent_scoped_policies() {
    let agent_id = AgentId::from_bytes([4u8; 16]);
    // No registry attached — falls back to no lineage
    let mut engine = make_engine();
    engine.load_policy(doc_for_scope(PolicyScope::Global));
    engine.load_policy(doc_for_scope(PolicyScope::Org("acme".into())));
    engine.load_policy(doc_for_scope(PolicyScope::Team("platform".into())));
    engine.load_policy(doc_for_scope(PolicyScope::Agent(agent_id)));

    let cascade = engine.collect_cascade(&agent_id);

    assert_eq!(cascade.len(), 2);
    assert_eq!(cascade[0].scope, PolicyScope::Global);
    assert_eq!(cascade[1].scope, PolicyScope::Agent(agent_id));
}
