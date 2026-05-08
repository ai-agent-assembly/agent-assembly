//! Tests for policy epoch invalidation and cache hit/miss counters (AAASM-1013).

use std::collections::BTreeMap;
use std::collections::HashMap;
use std::io::Write;

use aa_core::identity::{AgentId, SessionId};
use aa_core::{AgentContext, GovernanceAction, GovernanceLevel};
use aa_gateway::engine::PolicyEngine;
use aa_gateway::policy::document::PolicyDocument;
use aa_gateway::policy::scope::PolicyScope;

fn make_engine() -> PolicyEngine {
    let mut tmp = tempfile::NamedTempFile::new().unwrap();
    writeln!(tmp, "version: \"1\"").unwrap();
    tmp.flush().unwrap();
    let (alert_tx, _) = tokio::sync::broadcast::channel::<aa_gateway::budget::BudgetAlert>(64);
    PolicyEngine::load_from_file(tmp.path(), alert_tx).unwrap()
}

fn allow_doc(scope: PolicyScope) -> PolicyDocument {
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
        approval_policy: None,
        tools: HashMap::new(),
        capabilities: None,
    }
}

fn make_ctx(id: u8) -> AgentContext {
    AgentContext {
        agent_id: AgentId::from_bytes([id; 16]),
        session_id: SessionId::from_bytes([0u8; 16]),
        pid: 0,
        started_at: aa_core::time::Timestamp::from_nanos(0),
        metadata: BTreeMap::new(),
        governance_level: GovernanceLevel::default(),
        parent_agent_id: None,
        team_id: None,
        depth: 0,
        delegation_reason: None,
        spawned_by_tool: None,
        root_agent_id: None,
    }
}

fn tool_action(name: &str) -> GovernanceAction {
    GovernanceAction::ToolCall {
        name: name.to_string(),
        args: String::new(),
    }
}

// 1. A second evaluate call with the same agent/action/epoch is a cache hit.
#[test]
fn repeated_evaluate_with_cascade_produces_cache_hit() {
    let agent_id = AgentId::from_bytes([1u8; 16]);
    let mut engine = make_engine();
    engine.load_policy(allow_doc(PolicyScope::Global));
    engine.load_policy(allow_doc(PolicyScope::Agent(agent_id)));

    let ctx = make_ctx(1);
    let action = tool_action("bash");

    // First call — must be a miss.
    let _ = engine.evaluate(&ctx, &action);
    let misses_after_first = engine.cache_misses();
    let hits_after_first = engine.cache_hits();

    // Second call — same epoch → cache hit.
    let _ = engine.evaluate(&ctx, &action);
    assert_eq!(
        engine.cache_hits(),
        hits_after_first + 1,
        "second call should hit cache"
    );
    assert_eq!(
        engine.cache_misses(),
        misses_after_first,
        "miss count must not change on hit"
    );
}

// 2. Loading a new policy bumps the epoch, so the next call is a miss even for same action.
#[test]
fn load_policy_increments_epoch_and_invalidates_cache() {
    let agent_id = AgentId::from_bytes([2u8; 16]);
    let mut engine = make_engine();
    engine.load_policy(allow_doc(PolicyScope::Global));
    engine.load_policy(allow_doc(PolicyScope::Agent(agent_id)));

    let ctx = make_ctx(2);
    let action = tool_action("deploy");

    // Warm the cache.
    let _ = engine.evaluate(&ctx, &action);
    let misses_before = engine.cache_misses();

    // Load a new policy — epoch bumps.
    engine.load_policy(allow_doc(PolicyScope::Global));

    // Next call must be a miss (stale epoch).
    let _ = engine.evaluate(&ctx, &action);
    assert_eq!(
        engine.cache_misses(),
        misses_before + 1,
        "epoch bump must cause a cache miss"
    );
}

// 3. Different actions for the same agent produce different cache keys (separate misses).
#[test]
fn different_actions_produce_separate_cache_entries() {
    let agent_id = AgentId::from_bytes([3u8; 16]);
    let mut engine = make_engine();
    engine.load_policy(allow_doc(PolicyScope::Global));
    engine.load_policy(allow_doc(PolicyScope::Agent(agent_id)));

    let ctx = make_ctx(3);

    let _ = engine.evaluate(&ctx, &tool_action("bash"));
    let _ = engine.evaluate(&ctx, &tool_action("deploy"));

    // Both calls should be misses (different action_hash).
    assert_eq!(engine.cache_misses(), 2, "each distinct action must be a cache miss");
    assert_eq!(engine.cache_hits(), 0);
}
