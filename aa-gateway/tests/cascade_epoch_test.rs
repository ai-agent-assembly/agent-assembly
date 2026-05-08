//! Epoch integrity tests: concurrent increments and proptest convergence (AAASM-1013).

use std::collections::{BTreeMap, HashMap};
use std::io::Write;
use std::sync::Arc;

use aa_core::identity::{AgentId, SessionId};
use aa_core::{AgentContext, GovernanceAction, GovernanceLevel};
use aa_gateway::engine::PolicyEngine;
use aa_gateway::policy::document::PolicyDocument;
use aa_gateway::policy::scope::PolicyScope;
use proptest::prelude::*;

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

// 1. 100 concurrent load_policy calls via Arc<tokio::sync::Mutex<PolicyEngine>>.
//    Each call bumps the epoch; a subsequent evaluate must be a cache miss.
#[tokio::test]
async fn concurrent_load_policy_100_tasks_epoch_is_atomically_incremented() {
    let engine = Arc::new(tokio::sync::Mutex::new(make_engine()));

    // Prime with one Global policy so collect_cascade returns a non-empty cascade.
    engine.lock().await.load_policy(allow_doc(PolicyScope::Global));

    // Warm the cache for ctx(1)/bash.
    {
        let e = engine.lock().await;
        let _ = e.evaluate(&make_ctx(1), &tool_action("bash"));
    }
    let misses_before = engine.lock().await.cache_misses();

    // Spawn 100 tasks each performing one load_policy (epoch bump).
    let handles: Vec<_> = (0..100u8)
        .map(|i| {
            let engine = Arc::clone(&engine);
            tokio::spawn(async move {
                let mut e = engine.lock().await;
                e.load_policy(allow_doc(PolicyScope::Agent(AgentId::from_bytes([i; 16]))));
            })
        })
        .collect();

    for h in handles {
        h.await.unwrap();
    }

    // After 100 epoch bumps the previously-cached entry is stale.
    // The next evaluate for the same (agent, action) must be a miss.
    let e = engine.lock().await;
    let _ = e.evaluate(&make_ctx(1), &tool_action("bash"));
    assert_eq!(
        e.cache_misses(),
        misses_before + 1,
        "stale cached entry must produce exactly one new miss after 100 epoch bumps"
    );
}

// 2. Proptest: N load_policy calls always produce exactly one new cache miss on
//    the subsequent evaluate — regardless of N or starting epoch.
proptest! {
    #[test]
    fn n_epoch_bumps_always_invalidate_cache(n in 1usize..=100usize) {
        let mut engine = make_engine();
        engine.load_policy(allow_doc(PolicyScope::Global));

        let ctx = make_ctx(50);
        let action = tool_action("bash");

        // Warm the cache.
        let _ = engine.evaluate(&ctx, &action);
        let misses_before = engine.cache_misses();

        // N epoch bumps.
        for _ in 0..n {
            engine.load_policy(allow_doc(PolicyScope::Global));
        }

        // Next evaluate must be exactly one new miss.
        let _ = engine.evaluate(&ctx, &action);
        prop_assert_eq!(
            engine.cache_misses(),
            misses_before + 1,
            "epoch bumps must invalidate cache"
        );
    }
}
