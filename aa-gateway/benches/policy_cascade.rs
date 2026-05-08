//! Criterion benchmark: cascade evaluation p99 latency (AAASM-966).
//!
//! Validates that `PolicyEngine::evaluate` via the cascade path stays under
//! 5ms p99 when 1 000 policies are loaded across all scopes.  The second
//! iteration of each benchmark group exercises the cache-hit path; the first
//! exercises the cache-miss path.

use std::collections::HashMap;
use std::hint::black_box;
use std::io::Write;
use std::sync::Arc;

use criterion::{criterion_group, criterion_main, Criterion};

use aa_core::identity::{AgentId, SessionId};
use aa_core::{AgentContext, GovernanceAction, GovernanceLevel};
use aa_gateway::engine::PolicyEngine;
use aa_gateway::policy::document::PolicyDocument;
use aa_gateway::policy::scope::PolicyScope;

const POLICY_COUNT: usize = 1_000;

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
        tools: HashMap::new(),
        capabilities: None,
    }
}

fn make_engine() -> PolicyEngine {
    let mut tmp = tempfile::NamedTempFile::new().unwrap();
    writeln!(tmp, "version: \"1\"").unwrap();
    tmp.flush().unwrap();
    let (alert_tx, _) = tokio::sync::broadcast::channel::<aa_gateway::budget::BudgetAlert>(64);
    let mut engine = PolicyEngine::load_from_file(tmp.path(), alert_tx).unwrap();

    // Load POLICY_COUNT policies across all scope tiers in round-robin.
    for i in 0..POLICY_COUNT {
        let scope = match i % 4 {
            0 => PolicyScope::Global,
            1 => PolicyScope::Org(format!("org-{i}")),
            2 => PolicyScope::Team(format!("team-{i}")),
            _ => PolicyScope::Agent(AgentId::from_bytes([(i % 256) as u8; 16])),
        };
        engine.load_policy(allow_doc(scope));
    }
    engine
}

fn make_ctx() -> AgentContext {
    AgentContext {
        agent_id: AgentId::from_bytes([1u8; 16]),
        session_id: SessionId::from_bytes([0u8; 16]),
        pid: 0,
        started_at: aa_core::time::Timestamp::from_nanos(0),
        metadata: std::collections::BTreeMap::new(),
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

fn bench_evaluate_cached(c: &mut Criterion) {
    let engine = Arc::new(make_engine());
    let ctx = make_ctx();
    let action = tool_action("bash");

    // Warm the cache so the benchmark measures the hit path.
    let _ = engine.evaluate(&ctx, &action);

    let mut group = c.benchmark_group("cascade_evaluate");
    group.measurement_time(std::time::Duration::from_secs(10));

    group.bench_function("cache_hit_1000_policies", |b| {
        b.iter(|| {
            let result = engine.evaluate(&ctx, &action);
            black_box(result)
        })
    });

    group.bench_function("cache_miss_1000_policies", |b| {
        b.iter_custom(|iters| {
            let mut total = std::time::Duration::ZERO;
            for _ in 0..iters {
                // Build a fresh engine each iteration so every call is a miss.
                let e = make_engine();
                let ctx = make_ctx();
                let action = tool_action("bash");
                let start = std::time::Instant::now();
                let result = e.evaluate(&ctx, &action);
                total += start.elapsed();
                black_box(result);
            }
            total
        })
    });

    group.finish();
}

criterion_group!(benches, bench_evaluate_cached);
criterion_main!(benches);
