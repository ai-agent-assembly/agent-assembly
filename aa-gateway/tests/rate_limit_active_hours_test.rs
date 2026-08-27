//! AAASM-5883: dedicated coverage for golden-journey J28 ("Verify rate
//! limiting (`limit_per_hour`) and scheduling (`active_hours`)",
//! `qa/golden-journeys.yaml`).
//!
//! The AAASM-5873 baseline audit classified J28 `NOT_COVERED` because it
//! only found incidental `limit_per_hour`/`active_hours` hits in
//! `cascade_tool_scope_test.rs` / `cascade_merge_test.rs` that don't exercise
//! either field by name. That audit method (scanning `tests/` files) missed
//! real coverage that already existed in `#[cfg(test)] mod tests` blocks
//! inside `src/`: `engine::mod::rate_limit_denies_after_capacity_exhausted`
//! (since 2026-06-28) already asserts `limit_per_hour` allow-then-deny, and
//! `engine::decision`'s `stage_schedule_at::*` tests already assert
//! `active_hours` deterministically at the stage level via an injectable
//! clock. What was genuinely missing — and what this file adds — is a
//! deterministic, falsifying assertion of `active_hours` through the public
//! `PolicyEngine::evaluate()` path: the two existing engine-level tests
//! (`schedule_denies_outside_active_hours`,
//! `schedule_wide_active_hours_window_allows_through_the_full_pipeline`)
//! each accept *either* Allow or Deny as passing, so they do not fail if the
//! Stage 1 schedule check is removed from `evaluate()` entirely (verified by
//! temporarily deleting the call site during this ticket's investigation).
//!
//! `evaluate()` has no seam to inject a fixed instant (unlike
//! `decision::stage_schedule_at`), so the windows below are derived from
//! `Utc::now()` at test time instead of hardcoded constants — deterministic
//! on any clock, with the same accepted trade-off `schedule_denies_outside_active_hours`
//! already documents: a window computed to exclude/include `now` can, in
//! principle, straddle the exact instant `evaluate()` reads its own
//! `Utc::now()` a few microseconds later. The windows are sized with margin
//! specifically to make that gap negligible.

use std::collections::{BTreeMap, HashMap};
use std::io::Write;

use aa_core::identity::{AgentId, SessionId};
use aa_core::{AgentContext, GovernanceAction, GovernanceLevel, PolicyResult};
use aa_gateway::engine::PolicyEngine;
use aa_gateway::policy::document::{ActiveHours, PolicyDocument, SchedulePolicy, ToolPolicy};
use aa_gateway::policy::scope::PolicyScope;
use chrono::{Duration, Timelike, Utc};

const AGENT_BYTES: [u8; 16] = [1u8; 16];

fn make_engine() -> PolicyEngine {
    let mut tmp = tempfile::NamedTempFile::new().unwrap();
    writeln!(tmp, "version: \"1\"").unwrap();
    tmp.flush().unwrap();
    let (alert_tx, _) = tokio::sync::broadcast::channel::<aa_gateway::budget::BudgetAlert>(64);
    PolicyEngine::load_from_file(tmp.path(), alert_tx).unwrap()
}

fn make_ctx() -> AgentContext {
    AgentContext {
        agent_id: AgentId::from_bytes(AGENT_BYTES),
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

/// A policy with no sections — allows every action.
fn empty_doc(scope: PolicyScope) -> PolicyDocument {
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
        filesystem: None,
        syscall_allowlist: None,
    }
}

fn tool_call(name: &str) -> GovernanceAction {
    GovernanceAction::ToolCall {
        name: name.to_string(),
        args: String::new(),
    }
}

/// Format a UTC instant as the `HH:MM` string `active_hours` compares against.
fn hhmm(t: chrono::DateTime<Utc>) -> String {
    format!("{:02}:{:02}", t.hour(), t.minute())
}

fn schedule_doc(scope: PolicyScope, start: &str, end: &str) -> PolicyDocument {
    PolicyDocument {
        schedule: Some(SchedulePolicy {
            active_hours: Some(ActiveHours {
                start: start.to_string(),
                end: end.to_string(),
                timezone: "UTC".to_string(),
            }),
        }),
        ..empty_doc(scope)
    }
}

/// `limit_per_hour: Some(1)` must allow the first call and deny the second —
/// the AC's rate-limiting half, exercised through the public `evaluate()`
/// path with a dedicated selector J28 can cite as evidence (the underlying
/// token-bucket mechanism already has thorough coverage in
/// `engine::mod::tests` and `engine::rate_limit::tests`; this test's role is
/// giving the journey a named, resolvable anchor rather than adding new
/// mechanism coverage).
#[test]
fn limit_per_hour_allows_within_limit_then_denies_when_exceeded() {
    let mut engine = make_engine();
    let mut doc = empty_doc(PolicyScope::Global);
    doc.tools.insert(
        "search".to_string(),
        ToolPolicy {
            allow: true,
            limit_per_hour: Some(1),
            requires_approval_if: None,
        },
    );
    engine.load_policy(doc);

    let ctx = make_ctx();
    let action = tool_call("search");

    assert_eq!(
        engine.evaluate(&ctx, &action).decision,
        PolicyResult::Allow,
        "first call is within the limit_per_hour: 1 budget"
    );
    assert_eq!(
        engine.evaluate(&ctx, &action).decision,
        PolicyResult::Deny {
            reason: "rate limit exceeded".into()
        },
        "second call within the same hour must exceed limit_per_hour: 1"
    );
}

/// A call outside the configured `active_hours` window must be denied. The
/// window is placed 12 hours from `now` so it can never contain the instant
/// `evaluate()` reads, on any clock.
#[test]
fn active_hours_denies_a_call_outside_the_window() {
    let now = Utc::now();
    let start = hhmm(now + Duration::hours(12));
    let end = hhmm(now + Duration::hours(12) + Duration::minutes(1));

    let mut engine = make_engine();
    engine.load_policy(schedule_doc(PolicyScope::Global, &start, &end));

    let ctx = make_ctx();
    let result = engine.evaluate(&ctx, &tool_call("any")).decision;

    assert_eq!(
        result,
        PolicyResult::Deny {
            reason: "outside active hours".into()
        },
        "a window 12h from now must exclude the current instant"
    );
}

/// A call inside the configured `active_hours` window must be allowed. The
/// window brackets `now` with 90 minutes of margin on each side so the gap
/// between building the window here and `evaluate()` reading its own
/// `Utc::now()` can never fall outside it — this repo's shared
/// `CARGO_TARGET_DIR` convention means the process running this test can be
/// descheduled for minutes under contention from concurrent builds in other
/// worktrees, so a margin of only a few minutes was observed to flake here
/// (verified empirically: a several-minute scheduling stall pushed `now`
/// outside a +/-3min window before `evaluate()` re-read the clock).
///
/// `stage_schedule_at`'s `HH:MM` comparator has no midnight-wraparound
/// support (`current < start || current >= end`, compared lexicographically
/// as strings) — a naive `now - 90min .. now + 90min` window that crosses
/// `00:00` produces a `start > end` pair the comparator reads as "outside"
/// for nearly the entire window, which is a *deterministic* failure for any
/// run between ~22:30 and ~01:30 UTC, not a flake. Clamp each bound to stay
/// within `now`'s own calendar day instead of wrapping past it — `now`
/// always remains inside `[start, end)` either way, since clamping only
/// moves a bound *toward* `now`'s day, never past it.
#[test]
fn active_hours_allows_a_call_inside_the_window() {
    let now = Utc::now();
    let raw_start = now - Duration::minutes(90);
    let raw_end = now + Duration::minutes(90);

    let start = if raw_start.date_naive() != now.date_naive() {
        "00:00".to_string()
    } else {
        hhmm(raw_start)
    };
    let end = if raw_end.date_naive() != now.date_naive() {
        "23:59".to_string()
    } else {
        hhmm(raw_end)
    };

    let mut engine = make_engine();
    engine.load_policy(schedule_doc(PolicyScope::Global, &start, &end));

    let ctx = make_ctx();
    let result = engine.evaluate(&ctx, &tool_call("any")).decision;

    assert_eq!(
        result,
        PolicyResult::Allow,
        "a 90min window clamped to now's calendar day must include the current instant"
    );
}
