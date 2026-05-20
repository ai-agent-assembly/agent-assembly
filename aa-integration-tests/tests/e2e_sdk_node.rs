// F116 ST-B — Node.js SDK E2E fixture harness (AAASM-1514).
//
// Five hermetic selftest tests (no gateway, no native bindings) verify that
// each TypeScript fixture script exits 0 and emits the expected JSON-line
// contract.  Five companion tests marked `#[ignore]` cover the real
// `initAssembly()` → gRPC-gateway path and require a running aa-gateway plus
// native Node.js bindings; they are gated on AAASM-1514 follow-up work.

use std::path::PathBuf;
use std::process::{Command, Output};

use serde_json::Value;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn ts_fixtures_dir() -> PathBuf {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    PathBuf::from(manifest_dir)
        .join("tests")
        .join("fixtures")
        .join("agents")
        .join("typescript")
}

fn run_ts_script(script: &str, envs: &[(&str, &str)]) -> std::io::Result<Output> {
    let dir = ts_fixtures_dir();
    let mut cmd = Command::new("pnpm");
    cmd.arg("exec").arg("tsx").arg(script);
    cmd.current_dir(&dir);
    for (k, v) in envs {
        cmd.env(k, v);
    }
    cmd.output()
}

fn parse_events(stdout: &str) -> Vec<Value> {
    stdout
        .lines()
        .filter(|l| l.trim_start().starts_with('{'))
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect()
}

fn event_of_type<'a>(events: &'a [Value], kind: &str) -> Option<&'a Value> {
    events
        .iter()
        .find(|e| e.get("event").and_then(Value::as_str) == Some(kind))
}

fn assert_exit_zero(output: &Output, script: &str, stdout: &str, stderr: &str) {
    assert!(
        output.status.success(),
        "{script} must exit 0 in selftest mode; got {:?}\nstdout:\n{stdout}\nstderr:\n{stderr}",
        output.status.code(),
    );
}

// ---------------------------------------------------------------------------
// Selftest tests (hermetic — no gateway, no native bindings)
// ---------------------------------------------------------------------------

#[test]
fn selftest_langchain_single_agent_exits_zero_and_emits_started_done() {
    let output = run_ts_script(
        "single_agent/langchain_agent.ts",
        &[
            ("AA_SELFTEST", "1"),
            ("AA_GATEWAY_ADDR", "dummy"),
            ("AA_AGENT_ID", "e2e-lc"),
            ("AA_TASK", "f116-task"),
        ],
    )
    .expect("spawn pnpm exec tsx single_agent/langchain_agent.ts");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_exit_zero(&output, "langchain_agent.ts", &stdout, &stderr);

    let events = parse_events(&stdout);
    let started = event_of_type(&events, "started").expect("missing 'started' event");
    assert_eq!(started["agent_id"], "e2e-lc", "started.agent_id mismatch");

    assert!(
        event_of_type(&events, "tool_call").is_some(),
        "missing 'tool_call' event"
    );

    let done = event_of_type(&events, "done").expect("missing 'done' event");
    assert_eq!(done["result"], "selftest-ok", "done.result mismatch");
}

#[test]
fn selftest_langgraph_single_agent_exits_zero_and_emits_started_done() {
    let output = run_ts_script(
        "single_agent/langgraph_agent.ts",
        &[
            ("AA_SELFTEST", "1"),
            ("AA_GATEWAY_ADDR", "dummy"),
            ("AA_AGENT_ID", "e2e-lg"),
            ("AA_TASK", "f116-task"),
        ],
    )
    .expect("spawn pnpm exec tsx single_agent/langgraph_agent.ts");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_exit_zero(&output, "langgraph_agent.ts", &stdout, &stderr);

    let events = parse_events(&stdout);
    let started = event_of_type(&events, "started").expect("missing 'started' event");
    assert_eq!(started["agent_id"], "e2e-lg", "started.agent_id mismatch");

    assert!(
        event_of_type(&events, "tool_call").is_some(),
        "missing 'tool_call' event"
    );

    let done = event_of_type(&events, "done").expect("missing 'done' event");
    assert_eq!(done["result"], "selftest-ok", "done.result mismatch");
}

#[test]
fn selftest_langchain_team_exits_zero_and_emits_root_and_member_started() {
    let output = run_ts_script(
        "agent_team/langchain_team.ts",
        &[
            ("AA_SELFTEST", "1"),
            ("AA_GATEWAY_ADDR", "dummy"),
            ("AA_AGENT_ID", "e2e-lc-root"),
            ("AA_TASK", "f116-task"),
        ],
    )
    .expect("spawn pnpm exec tsx agent_team/langchain_team.ts");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_exit_zero(&output, "langchain_team.ts", &stdout, &stderr);

    let events = parse_events(&stdout);
    let started_events: Vec<&Value> = events
        .iter()
        .filter(|e| e.get("event").and_then(Value::as_str) == Some("started"))
        .collect();
    assert_eq!(
        started_events.len(),
        2,
        "expected 2 'started' events (root + member), got {}",
        started_events.len()
    );

    let root = started_events
        .iter()
        .find(|e| e["agent_id"] == "e2e-lc-root")
        .expect("missing root 'started' event");
    assert_eq!(root["role"], "root", "root.role mismatch");

    let member = started_events
        .iter()
        .find(|e| e["agent_id"] == "e2e-lc-root-member")
        .expect("missing member 'started' event");
    assert_eq!(member["role"], "member", "member.role mismatch");

    let done = event_of_type(&events, "done").expect("missing 'done' event");
    assert_eq!(done["result"], "selftest-ok", "done.result mismatch");
}

#[test]
fn selftest_langgraph_team_exits_zero_and_emits_coordinator_and_worker_started() {
    let output = run_ts_script(
        "agent_team/langgraph_team.ts",
        &[
            ("AA_SELFTEST", "1"),
            ("AA_GATEWAY_ADDR", "dummy"),
            ("AA_AGENT_ID", "e2e-lg-root"),
            ("AA_TASK", "f116-task"),
        ],
    )
    .expect("spawn pnpm exec tsx agent_team/langgraph_team.ts");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_exit_zero(&output, "langgraph_team.ts", &stdout, &stderr);

    let events = parse_events(&stdout);
    let started_events: Vec<&Value> = events
        .iter()
        .filter(|e| e.get("event").and_then(Value::as_str) == Some("started"))
        .collect();
    assert_eq!(
        started_events.len(),
        2,
        "expected 2 'started' events (coordinator + worker), got {}",
        started_events.len()
    );

    let coord = started_events
        .iter()
        .find(|e| e["agent_id"] == "e2e-lg-root")
        .expect("missing coordinator 'started' event");
    assert_eq!(coord["role"], "coordinator", "coordinator.role mismatch");

    let worker = started_events
        .iter()
        .find(|e| e["agent_id"] == "e2e-lg-root-worker")
        .expect("missing worker 'started' event");
    assert_eq!(worker["role"], "worker", "worker.role mismatch");

    let done = event_of_type(&events, "done").expect("missing 'done' event");
    assert_eq!(done["result"], "selftest-ok", "done.result mismatch");
}

#[test]
fn selftest_langgraph_hierarchy_exits_zero_and_emits_root_planner_executor_started() {
    let output = run_ts_script(
        "root_sub_agents/langgraph_hierarchy.ts",
        &[
            ("AA_SELFTEST", "1"),
            ("AA_GATEWAY_ADDR", "dummy"),
            ("AA_AGENT_ID", "e2e-root"),
            ("AA_TASK", "f116-task"),
        ],
    )
    .expect("spawn pnpm exec tsx root_sub_agents/langgraph_hierarchy.ts");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_exit_zero(&output, "langgraph_hierarchy.ts", &stdout, &stderr);

    let events = parse_events(&stdout);
    let started_events: Vec<&Value> = events
        .iter()
        .filter(|e| e.get("event").and_then(Value::as_str) == Some("started"))
        .collect();
    assert_eq!(
        started_events.len(),
        3,
        "expected 3 'started' events (root + planner + executor), got {}",
        started_events.len()
    );

    for (id, role) in [
        ("e2e-root", "root"),
        ("e2e-root-planner", "planner"),
        ("e2e-root-executor", "executor"),
    ] {
        let ev = started_events
            .iter()
            .find(|e| e["agent_id"] == id)
            .unwrap_or_else(|| panic!("missing 'started' event for {id}"));
        assert_eq!(ev["role"], role, "role mismatch for {id}");
    }

    let done = event_of_type(&events, "done").expect("missing 'done' event");
    assert_eq!(done["result"], "selftest-ok", "done.result mismatch");
}

// ---------------------------------------------------------------------------
// Real tests — require aa-gateway (gRPC) + native Node.js bindings.
// Blocked pending AAASM-1514 follow-up: native napi-rs build in CI +
// aa-gateway gRPC listener wired into the integration-test harness.
// ---------------------------------------------------------------------------

#[test]
#[ignore = "blocked on AAASM-1602: live-gateway + Node.js native-binding test fixture not yet available"]
fn real_langchain_single_agent_registers_with_gateway_and_emits_started_done() {
    let addr = std::env::var("AA_GATEWAY_ADDR").unwrap_or_else(|_| "127.0.0.1:50051".to_string());
    let output = run_ts_script(
        "single_agent/langchain_agent.ts",
        &[
            ("AA_GATEWAY_ADDR", &addr),
            ("AA_AGENT_ID", "e2e-lc-real"),
            ("AA_TASK", "f116-task"),
        ],
    )
    .expect("spawn pnpm exec tsx single_agent/langchain_agent.ts");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "langchain_agent.ts (real) must exit 0\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );

    let events = parse_events(&stdout);
    assert!(event_of_type(&events, "started").is_some(), "missing 'started' event");
    assert!(event_of_type(&events, "done").is_some(), "missing 'done' event");
}

#[test]
#[ignore = "blocked on AAASM-1602: live-gateway + Node.js native-binding test fixture not yet available"]
fn real_langgraph_single_agent_registers_with_gateway_and_emits_started_done() {
    let addr = std::env::var("AA_GATEWAY_ADDR").unwrap_or_else(|_| "127.0.0.1:50051".to_string());
    let output = run_ts_script(
        "single_agent/langgraph_agent.ts",
        &[
            ("AA_GATEWAY_ADDR", &addr),
            ("AA_AGENT_ID", "e2e-lg-real"),
            ("AA_TASK", "f116-task"),
        ],
    )
    .expect("spawn pnpm exec tsx single_agent/langgraph_agent.ts");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "langgraph_agent.ts (real) must exit 0\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );

    let events = parse_events(&stdout);
    assert!(event_of_type(&events, "started").is_some(), "missing 'started' event");
    assert!(event_of_type(&events, "done").is_some(), "missing 'done' event");
}

#[test]
#[ignore = "blocked on AAASM-1602: live-gateway + Node.js native-binding test fixture not yet available"]
fn real_langchain_team_registers_root_and_member_with_gateway() {
    let addr = std::env::var("AA_GATEWAY_ADDR").unwrap_or_else(|_| "127.0.0.1:50051".to_string());
    let output = run_ts_script(
        "agent_team/langchain_team.ts",
        &[
            ("AA_GATEWAY_ADDR", &addr),
            ("AA_AGENT_ID", "e2e-lc-root-real"),
            ("AA_TASK", "f116-task"),
        ],
    )
    .expect("spawn pnpm exec tsx agent_team/langchain_team.ts");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "langchain_team.ts (real) must exit 0\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );

    let events = parse_events(&stdout);
    let started_count = events
        .iter()
        .filter(|e| e.get("event").and_then(Value::as_str) == Some("started"))
        .count();
    assert_eq!(
        started_count, 2,
        "expected root + member registered (2 'started' events), got {started_count}"
    );
    assert!(event_of_type(&events, "done").is_some(), "missing 'done' event");
}

#[test]
#[ignore = "blocked on AAASM-1602: live-gateway + Node.js native-binding test fixture not yet available"]
fn real_langgraph_team_registers_coordinator_and_worker_with_gateway() {
    let addr = std::env::var("AA_GATEWAY_ADDR").unwrap_or_else(|_| "127.0.0.1:50051".to_string());
    let output = run_ts_script(
        "agent_team/langgraph_team.ts",
        &[
            ("AA_GATEWAY_ADDR", &addr),
            ("AA_AGENT_ID", "e2e-lg-root-real"),
            ("AA_TASK", "f116-task"),
        ],
    )
    .expect("spawn pnpm exec tsx agent_team/langgraph_team.ts");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "langgraph_team.ts (real) must exit 0\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );

    let events = parse_events(&stdout);
    let started_count = events
        .iter()
        .filter(|e| e.get("event").and_then(Value::as_str) == Some("started"))
        .count();
    assert_eq!(
        started_count, 2,
        "expected coordinator + worker registered (2 'started' events), got {started_count}"
    );
    assert!(event_of_type(&events, "done").is_some(), "missing 'done' event");
}

#[test]
#[ignore = "blocked on AAASM-1602: live-gateway + Node.js native-binding test fixture not yet available"]
fn real_langgraph_hierarchy_registers_root_planner_executor_with_gateway() {
    let addr = std::env::var("AA_GATEWAY_ADDR").unwrap_or_else(|_| "127.0.0.1:50051".to_string());
    let output = run_ts_script(
        "root_sub_agents/langgraph_hierarchy.ts",
        &[
            ("AA_GATEWAY_ADDR", &addr),
            ("AA_AGENT_ID", "e2e-root-real"),
            ("AA_TASK", "f116-task"),
        ],
    )
    .expect("spawn pnpm exec tsx root_sub_agents/langgraph_hierarchy.ts");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "langgraph_hierarchy.ts (real) must exit 0\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );

    let events = parse_events(&stdout);
    let started_count = events
        .iter()
        .filter(|e| e.get("event").and_then(Value::as_str) == Some("started"))
        .count();
    assert_eq!(
        started_count, 3,
        "expected root + planner + executor registered (3 'started' events), got {started_count}"
    );
    assert!(event_of_type(&events, "done").is_some(), "missing 'done' event");
}
