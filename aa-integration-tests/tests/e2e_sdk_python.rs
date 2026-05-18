//! AAASM-1513 F116 ST-A — Python SDK `init_assembly()` E2E smoke tests.
//!
//! Each test drives a fixture script under
//! `tests/fixtures/agents/python/{single_agent,agent_team,root_sub_agents}/`.
//! Selftest mode (`AA_SELFTEST=1`) emits JSON events without importing
//! `agent_assembly` or contacting a gateway, so these run hermetically on CI
//! without a Python venv.  Tests 2–3 exercise the error paths that hold
//! regardless of whether the SDK package is installed.

use std::path::PathBuf;
use std::process::{Command, Output};

fn fixtures_python_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("agents")
        .join("python")
}

fn run_agent(script: &str, envs: &[(&str, &str)]) -> std::io::Result<Output> {
    let path = fixtures_python_dir().join(script);
    let mut cmd = Command::new("python3");
    cmd.arg(&path);
    for (k, v) in envs {
        cmd.env(k, v);
    }
    cmd.output()
}

fn parse_events(stdout: &str) -> Vec<serde_json::Value> {
    stdout
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).unwrap_or_else(|e| panic!("invalid JSON line: {e}\nline: {l:?}")))
        .collect()
}

// ── test 1 ────────────────────────────────────────────────────────────────────

#[test]
fn selftest_langchain_single_agent() {
    let out = run_agent("single_agent/langchain_agent.py", &[("AA_SELFTEST", "1")]).expect("spawn langchain_agent.py");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "expected exit 0; got {:?}\nstdout:\n{stdout}\nstderr:\n{stderr}",
        out.status.code()
    );
    let events = parse_events(&stdout);
    assert!(!events.is_empty(), "expected at least one JSON event");
    assert_eq!(events[0]["event"], "started", "first event must be 'started'");
    assert_eq!(events[0]["framework"], "langchain");
    assert!(
        events[0].get("agent_id").and_then(|v| v.as_str()).is_some(),
        "started event must include agent_id"
    );
    assert_eq!(events.last().unwrap()["event"], "done", "last event must be 'done'");
}

// ── test 2 ────────────────────────────────────────────────────────────────────

#[test]
fn missing_gateway_addr_exits_nonzero() {
    // AA_GATEWAY_ADDR absent and AA_SELFTEST absent → load_config() calls sys.exit(2).
    let out = run_agent("single_agent/langchain_agent.py", &[]).expect("spawn langchain_agent.py");
    assert!(
        !out.status.success(),
        "expected non-zero exit when AA_GATEWAY_ADDR is unset and AA_SELFTEST is off"
    );
}

// ── test 3 ────────────────────────────────────────────────────────────────────

#[test]
fn unreachable_gateway_exits_nonzero() {
    // Port 1 on loopback is always refused; the SDK import or HTTP connect will fail.
    let out = run_agent(
        "single_agent/langchain_agent.py",
        &[("AA_GATEWAY_ADDR", "http://127.0.0.1:1")],
    )
    .expect("spawn langchain_agent.py");
    assert!(
        !out.status.success(),
        "expected non-zero exit for unreachable gateway at http://127.0.0.1:1"
    );
}

// ── test 4 ────────────────────────────────────────────────────────────────────

#[test]
fn selftest_langgraph_single_agent() {
    let out = run_agent("single_agent/langgraph_agent.py", &[("AA_SELFTEST", "1")]).expect("spawn langgraph_agent.py");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "exit {:?}\nstdout:\n{stdout}\nstderr:\n{stderr}",
        out.status.code()
    );
    let events = parse_events(&stdout);
    assert_eq!(events[0]["event"], "started");
    assert_eq!(events[0]["framework"], "langgraph");
    assert_eq!(events.last().unwrap()["event"], "done");
}

// ── test 5 ────────────────────────────────────────────────────────────────────

#[test]
fn selftest_crewai_single_agent() {
    let out = run_agent("single_agent/crewai_agent.py", &[("AA_SELFTEST", "1")]).expect("spawn crewai_agent.py");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "exit {:?}\nstdout:\n{stdout}\nstderr:\n{stderr}",
        out.status.code()
    );
    let events = parse_events(&stdout);
    assert_eq!(events[0]["event"], "started");
    assert_eq!(events[0]["framework"], "crewai");
    assert_eq!(events.last().unwrap()["event"], "done");
}

// ── test 6 ────────────────────────────────────────────────────────────────────

#[test]
fn selftest_langchain_agent_team_emits_two_started_events() {
    let out = run_agent("agent_team/langchain_team.py", &[("AA_SELFTEST", "1")]).expect("spawn langchain_team.py");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "exit {:?}\nstdout:\n{stdout}\nstderr:\n{stderr}",
        out.status.code()
    );
    let events = parse_events(&stdout);
    let started: Vec<_> = events.iter().filter(|e| e["event"] == "started").collect();
    assert_eq!(
        started.len(),
        2,
        "agent_team must emit exactly 2 'started' events; got {}",
        started.len()
    );
    let done = events.last().unwrap();
    assert_eq!(done["event"], "done");
    assert_eq!(done["agent_count"], 2, "done event must carry agent_count=2");
}

// ── test 7 ────────────────────────────────────────────────────────────────────

#[test]
fn selftest_langgraph_agent_team_emits_two_started_events() {
    let out = run_agent("agent_team/langgraph_team.py", &[("AA_SELFTEST", "1")]).expect("spawn langgraph_team.py");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "exit {:?}\nstdout:\n{stdout}\nstderr:\n{stderr}",
        out.status.code()
    );
    let events = parse_events(&stdout);
    let started: Vec<_> = events.iter().filter(|e| e["event"] == "started").collect();
    assert_eq!(
        started.len(),
        2,
        "agent_team must emit exactly 2 'started' events; got {}",
        started.len()
    );
    let done = events.last().unwrap();
    assert_eq!(done["event"], "done");
    assert_eq!(done["agent_count"], 2, "done event must carry agent_count=2");
}

// ── test 8 ────────────────────────────────────────────────────────────────────

#[test]
fn selftest_crewai_root_sub_agent_hierarchy() {
    let out =
        run_agent("root_sub_agents/crewai_hierarchy.py", &[("AA_SELFTEST", "1")]).expect("spawn crewai_hierarchy.py");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "exit {:?}\nstdout:\n{stdout}\nstderr:\n{stderr}",
        out.status.code()
    );
    let events = parse_events(&stdout);
    let started: Vec<_> = events.iter().filter(|e| e["event"] == "started").collect();
    assert_eq!(
        started.len(),
        2,
        "hierarchy must emit root + child 'started' events; got {}",
        started.len()
    );
    assert_eq!(started[0]["role"], "root", "first started must be root");
    assert_eq!(started[1]["role"], "child", "second started must be child");
    assert!(
        started[1].get("parent").and_then(|v| v.as_str()).is_some(),
        "child started event must include 'parent' field"
    );
    assert_eq!(events.last().unwrap()["event"], "done");
}
