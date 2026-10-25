//! AAASM-6384 - a runtime that allows every call must say so, in its startup
//! log and on `/health`, instead of reporting `healthy` and logging "active
//! enforcement mechanisms".
//!
//! Launches the real `aa-runtime` executable so the log lines and the served
//! `/health` body are what an operator actually sees. The governed case (lease
//! gate active) needs the gate and lives with the other lease wiring tests in
//! `aaasm_6259_lease_gate_wiring.rs`.
//!
//! Enforcement semantics are deliberately not touched by this ticket: an
//! ungoverned runtime still allows everything. These tests only pin what is
//! *reported*.
#![cfg(unix)]

use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

static COUNTER: AtomicU32 = AtomicU32::new(0);

struct Runtime {
    child: Child,
    agent: String,
    port: u16,
    log: PathBuf,
    _dir: tempfile::TempDir,
}

impl Runtime {
    /// `policy_toml`: `None` points `AA_POLICY_PATH` at a file that does not
    /// exist (not the default `/etc/aa/policy.toml`, which a dev host could have).
    /// `env` is extra environment for the runtime.
    fn spawn(policy_toml: Option<&str>, env: &[(&str, &str)]) -> Self {
        static WARM: std::sync::Once = std::sync::Once::new();
        WARM.call_once(|| {
            let _ = Command::new(env!("CARGO_BIN_EXE_aa-runtime")).arg("--version").output();
        });
        // `free_port` can lose a race for the port between probing and binding
        // (the runtime now refuses to start then); retry that one failure.
        for _ in 0..4 {
            if let Some(rt) = Self::try_spawn(policy_toml, env) {
                return rt;
            }
        }
        panic!("could not find a free health port");
    }

    fn try_spawn(policy_toml: Option<&str>, env: &[(&str, &str)]) -> Option<Self> {
        let agent = format!(
            "s6384-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::SeqCst)
        );
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("runtime.log");
        let out = std::fs::File::create(&log).unwrap();
        let policy_path = dir.path().join("policy.toml");
        if let Some(toml) = policy_toml {
            std::fs::write(&policy_path, toml).unwrap();
        }
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_aa-runtime"));
        cmd.env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .env("AA_AGENT_ID", &agent)
            .env("AA_POLICY_PATH", &policy_path)
            .env("AA_METRICS_ADDR", format!("127.0.0.1:{port}"))
            .env("AA_AUDIT_BUFFER_PATH", dir.path().join("audit.db"))
            .env("RUST_LOG", "info")
            .env("AA_RUNTIME_SHUTDOWN_TIMEOUT_SECS", "3");
        for (k, v) in env {
            cmd.env(k, v);
        }
        let child = cmd
            .stdout(Stdio::from(out.try_clone().unwrap()))
            .stderr(Stdio::from(out))
            .spawn()
            .expect("spawn aa-runtime");
        let mut rt = Self {
            child,
            agent,
            port,
            log,
            _dir: dir,
        };
        rt.wait_ready().then_some(rt)
    }

    /// `false` only when the runtime lost the health-port race and exited.
    fn wait_ready(&mut self) -> bool {
        let deadline = Instant::now() + Duration::from_secs(120);
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                let text = self.log_text();
                assert!(
                    text.contains("failed to bind health server"),
                    "runtime exited early with {status}:\n{text}"
                );
                return false;
            }
            // Lost the health-port race. Detected from the log so it works whether
            // or not the runtime also exits (it only does once a refusal exists).
            if self.log_text().contains("failed to bind health server") {
                let _ = self.child.kill();
                let _ = self.child.wait();
                return false;
            }
            if std::net::TcpStream::connect(("127.0.0.1", self.port)).is_ok() && self.health_try().is_some() {
                return true;
            }
            assert!(Instant::now() < deadline, "runtime never became ready");
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    fn health_try(&self) -> Option<serde_json::Value> {
        let mut s = std::net::TcpStream::connect(("127.0.0.1", self.port)).ok()?;
        s.set_read_timeout(Some(Duration::from_secs(2))).ok()?;
        s.write_all(b"GET /health HTTP/1.0\r\nHost: x\r\n\r\n").ok()?;
        let mut body = String::new();
        s.read_to_string(&mut body).ok()?;
        serde_json::from_str(body.split("\r\n\r\n").nth(1)?).ok()
    }

    fn log_text(&self) -> String {
        std::fs::read_to_string(&self.log).unwrap_or_default()
    }

    fn health(&self) -> serde_json::Value {
        let mut s = std::net::TcpStream::connect(("127.0.0.1", self.port)).expect("health connect");
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        s.write_all(b"GET /health HTTP/1.0\r\nHost: x\r\n\r\n").unwrap();
        let mut body = String::new();
        s.read_to_string(&mut body).unwrap();
        serde_json::from_str(body.split("\r\n\r\n").nth(1).expect("http body")).expect("health json")
    }
}

impl Drop for Runtime {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_file(format!("/tmp/aa-runtime-{}.sock", self.agent));
    }
}

#[test]
fn a_runtime_with_no_policy_reports_ungoverned_and_says_all_calls_are_allowed() {
    let rt = Runtime::spawn(None, &[]);
    let health = rt.health();
    let log = rt.log_text();

    assert_eq!(health["status"], "ungoverned", "{health}");
    assert_eq!(health["governance"]["state"], "ungoverned");
    assert_eq!(health["governance"]["local_rule_count"], 0);
    assert_eq!(health["governance"]["gateway_installed"], false);
    assert!(
        health.get("lease_governance").is_none(),
        "no lease_governance key when not governed"
    );
    // Compatibility: existing fields are all still there.
    for field in [
        "uptime_secs",
        "events_processed",
        "active_layers",
        "degraded_layers",
        "protection",
    ] {
        assert!(
            health.get(field).is_some(),
            "existing field {field} must remain: {health}"
        );
    }

    assert!(log.contains("UNGOVERNED"), "startup must say so:\n{log}");
    assert!(log.contains("ALLOWS"), "startup must say every call is allowed:\n{log}");
    assert!(
        log.contains("AA_LEASE_POLICY") && log.contains("AA_POLICY_PATH"),
        "startup must name how to govern:\n{log}"
    );
    assert!(
        !log.contains("\"policy loaded\""),
        "a missing file is not a loaded policy:\n{log}"
    );
    assert!(
        !log.contains("active enforcement mechanisms"),
        "layer presence must not be described as enforcement:\n{log}"
    );
}

#[test]
fn a_runtime_with_policy_rules_but_no_lease_governance_says_exactly_that() {
    let rt = Runtime::spawn(
        Some("[[rules]]\nname = \"block-exfil\"\nblocked_actions = [\"NETWORK_CALL\"]\n"),
        &[],
    );
    let health = rt.health();
    let log = rt.log_text();

    assert_eq!(health["status"], "healthy", "rules are a decision source: {health}");
    assert_eq!(health["governance"]["state"], "policy_only");
    assert_eq!(health["governance"]["local_rule_count"], 1);
    assert_eq!(health["governance"]["lease_governed"], false);
    assert!(health.get("lease_governance").is_none());

    assert!(
        log.contains("\"policy loaded\""),
        "a real file is reported as loaded:\n{log}"
    );
    assert!(
        log.contains("lease governance is not enabled"),
        "startup must say leases are off:\n{log}"
    );
    assert!(
        !log.contains("UNGOVERNED"),
        "a runtime with rules is not ungoverned:\n{log}"
    );
}

#[test]
fn an_invalid_gateway_endpoint_installs_no_gateway_and_is_still_ungoverned() {
    // An endpoint that cannot be parsed yields no gateway client, so calls fall
    // through to (absent) local rules: configured is not installed.
    let rt = Runtime::spawn(None, &[("AA_GATEWAY_ENDPOINT", "not a uri \u{1}")]);
    let health = rt.health();
    let log = rt.log_text();
    assert_eq!(health["status"], "ungoverned", "{health}");
    assert_eq!(health["governance"]["gateway_installed"], false);
    assert!(log.contains("UNGOVERNED"), "{log}");
}

#[test]
fn rules_that_decide_nothing_do_not_make_a_runtime_governed() {
    let rt = Runtime::spawn(Some("[[rules]]\nname = \"empty\"\nblocked_actions = []\n"), &[]);
    let health = rt.health();
    assert_eq!(health["status"], "ungoverned", "{health}");
    assert_eq!(health["governance"]["local_rule_count"], 0);
}

#[test]
fn a_fail_open_gateway_is_flagged_in_health_and_the_log() {
    // Valid endpoint, nothing listening; fail-closed explicitly turned off.
    let rt = Runtime::spawn(
        None,
        &[
            ("AA_GATEWAY_ENDPOINT", "http://127.0.0.1:9"),
            ("AA_GATEWAY_FAIL_CLOSED", "false"),
        ],
    );
    let health = rt.health();
    let log = rt.log_text();
    assert_eq!(health["governance"]["state"], "policy_only", "{health}");
    assert_eq!(health["governance"]["gateway_installed"], true);
    assert_eq!(health["governance"]["gateway_fail_open"], true);
    assert!(log.contains("fails OPEN"), "{log}");

    // And the default stays fail-closed, unflagged.
    let closed = Runtime::spawn(None, &[("AA_GATEWAY_ENDPOINT", "http://127.0.0.1:9")]);
    assert_eq!(closed.health()["governance"]["gateway_fail_open"], false);
    assert!(!closed.log_text().contains("fails OPEN"));
}

#[test]
fn rules_naming_no_real_action_type_do_not_make_a_runtime_governed() {
    // "send_email" is not an ActionType name, so the evaluator can never match it.
    let rt = Runtime::spawn(
        Some("[[rules]]\nname = \"typo\"\nblocked_actions = [\"send_email\"]\n"),
        &[],
    );
    let health = rt.health();
    let log = rt.log_text();
    assert_eq!(health["status"], "ungoverned", "{health}");
    assert_eq!(health["governance"]["local_rule_count"], 0);
    assert!(
        log.contains("match nothing"),
        "the load must warn about the dead entry:\n{log}"
    );
    assert!(log.contains("no effective local policy rules"), "{log}");
}
