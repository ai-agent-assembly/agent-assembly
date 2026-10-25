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
    /// `policy_toml`: `None` leaves `AA_POLICY_PATH` unset, so the runtime looks
    /// for the default `/etc/aa/policy.toml` (absent on a dev host) - the exact
    /// "only AA_AGENT_ID" repro.
    fn spawn(policy_toml: Option<&str>) -> Self {
        static WARM: std::sync::Once = std::sync::Once::new();
        WARM.call_once(|| {
            let _ = Command::new(env!("CARGO_BIN_EXE_aa-runtime")).arg("--version").output();
        });
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
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_aa-runtime"));
        cmd.env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .env("AA_AGENT_ID", &agent)
            .env("AA_METRICS_ADDR", format!("127.0.0.1:{port}"))
            .env("AA_AUDIT_BUFFER_PATH", dir.path().join("audit.db"))
            .env("RUST_LOG", "info")
            .env("AA_RUNTIME_SHUTDOWN_TIMEOUT_SECS", "3");
        if let Some(toml) = policy_toml {
            let path = dir.path().join("policy.toml");
            std::fs::write(&path, toml).unwrap();
            cmd.env("AA_POLICY_PATH", path);
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
        rt.wait_ready();
        rt
    }

    fn wait_ready(&mut self) {
        let deadline = Instant::now() + Duration::from_secs(120);
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                panic!("runtime exited early with {status}:\n{}", self.log_text());
            }
            if std::net::TcpStream::connect(("127.0.0.1", self.port)).is_ok() {
                return;
            }
            assert!(Instant::now() < deadline, "runtime never became ready");
            std::thread::sleep(Duration::from_millis(50));
        }
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
    let rt = Runtime::spawn(None);
    let health = rt.health();
    let log = rt.log_text();

    assert_eq!(health["status"], "ungoverned", "{health}");
    assert_eq!(health["governance"]["state"], "ungoverned");
    assert_eq!(health["governance"]["local_rule_count"], 0);
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
    assert!(
        log.contains("ALLOWED"),
        "startup must say every call is allowed:\n{log}"
    );
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
    let rt = Runtime::spawn(Some(
        "[[rules]]\nname = \"block-exfil\"\nblocked_actions = [\"send_email\"]\n",
    ));
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
