//! End-to-end tests for `aasm lease` against the real binary and a real
//! state directory (AAASM-6259).
#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use assert_cmd::prelude::*;

const DIGEST: &str = "0123456789abcdef0123456789abcdef";

fn aasm(home: &Path) -> Command {
    let mut c = Command::cargo_bin("aasm").expect("aasm binary");
    // Isolate from the developer's own config and from an inherited AA_LEASE_STATE.
    c.env("HOME", home).env_remove("AA_LEASE_STATE");
    c
}

fn state_dir() -> (tempfile::TempDir, PathBuf) {
    let d = tempfile::tempdir().unwrap();
    std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let p = d.path().join("lease.json");
    (d, p)
}

fn init(home: &Path, state: &Path, extra: &[&str]) -> Output {
    aasm(home)
        .args([
            "lease",
            "init",
            "--subject",
            "agent-1",
            "--policy-digest",
            DIGEST,
            "--state",
        ])
        .arg(state)
        .args(extra)
        .output()
        .unwrap()
}

fn status_json(home: &Path, state: &Path) -> serde_json::Value {
    let out = aasm(home)
        .args(["lease", "status", "--state"])
        .arg(state)
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    serde_json::from_slice(&out.stdout).unwrap()
}

#[test]
fn init_then_status_reports_the_record_with_mode_0600() {
    let (d, p) = state_dir();
    let out = init(d.path(), &p, &[]);
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains("agent-1:0123456789ab:"), "{stdout}");

    let v = status_json(d.path(), &p);
    assert_eq!(v["version"], 1);
    assert_eq!(v["subject"], "agent-1");
    assert_eq!(v["policy_digest"], DIGEST);
    assert_eq!(v["generation"], 1);
    assert_eq!(v["revoked"], serde_json::json!([]));
    assert_eq!(v["run_id"].as_str().unwrap().len(), 32);
    assert!(stdout.contains(v["run_id"].as_str().unwrap()), "{stdout}");
    assert_eq!(std::fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o600);
}

#[test]
fn init_without_force_refuses_an_existing_record_and_leaves_it_intact() {
    let (d, p) = state_dir();
    assert!(init(d.path(), &p, &[]).status.success());
    let before = std::fs::read(&p).unwrap();
    let out = init(d.path(), &p, &[]);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("already exists"));
    assert_eq!(std::fs::read(&p).unwrap(), before);
}

#[test]
fn init_force_starts_a_new_run_and_retires_earlier_revocations() {
    let (d, p) = state_dir();
    assert!(init(d.path(), &p, &[]).status.success());
    let first = status_json(d.path(), &p);
    let revoke = aasm(d.path())
        .args(["lease", "revoke", "--lease-id", "x", "--state"])
        .arg(&p)
        .output()
        .unwrap();
    assert!(revoke.status.success());
    assert_eq!(status_json(d.path(), &p)["generation"], 2);

    assert!(init(d.path(), &p, &["--force"]).status.success());
    let second = status_json(d.path(), &p);
    assert_eq!(second["generation"], 1);
    assert_eq!(second["revoked"], serde_json::json!([]));
    assert_ne!(second["run_id"], first["run_id"], "a new run must mint a new id space");
}

#[test]
fn revoke_adds_ids_idempotently_and_prints_the_generation() {
    let (d, p) = state_dir();
    assert!(init(d.path(), &p, &[]).status.success());
    let run = |ids: &[&str]| {
        aasm(d.path())
            .args(["lease", "revoke", "--state"])
            .arg(&p)
            .arg("--lease-id")
            .args(ids)
            .output()
            .unwrap()
    };
    let out = run(&["b", "a"]);
    assert!(out.status.success());
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "generation 2");
    let out = run(&["a"]);
    assert!(out.status.success());
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "generation 2");
    assert_eq!(status_json(d.path(), &p)["revoked"], serde_json::json!(["a", "b"]));
}

#[test]
fn revoke_on_a_missing_record_fails_and_creates_nothing() {
    let (d, p) = state_dir();
    let out = aasm(d.path())
        .args(["lease", "revoke", "--lease-id", "x", "--state"])
        .arg(&p)
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("not found"));
    assert_eq!(std::fs::read_dir(d.path()).unwrap().count(), 0);
}

#[test]
fn status_and_revoke_fail_closed_on_a_corrupt_record() {
    let (d, p) = state_dir();
    assert!(init(d.path(), &p, &[]).status.success());
    std::fs::write(&p, b"{\"version\":1").unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
    let st = aasm(d.path())
        .args(["lease", "status", "--state"])
        .arg(&p)
        .output()
        .unwrap();
    assert!(!st.status.success());
    assert!(String::from_utf8_lossy(&st.stderr).contains("corrupt"));
    let rv = aasm(d.path())
        .args(["lease", "revoke", "--lease-id", "x", "--state"])
        .arg(&p)
        .output()
        .unwrap();
    assert!(!rv.status.success());
    assert_eq!(std::fs::read(&p).unwrap(), b"{\"version\":1");
}

#[test]
fn init_rejects_a_bad_digest_and_creates_nothing() {
    let (d, p) = state_dir();
    let out = aasm(d.path())
        .args([
            "lease",
            "init",
            "--subject",
            "a",
            "--policy-digest",
            "nothex",
            "--state",
        ])
        .arg(&p)
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert_eq!(std::fs::read_dir(d.path()).unwrap().count(), 0);
}

#[test]
fn concurrent_revoke_processes_lose_no_id() {
    const PROCS: usize = 12;
    let (d, p) = state_dir();
    assert!(init(d.path(), &p, &[]).status.success());
    let children: Vec<_> = (0..PROCS)
        .map(|i| {
            aasm(d.path())
                .args(["lease", "revoke", "--state"])
                .arg(&p)
                .args(["--lease-id", &format!("id-{i:02}")])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .unwrap()
        })
        .collect();
    for c in children {
        let out = c.wait_with_output().unwrap();
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    }
    let v = status_json(d.path(), &p);
    assert_eq!(v["revoked"].as_array().unwrap().len(), PROCS, "an id was lost");
    assert_eq!(v["generation"], 1 + PROCS as u64);
}

#[test]
fn init_with_did_key_subject_prints_an_encoded_prefix() {
    let (d, p) = state_dir();
    let out = aasm(d.path())
        .args([
            "lease",
            "init",
            "--subject",
            "did:key:z6MkExample",
            "--policy-digest",
            DIGEST,
            "--state",
        ])
        .arg(&p)
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    assert!(String::from_utf8_lossy(&out.stdout).contains("did%3Akey%3Az6MkExample:0123456789ab:"));
    assert_eq!(status_json(d.path(), &p)["subject"], "did:key:z6MkExample");
}

/// A one-shot-per-request HTTP server answering `GET /health` with `body`.
fn fake_health(body: &'static str) -> String {
    use std::io::{Read, Write};
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    std::thread::spawn(move || {
        for s in l.incoming() {
            let Ok(mut s) = s else { break };
            let mut buf = [0u8; 1024];
            let _ = s.read(&mut buf);
            let resp = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = s.write_all(resp.as_bytes());
        }
    });
    format!("http://{addr}")
}

fn revoke_wait(home: &Path, state: &Path, url: &str, timeout: &str) -> Output {
    aasm(home)
        .env("NO_PROXY", "127.0.0.1")
        .env_remove("HTTPS_PROXY")
        .env_remove("HTTP_PROXY")
        .env_remove("ALL_PROXY")
        .args([
            "lease",
            "revoke",
            "--lease-id",
            "x",
            "--wait-health",
            url,
            "--wait-timeout-secs",
            timeout,
            "--state",
        ])
        .arg(state)
        .output()
        .unwrap()
}

#[test]
fn revoke_wait_health_returns_once_the_runtime_reports_the_generation() {
    let (d, p) = state_dir();
    assert!(init(d.path(), &p, &[]).status.success());
    let url = fake_health(r#"{"lease_governance":{"generation":2,"state":"governed"}}"#);
    let out = revoke_wait(d.path(), &p, &url, "5");
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    assert!(String::from_utf8_lossy(&out.stdout).contains("runtime applied generation 2"));
}

#[test]
fn revoke_wait_health_fails_when_the_runtime_never_catches_up() {
    let (d, p) = state_dir();
    assert!(init(d.path(), &p, &[]).status.success());
    let url = fake_health(r#"{"lease_governance":{"generation":1,"state":"governed"}}"#);
    let out = revoke_wait(d.path(), &p, &url, "1");
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("did not acknowledge"));
    // The revocation itself is recorded regardless.
    assert_eq!(status_json(d.path(), &p)["generation"], 2);
}

#[test]
fn revoke_wait_health_fails_against_an_ungoverned_runtime() {
    let (d, p) = state_dir();
    assert!(init(d.path(), &p, &[]).status.success());
    let url = fake_health(r#"{"status":"healthy"}"#);
    let out = revoke_wait(d.path(), &p, &url, "2");
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("not in governed lease mode"));
}

#[test]
fn init_computes_the_digest_from_a_policy_file() {
    let (d, p) = state_dir();
    let pol = d.path().join("policy.yaml");
    std::fs::write(&pol, "tools:\n  calc: { allow: true, capabilities: [none] }\n").unwrap();
    let out = aasm(d.path())
        .args(["lease", "init", "--subject", "agent-1", "--policy"])
        .arg(&pol)
        .arg("--state")
        .arg(&p)
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let digest = status_json(d.path(), &p)["policy_digest"].as_str().unwrap().to_string();
    assert_eq!(digest.len(), 64);
    assert!(!digest.starts_with("sha256:"));
}
