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

/// A lease id the record's run issues for `domain`: the documented
/// `{subject}:{digest12}:{run_id}:{issued_at}:{domain}` form (AAASM-6386
/// made `revoke` refuse ids that are not of this shape).
fn lease_id(home: &Path, state: &Path, domain: &str) -> String {
    let v = status_json(home, state);
    format!(
        "{}:{}:{}:{}:{domain}",
        v["subject"].as_str().unwrap(),
        &v["policy_digest"].as_str().unwrap()[..12],
        v["run_id"].as_str().unwrap(),
        v["issued_at"]
    )
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
        .args([
            "lease",
            "revoke",
            "--lease-id",
            &lease_id(d.path(), &p, "filesystem_write"),
            "--state",
        ])
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
    let (a, b) = (lease_id(d.path(), &p, "a"), lease_id(d.path(), &p, "b"));
    let run = |ids: &[&str]| {
        aasm(d.path())
            .args(["lease", "revoke", "--state"])
            .arg(&p)
            .arg("--lease-id")
            .args(ids)
            .output()
            .unwrap()
    };
    let out = run(&[b.as_str(), a.as_str()]);
    assert!(out.status.success());
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "generation 2");
    let out = run(&[a.as_str()]);
    assert!(out.status.success());
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "generation 2");
    assert_eq!(status_json(d.path(), &p)["revoked"], serde_json::json!([a, b]));
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
    let ids: Vec<String> = (0..PROCS)
        .map(|i| lease_id(d.path(), &p, &format!("id-{i:02}")))
        .collect();
    let children: Vec<_> = ids
        .iter()
        .map(|id| {
            aasm(d.path())
                .args(["lease", "revoke", "--state"])
                .arg(&p)
                .args(["--lease-id", id])
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

/// A server answering every request with the raw HTTP response `resp`.
fn fake_http(resp: String) -> std::net::SocketAddr {
    use std::io::{Read, Write};
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    std::thread::spawn(move || {
        for s in l.incoming() {
            let Ok(mut s) = s else { break };
            let mut buf = [0u8; 1024];
            let _ = s.read(&mut buf);
            let _ = s.write_all(resp.as_bytes());
        }
    });
    addr
}

fn json_response(body: &str) -> String {
    format!(
        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    )
}

fn fake_health(body: &str) -> String {
    format!("http://{}", fake_http(json_response(body)))
}

fn lg(run_id: &str, generation: u64, state: &str) -> String {
    format!(r#"{{"lease_governance":{{"run_id":"{run_id}","generation":{generation},"state":"{state}"}}}}"#)
}

/// A dead address standing in for a hostile or misconfigured environment proxy.
const DEAD_PROXY: &str = "http://127.0.0.1:9";

fn revoke_wait(home: &Path, state: &Path, url: &str, timeout: &str) -> Output {
    // The proxy variables are *set to a dead address*, not removed: if `revoke`
    // honoured them the loopback request below could never succeed.
    aasm(home)
        .env("HTTP_PROXY", DEAD_PROXY)
        .env("HTTPS_PROXY", DEAD_PROXY)
        .env("ALL_PROXY", DEAD_PROXY)
        .env("http_proxy", DEAD_PROXY)
        .env("https_proxy", DEAD_PROXY)
        .env("all_proxy", DEAD_PROXY)
        .env_remove("NO_PROXY")
        .env_remove("no_proxy")
        .args([
            "lease",
            "revoke",
            "--lease-id",
            &lease_id(home, state, "filesystem_write"),
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

fn run_id(home: &Path, state: &Path) -> String {
    status_json(home, state)["run_id"].as_str().unwrap().to_string()
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

#[test]
fn revoke_wait_health_returns_once_the_runtime_reports_this_run_at_the_generation() {
    let (d, p) = state_dir();
    assert!(init(d.path(), &p, &[]).status.success());
    let url = fake_health(&lg(&run_id(d.path(), &p), 2, "governed"));
    let out = revoke_wait(d.path(), &p, &url, "5");
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(String::from_utf8_lossy(&out.stdout).contains("runtime applied generation 2"));
}

#[test]
fn revoke_wait_health_ignores_a_different_runs_runtime_even_at_a_high_generation() {
    let (d, p) = state_dir();
    assert!(init(d.path(), &p, &[]).status.success());
    let url = fake_health(&lg(&"0".repeat(32), 99, "governed"));
    let out = revoke_wait(d.path(), &p, &url, "1");
    assert_eq!(out.status.code(), Some(1));
    assert!(stderr(&out).contains("different run"), "{}", stderr(&out));
}

#[test]
fn revoke_wait_health_fails_when_the_runtime_never_catches_up() {
    let (d, p) = state_dir();
    assert!(init(d.path(), &p, &[]).status.success());
    let url = fake_health(&lg(&run_id(d.path(), &p), 1, "governed"));
    let out = revoke_wait(d.path(), &p, &url, "1");
    assert_eq!(out.status.code(), Some(1));
    assert!(stderr(&out).contains("did not acknowledge"));
    // The revocation itself is recorded regardless.
    assert_eq!(status_json(d.path(), &p)["generation"], 2);
}

#[test]
fn revoke_wait_health_fails_against_an_ungoverned_runtime() {
    let (d, p) = state_dir();
    assert!(init(d.path(), &p, &[]).status.success());
    let url = fake_health(r#"{"status":"healthy"}"#);
    let out = revoke_wait(d.path(), &p, &url, "2");
    assert_eq!(out.status.code(), Some(1));
    assert!(stderr(&out).contains("not in governed lease mode"));
}

#[test]
fn a_denied_all_runtime_acknowledges_with_its_own_exit_status() {
    let (d, p) = state_dir();
    assert!(init(d.path(), &p, &[]).status.success());
    let url = fake_health(&lg(&run_id(d.path(), &p), 3, "denied_all"));
    let out = revoke_wait(d.path(), &p, &url, "5");
    assert_eq!(out.status.code(), Some(3), "{}", stderr(&out));
    assert!(stderr(&out).contains("denying all requests"));
    assert_eq!(status_json(d.path(), &p)["generation"], 2, "the revocation is recorded");
}

#[test]
fn credentials_in_the_health_url_never_reach_the_output() {
    let (d, p) = state_dir();
    assert!(init(d.path(), &p, &[]).status.success());
    // Three failure shapes, each of which prints the URL or a transport error.
    let ungoverned = fake_http(json_response(r#"{"status":"healthy"}"#));
    let closed = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap()
    };
    let stale = fake_http(json_response(&lg(&run_id(d.path(), &p), 1, "governed")));
    for addr in [ungoverned, closed, stale] {
        let url = format!("http://alice:s3cr3t-token@{addr}/base?token=also-secret#frag");
        let out = revoke_wait(d.path(), &p, &url, "1");
        assert!(!out.status.success());
        let all = format!("{}{}", stderr(&out), String::from_utf8_lossy(&out.stdout));
        for leak in ["alice", "s3cr3t-token", "also-secret", "frag"] {
            assert!(!all.contains(leak), "{leak:?} leaked into: {all}");
        }
        assert!(
            all.contains("127.0.0.1"),
            "the redacted URL should still say where: {all}"
        );
    }
}

#[test]
fn a_redirect_is_not_followed() {
    let (d, p) = state_dir();
    assert!(init(d.path(), &p, &[]).status.success());
    let good = fake_health(&lg(&run_id(d.path(), &p), 2, "governed"));
    let redirector = fake_http(format!(
        "HTTP/1.1 302 Found\r\nlocation: {good}/health\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
    ));
    let out = revoke_wait(d.path(), &p, &format!("http://{redirector}"), "1");
    assert!(!out.status.success(), "a redirected acknowledgement must not count");
}

#[test]
fn an_enormous_wait_timeout_is_clamped_not_a_panic() {
    let (d, p) = state_dir();
    assert!(init(d.path(), &p, &[]).status.success());
    let url = fake_health(&lg(&run_id(d.path(), &p), 2, "governed"));
    // An acknowledging runtime must return at once. A watchdog turns "waited the
    // clamped hour because it could not reach the runtime" into a failure.
    let (tx, rx) = std::sync::mpsc::channel();
    let (home, state) = (d.path().to_path_buf(), p.clone());
    std::thread::spawn(move || {
        let _ = tx.send(revoke_wait(&home, &state, &url, &u64::MAX.to_string()));
    });
    let out = rx
        .recv_timeout(std::time::Duration::from_secs(30))
        .expect("revoke did not return within 30s of an immediate acknowledgement");
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(!stderr(&out).contains("panicked"));
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

/// AAASM-6385: `init` prints the exact command that starts a governed runtime for
/// the record, with the values it just validated (and quoting a path that needs it).
#[test]
fn init_prints_the_runtime_start_recipe_for_this_record() {
    let (d, _) = state_dir();
    let spaced = d.path().join("my state");
    std::fs::create_dir(&spaced).unwrap();
    std::fs::set_permissions(&spaced, std::fs::Permissions::from_mode(0o700)).unwrap();
    let p = spaced.join("lease.json");
    let out = init(d.path(), &p, &[]);
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains("AA_AGENT_ID=agent-1"), "{stdout}");
    assert!(stdout.contains("AA_METRICS_ADDR=127.0.0.1:"), "{stdout}");
    assert!(stdout.contains("AA_LEASE_POLICY="), "{stdout}");
    let canonical = std::fs::canonicalize(&p).unwrap();
    assert!(
        stdout.contains(&format!("AA_LEASE_STATE='{}'", canonical.display())),
        "{stdout}"
    );
    assert!(stdout.contains("aa-runtime"), "{stdout}");
}

/// A digest-only init cannot know the policy file; the recipe must stay a runnable
/// command (a `<placeholder>` would be a shell redirect).
#[test]
fn a_digest_only_init_recipe_has_no_shell_redirect() {
    let (d, p) = state_dir();
    let out = init(d.path(), &p, &[]);
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains("# set POLICY_FILE"), "{stdout}");
    assert!(stdout.contains("AA_LEASE_POLICY=\"$POLICY_FILE\""), "{stdout}");
    let command: String = stdout.lines().filter(|l| l.starts_with("  ")).collect();
    assert!(!command.contains('<') && !command.contains('>'), "{command}");
}

/// AAASM-6386: an id that no run issued used to be stored as "revoked" and
/// bump the generation while revoking nothing, which reads as success.
#[test]
fn revoke_refuses_an_id_this_run_never_issued_without_bumping_the_generation() {
    let (d, p) = state_dir();
    assert!(init(d.path(), &p, &[]).status.success());
    let before = std::fs::read(&p).unwrap();
    for bad in [
        "notreal".to_string(),
        // Right shape, another run's id space.
        format!("agent-1:0123456789ab:{}:5:filesystem_write", "0".repeat(32)),
        // This run's prefix but not a domain word.
        format!("{}Not A Domain", lease_id(d.path(), &p, "")),
    ] {
        let out = aasm(d.path())
            .args(["lease", "revoke", "--state"])
            .arg(&p)
            .args(["--lease-id", &bad])
            .output()
            .unwrap();
        assert!(!out.status.success(), "{bad:?} must be refused");
        let err = stderr(&out);
        assert!(err.contains("not a lease id of this run"), "{err}");
        assert!(
            err.contains(&run_id(d.path(), &p)),
            "the message should show the expected form: {err}"
        );
    }
    assert_eq!(std::fs::read(&p).unwrap(), before, "the record must be untouched");
    assert_eq!(status_json(d.path(), &p)["generation"], 1);
}

#[test]
fn revoke_refuses_the_whole_call_when_any_id_is_unknown() {
    let (d, p) = state_dir();
    assert!(init(d.path(), &p, &[]).status.success());
    let good = lease_id(d.path(), &p, "filesystem_write");
    let out = aasm(d.path())
        .args(["lease", "revoke", "--state"])
        .arg(&p)
        .args(["--lease-id", &good, "notreal"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    let v = status_json(d.path(), &p);
    assert_eq!(
        v["revoked"],
        serde_json::json!([]),
        "no id may be recorded when one is refused"
    );
    assert_eq!(v["generation"], 1);
}

#[test]
fn init_into_a_missing_directory_names_the_path_and_says_it_must_exist() {
    let (d, _) = state_dir();
    let missing = d.path().join("no-such-dir").join("l.json");
    let out = init(d.path(), &missing, &[]);
    assert!(!out.status.success());
    let err = stderr(&out);
    assert!(
        err.contains(&d.path().join("no-such-dir").display().to_string()),
        "{err}"
    );
    assert!(err.contains("must exist"), "{err}");
    assert!(
        !d.path().join("no-such-dir").exists(),
        "init must not create the directory"
    );
}

#[test]
fn init_over_an_existing_record_points_at_force() {
    let (d, p) = state_dir();
    assert!(init(d.path(), &p, &[]).status.success());
    let err = stderr(&init(d.path(), &p, &[]));
    assert!(err.contains("--force"), "{err}");
}

#[test]
fn a_missing_record_error_names_the_command_that_creates_it() {
    let (d, p) = state_dir();
    for args in [["lease", "status", "--state"], ["lease", "revoke", "--state"]] {
        let mut c = aasm(d.path());
        c.args(args).arg(&p);
        if args[1] == "revoke" {
            c.args(["--lease-id", "x"]);
        }
        let err = stderr(&c.output().unwrap());
        assert!(err.contains("aasm lease init"), "{err}");
        assert!(err.contains(&p.display().to_string()), "{err}");
    }
}
