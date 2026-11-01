//! AAASM-6430: `aasm policy rollback` must not claim success when the running
//! server could not be told. It used to write a snapshot to the local history
//! store alone, print "Rolled back successfully.", and leave the active policy
//! untouched.
#![cfg(unix)]

use std::process::Command;

use aa_gateway::policy::history::{FsHistoryStore, HistoryConfig, PolicyHistoryStore};
use assert_cmd::prelude::*;

const POLICY: &str = "apiVersion: agent-assembly/v1\nkind: Policy\nmetadata:\n  name: p\n  version: \"1.0.0\"\n\
spec:\n  budget:\n    daily_limit_usd: 10.0\n";

#[tokio::test]
async fn rollback_with_no_server_fails_and_writes_nothing() {
    let tmp = tempfile::tempdir().unwrap();
    let data = tmp.path().join("data");
    let store = FsHistoryStore::new(HistoryConfig {
        history_dir: data.join("policy-history"),
        max_versions: 50,
    });
    let saved = store.save(POLICY, Some("test")).await.unwrap();

    // A loopback port nothing listens on: bind, note the port, drop.
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();

    let out = Command::cargo_bin("aasm")
        .unwrap()
        .env("HOME", tmp.path())
        .env("AA_DATA_DIR", &data)
        .env_remove("AASM_API_URL")
        .env_remove("AA_API_URL")
        .env_remove("AASM_API_KEY")
        .args(["--api-url", &format!("http://127.0.0.1:{port}")])
        .args(["policy", "rollback", &saved.sha256[..12]])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "must fail: {stdout}{stderr}");
    assert!(!stdout.contains("Rolled back successfully"), "false success: {stdout}");
    assert!(stderr.contains("not confirmed to have changed"), "{stderr}");
    assert_eq!(
        store.list(10).await.unwrap().len(),
        1,
        "no history entry may be written for a rollback that was not applied"
    );
}
