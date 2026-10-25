//! A bare `aasm status` follows the gateway `aasm start` left running
//! (AAASM-6385): it used to query `http://localhost:8080`, which nothing the
//! CLI starts listens on, while `aasm start` serves on 7391.
#![cfg(unix)]

use std::path::Path;
use std::process::Command;

use assert_cmd::prelude::*;

fn status_json_gateway_url(home: &Path, extra: &[&str]) -> String {
    let out = Command::cargo_bin("aasm")
        .expect("aasm binary")
        .env("HOME", home)
        .env_remove("AASM_API_URL")
        .env_remove("AA_API_URL")
        .args(["status", "--json"])
        .args(extra)
        .output()
        .unwrap();
    // The gateway is deliberately unreachable here (exit 1); the JSON header
    // still names the URL that was queried, which is what is under test.
    let v: serde_json::Value =
        serde_json::from_slice(&out.stdout).unwrap_or_else(|e| panic!("{e}: {}", String::from_utf8_lossy(&out.stdout)));
    v["gateway_url"].as_str().unwrap().to_string()
}

fn record(home: &Path, pid: u32, url: &str) {
    let dir = home.join(".aasm");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("gateway.pid"), format!("{pid}\n")).unwrap();
    std::fs::write(dir.join("gateway.url"), format!("{url}\n")).unwrap();
}

#[test]
fn with_no_gateway_running_the_default_is_the_port_start_uses() {
    let home = tempfile::tempdir().unwrap();
    assert_eq!(status_json_gateway_url(home.path(), &[]), "http://localhost:7391");
}

#[test]
fn a_gateway_started_on_another_port_is_followed() {
    let home = tempfile::tempdir().unwrap();
    // This test process stands in for the running gateway: only its liveness matters.
    record(home.path(), std::process::id(), "http://localhost:9123");
    assert_eq!(status_json_gateway_url(home.path(), &[]), "http://localhost:9123");
}

#[test]
fn a_stale_record_from_a_dead_gateway_is_not_followed() {
    let home = tempfile::tempdir().unwrap();
    record(home.path(), u32::MAX - 1, "http://localhost:9123");
    assert_eq!(status_json_gateway_url(home.path(), &[]), "http://localhost:7391");
}

#[test]
fn an_explicit_api_url_still_wins() {
    let home = tempfile::tempdir().unwrap();
    record(home.path(), std::process::id(), "http://localhost:9123");
    assert_eq!(
        status_json_gateway_url(home.path(), &["--api-url", "http://localhost:5555"]),
        "http://localhost:5555"
    );
}
