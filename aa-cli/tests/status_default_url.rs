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

/// A loopback server that answers every request like the aa health endpoint.
fn fake_health() -> String {
    use std::io::{Read, Write};
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    std::thread::spawn(move || {
        for s in l.incoming() {
            let Ok(mut s) = s else { break };
            let mut b = [0u8; 2048];
            let _ = s.read(&mut b);
            let body = r#"{"status":"ok","version":"0.0.0","api_version":"v1","uptime_secs":1}"#;
            let _ = write!(
                s,
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
        }
    });
    format!("http://{addr}")
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
    // This test process stands in for the running gateway process; the fake
    // server stands in for its API.
    let url = fake_health();
    record(home.path(), std::process::id(), &url);
    assert_eq!(status_json_gateway_url(home.path(), &[]), url);
}

#[test]
fn a_stale_record_from_a_dead_gateway_is_not_followed() {
    let home = tempfile::tempdir().unwrap();
    record(home.path(), u32::MAX - 1, "http://localhost:9123");
    assert_eq!(status_json_gateway_url(home.path(), &[]), "http://localhost:7391");
}

/// A recycled PID: the number is alive but nothing at the recorded address
/// answers like the API, so the record is not trusted.
#[test]
fn a_live_pid_whose_recorded_address_does_not_answer_is_not_followed() {
    let home = tempfile::tempdir().unwrap();
    let closed = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        format!("http://{}", l.local_addr().unwrap())
    };
    record(home.path(), std::process::id(), &closed);
    assert_eq!(status_json_gateway_url(home.path(), &[]), "http://localhost:7391");
}

#[test]
fn a_recorded_non_loopback_or_credentialed_url_is_not_followed() {
    for bad in [
        "http://evil.example.com:80",
        "http://user:pw@127.0.0.1:9",
        "https://localhost:9123",
    ] {
        let home = tempfile::tempdir().unwrap();
        record(home.path(), std::process::id(), bad);
        assert_eq!(
            status_json_gateway_url(home.path(), &[]),
            "http://localhost:7391",
            "{bad}"
        );
    }
}

#[test]
fn an_explicit_api_url_still_wins() {
    let home = tempfile::tempdir().unwrap();
    record(home.path(), std::process::id(), &fake_health());
    assert_eq!(
        status_json_gateway_url(home.path(), &["--api-url", "http://localhost:5555"]),
        "http://localhost:5555"
    );
}
