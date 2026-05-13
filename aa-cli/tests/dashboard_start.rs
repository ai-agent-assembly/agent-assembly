use std::net::TcpListener;
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

/// Spawn `aasm dashboard start --port <port>` and wait up to 5s for it to
/// answer HTTP requests. Returns the child process so the caller can kill it.
fn spawn_dashboard(port: u16) -> std::process::Child {
    Command::new(env!("CARGO_BIN_EXE_aasm"))
        .args(["dashboard", "start", "--port", &port.to_string()])
        .spawn()
        .expect("failed to spawn aasm dashboard start")
}

fn wait_for_http(url: &str, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if reqwest::blocking::get(url)
            .map(|r| r.status().as_u16() < 500)
            .unwrap_or(false)
        {
            return true;
        }
        thread::sleep(Duration::from_millis(100));
    }
    false
}

#[test]
fn dashboard_start_serves_static_files() {
    let port = free_port();
    let url = format!("http://127.0.0.1:{port}/");

    let mut child = spawn_dashboard(port);

    let started = wait_for_http(&url, Duration::from_secs(10));

    child.kill().ok();
    child.wait().ok();

    assert!(started, "dashboard did not become reachable within 10s on port {port}");
}

#[test]
fn dashboard_start_returns_200_for_root() {
    let port = free_port();
    let url = format!("http://127.0.0.1:{port}/");

    let mut child = spawn_dashboard(port);

    let status = {
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut result = None;
        while Instant::now() < deadline {
            if let Ok(resp) = reqwest::blocking::get(&url) {
                result = Some(resp.status().as_u16());
                break;
            }
            thread::sleep(Duration::from_millis(100));
        }
        result
    };

    child.kill().ok();
    child.wait().ok();

    assert_eq!(status, Some(200), "expected HTTP 200 from /");
}
