//! Integration tests for `aa_gateway::remote_mode::start_remote_with_handle`
//! exercised over plain HTTP — no TLS material required.
//!
//! Both tests bind to `127.0.0.1:0` so they can run in parallel without
//! contending for a fixed port. The `axum_server::Handle::listening()`
//! call gives us the actual bound port back so the reqwest probe knows
//! where to connect.

use std::time::Duration;

use aa_core::config::RemoteModeConfig;
use axum_server::Handle;

/// AAASM-1709 AC #1 — `start_remote_with_handle` binds, serves
/// `/healthz`, and the response carries the remote-mode JSON.
#[tokio::test]
async fn start_remote_serves_healthz_over_http() {
    let cfg = RemoteModeConfig {
        listen_addr: "127.0.0.1:0".parse().expect("listen_addr"),
        tls: None,
        ..Default::default()
    };

    let handle = Handle::new();
    let probe_handle = handle.clone();
    let shutdown_handle = handle.clone();

    let server = tokio::spawn(async move { aa_gateway::remote_mode::start_remote_with_handle(&cfg, handle).await });

    let addr = probe_handle.listening().await.expect("server bound");
    let body: serde_json::Value = reqwest::get(format!("http://{addr}/healthz"))
        .await
        .expect("GET /healthz")
        .json()
        .await
        .expect("parse JSON body");

    assert_eq!(body["mode"], "remote", "mode label");
    assert_eq!(body["storage"], "memory", "storage label");

    shutdown_handle.graceful_shutdown(Some(Duration::from_secs(5)));
    server.await.expect("server task").expect("server result");
}

/// AAASM-1709 AC #4 — graceful_shutdown drains and returns Ok within
/// the configured budget. The test asserts the bind/serve future does
/// not get stuck after the handle is triggered; if the drain exceeded
/// the budget the test would time out at the outer `tokio::time::timeout`.
#[tokio::test]
async fn graceful_shutdown_drains_cleanly() {
    let cfg = RemoteModeConfig {
        listen_addr: "127.0.0.1:0".parse().expect("listen_addr"),
        tls: None,
        ..Default::default()
    };

    let handle = Handle::new();
    let ready_handle = handle.clone();
    let shutdown_handle = handle.clone();

    let server = tokio::spawn(async move { aa_gateway::remote_mode::start_remote_with_handle(&cfg, handle).await });

    // Wait until the listener is actually bound before triggering shutdown
    // — otherwise the test races the bind step and `graceful_shutdown` is
    // a no-op against a not-yet-listening server.
    let _addr = ready_handle.listening().await.expect("server bound");

    shutdown_handle.graceful_shutdown(Some(Duration::from_secs(5)));

    // The bind/serve future resolves to `Ok(())` once the graceful-shutdown
    // drain completes; failure to exit within 10 s here would mean the
    // drain logic deadlocked.
    tokio::time::timeout(Duration::from_secs(10), server)
        .await
        .expect("server exited within timeout budget")
        .expect("server task joined")
        .expect("serve returned Ok");
}
