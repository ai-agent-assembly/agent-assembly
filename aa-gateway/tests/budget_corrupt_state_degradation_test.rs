//! AAASM-5647 — a corrupt budget state file must degrade the gateway loudly
//! at boot, not silently reset spend to zero.
//!
//! Boots the real `serve_tcp` entrypoint (the function `aasm-gateway` itself
//! calls) with `$HOME` redirected to a temp directory containing a corrupt
//! `.aa/budget.json`, and asserts a `LayerDegradation` event is observable on
//! the broadcast channel `serve_tcp` was handed — not just a `tracing::warn!`
//! line. `AA_AUDIT_DIR` is set explicitly (not left to default from the
//! redirected `$HOME`) so a boot failure on the audit path can't be mistaken
//! for the budget path being unfixed.
//!
//! # Process isolation
//!
//! This file sets `HOME` and `AA_AUDIT_DIR` and boots a server that writes
//! under them. It therefore contains exactly one test, and that test must be
//! the only thing in its process — which is what `cargo nextest`, this
//! repository's harness, guarantees.

use std::io::Write;
use std::sync::Arc;
use std::time::Duration;

use aa_gateway::registry::AgentRegistry;
use aa_runtime::pipeline::PipelineEvent;

#[tokio::test]
async fn corrupt_budget_state_degrades_the_booted_gateway() {
    let dir = tempfile::tempdir().expect("temp dir");
    std::env::set_var("HOME", dir.path());
    std::env::set_var("AA_AUDIT_DIR", dir.path().join("audit"));

    let budget_dir = dir.path().join(".aa");
    std::fs::create_dir_all(&budget_dir).unwrap();
    std::fs::write(budget_dir.join("budget.json"), b"NOT VALID JSON {{{").unwrap();

    let mut policy = tempfile::NamedTempFile::new().unwrap();
    writeln!(policy, "version: \"1\"").unwrap();
    policy.flush().unwrap();
    let policy_path = policy.path().to_path_buf();

    let registry = Arc::new(AgentRegistry::new());
    let queue = aa_runtime::approval::ApprovalQueue::new();
    let (alert_tx, _alert_rx) = tokio::sync::broadcast::channel(64);
    let (degradation_tx, mut degradation_rx) = tokio::sync::broadcast::channel::<PipelineEvent>(16);

    let probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = probe.local_addr().unwrap();
    drop(probe);

    let serve = tokio::spawn(async move {
        let _policy = policy;
        aa_gateway::server::serve_tcp(
            &policy_path,
            &addr.to_string(),
            registry,
            queue,
            alert_tx,
            degradation_tx,
            None,
        )
        .await
        .map_err(|e| e.to_string())
    });

    // Boot succeeded — otherwise "no degradation event within the timeout"
    // would be indistinguishable from the budget path being unfixed.
    connect(addr).await;
    assert!(!serve.is_finished(), "the gateway exited instead of booting degraded");

    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        match degradation_rx.try_recv() {
            Ok(PipelineEvent::LayerDegradation(info)) if info.layer == "gateway/budget" => {
                assert!(info.reason.starts_with("planned="), "reason: {}", info.reason);
                break;
            }
            Ok(_) => continue,
            Err(_) if std::time::Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            Err(e) => panic!("no gateway/budget degradation event within the timeout: {e}"),
        }
    }

    serve.abort();
}

async fn connect(addr: std::net::SocketAddr) -> tonic::transport::Channel {
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    loop {
        match tonic::transport::Channel::from_shared(format!("http://{addr}"))
            .unwrap()
            .connect()
            .await
        {
            Ok(channel) => return channel,
            Err(e) if std::time::Instant::now() < deadline => {
                let _ = e;
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            Err(e) => panic!("the booted gateway never accepted a connection: {e}"),
        }
    }
}
