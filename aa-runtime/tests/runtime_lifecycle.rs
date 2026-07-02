//! End-to-end lifecycle test for [`aa_runtime::run`] (AAASM-3805).
//!
//! `run()` is the runtime's top-level orchestrator: it installs the metrics
//! recorder, loads policy, detects layers, binds the IPC socket, spawns the
//! pipeline / correlation / health subsystems, and then blocks in
//! [`aa_runtime::lifecycle::wait_for_shutdown_signal`] until SIGTERM/SIGINT.
//! None of the existing unit tests drive this path because it depends on a real
//! OS shutdown signal.
//!
//! This test exercises the whole startup→serve→graceful-shutdown cycle in a
//! single process. It is isolated in its own integration-test binary so that the
//! process-global Prometheus recorder `run()` installs is never installed twice,
//! and so the self-directed SIGTERM only affects this test's process (nextest
//! runs each test binary as a separate process).

use std::path::PathBuf;
use std::time::Duration;

use aa_runtime::config::RuntimeConfig;
use aa_runtime::pipeline::enforcement::DEFAULT_MAX_FIELD_BYTES;

/// A runtime config that stands the agent up with every optional subsystem
/// (gateway forwarding, NATS audit, eBPF, policy file) disabled, an ephemeral
/// health port, and a uniquely-named IPC socket so the test never collides with
/// a real runtime or a concurrent test process.
fn lifecycle_config(agent_id: &str) -> RuntimeConfig {
    RuntimeConfig {
        agent_id: agent_id.to_string(),
        agent_team_id: String::new(),
        agent_org_id: String::new(),
        worker_threads: 0,
        // Generous enough that a clean drain never trips the timeout branch.
        shutdown_timeout_secs: 10,
        ipc_max_connections: 8,
        pipeline_input_buffer: 1_000,
        pipeline_batch_size: 16,
        pipeline_flush_interval_ms: 50,
        pipeline_broadcast_capacity: 256,
        // Port 0 → the OS assigns an ephemeral port, so the health server bind
        // never races another test or a real process on a fixed port.
        metrics_addr: "127.0.0.1:0".to_string(),
        // No policy file → enforcement disabled (empty rules), agent still runs.
        policy_path: None,
        // No gateway → policy evaluated locally, op-control kill switch inactive.
        gateway_endpoint: None,
        correlation_window_ms: 500,
        correlation_interval_ms: 50,
        // No NATS config → audit publisher disabled.
        nats_config_path: None,
        audit_buffer_path: std::env::temp_dir().join(format!("aa-audit-buffer-{agent_id}.db")),
        enforcement_max_field_bytes: DEFAULT_MAX_FIELD_BYTES,
        gateway_fail_closed: true,
        gateway_timeout_ms: aa_runtime::config::DEFAULT_GATEWAY_TIMEOUT_MS,
    }
}

/// `run()` must start every subsystem, serve, and then drain to completion when
/// it receives SIGTERM — proving the structured-concurrency shutdown path works
/// end to end and that the IPC socket is cleaned up on exit.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn run_starts_subsystems_and_shuts_down_on_sigterm() {
    let agent_id = format!("lifecycle-test-{}", std::process::id());
    let socket_path = PathBuf::from(format!("/tmp/aa-runtime-{agent_id}.sock"));
    // Defensive: clear any leftover socket from a previously aborted run.
    let _ = std::fs::remove_file(&socket_path);

    let config = lifecycle_config(&agent_id);
    let runtime = tokio::spawn(aa_runtime::run(config));

    // The IPC socket is created synchronously by `IpcServer::bind` inside `run()`,
    // shortly before it parks on the shutdown signal. Its appearance is the
    // observable proof that startup reached the serve phase.
    let mut bound = false;
    for _ in 0..200 {
        if socket_path.exists() {
            bound = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(bound, "runtime never bound its IPC socket — startup did not complete");

    // Small margin so `wait_for_shutdown_signal` has installed its SIGTERM
    // handler before we raise the signal (otherwise the default disposition
    // would terminate the process). Everything between the IPC bind and the
    // signal wait is non-blocking spawns, so this is comfortably sufficient.
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Deliver the shutdown signal the same way an orchestrator would.
    let rc = unsafe { libc::raise(libc::SIGTERM) };
    assert_eq!(rc, 0, "failed to raise SIGTERM");

    // `run()` must return after a graceful drain — not hang and not be killed.
    let result = tokio::time::timeout(Duration::from_secs(15), runtime).await;
    let join = result.expect("run() did not return within 15s of SIGTERM — shutdown hung");
    join.expect("run() task panicked during shutdown");

    // Graceful shutdown removes the IPC socket file.
    assert!(
        !socket_path.exists(),
        "IPC socket should be cleaned up after graceful shutdown"
    );
}
