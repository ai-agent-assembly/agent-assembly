//! Tests for the retention cron loop wired into the hardened local entrypoint
//! (AAASM-3383).
//!
//! AAASM-3369 constructed a [`RetentionEngine`] in `AppState::local_hardened`
//! for the on-demand `/api/v1/admin/retention*` handlers but DEFERRED the
//! scheduled background sweep. AAASM-3383 drives that same engine on its
//! configured cron schedule from `run_server` (mirroring the gateway's
//! `spawn_retention_engine` boot pattern).
//!
//! Running the production default (`0 0 3 * * *`, daily 03:00) in a test is
//! impractical, so these tests exercise the wiring contract `run_server` relies
//! on: the hardened state exposes a retention engine that can be started, ticks
//! on its schedule, and shuts down cleanly when its cancellation token fires.

use std::time::Duration;

use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

const TEST_KEY: &str = "aa_00112233445566778899aabbccddeeff";

/// The hardened entrypoint must hand back a wired retention engine for the
/// cron loop to drive — this is the precondition for the loop spawned by
/// `run_server`.
#[tokio::test]
async fn local_hardened_exposes_retention_engine() {
    let state = aa_api::AppState::local_hardened(aa_api::LocalAuth::ApiKey {
        key: TEST_KEY.to_string(),
    })
    .await
    .expect("local_hardened must construct");

    assert!(
        state.retention_engine.is_some(),
        "hardened state must expose a retention engine for the cron loop to drive"
    );
}

/// The retention engine from the hardened state can be started on its cron
/// schedule and fires at least one sweep — proving the exact contract the
/// `run_server` cron loop depends on. Uses a per-second schedule so the test
/// stays fast and deterministic instead of waiting for the 03:00 default.
#[tokio::test]
async fn retention_engine_runs_a_sweep_on_its_schedule() {
    let state = aa_api::AppState::local_hardened(aa_api::LocalAuth::Off)
        .await
        .expect("local_hardened must construct");
    let engine = state
        .retention_engine
        .clone()
        .expect("hardened state must expose a retention engine");

    // Speed the cron up from the daily 03:00 default to once per second so the
    // background loop fires within the test window. (6-field cron: every second.)
    let mut cfg = engine.current_config();
    cfg.schedule = "* * * * * *".to_string();
    engine.hot_reload(cfg).expect("per-second schedule must validate");

    let shutdown = CancellationToken::new();
    let handle = engine
        .clone()
        .start(shutdown.clone())
        .expect("valid schedule must spawn the cron loop");

    // Poll for the first completed sweep rather than sleeping a fixed amount.
    let fired = timeout(Duration::from_secs(5), async {
        loop {
            if engine.last_run_stats().is_some() {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap_or(false);
    assert!(fired, "cron loop must run at least one retention sweep within 5s");

    // Cancellation must drive a clean, prompt shutdown of the loop.
    shutdown.cancel();
    timeout(Duration::from_secs(5), handle)
        .await
        .expect("retention loop must exit promptly after cancel")
        .expect("retention loop task must not panic");
}
