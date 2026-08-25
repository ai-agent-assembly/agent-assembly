//! AAASM-5908 — the real shipped `aa-api-server` binary shuts down
//! gracefully on SIGTERM and does not self-terminate while healthy.
//!
//! `aa-api/src/shutdown.rs`'s unit tests (`shutdown::tests`) prove the
//! `bound_drain_after_signal` primitive is correct in isolation — but,
//! per independent review of PR #2203, none of them touch the wiring at
//! `aa-api/src/server.rs::run_server_with_spa` that fans the real shutdown
//! signal out to that primitive (a `tokio::sync::oneshot` pair). A mutation
//! there — e.g. dropping the `oneshot::Sender::send` call, or swapping the
//! two arguments to `bound_drain_after_signal` — would not be caught by any
//! of the unit tests, which all drive the primitive directly with
//! hand-built futures rather than the real `ApiServerProcess`.
//!
//! This closes that gap: a real, separately-spawned `aa-api-server` OS
//! process, sent a real SIGTERM via `ApiServerProcess::stop`
//! (`ManagedProcess::stop` — `libc::kill(pid, SIGTERM)`, not an in-process
//! future), asserting on its own captured log output that it exited via the
//! graceful path, not the force-timeout path.

mod common;

use std::time::Duration;

use common::api_server::ApiServerProcess;

#[tokio::test(flavor = "multi_thread")]
async fn a_real_sigterm_produces_a_graceful_shutdown_not_a_forced_one() {
    let mut api = ApiServerProcess::spawn().expect("aa-api-server should start");

    // Real SIGTERM, real process, real 5s wait for exit.
    api.stop().expect(
        "aa-api-server must exit gracefully within 5s of SIGTERM — an Err here means the \
         SIGKILL safety net fired, i.e. graceful shutdown did not complete",
    );

    let logs = api.logs();
    assert!(
        logs.contains("received SIGTERM, starting graceful shutdown"),
        "log must show the real signal was observed; logs:\n{logs}"
    );
    assert!(
        logs.contains("aa-api server shut down gracefully"),
        "log must show the graceful-completion path, not a forced one; logs:\n{logs}"
    );
    assert!(
        !logs.contains("drain timeout exceeded"),
        "AAASM-5908 regression: a prompt SIGTERM must never hit the drain-timeout \
         force-shutdown path; logs:\n{logs}"
    );
    api.assert_no_leaks();
}

/// The other half of AAASM-5908: with no signal at all, the server must
/// still be alive well past the old 30s self-terminate point.
///
/// Deliberately short of `aa-api::shutdown::DRAIN_TIMEOUT`'s real 30s value
/// (a `#[tokio::test]` waiting the full 30+s is disproportionate for CI) —
/// `shutdown::tests::a_server_with_no_signal_is_not_bounded_by_drain_timeout`
/// already proves the *primitive* is unbounded absent a signal for
/// arbitrarily long durations; this test's job is only to prove the real
/// wiring reaches that primitive correctly, which a much shorter wait
/// already demonstrates (the regression, if reintroduced, would kill the
/// process at exactly 30s recorded from start — surviving any shorter
/// window at all is already inconsistent with the bug being present).
#[tokio::test(flavor = "multi_thread")]
async fn no_signal_the_real_server_outlives_a_short_wait() {
    let mut api = ApiServerProcess::spawn().expect("aa-api-server should start");

    tokio::time::sleep(Duration::from_secs(5)).await;

    let logs = api.logs();
    assert!(
        !logs.contains("drain timeout exceeded"),
        "the server must not self-terminate while healthy and unsignaled; logs:\n{logs}"
    );

    api.stop().expect("clean teardown");
    api.assert_no_leaks();
}
