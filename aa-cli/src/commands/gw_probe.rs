//! Readiness probe for the locally-managed `aasm` gateway process.
//!
//! Used by `aasm start` (Impl-3, AAASM-1717) to confirm the spawned
//! gateway is accepting traffic before the command exits. While
//! `/healthz` is still pending (AAASM-1577 / S-C), this probe uses
//! TCP-listener detection as the readiness signal — the API is
//! shaped so swapping in an HTTP probe later is a one-line change.

use std::net::{SocketAddr, TcpStream};
use std::time::{Duration, Instant};

/// Errors that can occur while probing the gateway for readiness.
#[derive(Debug, thiserror::Error)]
pub enum ProbeError {
    /// `wait_for_ready` exhausted its overall timeout without ever
    /// observing a successful probe.
    #[error("gateway did not become ready within {elapsed:?}")]
    Timeout {
        /// Time spent polling before giving up.
        elapsed: Duration,
    },
}

/// One-shot probe — returns `true` if a TCP listener at `addr`
/// accepts a connection within `connect_timeout`.
///
/// Any failure (connection refused, timeout, network error) is
/// folded to `false`; callers only care about a single liveness
/// bit, not the reason it failed. The connected socket is dropped
/// immediately so the probe leaves no lingering state on the
/// listener side.
pub fn probe_tcp(addr: SocketAddr, connect_timeout: Duration) -> bool {
    TcpStream::connect_timeout(&addr, connect_timeout).is_ok()
}

/// Poll `probe_tcp` until it succeeds or `overall_timeout` elapses.
///
/// Each individual probe uses `poll_interval` as its connect-timeout
/// (so a slow listener doesn't block the whole budget on a single
/// attempt), and the loop also sleeps `poll_interval` between
/// unsuccessful attempts. Returns `Ok(())` as soon as a probe
/// succeeds, `Err(ProbeError::Timeout)` once the budget is spent.
pub fn wait_for_ready(addr: SocketAddr, overall_timeout: Duration, poll_interval: Duration) -> Result<(), ProbeError> {
    let start = Instant::now();
    loop {
        if probe_tcp(addr, poll_interval) {
            return Ok(());
        }
        if start.elapsed() >= overall_timeout {
            return Err(ProbeError::Timeout {
                elapsed: start.elapsed(),
            });
        }
        std::thread::sleep(poll_interval);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    #[test]
    fn probe_tcp_returns_true_against_open_listener() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        assert!(probe_tcp(addr, Duration::from_millis(200)));
    }

    #[test]
    fn probe_tcp_returns_false_when_nothing_is_listening() {
        // Grab an ephemeral port and immediately release it. The
        // kernel won't instantly hand the same port to another
        // process, so the addr is reliably "nothing listens here"
        // for the brief moment we probe it.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        assert!(!probe_tcp(addr, Duration::from_millis(200)));
    }

    #[test]
    fn wait_for_ready_returns_ok_when_listener_is_already_up() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        // 500ms budget is far more than enough; we expect the first
        // probe to succeed immediately.
        wait_for_ready(addr, Duration::from_millis(500), Duration::from_millis(50))
            .expect("wait_for_ready should succeed when listener is up");
    }

    #[test]
    fn wait_for_ready_returns_timeout_when_nothing_listens() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);

        let budget = Duration::from_millis(200);
        let result = wait_for_ready(addr, budget, Duration::from_millis(50));
        match result {
            Err(ProbeError::Timeout { elapsed }) => {
                assert!(
                    elapsed >= budget,
                    "elapsed {elapsed:?} should not be shorter than the budget {budget:?}",
                );
            }
            other => panic!("expected Timeout error, got {other:?}"),
        }
    }

    #[test]
    fn wait_for_ready_returns_ok_when_listener_appears_mid_wait() {
        // Reserve an ephemeral port, drop the listener so nothing is
        // listening when `wait_for_ready` begins polling.
        let probe = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = probe.local_addr().unwrap();
        drop(probe);

        // After ~150ms (≥ 2 poll cycles at 50ms), a helper thread
        // re-binds the same port. The polling loop must detect the
        // mid-wait state change and return `Ok(())` before the 2s
        // budget expires. Keep the listener alive on the thread for
        // the test's lifetime so concurrent probes are still served.
        let helper = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(150));
            let _held = TcpListener::bind(addr).expect("re-bind ephemeral port");
            // Keep the listener accepting until the main thread is done.
            std::thread::sleep(Duration::from_millis(500));
        });

        wait_for_ready(addr, Duration::from_secs(2), Duration::from_millis(50))
            .expect("listener should be detected once it appears mid-wait");

        helper.join().unwrap();
    }
}
