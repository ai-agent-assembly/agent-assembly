//! Graceful shutdown signal handler.
//!
//! Listens for `SIGTERM` (and `Ctrl-C` for dev convenience) and returns
//! a future that completes when the signal is received. The server uses
//! this to drain in-flight requests within a configurable timeout.

use std::time::Duration;

/// Default drain timeout after receiving a shutdown signal.
pub const DRAIN_TIMEOUT: Duration = Duration::from_secs(30);

/// Returns a future that completes when a shutdown signal is received.
///
/// On Unix, listens for both `SIGTERM` and `SIGINT` (Ctrl-C).
pub async fn shutdown_signal() {
    let ctrl_c = tokio::signal::ctrl_c();

    #[cfg(unix)]
    {
        let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to register SIGTERM handler");
        tokio::select! {
            _ = ctrl_c => {
                tracing::info!("received SIGINT, starting graceful shutdown");
            }
            _ = sigterm.recv() => {
                tracing::info!("received SIGTERM, starting graceful shutdown");
            }
        }
    }

    #[cfg(not(unix))]
    {
        ctrl_c.await.expect("failed to listen for Ctrl-C");
        tracing::info!("received Ctrl-C, starting graceful shutdown");
    }
}

/// Await `serve` to completion, bounding only the time it may take *after*
/// `signal` resolves — never before (AAASM-5908).
///
/// A prior version of `run_server_with_spa` wrapped the whole `serve` future
/// (which only completes once a shutdown signal fires) in
/// `tokio::time::timeout(DRAIN_TIMEOUT, serve)`. Since `signal` never
/// resolves in normal healthy operation, that meant every real deployment
/// self-terminated exactly `drain_timeout` after starting, with no signal
/// ever sent. Here, the timer that can force a `None` return is parked on
/// `signal` first and only starts counting once it resolves, so a server
/// that never receives a shutdown signal runs unbounded by this function.
///
/// Returns `Some(serve's output)` if `serve` completed on its own; `None` if
/// the drain (the time between `signal` resolving and `serve` completing)
/// exceeded `drain_timeout`.
pub async fn bound_drain_after_signal<S, T>(
    signal: impl std::future::Future<Output = ()>,
    serve: S,
    drain_timeout: Duration,
) -> Option<T>
where
    S: std::future::Future<Output = T>,
{
    tokio::select! {
        result = serve => Some(result),
        _ = async {
            signal.await;
            tokio::time::sleep(drain_timeout).await;
        } => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The regression this Bug exists for: with no signal, `serve` is not
    /// bounded by `drain_timeout` at all — even a `drain_timeout` far
    /// shorter than how long `serve` legitimately takes must not force an
    /// early `None`. The old (buggy) shape — wrapping `serve` itself in
    /// `tokio::time::timeout(drain_timeout, serve)` — would return `None`
    /// here at ~10ms; this asserts the healthy, un-signaled path runs to
    /// completion instead.
    #[tokio::test]
    async fn a_server_with_no_signal_is_not_bounded_by_drain_timeout() {
        let signal = std::future::pending::<()>();
        let serve = async {
            tokio::time::sleep(Duration::from_millis(80)).await;
            "served"
        };
        let result = bound_drain_after_signal(signal, serve, Duration::from_millis(10)).await;
        assert_eq!(
            result,
            Some("served"),
            "serve must run to completion when no signal ever fires, regardless of how short \
             drain_timeout is"
        );
    }

    /// Once `signal` has already resolved, the drain bound applies: a
    /// `serve` that would take far longer than `drain_timeout` to finish is
    /// force-completed (`None`) once the timeout elapses.
    #[tokio::test]
    async fn a_signaled_server_is_force_completed_after_drain_timeout() {
        let signal = std::future::ready(());
        let serve = async {
            tokio::time::sleep(Duration::from_secs(3600)).await;
            "served"
        };
        let result = bound_drain_after_signal(signal, serve, Duration::from_millis(20)).await;
        assert_eq!(
            result, None,
            "a drain that outlives drain_timeout after the signal fires must be force-completed"
        );
    }

    /// A signaled server that finishes draining well within the timeout
    /// still reports its real completion, not a forced one.
    #[tokio::test]
    async fn a_signaled_server_that_drains_quickly_completes_gracefully() {
        let signal = std::future::ready(());
        let serve = async {
            tokio::time::sleep(Duration::from_millis(5)).await;
            "served"
        };
        let result = bound_drain_after_signal(signal, serve, Duration::from_millis(200)).await;
        assert_eq!(
            result,
            Some("served"),
            "a drain that finishes inside drain_timeout must report the real completion"
        );
    }
}
