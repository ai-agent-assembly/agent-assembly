//! Server builder wiring router, middleware, state, and graceful shutdown.

use axum::Router;
use tokio::net::TcpListener;

use crate::config::ApiConfig;
use crate::middleware::apply_middleware;
use crate::routes;
use crate::state::AppState;

/// Build the full Axum application with middleware and state.
///
/// Auth components are injected as individual `Extension` layers so the
/// `AuthenticatedCaller` extractor can resolve them from request parts.
pub fn build_app(state: AppState) -> Router {
    let api = routes::v1_router();

    let app = Router::new()
        .nest("/api/v1", api)
        .fallback(routes::fallback_404)
        .with_state(());

    // Auth extensions — read by FromRequestParts extractors.
    let app = app
        .layer(axum::Extension(state.auth_config.clone()))
        .layer(axum::Extension(state.key_store.clone()))
        .layer(axum::Extension(state.rate_limiter.clone()))
        .layer(axum::Extension(state.jwt_signer.clone()))
        .layer(axum::Extension(state.jwt_verifier.clone()));

    let app = app.layer(axum::Extension(state));

    apply_middleware(app)
}

/// Serve the full `/api/v1/*` REST surface from a hardened, single-process
/// `AppState` (AAASM-3360 / AAASM-3369).
///
/// This is the shipped entrypoint that makes the entire REST surface reachable
/// without the operator hand-wiring ~30 subsystems. It builds an
/// [`AppState::local_hardened`] with the supplied [`LocalAuth`] posture,
/// constructs an [`ApiConfig`] bound to `addr`, and delegates to [`run_server`].
/// The process blocks until a shutdown signal (SIGTERM/SIGINT) arrives.
///
/// Unlike the original AAASM-3360 wiring, the protected routes require an API key
/// by default ([`LocalAuth::ApiKey`]) and the audit / retention seams are backed
/// by a local SQLite store, so `/api/v1/audit/*`, `/api/v1/logs/*` and
/// `/api/v1/admin/retention*` return real data instead of 503. `/api/v1/health`
/// stays public.
///
/// [`LocalAuth`]: crate::state::LocalAuth
pub async fn serve_local(
    addr: std::net::SocketAddr,
    auth: crate::state::LocalAuth,
) -> Result<(), Box<dyn std::error::Error>> {
    let state = AppState::local_hardened(auth).await?;
    let config = ApiConfig {
        bind_addr: addr,
        auth: (*state.auth_config).clone(),
    };
    run_server(config, state).await
}

/// Start the HTTP server and block until shutdown.
///
/// After receiving a shutdown signal the server drains in-flight requests.
/// If draining does not complete within [`DRAIN_TIMEOUT`] the server exits
/// anyway so the process is not stuck indefinitely.
///
/// [`DRAIN_TIMEOUT`]: crate::shutdown::DRAIN_TIMEOUT
pub async fn run_server(config: ApiConfig, state: AppState) -> Result<(), Box<dyn std::error::Error>> {
    // Spawn background task to capture budget alerts into the alert store.
    let budget_rx = state.events.subscribe_budget();
    let _alert_capture_handle = crate::alerts::capture::spawn_alert_capture(budget_rx, state.alert_store.clone());

    // Spawn background task to capture secret-detection alerts (AAASM-1545).
    let secret_rx = state.events.subscribe_secret();
    let _secret_alert_capture_handle =
        crate::alerts::capture::spawn_secret_alert_capture(secret_rx, state.alert_store.clone());

    // Spawn background task to capture anomaly detections into the alert
    // store (AAASM-3384) so gateway anomalies surface via GET /api/v1/alerts,
    // mirroring the budget/secret capture tasks above.
    let anomaly_rx = state.events.subscribe_anomaly();
    let _anomaly_alert_capture_handle =
        crate::alerts::capture::spawn_anomaly_alert_capture(anomaly_rx, state.alert_store.clone());

    // Spawn background task to restore alerts when their silence expires (AAASM-1646 / AAASM-1647).
    let _silence_expiry_handle = crate::alerts::silence_watcher::spawn_silence_expiry_watcher(
        state.silence_store.clone(),
        state.alert_store.clone(),
    );

    // Spawn the MVP alert-rule evaluator (AAASM-1386). AAASM-3369 wires the
    // real `BudgetMetricSource` (global daily spend vs. limit) so budget rules
    // fire against live spend; anomaly / approval-age / policy-violation metrics
    // still return None and stay follow-ups in the Story.
    let _rule_evaluator_handle = crate::alerts::rules::evaluator::spawn_rule_evaluator(
        state.alert_rule_store.clone(),
        std::sync::Arc::new(crate::alerts::rules::evaluator::BudgetMetricSource::new(
            state.budget_tracker.clone(),
        )),
        state.alert_store.clone(),
        std::time::Duration::from_secs(60),
    );

    // Spawn background task to sweep terminal entries from the ops registry
    // (AAASM-1657 PR-H). Default: tick every 10s, drop entries older than 60s.
    let _ops_sweep_handle = aa_gateway::ops::spawn_sweep_task(state.ops_registry.clone());

    let app = build_app(state);

    let listener = TcpListener::bind(config.bind_addr).await?;
    tracing::info!(addr = %config.bind_addr, "aa-api server listening");

    let serve = axum::serve(listener, app).with_graceful_shutdown(crate::shutdown::shutdown_signal());

    match tokio::time::timeout(crate::shutdown::DRAIN_TIMEOUT, serve).await {
        Ok(Ok(())) => {
            tracing::info!("aa-api server shut down gracefully");
        }
        Ok(Err(e)) => {
            return Err(e.into());
        }
        Err(_elapsed) => {
            tracing::warn!(
                timeout_secs = crate::shutdown::DRAIN_TIMEOUT.as_secs(),
                "drain timeout exceeded, forcing shutdown"
            );
        }
    }

    Ok(())
}
