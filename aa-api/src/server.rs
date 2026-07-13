//! Server builder wiring router, middleware, state, and graceful shutdown.

use std::sync::Arc;

use axum::routing::get;
use axum::Router;
use tokio::net::TcpListener;
use tonic::service::interceptor::InterceptedService;
use tonic::transport::Server;

use aa_gateway::registry::AgentRegistry;
use aa_proto::assembly::agent::v1::agent_lifecycle_service_server::AgentLifecycleServiceServer;

use crate::config::ApiConfig;
use crate::middleware::apply_middleware;
use crate::routes;
use crate::state::AppState;

/// Loopback gRPC endpoint for SDK agent registration in local mode (AAASM-4447).
///
/// Loopback-only by design: the agent-registration plane must never be exposed
/// off-host. This matches the SDK's `DEFAULT_GATEWAY_ENDPOINT`
/// (`http://127.0.0.1:50051`) so `RuntimeClient.register` reaches the same
/// process that serves the REST/dashboard surface, with zero SDK change.
///
/// `pub` so the security test can assert the shipped bind target is loopback
/// (never `0.0.0.0`) without reaching into private internals.
pub const LOCAL_GRPC_ADDR: &str = "127.0.0.1:50051";

/// Max accepted gRPC decode size (4 MiB). Parity with `aa-gateway`'s legacy-grpc
/// services (`aa-gateway/src/server.rs`): the registration endpoint is
/// attacker-influenceable, so the response/request buffer is bounded explicitly
/// rather than relying on tonic's implicit default.
const MAX_DECODING_MESSAGE_SIZE: usize = 4 * 1024 * 1024;

/// Build the full Axum application with middleware and state.
///
/// Auth components are injected as individual `Extension` layers so the
/// `AuthenticatedCaller` extractor can resolve them from request parts.
pub fn build_app(state: AppState) -> Router {
    build_app_with_spa(state, None)
}

/// Build the full Axum application, optionally serving the dashboard SPA from
/// `spa_dist` as the top-level fallback (AAASM-3382).
///
/// When `spa_dist` is `None` the behaviour is identical to [`build_app`]: an
/// unmatched route returns the RFC 7807 JSON 404 ([`routes::fallback_404`]).
///
/// When `spa_dist` is `Some`, the `/api/v1` nested router carries its own JSON
/// 404 fallback so unknown `/api/v1/*` routes still return `ProblemDetail` JSON,
/// while the *app-level* fallback serves the React SPA (via
/// [`aa_gateway::dashboard_server::dashboard_router`]) so browser routes resolve
/// to `index.html`. This lets the shipped `aa-api-server` binary serve the SPA
/// *and* the full `/api/v1/*` REST surface from a single process and port.
pub fn build_app_with_spa(state: AppState, spa_dist: Option<&std::path::Path>) -> Router {
    let app = match spa_dist {
        // SPA present: the nested API router owns its JSON 404 so `/api/v1/*`
        // never falls through to the HTML SPA fallback; the app-level fallback
        // is the SPA `ServeDir`.
        Some(dist) => Router::new()
            .route("/healthz", get(routes::health::health))
            .nest("/api/v1", routes::v1_router().fallback(routes::fallback_404))
            .merge(aa_gateway::dashboard_server::dashboard_router(dist))
            .with_state(()),
        // No SPA: only the `/api/v1/*` surface is exposed and unmatched routes
        // return JSON 404 via the app-level fallback — identical to the original
        // `build_app`. `/healthz` is intentionally *not* registered here: the
        // top-level liveness probe lives in `aa-gateway`, and the
        // `aa-integration-tests` harness mounts its own `/healthz` on top of
        // `build_app`. Registering it here would collide with that mount.
        None => Router::new()
            .nest("/api/v1", routes::v1_router())
            .fallback(routes::fallback_404)
            .with_state(()),
    };

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
    // AAASM-4447: back the registry with the durable `~/.aasm/local.db` shared
    // with `aa-gateway` (not the hermetic temp DB `local_hardened` defaults to),
    // so agents survive restart and match the gateway's legacy-grpc store.
    let state = AppState::local_hardened_at(auth, crate::state::resolve_local_registry_db_path()).await?;
    let config = ApiConfig {
        bind_addr: addr,
        auth: (*state.auth_config).clone(),
    };
    // AAASM-3382 / AAASM-4517: resolve the dashboard SPA so a single
    // `aa-api-server` process serves the React app at `/` *and* the full
    // `/api/v1/*` REST surface.
    //
    // First choice is a `dashboard/dist/` on disk (AAASM_DASHBOARD_DIST
    // override, an installed side-by-side layout, or the workspace dev layout).
    // A bare release tarball has none of those, so the fallback extracts the
    // SPA embedded into this binary at build time (AAASM-4517) to a temp dir and
    // serves that — this is what makes the shipped `aa-api-server` serve the UI
    // instead of degrading to REST-only. `_embedded_dashboard` owns the temp dir
    // and must outlive the server (dropping it deletes the files `ServeDir`
    // reads), so it is bound for the whole `serve_local` scope.
    let (spa_dist, _embedded_dashboard): (Option<std::path::PathBuf>, Option<tempfile::TempDir>) =
        match aa_gateway::dashboard_server::find_dashboard_dist() {
            Some(path) => (Some(path), None),
            None => match crate::embedded_dashboard::extract_embedded_dashboard() {
                Ok(tmp) => {
                    tracing::info!(
                        target: "aa_api::serve_local",
                        "no dashboard/dist/ resolved on disk; serving the dashboard SPA \
                         embedded in this binary (AAASM-4517)"
                    );
                    (Some(tmp.path().to_path_buf()), Some(tmp))
                }
                Err(e) => {
                    tracing::warn!(
                        target: "aa_api::serve_local",
                        error = %e,
                        "no dashboard/dist/ resolved and embedded SPA extraction failed; \
                         serving the REST API only"
                    );
                    (None, None)
                }
            },
        };

    // AAASM-4447: alongside the axum REST/dashboard server, serve the gRPC
    // `AgentLifecycleService` on loopback :50051 over the SAME
    // `Arc<AgentRegistry>` the REST surface reads. This closes the local-mode
    // registration gap — the SDK's gRPC `RuntimeClient.register` dials
    // `127.0.0.1:50051`, which local mode previously never served — so a
    // registered agent is immediately visible in the dashboard. Both servers run
    // concurrently and drain on the same shutdown signal; a port-in-use gRPC bind
    // degrades gracefully to REST-only (see `serve_local_grpc`).
    let registry = std::sync::Arc::clone(&state.agent_registry);
    let grpc_addr: std::net::SocketAddr = LOCAL_GRPC_ADDR
        .parse()
        .expect("LOCAL_GRPC_ADDR is a valid loopback address");

    let rest = run_server_with_spa(config, state, spa_dist.as_deref());
    let grpc = serve_local_grpc(grpc_addr, registry);
    tokio::try_join!(rest, grpc)?;
    Ok(())
}

/// Bind the local-mode gRPC `AgentLifecycleService` on `addr` and serve until
/// shutdown, reusing `aa-gateway`'s service impl and possession-proof
/// enrich interceptor (AAASM-4447 / AAASM-4460 / AAASM-4461).
///
/// `addr` must be a loopback address ([`LOCAL_GRPC_ADDR`]); the caller controls
/// that. If the port is already in use (e.g. an `aa-gateway` process is already
/// serving it) the bind failure is downgraded to a warning and this returns
/// `Ok(())` so the REST surface still comes up — the process degrades to
/// REST-only rather than failing to start. Any other bind error propagates.
async fn serve_local_grpc(
    addr: std::net::SocketAddr,
    registry: Arc<AgentRegistry>,
) -> Result<(), Box<dyn std::error::Error>> {
    let listener = match TcpListener::bind(addr).await {
        Ok(listener) => listener,
        Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
            tracing::warn!(
                target: "aa_api::serve_local",
                %addr,
                error = %e,
                "gRPC agent-registration port already in use — serving REST only; \
                 SDK registration to this endpoint is handled by the process that \
                 owns the port"
            );
            return Ok(());
        }
        Err(e) => return Err(e.into()),
    };
    tracing::info!(%addr, "aa-api local gRPC AgentLifecycleService listening (loopback-only)");
    serve_lifecycle_grpc(listener, registry, crate::shutdown::shutdown_signal()).await
}

/// Serve the gRPC `AgentLifecycleService` on an already-bound `listener` over
/// `registry`, until `shutdown` resolves (AAASM-4460).
///
/// Extracted so tests can drive the exact production wiring on an ephemeral
/// port. Reuses `aa-gateway`'s [`AgentLifecycleServiceImpl`] (Register +
/// RequestChallenge + heartbeat/deregister — the RPCs `RuntimeClient` uses)
/// rather than duplicating it, and applies the same `enrich_interceptor` the
/// gateway wraps its lifecycle service with. The `Register` RPC self-validates
/// the possession-proof challenge, so this adds no new unauthenticated surface.
pub async fn serve_lifecycle_grpc(
    listener: TcpListener,
    registry: Arc<AgentRegistry>,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> Result<(), Box<dyn std::error::Error>> {
    let tenancy_mode = aa_gateway::service::TenancyMode::from_env();
    let lifecycle =
        aa_gateway::service::AgentLifecycleServiceImpl::new(Arc::clone(&registry)).with_tenancy_mode(tenancy_mode);
    let enrich = aa_gateway::iam::enrich_interceptor(registry);
    let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);

    Server::builder()
        .add_service(InterceptedService::new(
            AgentLifecycleServiceServer::new(lifecycle).max_decoding_message_size(MAX_DECODING_MESSAGE_SIZE),
            enrich,
        ))
        .serve_with_incoming_shutdown(incoming, shutdown)
        .await?;
    Ok(())
}

/// Start the HTTP server and block until shutdown.
///
/// After receiving a shutdown signal the server drains in-flight requests.
/// If draining does not complete within [`DRAIN_TIMEOUT`] the server exits
/// anyway so the process is not stuck indefinitely.
///
/// [`DRAIN_TIMEOUT`]: crate::shutdown::DRAIN_TIMEOUT
pub async fn run_server(config: ApiConfig, state: AppState) -> Result<(), Box<dyn std::error::Error>> {
    run_server_with_spa(config, state, None).await
}

/// Same as [`run_server`] but additionally serves the dashboard SPA from
/// `spa_dist` as the top-level fallback when `Some` (AAASM-3382).
pub async fn run_server_with_spa(
    config: ApiConfig,
    state: AppState,
    spa_dist: Option<&std::path::Path>,
) -> Result<(), Box<dyn std::error::Error>> {
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

    // Spawn the retention engine's cron-driven background loop (AAASM-3383).
    // AAASM-3369 constructed the engine in `local_hardened` for the on-demand
    // `/api/v1/admin/retention*` handlers but DEFERRED the scheduled sweep.
    // Drive the same engine on its configured cron schedule here, mirroring the
    // gateway's `spawn_retention_engine` boot pattern. The token is cancelled
    // after the HTTP server drains so the loop exits cleanly on shutdown.
    let retention_shutdown = tokio_util::sync::CancellationToken::new();
    let _retention_handle = match state.retention_engine.clone() {
        Some(engine) => match engine.start(retention_shutdown.clone()) {
            Ok(handle) => Some(handle),
            Err(e) => {
                tracing::error!(error = %e, "retention engine has an invalid schedule; cron loop not started");
                None
            }
        },
        None => {
            tracing::debug!("no retention engine wired; cron loop not started");
            None
        }
    };

    // Mount the dashboard SPA (+ top-level /healthz) alongside the full
    // `/api/v1/*` router when a dist resolves (AAASM-3382). `state` is moved
    // here, so the retention engine was cloned above before this point.
    let app = build_app_with_spa(state, spa_dist);

    let listener = TcpListener::bind(config.bind_addr).await?;
    tracing::info!(addr = %config.bind_addr, "aa-api server listening");

    let serve = axum::serve(listener, app).with_graceful_shutdown(crate::shutdown::shutdown_signal());

    let serve_result = tokio::time::timeout(crate::shutdown::DRAIN_TIMEOUT, serve).await;

    // Signal the retention loop to exit and let it finish its current tick
    // before the process tears down storage (AAASM-3383).
    retention_shutdown.cancel();
    if let Some(handle) = _retention_handle {
        let _ = handle.await;
    }

    match serve_result {
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
