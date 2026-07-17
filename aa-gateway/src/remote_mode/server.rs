//! Remote Control-Plane Mode listener bootstrap.
//!
//! Owns `start_remote` and the `router` builder. See AAASM-1709 for the
//! design rationale; the deeper architectural context lives in
//! AAASM-1577 / E17 S-C.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use aa_auth::config::AuthMode;
use aa_core::config::RemoteModeConfig;
use axum::{routing::get, Extension, Router};
use axum_server::tls_rustls::RustlsConfig;
use axum_server::Handle;

use super::error::GatewayError;
use super::tls::{self, TlsValidation};
use crate::auth::AuthExtensions;
use crate::routes::admin_status::{admin_status, AdminStatusState};
use crate::routes::healthz::{healthz, HealthzState};
use crate::storage::{open_postgres_backend, PostgresConfig, StorageBackend};

/// Build the remote-mode Axum router.
///
/// Always mounts `/healthz` via [`crate::routes::healthz::healthz`].
/// When `storage` is `Some`, additionally mounts
/// `/api/v1/admin/status` via
/// [`crate::routes::admin_status::admin_status`] — the deeper readiness
/// signal that backs `aasm status` (AAASM-1591 / Epic 18 S-J).
///
/// `HealthzState`'s `"storage"` label tracks the chosen backend so the
/// minimal `/healthz` body still surfaces `"memory"` vs `"postgres"`
/// without requiring a backend round-trip.
///
/// AAASM-4744 — fail-closed admin-status guard. `/api/v1/admin/status`
/// discloses backend detail (database host, sqlite path, row counts) and in
/// BYPASS-DEFAULT mode answers with no credential. That is acceptable on
/// loopback (the zero-config `aasm status` contract), but exposing it to an
/// off-loopback caller with no auth is a disclosure gap. `listen_addr` is
/// consulted so the route is **omitted** when the gateway is bound off-loopback
/// in bypass mode; the operator is told to enable auth to expose it.
pub fn router(
    storage: Option<Arc<dyn StorageBackend>>,
    database_url: Option<String>,
    listen_addr: SocketAddr,
) -> Router {
    let storage_label = if storage.is_some() { "postgres" } else { "memory" };
    let healthz_state = HealthzState::new("remote", storage_label);
    let mut app = Router::new()
        .route("/healthz", get(healthz))
        .layer(Extension(healthz_state));
    // AAASM-3908: layer the four `aa-auth` extensions so the `RequireAdmin`
    // guard on `/api/v1/admin/status` can resolve. BYPASS-DEFAULT — with no
    // auth env set this builds an `AuthMode::Off` config so a bare gateway keeps
    // answering `aasm status` with no credential (AAASM-1591).
    let auth = AuthExtensions::from_env();
    if let Some(backend) = storage {
        // Fail-closed (AAASM-4744): in bypass mode the admin endpoint is only
        // exposed on loopback. Bound off-loopback with no auth, it would leak
        // backend detail to any reachable caller — refuse to mount it and point
        // the operator at the auth opt-in instead.
        let bypass = auth.config.mode == AuthMode::Off;
        if bypass && !listen_addr.ip().is_loopback() {
            tracing::warn!(
                addr = %listen_addr,
                "not exposing /api/v1/admin/status: bound off-loopback with auth disabled. \
                 Set AA_GATEWAY_AUTH=on (with AA_JWT_SECRET) to enable the admin endpoint"
            );
        } else {
            let admin_state = AdminStatusState::new("remote", backend, None, database_url);
            app = app
                .route("/api/v1/admin/status", get(admin_status))
                .layer(Extension(admin_state));
        }
    }
    auth.apply(app)
}

/// Print the operator-facing startup banner via `tracing::info!`.
///
/// Five lines — mode, listen addr, scheme (http / https), storage label,
/// version — sized to fit a typical 80-column terminal so the boot log
/// is scannable.
fn log_startup_banner(cfg: &RemoteModeConfig) {
    let scheme = if cfg.tls.is_some() { "https" } else { "http" };
    tracing::info!(
        scheme,
        addr = %cfg.listen_addr,
        storage = "memory",
        version = env!("CARGO_PKG_VERSION"),
        "Agent Assembly [remote mode] starting on {scheme}://{}",
        cfg.listen_addr
    );
}

/// How long graceful shutdown waits for in-flight requests to drain
/// before forcefully closing the listener. Matches the 30-second
/// budget the Story AC documents.
const GRACEFUL_SHUTDOWN_BUDGET: Duration = Duration::from_secs(30);

/// Bind the remote-mode listener and serve until SIGTERM / SIGINT.
///
/// Top-level entrypoint for `aasm-gateway --mode remote`. Creates an
/// internal [`Handle`], spawns a signal listener that drives graceful
/// shutdown on SIGTERM (Unix) or Ctrl+C, then defers to
/// [`start_remote_with_handle`] for the actual bind + serve loop.
///
/// Returns `Ok(())` after the server has drained, or `Err(GatewayError)`
/// for any pre-flight / bind / serve / signal-installation failure.
pub async fn start_remote(cfg: &RemoteModeConfig) -> Result<(), GatewayError> {
    let handle = Handle::new();
    let signal_handle = handle.clone();

    tokio::spawn(async move {
        if let Err(err) = wait_for_shutdown_signal().await {
            tracing::error!(error = %err, "shutdown signal listener failed");
            signal_handle.shutdown();
            return;
        }
        tracing::info!(
            secs = GRACEFUL_SHUTDOWN_BUDGET.as_secs(),
            "shutdown signal received — draining in-flight requests"
        );
        signal_handle.graceful_shutdown(Some(GRACEFUL_SHUTDOWN_BUDGET));
    });

    start_remote_with_handle(cfg, handle).await
}

/// Wait for SIGTERM (Unix) or SIGINT (Ctrl+C, all platforms), whichever
/// arrives first. Returns `Err(GatewayError::Signal)` only when the
/// underlying signal handler could not be installed.
async fn wait_for_shutdown_signal() -> Result<(), GatewayError> {
    let ctrl_c = tokio::signal::ctrl_c();

    #[cfg(unix)]
    {
        let mut sigterm =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).map_err(GatewayError::Signal)?;
        tokio::select! {
            res = ctrl_c => res.map_err(GatewayError::Signal),
            _ = sigterm.recv() => Ok(()),
        }
    }

    #[cfg(not(unix))]
    {
        ctrl_c.await.map_err(GatewayError::Signal)
    }
}

/// Bind the remote-mode listener and serve until `handle` triggers
/// shutdown. Plain-HTTP path — TLS is added in a follow-up commit.
///
/// Returns `Ok(())` after the server has drained on graceful shutdown,
/// or `Err(GatewayError)` if bind / serve failed.
///
/// `handle` is the caller's lever for shutdown: tests build their own
/// and call `handle.graceful_shutdown(Some(_))` to exit cleanly; the
/// production [`start_remote`] entrypoint wires the handle to a
/// SIGTERM / SIGINT listener.
pub async fn start_remote_with_handle(cfg: &RemoteModeConfig, handle: Handle<SocketAddr>) -> Result<(), GatewayError> {
    log_startup_banner(cfg);

    // Epic 18 Story S-I.1 (AAASM-1859): when a database URL is
    // configured, open the PostgreSQL backend and apply pending
    // migrations before binding the listener. The handle stays in
    // scope for the lifetime of the serve loop so the connection
    // pool is not dropped mid-request.
    //
    // AAASM-1908 (Epic 18 S-J #1): the storage handle is now passed
    // into `router(...)` so it can mount `/api/v1/admin/status` against
    // the real backend. When `database_url` is `None`, the route is
    // omitted and remote mode keeps its pre-S-I.1 behaviour: no backend
    // is opened, healthz reports `storage: memory`.
    let storage: Option<Arc<dyn StorageBackend>> = if let Some(url) = cfg.database_url.as_ref() {
        let pg = PostgresConfig {
            database_url: Some(url.clone()),
            ..PostgresConfig::default()
        };
        Some(open_postgres_backend(&pg).await.map_err(GatewayError::Storage)?)
    } else {
        None
    };

    let app = router(storage, cfg.database_url.clone(), cfg.listen_addr).into_make_service();

    if let Some(tls_cfg) = &cfg.tls {
        // Pre-flight cert + key (existence, readability, PEM parse, expiry).
        match tls::validate(tls_cfg)? {
            TlsValidation::Ok => {}
            TlsValidation::ExpiringSoon { days_until_expiry } => {
                tracing::warn!(
                    days_until_expiry,
                    "⚠ TLS cert expires within 30 days — rotate before notAfter"
                );
            }
            TlsValidation::Expired { expired_days_ago } => {
                tracing::error!(
                    expired_days_ago,
                    "TLS cert has already expired — new TLS clients will reject the chain"
                );
            }
        }

        let rustls_cfg = RustlsConfig::from_pem_file(&tls_cfg.cert_file, &tls_cfg.key_file)
            .await
            .map_err(GatewayError::TlsLoad)?;

        axum_server::bind_rustls(cfg.listen_addr, rustls_cfg)
            .handle(handle)
            .serve(app)
            .await
            .map_err(GatewayError::Serve)
    } else {
        tracing::warn!("⚠ TLS not configured — running over plain HTTP");

        axum_server::bind(cfg.listen_addr)
            .handle(handle)
            .serve(app)
            .await
            .map_err(GatewayError::Serve)
    }
}

/// AAASM-4744 — the fail-closed guard on `/api/v1/admin/status`: in bypass mode
/// the endpoint is exposed on loopback (the zero-config `aasm status` contract)
/// but withheld off-loopback so its backend detail can't leak to an
/// unauthenticated remote caller.
#[cfg(test)]
mod admin_status_bind_guard_tests {
    use super::*;
    use crate::storage::{SqliteBackend, SqliteConfig};
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    /// Open a real SQLite-backed `StorageBackend` under a per-test tempdir.
    async fn sqlite_backend() -> (tempfile::TempDir, Arc<dyn StorageBackend>) {
        let tmp = tempfile::tempdir().expect("create tempdir");
        let backend = SqliteBackend::open(&SqliteConfig {
            path: tmp.path().join("local.db"),
        })
        .await
        .expect("open sqlite backend");
        backend.migrate().await.expect("migrate");
        (tmp, Arc::new(backend))
    }

    /// Ensure no auth opt-in leaks in from the ambient environment so the router
    /// resolves to bypass (`AuthMode::Off`) — the posture under test.
    fn clear_auth_env() {
        std::env::remove_var("AA_GATEWAY_AUTH");
        std::env::remove_var("AA_JWT_SECRET");
    }

    async fn admin_status_code(bind: &str) -> StatusCode {
        let (_tmp, backend) = sqlite_backend().await;
        let app = router(Some(backend), None, bind.parse().expect("listen_addr"));
        app.oneshot(
            Request::builder()
                .uri("/api/v1/admin/status")
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("oneshot")
        .status()
    }

    #[tokio::test]
    async fn bypass_on_loopback_exposes_admin_status() {
        clear_auth_env();
        assert_eq!(
            admin_status_code("127.0.0.1:0").await,
            StatusCode::OK,
            "loopback bypass must keep /admin/status reachable (zero-config contract)"
        );
    }

    #[tokio::test]
    async fn bypass_off_loopback_withholds_admin_status() {
        clear_auth_env();
        assert_eq!(
            admin_status_code("0.0.0.0:0").await,
            StatusCode::NOT_FOUND,
            "off-loopback bypass must not expose /admin/status without auth"
        );
    }
}
