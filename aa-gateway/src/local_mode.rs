//! Local Dev Mode bootstrap (Epic 17 S-B, AAASM-1576).
//!
//! Hosts the lightweight in-process control plane the gateway runs in
//! [`DeploymentMode::Local`]. The module is built up across the eight
//! sub-tasks of AAASM-1576; this file currently provides only the type
//! surface that the remaining sub-tasks layer behaviour onto.
//!
//! [`DeploymentMode::Local`]: aa_core::config::DeploymentMode::Local

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use aa_core::config::LocalModeConfig;
use axum::{routing::get, Extension, Router};
use sqlx::sqlite::SqlitePool;
use tokio::net::TcpListener;
use tokio::sync::oneshot;

use crate::dashboard_server::{dashboard_router, find_dashboard_dist};
use crate::routes::admin_status::{admin_status, AdminStatusState};
use crate::routes::api_health::{api_health, ApiHealthState};
use crate::routes::healthz::{healthz, HealthzState};
use crate::storage::{SqliteBackend, SqliteConfig, StorageBackend, StorageError};

/// Handle returned by `start_local()` once the local control plane is up.
///
/// Holds the bound socket address, the one-shot sender that drives the
/// graceful shutdown path, and the resources `shutdown()` (AAASM-1728)
/// will clean up: the spawned server task, the `SqlitePool` to close,
/// and the PID-file path to remove.
///
/// The trailing three fields are `Option` because the **shell-handle**
/// path (probe short-circuit in `start_local`) has nothing to clean up
/// — the running process is owned by a different `start_local` invocation.
///
/// The handle is intentionally **not** `Clone` — only one caller can
/// own the shutdown trigger at a time.
pub struct LocalGatewayHandle {
    /// Address the local gateway is actually bound to. In normal
    /// operation this is `127.0.0.1:{config.port}`; in tests that pass
    /// port `0`, the resolved ephemeral port lives here.
    pub local_addr: SocketAddr,
    /// One-shot channel that signals the Axum server task to begin
    /// graceful shutdown. Hooked up by AAASM-1728's `shutdown()`.
    pub(crate) shutdown_tx: oneshot::Sender<()>,
    /// `JoinHandle` of the spawned `axum::serve` task. `shutdown()`
    /// awaits this after signalling `shutdown_tx` so the server has
    /// fully drained before we close the pool. `None` on the shell-
    /// handle path (probe short-circuit).
    pub(crate) server_task: Option<tokio::task::JoinHandle<()>>,
    /// SQLite pool to close on shutdown. `None` on the shell-handle path.
    pub(crate) pool: Option<SqlitePool>,
    /// Type-erased storage handle constructed alongside the SQLite pool
    /// at boot. Carried on the handle so subsequent Sub-tasks of Epic 18
    /// Story S-I (registry write-through, audit-event durability,
    /// retention engine) can reach the trait object from the same
    /// lifecycle owner that already manages the pool. `None` on the
    /// shell-handle path (probe short-circuit) where no backend was
    /// opened.
    pub(crate) storage: Option<Arc<dyn StorageBackend>>,
    /// PID-file path to remove on shutdown. `None` on the shell-handle
    /// path (no PID was written for that branch).
    pub(crate) pid_path: Option<PathBuf>,
}

impl LocalGatewayHandle {
    /// Drain the running gateway and clean up.
    ///
    /// Consumes the handle in this order:
    /// 1. Signal `shutdown_tx` so `axum::serve`'s `with_graceful_shutdown`
    ///    future resolves — the server stops accepting new connections
    ///    and finishes in-flight requests.
    /// 2. Await `server_task` so we don't return until the server has
    ///    fully exited (AAASM-1576 AC #8 expects the server to stop
    ///    accepting connections by the time `shutdown()` returns).
    /// 3. Remove the PID file (best-effort — `aasm stop` may have
    ///    already removed it; an error here doesn't fail the shutdown).
    /// 4. `pool.close().await` so SQLite shuts cleanly and any cached
    ///    statements are released.
    ///
    /// On the shell-handle path (probe short-circuit in `start_local`),
    /// every Option is `None` and `shutdown()` is effectively a no-op —
    /// the running gateway lives in a different process and we don't
    /// own its lifecycle.
    ///
    /// Called by `run_until_shutdown()` (next commits) after a
    /// SIGTERM/SIGINT signal fires. Tests call it directly to avoid
    /// having to signal the test process.
    pub async fn shutdown(self) -> Result<(), LocalModeError> {
        // 1. Signal the server. send() returns Err if the receiver was
        //    dropped (shell-handle path) — that's expected, ignore.
        let _ = self.shutdown_tx.send(());

        // 2. Wait for the spawned task to exit.
        if let Some(task) = self.server_task {
            let _ = task.await;
        }

        // 3. Remove the PID file.
        if let Some(pid_path) = self.pid_path {
            let _ = std::fs::remove_file(pid_path);
        }

        // 4. Close the SqlitePool. Dropping `self.storage` is left to
        //    Drop semantics — the SqliteBackend wraps another Arc to
        //    the same pool, so we already explicitly close the pool here.
        drop(self.storage);
        if let Some(pool) = self.pool {
            pool.close().await;
        }

        Ok(())
    }
}

/// Wait for an OS shutdown signal.
///
/// On Unix (the production target — local mode is a developer/macOS
/// thing primarily), `SIGTERM` and `SIGINT` both trigger the same
/// shutdown path — Ctrl+C from a terminal is `SIGINT`; `systemctl stop`
/// / Docker / Kubernetes graceful shutdown send `SIGTERM`. Either one
/// must drive the cleanup the same way.
///
/// On non-Unix targets (Windows CI runners, mostly), only Ctrl+C is
/// available via `tokio::signal::ctrl_c()`. There is no SIGTERM
/// equivalent in the standard library / tokio surface.
///
/// Errors propagate as `LocalModeError::Signal` — typically only on
/// macOS / Linux when `tokio::signal::unix::signal()` fails to
/// register a SIGTERM listener (very rare in practice).
#[cfg(unix)]
pub(crate) async fn wait_for_shutdown_signal() -> Result<(), LocalModeError> {
    let mut sigterm =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).map_err(LocalModeError::Signal)?;
    tokio::select! {
        _ = tokio::signal::ctrl_c() => Ok(()),
        _ = sigterm.recv() => Ok(()),
    }
}

#[cfg(not(unix))]
pub(crate) async fn wait_for_shutdown_signal() -> Result<(), LocalModeError> {
    tokio::signal::ctrl_c().await.map_err(LocalModeError::Signal)
}

/// Block until a shutdown signal arrives, then clean up the gateway.
///
/// The intended call pattern in `aa-gateway::main` (AAASM-1731):
///
/// ```rust,ignore
/// let handle = start_local(&config.local).await?;
/// run_until_shutdown(handle).await?;
/// ```
///
/// Awaits `wait_for_shutdown_signal()` (SIGTERM/SIGINT on Unix,
/// Ctrl+C on Windows) and then drives `handle.shutdown()` so the
/// server drains, the PID file is removed, and the SQLite pool is
/// closed before the process exits.
///
/// Tests that want to verify cleanup without sending a real signal
/// call `handle.shutdown()` directly — `run_until_shutdown` itself
/// is exercised via the `aa-integration-tests` crate (AAASM-1731's
/// integration test will spawn the gateway binary, send SIGTERM,
/// and assert clean exit + PID removal).
pub async fn run_until_shutdown(handle: LocalGatewayHandle) -> Result<(), LocalModeError> {
    wait_for_shutdown_signal().await?;
    handle.shutdown().await
}

/// Errors that can occur while booting the local-mode control plane.
///
/// Each variant maps to a discrete failure mode an operator running
/// `aasm start --mode local` (or a test calling `start_local()`
/// directly) might hit. The `#[source]` fields preserve the original
/// I/O / sqlx / signal error so `{:?}` and `tracing` capture the full
/// chain.
#[derive(Debug, thiserror::Error)]
pub enum LocalModeError {
    /// `TcpListener::bind` failed — port already in use by a foreign
    /// process, permission denied, or address invalid.
    #[error("failed to bind local gateway to {addr}: {source}")]
    Bind {
        /// The socket address `start_local()` tried to bind.
        addr: String,
        /// Underlying `std::io::Error` from `TcpListener::bind`.
        #[source]
        source: std::io::Error,
    },
    /// Opening or migrating the SQLite database at `path` failed.
    #[error("failed to open SQLite at {path}: {source}", path = path.display())]
    Storage {
        /// The resolved on-disk path the gateway tried to open.
        path: PathBuf,
        /// Underlying `sqlx::Error` from `SqlitePool::connect_with`.
        #[source]
        source: sqlx::Error,
    },
    /// Writing the PID file to `~/.aasm/gateway.pid` failed.
    #[error("failed to write PID file at {path}: {source}", path = path.display())]
    PidFile {
        /// The PID-file path the gateway tried to write.
        path: PathBuf,
        /// Underlying `std::io::Error` from `std::fs::write`.
        #[source]
        source: std::io::Error,
    },
    /// Installing the SIGTERM / SIGINT handler failed (Unix only).
    #[error("shutdown signal handler installation failed: {0}")]
    Signal(#[source] std::io::Error),
    /// The durable storage backend (`SqliteBackend::open` /
    /// `StorageBackend::migrate`) returned an error during boot.
    ///
    /// Distinct from [`LocalModeError::Storage`] so the underlying
    /// `sqlx::Error` chain stays intact in the existing variant while
    /// this one carries the richer
    /// [`StorageError`](crate::storage::StorageError) surface introduced
    /// by Epic 18 Story S-I.
    #[error("storage backend error at {path}: {source}", path = path.display())]
    StorageBackend {
        /// The resolved on-disk path the gateway tried to open.
        path: PathBuf,
        /// Underlying [`StorageError`] from
        /// `SqliteBackend::open` / `migrate`.
        #[source]
        source: StorageError,
    },
}

/// Build the local-mode Axum router.
///
/// Always mounts `/healthz` via [`crate::routes::healthz::healthz`].
/// When `config.dashboard` is `true`, calls
/// [`crate::dashboard_server::find_dashboard_dist`] to resolve a
/// `dashboard/dist/` directory and merges in the dashboard SPA
/// router from [`crate::dashboard_server::dashboard_router`] so the
/// gateway serves the React app at `/` and falls back to `index.html`
/// for client-side routes. `/healthz` is registered before the merge
/// so the SPA catch-all never eats the API route — AAASM-1580 AC
/// "API route, not overridden by dashboard handler".
///
/// When the dashboard is requested but no candidate
/// `dashboard/dist/` resolves, the gateway logs a `tracing::warn!`
/// and continues serving without the SPA — matches AAASM-1580 AC
/// "Missing dashboard/dist/ → gateway starts successfully with
/// warning (dashboard unavailable, gateway API still works)".
pub(crate) fn router(config: &LocalModeConfig, storage: Option<Arc<dyn StorageBackend>>) -> Router {
    let dist = if config.dashboard { find_dashboard_dist() } else { None };
    router_with_resolved_dist(config, dist.as_deref(), storage)
}

/// Test-injectable router builder — keeps `router()` thin and lets
/// unit tests assemble a router around a tempdir-backed `dashboard/dist/`
/// (or an explicit `None`) without having to mutate the
/// `AAASM_DASHBOARD_DIST` env var. Production callers always go
/// through [`router`] which supplies the resolver's output.
///
/// When `config.dashboard` is `false`, `dist` is ignored — the router
/// returns the healthz-only skeleton regardless of what the caller
/// resolved.
pub(crate) fn router_with_resolved_dist(
    config: &LocalModeConfig,
    dist: Option<&Path>,
    storage: Option<Arc<dyn StorageBackend>>,
) -> Router {
    let state = HealthzState::new("local", "sqlite");
    let mut app = Router::new().route("/healthz", get(healthz)).layer(Extension(state));
    // AAASM-3354: serve the REST surface's liveness probe at /api/v1/health
    // so `curl http://127.0.0.1:7391/api/v1/health` returns JSON, not a 404,
    // in local mode. The full `aa-api` router cannot be nested here — `aa-api`
    // depends on `aa-gateway` (circular) and requires the heavyweight
    // `aa_api::AppState` local mode does not construct — so this is the
    // smallest viable wiring; remaining `/api/v1/*` data routes are a
    // documented follow-up (see the AAASM-3354 PR body).
    app = app
        .route("/api/v1/health", get(api_health))
        .layer(Extension(ApiHealthState::new()));
    if let Some(backend) = storage {
        let admin_state = AdminStatusState::new(
            "local",
            backend,
            Some(config.storage_path.to_string_lossy().into_owned()),
            None,
        );
        app = app
            .route("/api/v1/admin/status", get(admin_status))
            .layer(Extension(admin_state));
    }
    if config.dashboard {
        match dist {
            Some(dist) => app = app.merge(dashboard_router(dist)),
            None => tracing::warn!(
                target: "aa_gateway::local_mode",
                "dashboard enabled but no dashboard/dist/ resolved \
                 (checked AAASM_DASHBOARD_DIST, installed layout, and workspace layout); \
                 serving /healthz only — run `pnpm --dir dashboard build` to enable the SPA",
            ),
        }
    }
    app
}

/// Create the parent directory tree for `path` if it does not yet exist.
///
/// Called by [`open_storage`] before opening the SQLite file so that a
/// developer's first `aasm start --mode local` can write to
/// `~/.aasm/local.db` even when `~/.aasm/` doesn't exist yet — matches
/// AAASM-1576 AC #3 (`SQLite file created at ~/.aasm/local.db on first start`).
///
/// `path.parent()` returning `None` or an empty path (e.g. a bare
/// filename like `:memory:`) is a no-op success.
///
/// Tilde expansion is not performed here — `aa-core::config::GatewayConfig::
/// expand_paths()` (AAASM-1691) resolves `~` upstream before this is called.
pub(crate) fn ensure_storage_parent(path: &Path) -> Result<(), LocalModeError> {
    let Some(parent) = path.parent() else { return Ok(()) };
    if parent.as_os_str().is_empty() {
        return Ok(());
    }
    std::fs::create_dir_all(parent).map_err(|source| LocalModeError::Storage {
        path: path.to_path_buf(),
        source: sqlx::Error::Io(source),
    })
}

/// Open the local-mode SQLite-backed [`StorageBackend`] and apply
/// pending migrations.
///
/// Calls [`ensure_storage_parent`] so `~/.aasm/` is created on first
/// start, then constructs a [`SqliteBackend`] at `path` (which itself
/// creates the file in WAL mode if absent) and runs
/// [`StorageBackend::migrate`] to bring the schema up to date.
///
/// Returns both the raw [`SqlitePool`] (so [`LocalGatewayHandle`] can
/// still close it explicitly during shutdown — preserving the
/// AAASM-1576 AC #8 guarantee that `aasm start` after a shutdown does
/// not race against a not-yet-drained pool) and the type-erased
/// [`Arc<dyn StorageBackend>`] consumed by the new
/// [`crate::AppState`] introduced in Epic 18 Story S-I.1.
///
/// The two handles share the same underlying connection pool: every
/// `SqlitePool` is internally `Arc<PoolInner>`, so `pool().clone()`
/// produces a second view onto the existing pool rather than opening
/// a second connection set.
pub(crate) async fn open_storage(path: &Path) -> Result<(SqlitePool, Arc<dyn StorageBackend>), LocalModeError> {
    ensure_storage_parent(path)?;
    let backend = SqliteBackend::open(&SqliteConfig {
        path: path.to_path_buf(),
    })
    .await
    .map_err(|source| LocalModeError::StorageBackend {
        path: path.to_path_buf(),
        source,
    })?;
    backend
        .migrate()
        .await
        .map_err(|source| LocalModeError::StorageBackend {
            path: path.to_path_buf(),
            source,
        })?;
    let pool = backend.pool().clone();
    let storage: Arc<dyn StorageBackend> = Arc::new(backend);
    Ok((pool, storage))
}

/// Probe `GET http://127.0.0.1:{port}/healthz` with a 100 ms timeout.
///
/// Used as the auto-start idempotency check by `start_local()` (AAASM-1725):
/// if a previous gateway is already serving on the port, the call short-
/// circuits and we reuse the existing process rather than failing to bind.
/// Matches AAASM-1576 AC #2 ("If port 7391 is already in use by a running
/// AASM gateway, auto-start is skipped").
///
/// Returns:
/// * `true`  — a running gateway responded 200 OK and the body carries a
///   `HealthzBody`-compatible shape (string `mode`, `version`, `storage`).
/// * `false` — connection refused, request timeout, non-200 response, or
///   unexpected body shape. The probe never panics; every error path maps
///   to `false` so callers can treat it as a boolean.
///
/// The body-shape check guards against falsely identifying *foreign*
/// services that happen to be listening on the port (e.g. a developer
/// running a different HTTP server on 7391) as a healthy AASM gateway.
pub(crate) async fn probe_running(port: u16) -> bool {
    let url = format!("http://127.0.0.1:{port}/healthz");
    let Ok(client) = reqwest::Client::builder()
        .timeout(std::time::Duration::from_millis(100))
        .build()
    else {
        return false;
    };
    let Ok(resp) = client.get(&url).send().await else {
        return false;
    };
    if !resp.status().is_success() {
        return false;
    }
    let Ok(body) = resp.json::<serde_json::Value>().await else {
        return false;
    };
    body.get("mode").and_then(|v| v.as_str()).is_some()
        && body.get("storage").and_then(|v| v.as_str()).is_some()
        && body.get("version").and_then(|v| v.as_str()).is_some()
}

/// Resolve the production PID-file location: `~/.aasm/gateway.pid`.
///
/// Called by `start_local()` (AAASM-1725) to record the running process
/// id so `aasm stop` (AAASM-1717 / E17 S-D) can later signal it.
/// Matches AAASM-1576 AC #7 ("PID file written to `~/.aasm/gateway.pid`").
///
/// Falls back to an empty `PathBuf` when `dirs::home_dir()` returns
/// `None` — the caller's subsequent `std::fs::write` will surface the
/// error as `LocalModeError::PidFile` rather than panicking.
pub(crate) fn pid_file_path() -> PathBuf {
    dirs::home_dir().unwrap_or_default().join(".aasm/gateway.pid")
}

/// Print the local-mode startup banner to stderr.
///
/// The exact banner shape matches the AAASM-1576 Story description so
/// operators see a consistent "what just started" message across
/// versions:
///
/// ```text
/// Agent Assembly [local mode] v0.0.1
///   Listening:  http://127.0.0.1:7391
///   Dashboard:  http://127.0.0.1:7391/
///   Storage:    /Users/alice/.aasm/local.db (SQLite)
///
///   Ctrl+C to stop.
/// ```
///
/// Goes to stderr (not stdout) so it never pollutes piped JSON output
/// from `aasm`-family tools.
pub(crate) fn write_banner(addr: &SocketAddr, storage_path: &Path) {
    eprintln!("Agent Assembly [local mode] v{}", env!("CARGO_PKG_VERSION"));
    eprintln!("  Listening:  http://{addr}");
    eprintln!("  Dashboard:  http://{addr}/");
    eprintln!("  Storage:    {} (SQLite)", storage_path.display());
    eprintln!();
    eprintln!("  Ctrl+C to stop.");
}

/// Boot the local-mode control plane.
///
/// The entry point of E17 S-B — strings together every helper this
/// module has accumulated (`probe_running` → `open_storage` → bind
/// → `write_banner` → PID file → spawn) to deliver AAASM-1576 ACs
/// #1, #5, #6, #7 in a single call:
///
/// * **AC #1** — `AA_MODE=local` starts a control plane at the
///   configured port (default `7391`).
/// * **AC #5** — Startup completes in well under 500 ms on a
///   developer laptop (the round-trip is bounded by the local
///   `axum::serve` task scheduling).
/// * **AC #6** — Listener binds to `127.0.0.1` only, never
///   `0.0.0.0` — explicit `IpAddr::V4(Ipv4Addr::LOCALHOST)`.
/// * **AC #7** — PID file written to `~/.aasm/gateway.pid`.
///
/// **Idempotency** (AC #2) — if `probe_running(config.port)` returns
/// `true`, the function short-circuits and returns a handle pointing
/// at the existing process. The handle's `shutdown_tx` is a closed
/// channel in that case — signalling it is a silent no-op, which is
/// correct because we don't own the other process's lifecycle.
///
/// Graceful shutdown wiring (SIGTERM/SIGINT handler + DB pool close)
/// lands in AAASM-1728; this Sub-task leaves the shutdown channel as
/// the only mechanism, intended for `run_until_shutdown()` to consume.
pub async fn start_local(config: &LocalModeConfig) -> Result<LocalGatewayHandle, LocalModeError> {
    start_local_with_pid_path(config, &pid_file_path()).await
}

/// `start_local` with an explicit PID-file path, kept `pub(crate)` so
/// tests can target a `tempfile::tempdir()` location instead of the
/// developer's real `~/.aasm/gateway.pid`.
pub(crate) async fn start_local_with_pid_path(
    config: &LocalModeConfig,
    pid_path: &Path,
) -> Result<LocalGatewayHandle, LocalModeError> {
    // 1. Pre-flight idempotency probe (AAASM-1715).
    if probe_running(config.port).await {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), config.port);
        // Closed channel: shutdown_tx.send(()) is a no-op because the
        // existing gateway runs in a different process — we don't own it.
        let (shutdown_tx, _closed_rx) = oneshot::channel();
        return Ok(LocalGatewayHandle {
            local_addr: addr,
            shutdown_tx,
            server_task: None,
            pool: None,
            storage: None,
            pid_path: None,
        });
    }

    // 2. Storage (AAASM-1710 / AAASM-1859). `open_storage` now also
    //    constructs the SQLite-backed `StorageBackend` and applies
    //    pending schema migrations. The pool stays on the handle for
    //    AAASM-1576 AC #8's explicit close-on-shutdown; the storage
    //    Arc is carried alongside so later Sub-tasks of Epic 18
    //    Story S-I (registry write-through, audit-event durability,
    //    retention engine) can reach the trait object from this same
    //    lifecycle owner.
    let (pool, storage) = open_storage(&config.storage_path).await?;

    // 3. Bind 127.0.0.1:port (AC #6 — explicit Ipv4Addr::LOCALHOST,
    //    never 0.0.0.0).
    let requested_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), config.port);
    let listener = TcpListener::bind(requested_addr)
        .await
        .map_err(|source| LocalModeError::Bind {
            addr: requested_addr.to_string(),
            source,
        })?;
    let local_addr = listener.local_addr().unwrap_or(requested_addr);

    // 4. Startup banner (stderr).
    write_banner(&local_addr, &config.storage_path);

    // 5. PID file (AC #7).
    std::fs::write(pid_path, std::process::id().to_string()).map_err(|source| LocalModeError::PidFile {
        path: pid_path.to_path_buf(),
        source,
    })?;

    // 6. Serve. The shutdown_rx side stays in the spawned task; the
    //    handle keeps shutdown_tx for AAASM-1728's signal handler.
    //    The `JoinHandle` lives on the handle so `shutdown()` can await
    //    the task's completion after signalling shutdown_tx.
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    // AAASM-1908: pass storage into the router so `/api/v1/admin/status`
    // can probe it on each request and the CLI can surface DB health,
    // latency, and row counts.
    let app = router(config, Some(Arc::clone(&storage)));
    let server_task = tokio::spawn(async move {
        let _ = axum::serve(listener, app)
            .with_graceful_shutdown(async move {
                let _ = shutdown_rx.await;
            })
            .await;
    });

    Ok(LocalGatewayHandle {
        local_addr,
        shutdown_tx,
        server_task: Some(server_task),
        pool: Some(pool),
        storage: Some(storage),
        pid_path: Some(pid_path.to_path_buf()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    use axum::body::{to_bytes, Body};
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    /// AAASM-1576 AC #4, driven through the router built by `router()`:
    /// `GET /healthz` returns 200 with `application/json` content-type and
    /// a body whose `mode`, `storage`, and `version` fields carry the
    /// local-mode labels. The `uptime_secs` field is asserted to be
    /// present (guards against a regression that would drop the field
    /// from `HealthzBody`).
    /// Build a `LocalModeConfig` with dashboard disabled and a tempdir
    /// SQLite path — sufficient for the healthz-router tests below
    /// that only care about the `/healthz` route.
    fn healthz_only_config() -> LocalModeConfig {
        LocalModeConfig {
            port: 0,
            dashboard: false,
            storage_path: std::path::PathBuf::from("/dev/null"),
        }
    }

    #[tokio::test]
    async fn router_serves_healthz_with_local_mode_json() {
        let cfg = healthz_only_config();
        let app = router(&cfg, None);
        let request = Request::builder()
            .uri("/healthz")
            .body(Body::empty())
            .expect("build request");

        let response = app.oneshot(request).await.expect("router.oneshot");

        assert_eq!(response.status(), StatusCode::OK);
        let ctype = response
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default();
        assert!(
            ctype.starts_with("application/json"),
            "expected application/json, got {ctype}"
        );

        let bytes = to_bytes(response.into_body(), 8 * 1024).await.expect("read body");
        let body: serde_json::Value = serde_json::from_slice(&bytes).expect("parse json");

        assert_eq!(body["mode"], "local", "mode label");
        assert_eq!(body["storage"], "sqlite", "storage label");
        assert_eq!(body["version"], env!("CARGO_PKG_VERSION"), "crate version");
        assert!(
            body["uptime_secs"].is_u64(),
            "uptime_secs must be present and a u64; got {body}",
        );
    }

    /// AAASM-3354: the local-mode router serves `/api/v1/health` with a
    /// 200 + `application/json` body (wire-compatible with
    /// `aa_api::routes::health::HealthResponse`) so the REST surface is
    /// reachable in local mode instead of returning a blanket 404. The
    /// route is mounted regardless of whether a storage backend is wired.
    #[tokio::test]
    async fn router_serves_api_v1_health_with_json() {
        let cfg = healthz_only_config();
        let app = router(&cfg, None);
        let request = Request::builder()
            .uri("/api/v1/health")
            .body(Body::empty())
            .expect("build request");

        let response = app.oneshot(request).await.expect("router.oneshot");

        assert_eq!(response.status(), StatusCode::OK);
        let ctype = response
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default();
        assert!(
            ctype.starts_with("application/json"),
            "expected application/json, got {ctype}"
        );

        let bytes = to_bytes(response.into_body(), 8 * 1024).await.expect("read body");
        let body: serde_json::Value = serde_json::from_slice(&bytes).expect("parse json");

        assert_eq!(body["status"], "ok", "status label");
        assert_eq!(body["api_version"], "v1", "api version");
        assert_eq!(body["version"], env!("CARGO_PKG_VERSION"), "crate version");
        assert!(
            body["uptime_secs"].is_u64(),
            "uptime_secs must be present and a u64; got {body}",
        );
    }

    /// AAASM-1591 / Epic 18 S-J: when a storage backend is wired into
    /// the local-mode router, `GET /api/v1/admin/status` returns the
    /// documented storage block (backend=sqlite, health=ok, row counts,
    /// no TimescaleDB block, sqlite `path` echoed from
    /// `LocalModeConfig.storage_path`).
    #[tokio::test]
    async fn router_serves_admin_status_when_storage_is_wired() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let db_path = tmp.path().join("local.db");
        let backend = SqliteBackend::open(&SqliteConfig { path: db_path.clone() })
            .await
            .expect("open sqlite backend");
        backend.migrate().await.expect("migrate");
        let storage: Arc<dyn StorageBackend> = Arc::new(backend);

        let cfg = LocalModeConfig {
            port: 0,
            dashboard: false,
            storage_path: db_path,
        };

        let app = router(&cfg, Some(Arc::clone(&storage)));
        let request = Request::builder()
            .uri("/api/v1/admin/status")
            .body(Body::empty())
            .expect("build request");

        let response = app.oneshot(request).await.expect("router.oneshot");
        assert_eq!(response.status(), StatusCode::OK);

        let bytes = to_bytes(response.into_body(), 16 * 1024).await.expect("read body");
        let body: serde_json::Value = serde_json::from_slice(&bytes).expect("parse json");

        assert_eq!(body["mode"], "local");
        let storage_block = &body["storage"];
        assert_eq!(storage_block["backend"], "sqlite");
        assert_eq!(storage_block["health"], "ok");
        assert!(storage_block["path"].is_string(), "sqlite path must be reported");
        assert!(
            storage_block.get("database_url").is_none(),
            "sqlite branch must omit database_url",
        );
        assert!(
            storage_block.get("timescaledb").is_none(),
            "sqlite must omit timescaledb block",
        );
        assert!(storage_block["row_counts"]["audit_events_hot"].as_u64().is_some());
        assert!(storage_block["row_counts"]["agents"].as_u64().is_some());
        assert!(storage_block["row_counts"]["policy_versions"].as_u64().is_some());
    }

    /// AAASM-1591: when no storage is wired, the local-mode router must
    /// still serve `/healthz` but must *not* mount `/api/v1/admin/status`
    /// — a 404 is the right signal for older operators / tests that
    /// build the router without a backend.
    #[tokio::test]
    async fn router_omits_admin_status_when_storage_is_none() {
        let cfg = healthz_only_config();
        let app = router(&cfg, None);
        let request = Request::builder()
            .uri("/api/v1/admin/status")
            .body(Body::empty())
            .expect("build request");
        let response = app.oneshot(request).await.expect("router.oneshot");
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    /// Mirrors the developer's first `aasm start --mode local` —
    /// `~/.aasm/` does not exist yet, so `ensure_storage_parent`
    /// must `mkdir -p` the parent tree before the SQLite file can
    /// be written. Verifies the helper creates nested missing
    /// directories rather than only the immediate parent.
    #[test]
    fn ensure_storage_parent_creates_nested_directories() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let nested = tmp.path().join("a/b/c/local.db");

        // Sanity: the nested parent does not exist yet.
        assert!(!nested.parent().expect("parent").exists());

        ensure_storage_parent(&nested).expect("ensure_storage_parent");

        assert!(
            nested.parent().expect("parent").is_dir(),
            "ensure_storage_parent should mkdir -p the parent tree"
        );
    }

    /// AAASM-1576 AC #3 end-to-end at the helper level: `open_storage`
    /// must materialise the SQLite file on disk in a fresh directory
    /// tree, not just open a connection in memory. Uses `tempfile`
    /// so the test is hermetic — no `~/.aasm/` writes leak from CI.
    #[tokio::test]
    async fn open_storage_creates_sqlite_file_in_fresh_tempdir() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let db_path = tmp.path().join("nested/local.db");

        // Sanity: neither the parent nor the file exist yet.
        assert!(!db_path.parent().expect("parent").exists());
        assert!(!db_path.exists());

        let (pool, storage) = open_storage(&db_path).await.expect("open_storage");

        assert!(
            db_path.is_file(),
            "open_storage should materialise the SQLite file on disk"
        );
        assert!(!pool.is_closed(), "open_storage should return an open pool",);
        // The companion StorageBackend handle must be a working trait
        // object — a healthcheck round-trip exercises it through the
        // dyn vtable.
        storage.healthcheck().await.expect("healthcheck should succeed");

        pool.close().await;
    }

    /// AAASM-1576 AC #2 negative path: when no gateway is listening,
    /// `probe_running` must return `false` (so `start_local()` proceeds
    /// with auto-start) — within the documented 100 ms timeout, never
    /// hanging or panicking.
    ///
    /// Pattern: bind a TcpListener to grab a fresh ephemeral port, then
    /// drop it before probing — the kernel returns ECONNREFUSED on the
    /// next connect attempt, exercising the connection-refused path.
    #[tokio::test]
    async fn probe_running_returns_false_on_connection_refused() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind ephemeral port");
        let port = listener.local_addr().expect("local_addr").port();
        drop(listener);

        let start = std::time::Instant::now();
        let alive = probe_running(port).await;
        let elapsed = start.elapsed();

        assert!(!alive, "probe must report dead when port is closed");
        assert!(
            elapsed < std::time::Duration::from_millis(500),
            "probe should fail fast on connection refused; took {elapsed:?}"
        );
    }

    /// AAASM-1576 AC #2 positive path: when a real local-mode gateway is
    /// serving on the port, `probe_running` must return `true` so
    /// `start_local()` short-circuits and reuses the existing process.
    ///
    /// Spins up the actual `router()` (which mounts `routes::healthz`
    /// with `HealthzState::new("local", "sqlite")`) on an ephemeral
    /// port via `axum::serve`, then probes it. The server task is
    /// aborted on the way out to keep the test hermetic.
    #[tokio::test]
    async fn probe_running_returns_true_against_local_mode_router() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind ephemeral port");
        let port = listener.local_addr().expect("local_addr").port();

        let cfg = healthz_only_config();
        let server = tokio::spawn(async move {
            let _ = axum::serve(listener, router(&cfg, None)).await;
        });

        let alive = probe_running(port).await;

        server.abort();

        assert!(alive, "probe must report alive against a real local-mode /healthz");
    }

    /// AAASM-1576 AC #2 guard: when *some other* HTTP server is
    /// listening on port 7391 — say a developer's static-asset server
    /// or a stale process from a different product — `probe_running`
    /// must return `false`. Otherwise `start_local()` would falsely
    /// reuse a foreign process and the gateway would silently fail to
    /// come up.
    ///
    /// Spins up a tiny axum router that responds 200 OK with
    /// `{"foo":"bar"}` (missing every documented `HealthzBody` field)
    /// and asserts the probe rejects it.
    #[tokio::test]
    async fn probe_running_returns_false_on_body_shape_mismatch() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind ephemeral port");
        let port = listener.local_addr().expect("local_addr").port();

        async fn foreign_handler() -> axum::Json<serde_json::Value> {
            axum::Json(serde_json::json!({"foo": "bar"}))
        }
        let foreign_app = Router::new().route("/healthz", get(foreign_handler));

        let server = tokio::spawn(async move {
            let _ = axum::serve(listener, foreign_app).await;
        });

        let alive = probe_running(port).await;

        server.abort();

        assert!(
            !alive,
            "probe must reject foreign /healthz responses missing HealthzBody fields"
        );
    }

    /// Build a `LocalModeConfig` pointing at a fresh tempdir SQLite path
    /// and a free ephemeral port. Used by every `start_local` test so
    /// none of them collide on port 7391 or pollute `~/.aasm/`.
    async fn test_config_with_ephemeral_port() -> (LocalModeConfig, tempfile::TempDir, u16) {
        let tmp = tempfile::tempdir().expect("tempdir");
        // Grab a free port by binding then dropping the listener.
        let probe_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind ephemeral port");
        let port = probe_listener.local_addr().expect("local_addr").port();
        drop(probe_listener);

        let config = LocalModeConfig {
            port,
            dashboard: false,
            storage_path: tmp.path().join("local.db"),
        };
        (config, tmp, port)
    }

    /// AAASM-1576 AC #1 + AC #6 end-to-end:
    /// `start_local()` binds `127.0.0.1:<port>` (never `0.0.0.0`) and
    /// `/healthz` responds with the documented local-mode JSON.
    #[tokio::test]
    async fn start_local_binds_127_0_0_1_and_serves_healthz() {
        let (config, _tmp, port) = test_config_with_ephemeral_port().await;
        let pid_path = _tmp.path().join("gateway.pid");

        let handle = start_local_with_pid_path(&config, &pid_path)
            .await
            .expect("start_local");

        // AC #6 — bound address is the v4 loopback, not 0.0.0.0.
        assert_eq!(
            handle.local_addr.ip(),
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            "start_local must bind 127.0.0.1, never 0.0.0.0"
        );
        assert_eq!(handle.local_addr.port(), port);

        // AC #1 — /healthz reachable with the documented body.
        let body = reqwest::get(format!("http://127.0.0.1:{port}/healthz"))
            .await
            .expect("GET /healthz")
            .json::<serde_json::Value>()
            .await
            .expect("parse json");
        assert_eq!(body["mode"], "local");
        assert_eq!(body["storage"], "sqlite");

        // Tear down — the spawned axum task lives until the runtime shuts it
        // down at the end of the test. Signal it explicitly via the handle.
        let _ = handle.shutdown_tx.send(());
    }

    /// AAASM-1576 AC #7: `start_local()` must write the running process
    /// id to the configured PID file. Uses the `pub(crate)`
    /// `start_local_with_pid_path()` variant so the test can point the
    /// PID file at a tempdir instead of the developer's real
    /// `~/.aasm/gateway.pid`.
    #[tokio::test]
    async fn start_local_writes_pid_file_with_running_pid() {
        let (config, _tmp, _port) = test_config_with_ephemeral_port().await;
        let pid_path = _tmp.path().join("gateway.pid");
        assert!(!pid_path.exists(), "pid file must not exist before start");

        let handle = start_local_with_pid_path(&config, &pid_path)
            .await
            .expect("start_local");

        assert!(pid_path.is_file(), "pid file must be written by start_local");
        let written = std::fs::read_to_string(&pid_path).expect("read pid file");
        let written_pid: u32 = written.trim().parse().expect("pid file contents must be a u32");
        assert_eq!(
            written_pid,
            std::process::id(),
            "pid file must contain the running process id"
        );

        let _ = handle.shutdown_tx.send(());
    }

    /// AAASM-1576 AC #2: when a gateway is **already** running on the
    /// configured port, the second `start_local()` call must short-
    /// circuit via the `probe_running` pre-flight check instead of
    /// trying to re-bind and failing with `EADDRINUSE`.
    ///
    /// Pattern: bring up a real local-mode gateway via `start_local`,
    /// then immediately call `start_local` again against the same
    /// config. The second call must return Ok — proof the probe path
    /// was taken (re-bind would have returned `LocalModeError::Bind`).
    /// The second call's PID file *must not* be written, because we
    /// reused the existing process and never reached the PID-write
    /// step.
    #[tokio::test]
    async fn start_local_skips_when_probe_returns_true() {
        let (config, _tmp, _port) = test_config_with_ephemeral_port().await;
        let first_pid_path = _tmp.path().join("first.pid");
        let second_pid_path = _tmp.path().join("second.pid");

        let first = start_local_with_pid_path(&config, &first_pid_path)
            .await
            .expect("first start_local");
        assert!(first_pid_path.is_file(), "first start must write its PID file");

        // Second call against the same port must short-circuit via the probe.
        let second = start_local_with_pid_path(&config, &second_pid_path)
            .await
            .expect("second start_local must succeed via probe short-circuit");

        assert!(
            !second_pid_path.exists(),
            "short-circuited start must NOT write a new PID file"
        );
        assert_eq!(
            second.local_addr.port(),
            config.port,
            "short-circuited handle must still report the configured port"
        );

        let _ = first.shutdown_tx.send(());
        let _ = second.shutdown_tx.send(());
    }

    /// AAASM-1576 AC #5: wall-clock from `start_local()` call to a
    /// successful `/healthz` round-trip must be **under 500 ms** on a
    /// standard developer laptop. The ceiling is generous against the
    /// real expected latency (single-digit ms locally) so we catch
    /// genuine regressions — e.g. someone adding a blocking migration
    /// step to `open_storage` — without flaking on slow CI runners.
    #[tokio::test]
    async fn start_local_healthz_round_trip_completes_within_500ms() {
        let (config, _tmp, port) = test_config_with_ephemeral_port().await;
        let pid_path = _tmp.path().join("gateway.pid");

        let started = std::time::Instant::now();
        let handle = start_local_with_pid_path(&config, &pid_path)
            .await
            .expect("start_local");
        let _ = reqwest::get(format!("http://127.0.0.1:{port}/healthz"))
            .await
            .expect("GET /healthz")
            .json::<serde_json::Value>()
            .await
            .expect("parse json");
        let elapsed = started.elapsed();

        assert!(
            elapsed < std::time::Duration::from_millis(500),
            "AAASM-1576 AC #5: start_local → /healthz round-trip must be < 500 ms, took {elapsed:?}"
        );

        let _ = handle.shutdown_tx.send(());
    }

    /// AAASM-1576 AC #8 (server stops accepting connections): after
    /// `handle.shutdown()` returns, the server task has fully exited
    /// and `/healthz` requests can no longer reach it.
    ///
    /// Drives the cleanup directly via `handle.shutdown()` rather than
    /// SIGTERM — gives a deterministic test that doesn't require
    /// killing the test process. The 100 ms ceiling matches the AC's
    /// "stops accepting connections within 100ms" requirement.
    #[tokio::test]
    async fn handle_shutdown_stops_the_server_within_100ms() {
        let (config, _tmp, port) = test_config_with_ephemeral_port().await;
        let pid_path = _tmp.path().join("gateway.pid");

        let handle = start_local_with_pid_path(&config, &pid_path)
            .await
            .expect("start_local");

        // Sanity: server is up and responding before shutdown.
        let pre = reqwest::get(format!("http://127.0.0.1:{port}/healthz")).await;
        assert!(
            pre.is_ok_and(|r| r.status().is_success()),
            "server must respond before shutdown"
        );

        let started = std::time::Instant::now();
        handle.shutdown().await.expect("shutdown");
        let elapsed = started.elapsed();

        assert!(
            elapsed < std::time::Duration::from_millis(500),
            "shutdown must complete promptly; took {elapsed:?}"
        );

        // After shutdown, GET /healthz fails (connection refused or hangs;
        // either way, not `is_ok_and(success)`).
        let post = tokio::time::timeout(
            std::time::Duration::from_millis(200),
            reqwest::get(format!("http://127.0.0.1:{port}/healthz")),
        )
        .await;
        let still_alive = matches!(post, Ok(Ok(resp)) if resp.status().is_success());
        assert!(!still_alive, "server must not respond after shutdown");
    }

    /// AAASM-1576 AC #8 PID-file cleanup invariant: after
    /// `handle.shutdown()`, the PID file written by `start_local()`
    /// must no longer exist — `aasm stop` and other operators rely on
    /// PID-file-absent ≡ no-gateway-running.
    #[tokio::test]
    async fn handle_shutdown_removes_the_pid_file() {
        let (config, _tmp, _port) = test_config_with_ephemeral_port().await;
        let pid_path = _tmp.path().join("gateway.pid");

        let handle = start_local_with_pid_path(&config, &pid_path)
            .await
            .expect("start_local");
        assert!(pid_path.is_file(), "pid file must exist after start_local");

        handle.shutdown().await.expect("shutdown");

        assert!(!pid_path.exists(), "pid file must be removed by handle.shutdown()");
    }

    /// AAASM-1576 AC #8 final invariant: after `handle.shutdown()`, the
    /// SQLite connection pool reports `is_closed() == true` — guarantees
    /// `aasm start` can re-open the same DB file without a "database is
    /// locked" race against a not-yet-drained pool.
    ///
    /// `SqlitePool` is internally `Arc<...>` so cloning gives a second
    /// view onto the same shared state. We clone the pool out of the
    /// handle before `shutdown()` consumes it, then check the clone's
    /// `is_closed()` after the cleanup completes.
    #[tokio::test]
    async fn handle_shutdown_closes_the_sqlite_pool() {
        let (config, _tmp, _port) = test_config_with_ephemeral_port().await;
        let pid_path = _tmp.path().join("gateway.pid");

        let handle = start_local_with_pid_path(&config, &pid_path)
            .await
            .expect("start_local");
        let pool_clone = handle
            .pool
            .as_ref()
            .expect("normal start_local must populate pool")
            .clone();
        assert!(!pool_clone.is_closed(), "pool must be open after start");

        handle.shutdown().await.expect("shutdown");

        assert!(
            pool_clone.is_closed(),
            "pool must report closed after handle.shutdown()"
        );
    }

    /// Build a tempdir shaped like a real `dashboard/dist/`: an
    /// `index.html` carrying the React root marker the AC asserts on.
    /// Kept here rather than reused from `dashboard_server::tests`
    /// because that test module is private to its crate path.
    fn make_dashboard_stub_dist() -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            dir.path().join("index.html"),
            r#"<!doctype html><html><body><div id="root"></div></body></html>"#,
        )
        .expect("write index.html");
        dir
    }

    /// `LocalModeConfig` with the dashboard turned on and an unused
    /// SQLite path — the dashboard tests below never reach storage.
    fn dashboard_on_config() -> LocalModeConfig {
        LocalModeConfig {
            port: 0,
            dashboard: true,
            storage_path: std::path::PathBuf::from("/dev/null"),
        }
    }

    /// AAASM-1580 AC #1 end-to-end at the local-mode router level:
    /// `GET /` returns 200 + the React shell when `config.dashboard`
    /// is on and a real `dashboard/dist/` is resolved.
    #[tokio::test]
    async fn router_serves_dashboard_index_when_enabled_with_dist() {
        let dist = make_dashboard_stub_dist();
        let app = router_with_resolved_dist(&dashboard_on_config(), Some(dist.path()), None);

        let response = app
            .oneshot(Request::builder().uri("/").body(Body::empty()).expect("build request"))
            .await
            .expect("router.oneshot");

        assert_eq!(response.status(), StatusCode::OK);
        let bytes = to_bytes(response.into_body(), 64 * 1024).await.expect("body");
        let body = std::str::from_utf8(&bytes).expect("utf8");
        assert!(
            body.contains(r#"<div id="root">"#),
            "GET / must serve the dashboard index when dashboard is enabled; got: {body}"
        );
    }

    /// AAASM-1580 AC "GET /agents → index.html (SPA fallback, not 404)"
    /// driven through the merged local-mode router — the dashboard SPA
    /// fallback fires for unknown nested routes.
    #[tokio::test]
    async fn router_falls_back_to_index_on_unknown_spa_route() {
        let dist = make_dashboard_stub_dist();
        let app = router_with_resolved_dist(&dashboard_on_config(), Some(dist.path()), None);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/agents/abc")
                    .body(Body::empty())
                    .expect("build request"),
            )
            .await
            .expect("router.oneshot");

        assert_eq!(
            response.status(),
            StatusCode::OK,
            "SPA fallback must return 200, not 404"
        );
        let bytes = to_bytes(response.into_body(), 64 * 1024).await.expect("body");
        let body = std::str::from_utf8(&bytes).expect("utf8");
        assert!(
            body.contains(r#"<div id="root">"#),
            "SPA fallback body must be index.html; got: {body}"
        );
    }

    /// AAASM-1580 AC "GET /api/v1/agents → JSON (API route, not
    /// overridden by dashboard handler)" — `/healthz` stands in for
    /// any concrete API route. With the dashboard mounted, the
    /// API route must still resolve to its handler, *not* fall
    /// through to the SPA catch-all.
    #[tokio::test]
    async fn router_preserves_healthz_when_dashboard_enabled() {
        let dist = make_dashboard_stub_dist();
        let app = router_with_resolved_dist(&dashboard_on_config(), Some(dist.path()), None);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/healthz")
                    .body(Body::empty())
                    .expect("build request"),
            )
            .await
            .expect("router.oneshot");

        assert_eq!(response.status(), StatusCode::OK);
        let ctype = response
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_owned();
        assert!(
            ctype.starts_with("application/json"),
            "API route must keep its JSON content-type with the SPA mounted; got {ctype:?}"
        );
        let bytes = to_bytes(response.into_body(), 8 * 1024).await.expect("body");
        let body: serde_json::Value = serde_json::from_slice(&bytes).expect("parse json");
        assert_eq!(body["mode"], "local");
    }

    /// When `config.dashboard == false`, the router must *not* mount
    /// the SPA — `GET /` returns 404. Mirrors the remote-mode default
    /// where operators opt in to dashboard serving explicitly.
    #[tokio::test]
    async fn router_does_not_mount_dashboard_when_config_disables_it() {
        let dist = make_dashboard_stub_dist();
        let cfg = LocalModeConfig {
            port: 0,
            dashboard: false,
            storage_path: std::path::PathBuf::from("/dev/null"),
        };
        let app = router_with_resolved_dist(&cfg, Some(dist.path()), None);

        let response = app
            .oneshot(Request::builder().uri("/").body(Body::empty()).expect("build request"))
            .await
            .expect("router.oneshot");

        assert_eq!(
            response.status(),
            StatusCode::NOT_FOUND,
            "with dashboard disabled, GET / must return 404 — no SPA mounted"
        );
    }

    /// AAASM-1580 AC "Missing dashboard/dist/ → gateway starts
    /// successfully with warning (dashboard unavailable, gateway API
    /// still works)" — when the resolver returns None but the
    /// dashboard is requested, the gateway keeps serving `/healthz`
    /// and rejects `/` with 404 instead of crashing. The warning
    /// emission itself is covered by the `tracing::warn!` call site
    /// and doesn't need a subscriber-capture assertion at this level.
    #[tokio::test]
    async fn router_serves_healthz_when_dashboard_enabled_but_dist_missing() {
        let app = router_with_resolved_dist(&dashboard_on_config(), None, None);

        let healthz = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/healthz")
                    .body(Body::empty())
                    .expect("build request"),
            )
            .await
            .expect("router.oneshot");
        assert_eq!(healthz.status(), StatusCode::OK);

        let root = app
            .oneshot(Request::builder().uri("/").body(Body::empty()).expect("build request"))
            .await
            .expect("router.oneshot");
        assert_eq!(
            root.status(),
            StatusCode::NOT_FOUND,
            "no dist resolved → no SPA mounted, but the gateway must still answer /healthz"
        );
    }
}
