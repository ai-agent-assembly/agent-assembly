//! Local Dev Mode bootstrap (Epic 17 S-B, AAASM-1576).
//!
//! Hosts the lightweight in-process control plane the gateway runs in
//! [`DeploymentMode::Local`]. The module is built up across the eight
//! sub-tasks of AAASM-1576; this file currently provides only the type
//! surface that the remaining sub-tasks layer behaviour onto.
//!
//! [`DeploymentMode::Local`]: aa_core::config::DeploymentMode::Local

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use axum::{routing::get, Extension, Router};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePool};
use tokio::sync::oneshot;

use crate::routes::healthz::{healthz, HealthzState};

/// Handle returned by `start_local()` once the local control plane is up.
///
/// Holds the bound socket address (useful in tests that bind to port `0`
/// to pick a free port) and the one-shot sender that drives the graceful
/// shutdown path installed in AAASM-1728.
///
/// The handle is intentionally **not** `Clone` — only one caller can
/// own the shutdown trigger at a time.
#[allow(dead_code)] // consumed by start_local() / run_until_shutdown — AAASM-1725, AAASM-1728
pub struct LocalGatewayHandle {
    /// Address the local gateway is actually bound to. In normal
    /// operation this is `127.0.0.1:{config.port}`; in tests that pass
    /// port `0`, the resolved ephemeral port lives here.
    pub local_addr: SocketAddr,
    /// One-shot channel that signals the Axum server task to begin
    /// graceful shutdown. Hooked up by AAASM-1728's signal handler.
    pub(crate) shutdown_tx: oneshot::Sender<()>,
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
}

/// Build the local-mode Axum router skeleton.
///
/// Mounts only `/healthz` for now via [`crate::routes::healthz::healthz`];
/// later sub-tasks (dashboard SPA in AAASM-1580, API routes wired by
/// AAASM-1731) merge into this same router.
///
/// The `Extension(HealthzState::new("local", "sqlite"))` layer supplies
/// the labels the shared `/healthz` handler reads, so the response body
/// carries `mode: "local"` and `storage: "sqlite"` per AAASM-1576 AC #4.
#[allow(dead_code)] // consumed by start_local() — AAASM-1725
pub(crate) fn router() -> Router {
    let state = HealthzState::new("local", "sqlite");
    Router::new().route("/healthz", get(healthz)).layer(Extension(state))
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
#[allow(dead_code)] // consumed by open_storage / start_local — AAASM-1710, AAASM-1725
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

/// Open a SQLite connection pool backing the local control plane.
///
/// Calls [`ensure_storage_parent`] so `~/.aasm/` is created on first
/// start, then opens `SqlitePool` with `create_if_missing(true)` so
/// the SQLite file itself is materialised on the same call — the
/// behaviour AAASM-1576 AC #3 requires (`SQLite file created at
/// ~/.aasm/local.db on first start`).
///
/// Migrations are deliberately out of scope here — the durable
/// storage layer (`E18 S-B`, AAASM-1574) owns the migration runner.
/// Until that lands, the pool returned here is empty/schema-less; it
/// satisfies the `/healthz` `"storage": "sqlite"` contract and lets
/// the later sub-tasks (AAASM-1725, AAASM-1728) treat it as a real
/// resource that must be opened and closed cleanly.
#[allow(dead_code)] // consumed by start_local() — AAASM-1725
pub(crate) async fn open_storage(path: &Path) -> Result<SqlitePool, LocalModeError> {
    ensure_storage_parent(path)?;
    let opts = SqliteConnectOptions::new().filename(path).create_if_missing(true);
    SqlitePool::connect_with(opts)
        .await
        .map_err(|source| LocalModeError::Storage {
            path: path.to_path_buf(),
            source,
        })
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
#[allow(dead_code)] // consumed by start_local() — AAASM-1725
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
    #[tokio::test]
    async fn router_serves_healthz_with_local_mode_json() {
        let app = router();
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

        let pool = open_storage(&db_path).await.expect("open_storage");

        assert!(
            db_path.is_file(),
            "open_storage should materialise the SQLite file on disk"
        );
        assert!(!pool.is_closed(), "open_storage should return an open pool",);

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
}
