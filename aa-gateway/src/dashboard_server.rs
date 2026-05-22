//! Dashboard SPA static-asset server for local-mode (Epic 17 S-F, AAASM-1580).
//!
//! Serves the compiled React dashboard out of `dashboard/dist/` from the
//! same Axum process as the local-mode control plane so a developer running
//! `aasm start --mode local` can open `http://localhost:7391/` and see the
//! UI without standing up a separate Vite dev server.
//!
//! The module is built up across the sub-tasks of AAASM-1580; this file
//! currently provides only the module surface that the next commits layer
//! `dashboard_router()` and `find_dashboard_dist()` onto.

use std::path::{Path, PathBuf};

use axum::Router;
use tower_http::services::{ServeDir, ServeFile};

/// Build an Axum `Router` that serves the compiled dashboard SPA from
/// `dist_path`.
///
/// File requests resolve against `dist_path` directly; anything
/// `ServeDir` cannot find falls through to `dist_path/index.html` so
/// client-side React Router paths like `/agents/abc` reach the SPA
/// instead of returning 404. Mounted via `nest_service("/")` so the
/// router can be `.merge()`d into a parent that already owns concrete
/// API routes (e.g. `/healthz`) without the SPA fallback eating them.
///
/// Consumer: `local_mode::router()` mounts this in the next sub-task
/// (AAASM-1844) when `LocalModeConfig.dashboard == true`.
pub fn dashboard_router(dist_path: &Path) -> Router {
    let index_html = dist_path.join("index.html");
    let serve_dir = ServeDir::new(dist_path).not_found_service(ServeFile::new(index_html));
    Router::new().nest_service("/", serve_dir)
}

/// Resolve the `dashboard/dist/` directory the gateway should serve.
///
/// Resolution order, first match wins:
///
/// 1. `AAASM_DASHBOARD_DIST` — operator-supplied override; takes
///    precedence over every other source so a developer can point at
///    a sibling checkout or a custom build.
/// 2. `{binary_dir}/../dashboard/dist/` — installed layout where the
///    `aasm` / `aa-gateway` binary lives alongside its assets, e.g.
///    `/usr/local/bin/aasm` + `/usr/local/dashboard/dist`.
/// 3. `{cargo_manifest_dir}/../dashboard/dist/` — workspace
///    development layout, used by `cargo run -p aa-gateway` against a
///    locally-built `dashboard/dist/`.
///
/// Returns `None` when every candidate is missing. The local-mode
/// router (next sub-task) interprets `None` as "log a warning and
/// skip mounting the SPA" so the gateway still starts and `/healthz`
/// keeps working — AAASM-1580 AC "Missing dashboard/dist/ → gateway
/// starts successfully with warning".
pub fn find_dashboard_dist() -> Option<PathBuf> {
    find_dashboard_dist_in(
        std::env::var("AAASM_DASHBOARD_DIST").ok(),
        std::env::current_exe()
            .ok()
            .as_deref()
            .and_then(Path::parent)
            .and_then(Path::parent)
            .map(Path::to_path_buf),
        Some(Path::new(env!("CARGO_MANIFEST_DIR")).join("..")),
    )
}

/// Pure resolution helper exposed for hermetic testing — `find_dashboard_dist`
/// is a thin wrapper that supplies real process inputs.
///
/// Each `*_root` is treated as the parent of `dashboard/dist`. The
/// helper validates `is_dir()` on every candidate so it never returns
/// a path that does not actually exist on disk; an empty
/// `env_override` skips straight to the disk fallbacks.
fn find_dashboard_dist_in(
    env_override: Option<String>,
    installed_root: Option<PathBuf>,
    dev_root: Option<PathBuf>,
) -> Option<PathBuf> {
    if let Some(env_path) = env_override {
        let p = PathBuf::from(env_path);
        if p.is_dir() {
            return Some(p);
        }
    }
    for root in [installed_root, dev_root].into_iter().flatten() {
        let candidate = root.join("dashboard").join("dist");
        if candidate.is_dir() {
            return Some(candidate);
        }
    }
    None
}
