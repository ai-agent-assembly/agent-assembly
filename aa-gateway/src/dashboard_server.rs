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

use std::path::Path;

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
