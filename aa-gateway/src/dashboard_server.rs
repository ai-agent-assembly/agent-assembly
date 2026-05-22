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
/// `ServeDir` cannot find falls through to `ServeDir::fallback` —
/// `ServeFile(index.html)` — so client-side React Router paths like
/// `/agents/abc` reach the SPA shell with a real **200 OK** instead of
/// a 404. `fallback` is used here rather than `not_found_service`
/// because the latter preserves the original `404` status alongside
/// the substituted body, which is the wrong UX for SPA routing.
///
/// The `ServeDir` is registered as the router's `fallback_service` so
/// it only handles requests that did not match a concrete route — a
/// parent router can therefore `.merge()` this in alongside
/// `/healthz` and future `/api/v1/*` routes without the SPA catch-all
/// eating them.
///
/// Consumer: `local_mode::router()` mounts this in the next sub-task
/// (AAASM-1844) when `LocalModeConfig.dashboard == true`.
pub fn dashboard_router(dist_path: &Path) -> Router {
    let index_html = dist_path.join("index.html");
    let serve_dir = ServeDir::new(dist_path).fallback(ServeFile::new(index_html));
    Router::new().fallback_service(serve_dir)
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

#[cfg(test)]
mod tests {
    use super::*;

    use axum::body::{to_bytes, Body};
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    /// Build a minimal `dashboard/dist/`-shaped tempdir for the router
    /// tests: `index.html` at the root plus an `assets/main.js` file
    /// whose contents we assert against to prove `ServeDir` is reaching
    /// real files (rather than always returning the index fallback).
    fn make_stub_dist() -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            dir.path().join("index.html"),
            r#"<!doctype html><html><body><div id="root"></div></body></html>"#,
        )
        .expect("write index.html");
        std::fs::create_dir_all(dir.path().join("assets")).expect("mkdir assets");
        std::fs::write(dir.path().join("assets/main.js"), "export const main = () => 42;\n")
            .expect("write assets/main.js");
        dir
    }

    async fn get(router: Router, path: &str) -> axum::http::Response<Body> {
        router
            .oneshot(Request::builder().uri(path).body(Body::empty()).expect("build request"))
            .await
            .expect("router.oneshot")
    }

    /// AAASM-1580 AC #1 at the helper level: `GET /` returns 200 and
    /// the body contains `<div id="root">`, proving the React SPA's
    /// `index.html` is what the router serves at the root.
    #[tokio::test]
    async fn dashboard_router_serves_index_at_root() {
        let dist = make_stub_dist();
        let response = get(dashboard_router(dist.path()), "/").await;

        assert_eq!(response.status(), StatusCode::OK);
        let bytes = to_bytes(response.into_body(), 64 * 1024).await.expect("body");
        let body = std::str::from_utf8(&bytes).expect("utf8");
        assert!(
            body.contains(r#"<div id="root">"#),
            "GET / must serve index.html with the React mount node; got: {body}"
        );
    }

    /// AAASM-1580 AC "All JS/CSS assets served with correct Content-Type":
    /// `GET /assets/main.js` reaches the real file and `ServeDir` sets
    /// a JavaScript content-type from its mime-guess table — covers
    /// both `application/javascript` and `text/javascript` because the
    /// canonical value has moved between tower-http releases.
    #[tokio::test]
    async fn dashboard_router_serves_static_assets_with_javascript_content_type() {
        let dist = make_stub_dist();
        let response = get(dashboard_router(dist.path()), "/assets/main.js").await;

        assert_eq!(response.status(), StatusCode::OK);
        let ctype = response
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_owned();
        assert!(
            ctype.contains("javascript"),
            "asset must be served with a JavaScript content-type; got {ctype:?}"
        );
        let bytes = to_bytes(response.into_body(), 64 * 1024).await.expect("body");
        assert_eq!(
            std::str::from_utf8(&bytes).expect("utf8"),
            "export const main = () => 42;\n",
            "asset body must match the file on disk"
        );
    }

    /// AAASM-1580 AC "AAASM_DASHBOARD_DIST=/custom/path env var
    /// overrides default dist path": when the env override resolves to
    /// an existing directory, it wins regardless of what the installed
    /// or dev roots contain — even when *both* would otherwise match.
    #[test]
    fn find_dashboard_dist_prefers_env_override() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let installed = tempfile::tempdir().expect("installed root");
        std::fs::create_dir_all(installed.path().join("dashboard").join("dist")).expect("installed dist");

        let resolved = find_dashboard_dist_in(
            Some(tmp.path().to_string_lossy().into_owned()),
            Some(installed.path().to_path_buf()),
            None,
        );

        assert_eq!(
            resolved.as_deref(),
            Some(tmp.path()),
            "env-var override must beat the installed-layout root"
        );
    }

    /// Negative path of the override: an env value pointing at a path
    /// that is *not* an existing directory must be ignored, and the
    /// helper must fall through to the installed/dev fallbacks. This
    /// keeps a stale env var from blocking a working development tree.
    #[test]
    fn find_dashboard_dist_falls_through_when_env_path_missing() {
        let installed = tempfile::tempdir().expect("installed root");
        let installed_dist = installed.path().join("dashboard").join("dist");
        std::fs::create_dir_all(&installed_dist).expect("installed dist");

        let resolved = find_dashboard_dist_in(
            Some("/definitely/does/not/exist".to_string()),
            Some(installed.path().to_path_buf()),
            None,
        );

        assert_eq!(
            resolved.as_deref(),
            Some(installed_dist.as_path()),
            "missing env-var path must fall through to the installed root"
        );
    }

    /// AAASM-1580 AC "Missing dashboard/dist/ → gateway starts
    /// successfully with warning" at the helper level: when every
    /// candidate root is absent, the resolver returns `None` so the
    /// caller (the local-mode router in AAASM-1844) can warn and skip
    /// mounting the SPA instead of crashing.
    #[test]
    fn find_dashboard_dist_returns_none_when_no_candidate_resolves() {
        let installed = tempfile::tempdir().expect("installed root"); // no dashboard/dist inside
        let dev = tempfile::tempdir().expect("dev root"); //          no dashboard/dist inside

        let resolved = find_dashboard_dist_in(
            None,
            Some(installed.path().to_path_buf()),
            Some(dev.path().to_path_buf()),
        );

        assert_eq!(resolved, None, "missing every candidate must yield None");
    }

    /// AAASM-1580 AC "GET /agents → index.html (SPA fallback, not 404)":
    /// an unknown nested path falls through to `ServeDir::fallback`
    /// (ServeFile of index.html), so React Router receives the SPA
    /// shell with a real 200 status instead of a 404.
    #[tokio::test]
    async fn dashboard_router_falls_back_to_index_on_unknown_path() {
        let dist = make_stub_dist();
        let response = get(dashboard_router(dist.path()), "/agents/abc").await;

        assert_eq!(
            response.status(),
            StatusCode::OK,
            "SPA fallback must return 200, not 404"
        );
        let bytes = to_bytes(response.into_body(), 64 * 1024).await.expect("body");
        let body = std::str::from_utf8(&bytes).expect("utf8");
        assert!(
            body.contains(r#"<div id="root">"#),
            "fallback body must be index.html; got: {body}"
        );
    }
}
