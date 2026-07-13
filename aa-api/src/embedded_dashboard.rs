//! Dashboard SPA embedded into the `aa-api-server` binary (AAASM-4517).
//!
//! `aasm start --mode local` execs `aa-api-server` to serve the dashboard at
//! `GET /` plus the full `/api/v1/*` REST surface from one process. That SPA is
//! normally resolved from a `dashboard/dist/` directory on disk
//! (`aa_gateway::dashboard_server::find_dashboard_dist`), but a bare release
//! tarball unpacks to just the binary — no `dashboard/dist/` adjacent — so the
//! path lookup returns `None` and the server previously fell back to REST-only,
//! leaving the flagship quick-start's "see your agent in the dashboard" step
//! with a 404 (the rc.4 gap this ticket fixes).
//!
//! To close that gap the compiled SPA is baked into the binary via
//! `include_dir!`, exactly as `aa-cli` already does for `aasm dashboard start`
//! (`aa-cli/src/commands/dashboard/start.rs`, ADR AAASM-2340). `aa-api` serves
//! the SPA through `aa_gateway::dashboard_server::dashboard_router`, which reads
//! from a filesystem path (`ServeDir`), so the embedded bundle is extracted to a
//! temp directory at boot and that path is handed to the existing SPA wiring —
//! reusing the one code path rather than duplicating the static-file handler.
//!
//! The embedded directory is populated by `build.rs`: it mirrors a sibling
//! `../dashboard/dist/` when present (local dev) and otherwise writes a
//! "dashboard not built" stub so the crate always compiles. The real release
//! artifact is produced by staging the freshly-built `dashboard/dist/` into
//! `_embedded/` before `cargo build -p aa-api` (release.yml).

use include_dir::{include_dir, Dir};

/// The compiled dashboard SPA, embedded at build time from
/// `_embedded/dashboard/dist/` (populated by `build.rs`).
static DASHBOARD_ASSETS: Dir<'_> = include_dir!("$CARGO_MANIFEST_DIR/_embedded/dashboard/dist");

/// Extract the embedded dashboard SPA into a fresh temporary directory and
/// return its guard.
///
/// The returned [`tempfile::TempDir`]'s path is a ready-to-serve
/// `dashboard/dist/` layout (its contents are `index.html` + `assets/…`). The
/// caller must keep the guard alive for as long as the SPA is served: dropping
/// it deletes the extracted files that `ServeDir` reads. Returns an
/// `io::Error` only if the temp dir cannot be created or written.
pub fn extract_embedded_dashboard() -> std::io::Result<tempfile::TempDir> {
    let tmp = tempfile::Builder::new().prefix("aasm-dashboard-").tempdir()?;
    DASHBOARD_ASSETS.extract(tmp.path())?;
    Ok(tmp)
}
