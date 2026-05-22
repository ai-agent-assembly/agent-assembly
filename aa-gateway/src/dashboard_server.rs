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
