//! `aasm start` — explicit lifecycle command for the locally-managed
//! gateway process (Epic 17 / AAASM-1568 / Story AAASM-1578).
//!
//! This module is the CLI surface. It spawns the existing
//! `aa-gateway` binary, manages the PID file via [`pidfile`], and
//! waits for the listener to come up via [`gw_probe`]. The actual
//! mode-dispatch logic (`--mode local` vs `--mode remote`) is
//! delivered by AAASM-1576 and AAASM-1577 — until those land,
//! `aasm start` translates its high-level flags into the gateway's
//! current `--listen` flag and accepts `--config` / `--no-dashboard`
//! as a no-op so the operator-facing surface is stable.
//!
//! See the sibling `pidfile` and `gw_probe` modules for the
//! primitives used here.
//!
//! [`pidfile`]: super::pidfile
//! [`gw_probe`]: super::gw_probe

/// Which deployment mode `aasm start` should hand off to.
///
/// Mirrors `aa_core::config::DeploymentMode` but is defined here so
/// the CLI parser doesn't pull a runtime dependency into a value-
/// type module that other crates may want to import standalone.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
#[clap(rename_all = "lowercase")]
pub enum ModeArg {
    /// In-process control plane on `127.0.0.1` (default).
    Local,
    /// Remote control plane bound to `0.0.0.0`.
    Remote,
}
