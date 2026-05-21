//! `aasm stop` — graceful shutdown of the locally-managed gateway
//! process (Epic 17 / AAASM-1568 / Story AAASM-1578).
//!
//! Reads the PID file written by `aasm start` (Impl-3, AAASM-1717),
//! sends `SIGTERM`, polls the target until it exits or `--timeout`
//! elapses, and escalates to `SIGKILL` if necessary. Always cleans
//! up the PID file before exiting so the next `aasm start` sees a
//! clean slate.

/// `aasm stop` command-line arguments.
#[derive(Debug, clap::Args)]
pub struct StopArgs {
    /// Seconds to wait for graceful shutdown before SIGKILL.
    #[arg(long, default_value_t = 30)]
    pub timeout: u64,
}
