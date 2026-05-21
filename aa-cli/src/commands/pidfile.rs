//! PID-file management for the locally-managed `aasm` gateway process.
//!
//! Shared infrastructure for `aasm start` (Impl-3, AAASM-1717) and
//! `aasm stop` (Impl-4, AAASM-1722). Default on-disk location is
//! `~/.aasm/gateway.pid`; tests inject a temp path via the explicit
//! `&Path` arguments on each operation.

/// Errors that can occur while interacting with the PID file.
#[derive(Debug, thiserror::Error)]
pub enum PidFileError {
    /// Filesystem error reading, writing, or removing the file.
    #[error("pid file I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// File contents could not be parsed as a `u32`.
    #[error("pid file contents are not a valid PID: {raw:?}")]
    Parse {
        /// Raw bytes (trimmed) as they appeared on disk.
        raw: String,
    },
    /// `dirs::home_dir()` returned `None` — no resolvable home directory.
    #[error("no home directory could be resolved for the pid file path")]
    NoHomeDir,
}
