//! PID-file management for the locally-managed `aasm` gateway process.
//!
//! Shared infrastructure for `aasm start` (Impl-3, AAASM-1717) and
//! `aasm stop` (Impl-4, AAASM-1722). Default on-disk location is
//! `~/.aasm/gateway.pid`; tests inject a temp path via the explicit
//! `&Path` arguments on each operation.

use std::path::{Path, PathBuf};

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

/// Default PID file path: `$HOME/.aasm/gateway.pid`.
///
/// Returns `PidFileError::NoHomeDir` if `dirs::home_dir()` cannot
/// resolve a home directory (rare; sandboxed CI environments).
pub fn pid_file_path() -> Result<PathBuf, PidFileError> {
    let home = dirs::home_dir().ok_or(PidFileError::NoHomeDir)?;
    Ok(home.join(".aasm").join("gateway.pid"))
}

/// Write `pid` to `path`, creating parent directories if needed.
///
/// Overwrites any existing file. The PID is written as ASCII
/// decimal with a single trailing newline so the file is editor-
/// and `cat`-friendly.
pub fn write_pid(path: &Path, pid: u32) -> Result<(), PidFileError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, format!("{pid}\n"))?;
    Ok(())
}

/// Read the PID from `path`.
///
/// Returns `Ok(None)` (not `Err`) when the file is absent — that
/// is the common "no gateway running" case and shouldn't surface
/// as an error to callers. Garbage contents yield `PidFileError::Parse`.
pub fn read_pid(path: &Path) -> Result<Option<u32>, PidFileError> {
    let raw = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    let trimmed = raw.trim();
    trimmed.parse::<u32>().map(Some).map_err(|_| PidFileError::Parse {
        raw: trimmed.to_string(),
    })
}
