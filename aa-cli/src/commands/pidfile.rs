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

/// Check whether `pid` refers to a process that is currently alive.
///
/// Implemented via the Unix idiom `kill(pid, 0)`: signal `0` performs
/// no delivery but still runs the kernel's permission and existence
/// checks. Returns `false` for any failure (process gone, permission
/// denied, invalid PID) — callers treat liveness as a single bit.
pub fn is_pid_alive(pid: u32) -> bool {
    // SAFETY: `kill` with signal 0 is signal-safe and side-effect free;
    // it returns 0 if the process exists and the caller has permission
    // to signal it, -1 otherwise. No memory is dereferenced.
    let rc = unsafe { libc::kill(pid as libc::pid_t, 0) };
    rc == 0
}

/// Remove the PID file at `path`. Idempotent — a missing file is
/// not an error.
///
/// Called by `aasm stop` after the gateway has terminated. Returns
/// any non-`NotFound` filesystem error verbatim so the operator
/// sees permission issues rather than a silently-stuck PID file.
pub fn remove_pid(path: &Path) -> Result<(), PidFileError> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pid_file_path_lives_under_aasm_directory() {
        let path = pid_file_path().expect("home dir resolves in tests");
        // Don't assert against a literal absolute path — `$HOME` differs
        // per machine. Just confirm the structure: `.../.aasm/gateway.pid`.
        assert!(
            path.ends_with(".aasm/gateway.pid"),
            "expected suffix `.aasm/gateway.pid`, got {}",
            path.display()
        );
    }

    #[test]
    fn write_pid_creates_missing_parent_directory() {
        let tmp = tempfile::TempDir::new().unwrap();
        let nested = tmp.path().join("layer-a").join("layer-b").join("gateway.pid");
        // Parent directories do not exist yet.
        assert!(!nested.parent().unwrap().exists());
        write_pid(&nested, 42).expect("write_pid should mkdir -p the parent");
        assert!(nested.exists(), "pid file should exist after write_pid");
    }

    #[test]
    fn read_pid_returns_none_for_missing_file() {
        let tmp = tempfile::TempDir::new().unwrap();
        let absent = tmp.path().join("gateway.pid");
        // Sanity-check: the path really does not exist before we probe it.
        assert!(!absent.exists());
        assert_eq!(read_pid(&absent).unwrap(), None);
    }

    #[test]
    fn write_then_read_round_trip_preserves_pid() {
        let tmp = tempfile::TempDir::new().unwrap();
        let pid_file = tmp.path().join("gateway.pid");
        write_pid(&pid_file, 13_579).unwrap();
        assert_eq!(read_pid(&pid_file).unwrap(), Some(13_579));
    }
}
