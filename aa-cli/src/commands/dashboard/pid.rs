//! PID file helpers for `aasm dashboard start` / `stop`.
//!
//! File location: `~/.local/share/aasm/dashboard.pid`
//! File format:   `<pid>\n<port>\n`

use std::io;
use std::path::PathBuf;

/// Returns the path to the dashboard PID file.
pub fn pid_path() -> PathBuf {
    dirs::data_local_dir()
        .expect("cannot determine local data directory")
        .join("aasm")
        .join("dashboard.pid")
}

/// Write `<pid>\n<port>\n` to the PID file, creating parent directories as needed.
pub fn write_pid(port: u16) -> io::Result<()> {
    let path = pid_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let content = format!("{}\n{}\n", std::process::id(), port);
    std::fs::write(&path, content)
}

/// Read `(pid, port)` from the PID file. Returns `None` if the file is absent or malformed.
pub fn read_pid() -> Option<(u32, u16)> {
    let content = std::fs::read_to_string(pid_path()).ok()?;
    let mut lines = content.lines();
    let pid: u32 = lines.next()?.parse().ok()?;
    let port: u16 = lines.next()?.parse().ok()?;
    Some((pid, port))
}

/// Remove the PID file. Succeeds silently if the file does not exist.
pub fn remove_pid() -> io::Result<()> {
    let path = pid_path();
    if path.exists() {
        std::fs::remove_file(path)?;
    }
    Ok(())
}
