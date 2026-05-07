//! Shared utilities for dev tool detection adapters.

use std::path::PathBuf;

/// Search PATH entries for a binary with the given name.
///
/// Returns the first matching executable path, or `None` if the binary
/// is not found in any PATH directory.
pub fn find_on_path(binary: &str) -> Option<PathBuf> {
    let path_var = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path_var) {
        let candidate = dir.join(binary);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

/// Run `<binary> --version` and return the first non-empty line of stdout.
///
/// Returns `None` if the process fails to start, exits with a non-zero status,
/// or produces no output.
pub fn probe_version(binary: &std::path::Path) -> Option<String> {
    let output = std::process::Command::new(binary).arg("--version").output().ok()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    stdout
        .lines()
        .find(|l| !l.trim().is_empty())
        .map(|l| l.trim().to_owned())
}
