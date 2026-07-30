//! Shared utilities for dev tool detection adapters.
//!
//! No in-tree adapter uses these any more: each `aa-devtool-*` crate owns its
//! own detection (AAASM-5274 removed the duplicate adapters that lived here).
//! They are kept as the generic PATH/version helpers for out-of-tree adapters
//! and for future registry-level probing, and are deliberately dependency-free
//! (`std` only) so linking them costs nothing.

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn find_on_path_returns_none_for_nonexistent_binary() {
        assert!(find_on_path("aaasm_nonexistent_binary_xyz123").is_none());
    }

    #[test]
    fn probe_version_returns_none_for_nonexistent_path() {
        assert!(probe_version(std::path::Path::new("/this/path/does/not/exist/aaasm_binary")).is_none());
    }
}
