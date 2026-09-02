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
    find_on_path_in(binary, std::env::var_os("PATH")?)
}

/// The search itself, over the `$PATH` value [`find_on_path`] reads from the
/// environment. Split out so it can be tested without racing every other test
/// in the binary over the process environment.
///
/// # Why `$PATH` entries are filtered to absolute paths
///
/// A zero-length or relative `$PATH` entry is not a directory to search —
/// `std::env::split_paths` does not drop empty entries, and joining `binary`
/// onto one yields a bare relative path that `is_file()` resolves against the
/// process cwd (POSIX treats a zero-length `$PATH` prefix as "."). This
/// function's return value is meant to be executed (`probe_version` does
/// exactly that immediately beside it), so a relative candidate here is the
/// same attacker-substitution primitive AAASM-4020/AAASM-5937/AAASM-5979
/// removed from the launcher lookups: an attacker who controls the directory
/// the caller runs from, on a host whose `$PATH` carries a stray colon, gets
/// their binary executed as the probed tool. Non-absolute entries are
/// skipped, not rejected, so the rest of `$PATH` still resolves. See
/// AAASM-5979.
fn find_on_path_in(binary: &str, path_var: std::ffi::OsString) -> Option<PathBuf> {
    for dir in std::env::split_paths(&path_var).filter(|d| d.is_absolute()) {
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

    /// Serializes every test below that calls `std::env::set_current_dir` — the
    /// process cwd is global state shared across every test in this binary.
    static CWD_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn cwd_guard() -> std::sync::MutexGuard<'static, ()> {
        CWD_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn touch(path: &std::path::Path) {
        std::fs::write(path, b"#!/bin/sh\n").unwrap();
    }

    /// AAASM-5979 AC 3 (regression) and AC 5 (falsified against the pre-fix
    /// shape): with cwd set to a directory holding a planted binary at the bare
    /// name, every one of `""`, `":"`, `"rel/bin"` and `"./rel/bin"` on `$PATH`
    /// must resolve nothing. The plant is at the bare binary name because that
    /// is exactly the candidate those entries produce
    /// (`PathBuf::from("").join(binary)` is the bare relative path); a plant
    /// anywhere else cannot detect this defect.
    ///
    /// Falsified: reverting the `.filter(|d| d.is_absolute())` in
    /// `find_on_path_in` turns every case below into `Some(..)`, reddening this
    /// test.
    #[test]
    fn a_relative_or_empty_path_entry_contributes_no_candidate() {
        let _cwd_lock = cwd_guard();

        let binary = "aaasm-adversarial-probe";
        let cwd = tempfile::tempdir().unwrap();
        touch(&cwd.path().join(binary));
        let rel_dir = cwd.path().join("rel").join("bin");
        std::fs::create_dir_all(&rel_dir).unwrap();
        touch(&rel_dir.join(binary));

        let prior_cwd = std::env::current_dir().unwrap();
        std::env::set_current_dir(cwd.path()).unwrap();
        let results: Vec<_> = ["", ":", "rel/bin", "./rel/bin"]
            .into_iter()
            .map(|path_var| {
                let got = find_on_path_in(binary, std::ffi::OsString::from(path_var));
                (path_var, got)
            })
            .collect();
        std::env::set_current_dir(&prior_cwd).unwrap();

        for (path_var, got) in results {
            assert!(
                got.is_none(),
                "PATH={path_var:?} resolved {got:?} — a non-absolute $PATH entry let a \
                 cwd-planted binary stand in for the probed tool (AAASM-5979)"
            );
        }
    }

    /// AAASM-5979 AC 4 (no-behaviour-change control) and AC 5 (falsified
    /// against an over-broad fix): the same unsafe entries paired with a real
    /// absolute directory on the same `$PATH` string — including with the
    /// unsafe entry first — must still resolve that directory's binary.
    ///
    /// Falsified: replacing the `is_absolute()` filter with one that drops
    /// every entry turns every case below into `None`, reddening this test.
    #[test]
    fn a_real_absolute_path_entry_still_resolves_beside_an_unsafe_one() {
        let _cwd_lock = cwd_guard();

        let binary = "aaasm-adversarial-probe";
        let cwd = tempfile::tempdir().unwrap();
        touch(&cwd.path().join(binary));
        let rel_dir = cwd.path().join("rel").join("bin");
        std::fs::create_dir_all(&rel_dir).unwrap();
        touch(&rel_dir.join(binary));

        let real = tempfile::tempdir().unwrap();
        let real_binary = real.path().join(binary);
        touch(&real_binary);
        let real_dir = real.path().to_str().unwrap();

        let prior_cwd = std::env::current_dir().unwrap();
        std::env::set_current_dir(cwd.path()).unwrap();
        let results: Vec<_> = [
            format!(":{real_dir}"),
            format!("{real_dir}:"),
            format!("rel/bin:{real_dir}"),
            format!("{real_dir}:rel/bin"),
        ]
        .into_iter()
        .map(|path_var| {
            let got = find_on_path_in(binary, std::ffi::OsString::from(path_var.clone()));
            (path_var, got)
        })
        .collect();
        std::env::set_current_dir(&prior_cwd).unwrap();

        for (path_var, got) in results {
            assert_eq!(
                got,
                Some(real_binary.clone()),
                "PATH={path_var:?} failed to resolve the real binary directory alongside \
                 an unsafe entry"
            );
        }
    }
}
