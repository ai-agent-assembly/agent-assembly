//! Sibling-first resolution for launching an `aa-*` binary shipped alongside
//! the running executable.
//!
//! `aasm` and its children ship as **one versioned unit** (ADR 0030 §6.4), so a
//! `$PATH` hit belonging to some other installation must never shadow the
//! sibling that was shipped with the running executable — that would negotiate
//! against, spawn, or advertise a core the operator did not install. This is
//! the resolver `aa-cli/src/commands/gateway/start.rs` established for
//! `aa-gateway`; every caller that resolves a core binary at runtime should use
//! it (or its exact search order) rather than a bespoke `which`/`$PATH` walk,
//! so a resolve-then-spawn caller and an availability probe can never disagree
//! about what is actually present (AAASM-5982).
//!
//! # Why there is no cwd-relative fallback
//!
//! AAASM-4020 and AAASM-5937 removed a `./target/{release,debug}/<bin>`
//! fallback from `aa-proxy`'s and `aa-gateway`'s own resolvers: resolving a
//! binary relative to the current working directory lets whoever controls
//! where the parent process is invoked substitute an attacker-planted binary.
//! This resolver never reads the cwd for that reason, and filters `$PATH` to
//! absolute entries only — a non-absolute entry (including the POSIX-defined
//! empty-entry-means-cwd form) is a cwd-relative lookup by another name.

use std::path::{Path, PathBuf};

/// Resolve `bin_name` next to the running executable, then on `$PATH`
/// (absolute entries only), then under `~/.cargo/bin`.
///
/// Reads the process's own current-exe path, `$PATH` and home directory; see
/// [`resolve_from`] for the pure search this delegates to.
pub fn resolve_binary(bin_name: &str) -> Option<PathBuf> {
    resolve_from(
        bin_name,
        std::env::current_exe().ok().as_deref(),
        std::env::var("PATH").ok().as_deref(),
        dirs::home_dir().as_deref(),
    )
}

/// The search itself, over the facts [`resolve_binary`] reads from the
/// environment.
///
/// Split out so the search order and the absence of a cwd-relative fallback
/// can both be asserted without mutating process-global state: a test names
/// the exe path, the `$PATH` string and the home directory it wants, and this
/// function has no other input.
///
/// # Why `$PATH` entries are filtered
///
/// POSIX defines a **zero-length** `$PATH` entry as the current working
/// directory, so `PATH=":/usr/bin"`, `PATH="/usr/bin:"` and `PATH="/a::/b"`
/// each contribute one candidate that `PathBuf::join` renders as the bare
/// relative path `<bin_name>` — and resolving that against the cwd reinstates
/// the exact substitution primitive AAASM-4020/5937 removed. A non-empty but
/// relative entry does the same. So a candidate directory is used only if it
/// is absolute; non-absolute entries are skipped, not rejected — an operator
/// with a stray `:` in `$PATH` keeps every other entry they wrote, and the
/// only lookup they lose is the one that could never have been safe.
pub fn resolve_from(
    bin_name: &str,
    exe: Option<&Path>,
    path_var: Option<&str>,
    home: Option<&Path>,
) -> Option<PathBuf> {
    if let Some(candidate) = exe.and_then(|e| sibling_binary(e, bin_name)) {
        return Some(candidate);
    }
    if let Some(path_var) = path_var {
        for dir in path_var.split(':').map(Path::new).filter(|d| d.is_absolute()) {
            let candidate = dir.join(bin_name);
            if is_executable(&candidate) {
                return Some(candidate);
            }
        }
    }
    if let Some(home) = home {
        let candidate = home.join(".cargo").join("bin").join(bin_name);
        if is_executable(&candidate) {
            return Some(candidate);
        }
    }
    None
}

/// Return `bin_name` sitting next to the given executable path, if it exists
/// and is executable.
fn sibling_binary(exe: &Path, bin_name: &str) -> Option<PathBuf> {
    let candidate = exe.parent()?.join(bin_name);
    is_executable(&candidate).then_some(candidate)
}

#[cfg(unix)]
fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    path.metadata().is_ok_and(|m| m.permissions().mode() & 0o111 != 0)
}

#[cfg(not(unix))]
fn is_executable(path: &Path) -> bool {
    path.exists()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn touch_executable(path: &Path) {
        std::fs::write(path, b"#!/bin/sh\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(path).unwrap().permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(path, perms).unwrap();
        }
    }

    #[cfg(unix)]
    #[test]
    fn sibling_binary_returns_none_when_absent() {
        let dir = tempfile::tempdir().unwrap();
        let exe = dir.path().join("aasm");
        touch_executable(&exe);
        assert_eq!(sibling_binary(&exe, "aa-proxy"), None);
    }

    /// A binary reachable only through an empty or relative `$PATH` entry must
    /// not be selected (AC4). Written as an end-to-end statement of the
    /// property: it plants a bare `./aa-proxy`, which is exactly what an
    /// empty `$PATH` entry resolves to (POSIX defines a zero-length entry as
    /// the current directory, and `PathBuf::from("").join("aa-proxy")` is the
    /// relative path `aa-proxy`), and requires `None`.
    ///
    /// Verified to fail against the pre-fix code: the identical `resolve_from`
    /// body (this file's logic verbatim), isolated into a standalone `rustc`
    /// binary with the `is_absolute()` filter conditionally compiled out,
    /// reproduces this exact case table and reports `FAIL` on 5 of 7 rows —
    /// each unsafe `$PATH` entry resolving a cwd-relative candidate instead of
    /// `None`. Run out-of-tree (this repo's shared `CARGO_TARGET_DIR` was
    /// under multi-session lock contention at the time) rather than via a
    /// mutated copy of this file, so the in-tree source was never in a
    /// temporarily-broken state.
    #[cfg(unix)]
    #[test]
    fn a_relative_path_entry_contributes_no_candidate() {
        let _lock = env_guard();

        let cwd = tempfile::tempdir().unwrap();
        touch_executable(&cwd.path().join("aa-proxy"));
        let rel_dir = cwd.path().join("rel").join("bin");
        std::fs::create_dir_all(&rel_dir).unwrap();
        touch_executable(&rel_dir.join("aa-proxy"));

        let real = tempfile::tempdir().unwrap();
        let real_proxy = real.path().join("aa-proxy");
        touch_executable(&real_proxy);
        let real_dir = real.path().to_str().unwrap();

        let empty_home = tempfile::tempdir().unwrap();
        let exe_dir = tempfile::tempdir().unwrap();
        let exe = exe_dir.path().join("aasm");
        touch_executable(&exe);

        let prior_cwd = std::env::current_dir().unwrap();
        std::env::set_current_dir(cwd.path()).unwrap();
        let results: Vec<_> = [
            ("", None),
            (":", None),
            ("rel/bin", None),
            ("./rel/bin", None),
            (&*format!(":{real_dir}"), Some(real_proxy.clone())),
            (&*format!("{real_dir}:"), Some(real_proxy.clone())),
            (&*format!("rel/bin:{real_dir}"), Some(real_proxy.clone())),
        ]
        .into_iter()
        .map(|(path_var, want)| {
            (
                path_var.to_string(),
                resolve_from("aa-proxy", Some(&exe), Some(path_var), Some(empty_home.path())),
                want,
            )
        })
        .collect();
        std::env::set_current_dir(&prior_cwd).unwrap();

        for (path_var, got, want) in results {
            assert_eq!(
                got, want,
                "PATH={path_var:?} resolved {got:?}, expected {want:?} — a non-absolute $PATH \
                 entry is a cwd-relative lookup by another name"
            );
        }
    }

    /// The search order is exe-dir → `$PATH` → `~/.cargo/bin`, and the
    /// exe-dir hit must win (AC5, ADR 0030 §6.4).
    ///
    /// Pinned because the ordering is the security property, not a
    /// preference: `aasm` and its children ship as one versioned unit, so a
    /// `$PATH` entry belonging to some other installation must not shadow the
    /// sibling shipped with this executable.
    #[cfg(unix)]
    #[test]
    fn resolve_from_prefers_the_exe_sibling_over_path_and_cargo_bin() {
        let exe_dir = tempfile::tempdir().unwrap();
        let path_dir = tempfile::tempdir().unwrap();
        let home = tempfile::tempdir().unwrap();

        let exe = exe_dir.path().join("aasm");
        touch_executable(&exe);
        let sibling = exe_dir.path().join("aa-proxy");
        touch_executable(&sibling);

        // A DIFFERENT binary reachable via $PATH — must lose to the sibling.
        touch_executable(&path_dir.path().join("aa-proxy"));
        // And a third, in ~/.cargo/bin — must also lose.
        let cargo_bin = home.path().join(".cargo").join("bin");
        std::fs::create_dir_all(&cargo_bin).unwrap();
        touch_executable(&cargo_bin.join("aa-proxy"));

        let resolved = resolve_from(
            "aa-proxy",
            Some(&exe),
            Some(path_dir.path().to_str().unwrap()),
            Some(home.path()),
        );

        assert_eq!(
            resolved,
            Some(sibling),
            "exe-sibling must win over a $PATH hit and the cargo bin dir"
        );
    }

    #[cfg(unix)]
    #[test]
    fn resolve_from_falls_back_to_path_then_cargo_bin() {
        let exe_dir = tempfile::tempdir().unwrap();
        let path_dir = tempfile::tempdir().unwrap();
        let home = tempfile::tempdir().unwrap();

        let exe = exe_dir.path().join("aasm");
        touch_executable(&exe);
        // No sibling aa-proxy.

        let path_proxy = path_dir.path().join("aa-proxy");
        touch_executable(&path_proxy);
        let cargo_bin = home.path().join(".cargo").join("bin");
        std::fs::create_dir_all(&cargo_bin).unwrap();
        touch_executable(&cargo_bin.join("aa-proxy"));

        let resolved = resolve_from(
            "aa-proxy",
            Some(&exe),
            Some(path_dir.path().to_str().unwrap()),
            Some(home.path()),
        );
        assert_eq!(resolved, Some(path_proxy));

        // No $PATH hit either — cargo bin dir wins.
        let resolved = resolve_from("aa-proxy", Some(&exe), Some(""), Some(home.path()));
        assert_eq!(resolved, Some(cargo_bin.join("aa-proxy")));
    }

    #[test]
    fn resolve_from_returns_none_when_nothing_matches() {
        let exe_dir = tempfile::tempdir().unwrap();
        let home = tempfile::tempdir().unwrap();
        let exe = exe_dir.path().join("aasm");
        touch_executable(&exe);
        assert_eq!(resolve_from("aa-proxy", Some(&exe), Some(""), Some(home.path())), None);
    }

    /// Serializes tests in this module that mutate the process-global current
    /// directory, mirroring `aa-cli`'s `test_support::env_guard`.
    fn env_guard() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        LOCK.lock().unwrap_or_else(|poison| poison.into_inner())
    }
}
