//! Per-launch temp state allocation for the dedicated proxy (AAASM-5862).
//!
//! What [`ProxyGuard`](super::guard::ProxyGuard) needs from a caller is a
//! `ready_file` path and (optionally) an `audit_jsonl_path` — this module is
//! where those get decided for the `aasm run` golden path, kept separate
//! from `ProxyGuard` itself so the guard's own mechanics stay agnostic to
//! storage layout (see that module's crate doc).
//!
//! `ca_dir` deliberately has **no** per-launch counterpart here: the whole
//! point of [`shared_ca_dir`] is that every launch resolves to the *same*
//! path (`aa-cli/src/commands/proxy/ca.rs::default_ca_dir`, the identical
//! default `ProxyConfig::from_env` uses) — see `ProxyGuardOptions::ca_dir`'s
//! doc for why a per-launch CA dir would be actively wrong (a fresh CA per
//! launch, re-prompting macOS Keychain trust every `aasm run`).

use std::path::PathBuf;

/// Everything a launch's dedicated proxy needs written to disk, all inside
/// one directory so cleanup can reason about it as a unit.
pub struct PerLaunchState {
    /// The directory this state lives in — `${state_root}/runs/<label>`.
    /// Not itself removed by anything in this crate: see the module doc on
    /// [`PerLaunchState::audit_jsonl_path`] for why.
    pub dir: PathBuf,
    /// Passed to `ProxyGuardOptions::ready_file`. Removed by `ProxyGuard`'s
    /// own `Drop` — that lifecycle is the guard's, not this module's.
    pub ready_file: PathBuf,
    /// Passed to `ProxyGuardOptions::audit_jsonl_path`. **Never removed by
    /// this module or by `ProxyGuard`** — "remove temporary proxy state"
    /// (the ready file, a pure coordination artifact) and "preserve final
    /// audit evidence" (this file, the actual governance record) are
    /// different obligations on the same per-launch directory, and
    /// conflating them would delete the evidence a governed launch exists
    /// to produce. A retention/pruning policy for old launches' audit
    /// evidence, if wanted, is separate scope from allocating it.
    pub audit_jsonl_path: PathBuf,
}

/// Allocate a fresh per-launch directory under `${AASM_STATE_DIR:-~/.aasm}/
/// runs/` and the paths within it `ProxyGuardOptions` needs.
///
/// `label` names the directory (typically the registered agent id — see
/// `run_state_label` below) and only affects readability; uniqueness comes
/// from `tempfile`'s own suffix generation, not from the label being unique
/// on its own. Two launches with the same label (e.g. two calls with no
/// agent id) still get two distinct directories.
pub fn allocate(label: &str) -> std::io::Result<PerLaunchState> {
    let root = runs_root()?;
    std::fs::create_dir_all(&root)?;

    // `tempfile::Builder::tempdir_in` for the collision-proof unique suffix
    // it already implements correctly (mkdtemp-style), then `.keep()`
    // to hand back a plain `PathBuf` and disarm `TempDir`'s auto-delete-on-
    // drop — this directory's lifetime is this module's/`ProxyGuard`'s to
    // manage explicitly (see `PerLaunchState::audit_jsonl_path`'s doc), not
    // tied to how long some Rust value happens to stay in scope.
    let dir = tempfile::Builder::new()
        .prefix(&format!("{}-", sanitize_label(label)))
        .tempdir_in(&root)?
        .keep();

    Ok(PerLaunchState {
        ready_file: dir.join("ready"),
        audit_jsonl_path: dir.join("audit.jsonl"),
        dir,
    })
}

/// `${AASM_STATE_DIR:-~/.aasm}/runs` — sibling of
/// `aa-proxy/src/config.rs::integration_state_dir`'s `integrations/` under
/// the same state root, so both respect the same override.
fn runs_root() -> std::io::Result<PathBuf> {
    let base = match std::env::var_os("AASM_STATE_DIR") {
        Some(dir) if !dir.is_empty() => PathBuf::from(dir),
        _ => dirs::home_dir()
            .ok_or_else(|| std::io::Error::other("cannot determine home directory"))?
            .join(".aasm"),
    };
    Ok(base.join("runs"))
}

/// A directory-name-safe rendering of `label`. Registered agent ids are
/// `did:key:...` — colons are valid in a Unix path component but needlessly
/// hostile to shell-glob and log-grep ergonomics, so they (and anything else
/// outside a conservative safe set) become `_`. Never the sole source of
/// uniqueness — see [`allocate`]'s doc.
fn sanitize_label(label: &str) -> String {
    let cleaned: String = label
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    if cleaned.is_empty() {
        "launch".to_string()
    } else {
        cleaned
    }
}

/// The label `allocate` should be called with for a normal `aasm run`
/// launch: the registered agent id if one exists, or a fixed fallback for
/// contexts with no registered identity (`--no-proxy`-adjacent paths never
/// reach here at all, since they skip the dedicated proxy entirely).
pub fn run_state_label(agent_id: Option<&str>) -> &str {
    agent_id.unwrap_or("unregistered")
}

/// The one CA directory every launch — dedicated or standalone — must agree
/// on. See the module doc for why this has no per-launch variant.
pub fn shared_ca_dir() -> PathBuf {
    super::ca::default_ca_dir()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Sets `AASM_STATE_DIR` to a fresh temp dir for the duration of the
    /// guard, restoring whatever was there before on drop, under the
    /// crate-wide environment lock (`crate::test_support::env_guard`) — this
    /// module's tests are not the only ones in the crate that read this
    /// process-global table, and libtest's default multi-threaded harness
    /// runs them concurrently unless something serializes the mutation.
    struct StateDirGuard {
        _lock: std::sync::MutexGuard<'static, ()>,
        _tmp: tempfile::TempDir,
        prior: Option<std::ffi::OsString>,
    }
    impl StateDirGuard {
        fn new() -> Self {
            let lock = crate::test_support::env_guard();
            let prior = std::env::var_os("AASM_STATE_DIR");
            let tmp = tempfile::tempdir().unwrap();
            std::env::set_var("AASM_STATE_DIR", tmp.path());
            Self {
                _lock: lock,
                _tmp: tmp,
                prior,
            }
        }
    }
    impl Drop for StateDirGuard {
        fn drop(&mut self) {
            match self.prior.take() {
                Some(v) => std::env::set_var("AASM_STATE_DIR", v),
                None => std::env::remove_var("AASM_STATE_DIR"),
            }
        }
    }

    /// AAASM-5862's own acceptance test: two launches must not collide on
    /// the artifacts they each need to be unique, must agree on the one
    /// they must not be.
    #[test]
    fn two_allocations_get_distinct_audit_and_ready_paths_but_share_the_ca_dir() {
        let _guard = StateDirGuard::new();

        let a = allocate(run_state_label(Some("did:key:agentA"))).unwrap();
        let b = allocate(run_state_label(Some("did:key:agentB"))).unwrap();

        assert_ne!(a.ready_file, b.ready_file, "two launches must not share a ready file");
        assert_ne!(
            a.audit_jsonl_path, b.audit_jsonl_path,
            "two launches must not share an audit log"
        );
        assert_ne!(a.dir, b.dir, "two launches must not share a state directory");

        // The regression this test exists to guard: ca_dir is not part of
        // PerLaunchState at all — it comes from shared_ca_dir(), called
        // once, independent of any per-launch label.
        assert_eq!(
            shared_ca_dir(),
            shared_ca_dir(),
            "the CA dir resolution must be a pure function of the environment, not of the launch"
        );
    }

    /// Same label (the common case: two launches with no registered agent
    /// id both fall back to "unregistered") must still not collide —
    /// uniqueness comes from `tempfile`, not from the label.
    #[test]
    fn identical_labels_still_get_distinct_directories() {
        let _guard = StateDirGuard::new();

        let a = allocate(run_state_label(None)).unwrap();
        let b = allocate(run_state_label(None)).unwrap();
        assert_ne!(a.dir, b.dir);
    }

    #[test]
    fn sanitize_label_replaces_unsafe_characters() {
        assert_eq!(sanitize_label("did:key:z6MkAbC123"), "did_key_z6MkAbC123");
        assert_eq!(sanitize_label(""), "launch");
        assert_eq!(sanitize_label("already-safe_123"), "already-safe_123");
    }

    #[test]
    fn allocate_creates_a_real_readable_directory() {
        let _guard = StateDirGuard::new();
        let state = allocate("test").unwrap();
        assert!(
            state.dir.is_dir(),
            "allocate must actually create the directory, not just name it"
        );
    }
}
