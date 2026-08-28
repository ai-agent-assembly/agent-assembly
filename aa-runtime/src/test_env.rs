//! Crate-wide, panic-safe env-var guard for `aa-runtime`'s unit tests (AAASM-5970).
//!
//! # Why one guard, one lock, for the whole crate
//!
//! `cargo test -p aa-runtime` (plain, multi-threaded — the command a developer
//! reaches for locally, as opposed to `cargo nextest`, which isolates every
//! test in its own process) runs every `#[test]` in this crate inside ONE
//! process. Three modules mutate process-global env vars that collide across
//! module boundaries: `AA_DEVINT_TOKEN_FILE` (`devint::enrolment` and
//! `runtime::devint_wiring_tests`), `AA_AGENT_ID` / `AA_DEVINT_ENABLED`
//! (`runtime.rs` and `config.rs`), and `PATH` (two sibling tests in
//! `runtime.rs`). A lock scoped to one module only serialises that module's
//! own tests against each other — every other module's tests can still
//! interleave with it, which is exactly the defect this ticket fixes:
//! `devint::enrolment` used to take a `static LOCK` declared *inside* its
//! `with_path` helper, so it excluded only other callers of `with_path` and
//! did nothing about `runtime.rs` or `config.rs` mutating the very same
//! `AA_DEVINT_TOKEN_FILE` / `AA_AGENT_ID` with no lock at all.
//!
//! [`EnvGuard`] is the one lock for the whole crate. Construct it, call
//! [`EnvGuard::set`] / [`EnvGuard::unset`] for every var the test needs to
//! control, and keep the guard bound for as long as those vars must hold
//! their test value. Dropping it — including on an early return via a
//! panicking `assert!` or `.unwrap()` — restores every var to exactly what it
//! held before, newest mutation first, so a test that panics mid-body still
//! leaves the process environment clean for whatever test the harness
//! schedules next (this is the panic-safety property `redirect_into`'s old
//! success-path-only restore, and `with_path`'s unconditional `remove_var`,
//! did not have).
//!
//! # What this guard covers, and what AAASM-5970 deliberately left alone
//!
//! Every test site AAASM-5970 names — `config.rs`, `runtime.rs` (`redirect_into`
//! / `config_with_devint`, both `spawn_proxy_*` `PATH` tests), and
//! `devint/enrolment.rs`'s `with_path` — now goes through this one guard
//! (AC3/AC6).
//!
//! Three more modules mutate process env in their own tests and were **not**
//! converted, because none of them collide with the vars above or with each
//! other, so a crate-wide lock buys them nothing that their existing
//! self-contained serialization doesn't already provide:
//!
//! - `devint/server.rs` has its own module-local `ENV_LOCK` guarding only
//!   `AASM_CLAUDE_MANAGED_ROOT`, a var no other module touches.
//! - `ebpf_control.rs`'s `resolve_socket_honours_env_then_falls_back_to_default`
//!   is the only test in the crate that touches `AA_LOADERD_SOCKET`, sets and
//!   restores it within one `#[test]` body (no cross-test window it can race
//!   through), and already wraps its `set_var`/`remove_var` in `unsafe`.
//!
//! **`layer.rs` is the one exception, and it is a real residual gap, not a
//! safe one:** it has its own module-local `ENV_LOCK` (guarding `AA_LAYERS`,
//! which nothing else touches — fine) but one of its tests
//! (`proxy_layer_detected_via_artifact_presence`, approximately) also blanks
//! and restores `PATH` — the exact same var the two `spawn_proxy_*` tests in
//! `runtime.rs` now guard through *this* module's `EnvGuard`. `layer.rs`'s
//! `ENV_LOCK` and `test_env::EnvGuard`'s lock are two different `Mutex`es
//! over the same process resource, which AAASM-5970 itself identifies as
//! "the same bug with an extra step" when it happens between `enrolment.rs`
//! and `runtime.rs`. It was left unconverted here because AAASM-5970's
//! acceptance criteria enumerate `config.rs`, `runtime.rs`, and
//! `devint/enrolment.rs` specifically and not `layer.rs`; closing it is a
//! judgment call outside this ticket's stated scope, flagged in the PR
//! rather than silently folded in. A follow-up ticket should route
//! `layer.rs`'s `PATH` test through `test_env::EnvGuard` too.
//!
//! # Reentrancy note
//!
//! [`EnvGuard`] holds the crate-wide lock for its entire lifetime, so acquire
//! exactly one per test (or one per helper a test calls exactly once).
//! Acquiring a second guard on the same thread while the first is still alive
//! deadlocks — `std::sync::Mutex` is not reentrant. Add more vars to an
//! already-held guard with [`EnvGuard::set`] / [`EnvGuard::unset`] instead of
//! constructing a second one (see `runtime.rs`'s `redirect_into`, which
//! returns its guard so callers can keep adding to it).

use std::ffi::{OsStr, OsString};
use std::sync::{Mutex, MutexGuard, OnceLock};

fn env_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

/// RAII guard over one or more process env vars, serialized crate-wide.
#[must_use = "dropping this immediately undoes the env-var mutation it just made"]
pub(crate) struct EnvGuard {
    /// Mutations applied so far, oldest first. Restored newest-first on drop
    /// so overriding the same key twice within one guard unwinds correctly:
    /// the second override's "prior" is the first override's value, not the
    /// true original, but LIFO restore walks back through both and lands on
    /// the true original either way.
    entries: Vec<(&'static str, Option<OsString>)>,
    _lock: MutexGuard<'static, ()>,
}

impl EnvGuard {
    /// Acquire the crate-wide lock with no mutations applied yet.
    pub(crate) fn new() -> Self {
        let lock = env_lock().lock().unwrap_or_else(|e| e.into_inner());
        Self {
            entries: Vec::new(),
            _lock: lock,
        }
    }

    /// Set `key` to `value`, remembering whatever it held before.
    pub(crate) fn set(&mut self, key: &'static str, value: impl AsRef<OsStr>) -> &mut Self {
        let prior = std::env::var_os(key);
        // SAFETY: `self._lock` is held for this guard's entire lifetime and
        // every env-mutating test in this crate goes through an `EnvGuard`,
        // so this call is serialized against every other one crate-wide.
        unsafe {
            std::env::set_var(key, value.as_ref());
        }
        self.entries.push((key, prior));
        self
    }

    /// Remove `key`, remembering whatever it held before.
    pub(crate) fn unset(&mut self, key: &'static str) -> &mut Self {
        let prior = std::env::var_os(key);
        // SAFETY: see `set` above.
        unsafe {
            std::env::remove_var(key);
        }
        self.entries.push((key, prior));
        self
    }
}

impl Default for EnvGuard {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        for (key, prior) in self.entries.iter().rev() {
            // SAFETY: see `set` above — the lock is still held here, we are
            // still inside the guard's lifetime during `drop`.
            unsafe {
                match prior {
                    Some(value) => std::env::set_var(key, value),
                    None => std::env::remove_var(key),
                }
            }
        }
    }
}
