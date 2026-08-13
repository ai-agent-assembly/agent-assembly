//! Shared synchronization for this crate's unit tests.
//!
//! The process environment is one global table, so two tests that
//! `set_var`/`remove_var` concurrently race. `cargo nextest` hides this by
//! giving each test its own process, but plain `cargo test` — which the
//! SonarCloud coverage job runs — executes a crate's tests in one process under
//! libtest's multi-threaded harness, where the race is real.
//!
//! A lock is per test binary, so this is deliberately `aa-policy`'s own rather
//! than something shared with `aa-cli`: that crate's tests run in a different
//! process and cannot contend with these.

use std::sync::{Mutex, MutexGuard};

/// Serializes every test in this crate that mutates a process environment
/// variable.
static ENV_LOCK: Mutex<()> = Mutex::new(());

/// Acquire the shared environment lock for the duration of the returned guard.
///
/// Recovers from a poisoned mutex so one panicking test does not cascade into
/// every later test that needs the environment.
pub(crate) fn env_guard() -> MutexGuard<'static, ()> {
    ENV_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}
