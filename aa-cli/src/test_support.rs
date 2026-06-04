//! Shared synchronization for `aa-cli` unit tests.
//!
//! The `aa-cli` unit tests run inside one process under libtest's multi-threaded
//! harness — and so does `cargo test`, which the SonarCloud coverage job uses
//! (unlike `cargo nextest`, which isolates each test in its own process). Several
//! tests mutate process-global state that is unsafe to touch concurrently:
//!
//! - **environment variables** — the process environment is a single global
//!   table, so concurrent `set_var`/`remove_var` from different tests race; and
//! - **ephemeral TCP ports** — a test that frees a `bind(:0)` port can have it
//!   immediately handed to a concurrent `bind(:0)`, breaking "nothing is
//!   listening here" assumptions.
//!
//! These crate-wide locks serialize that access across every test module.

use std::sync::{Mutex, MutexGuard};

/// Serializes all tests that mutate a process environment variable.
static ENV_LOCK: Mutex<()> = Mutex::new(());

/// Serializes all tests that bind an ephemeral (`:0`) TCP port.
static NET_LOCK: Mutex<()> = Mutex::new(());

/// Acquire the shared environment lock for the duration of the returned guard.
///
/// Recovers from a poisoned mutex so a single panicking test does not cascade
/// into every later test.
pub(crate) fn env_guard() -> MutexGuard<'static, ()> {
    ENV_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Acquire the shared ephemeral-port lock for the duration of the returned guard.
pub(crate) fn net_guard() -> MutexGuard<'static, ()> {
    NET_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}
