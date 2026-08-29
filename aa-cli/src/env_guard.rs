//! Process-global serialization for fixtures that mutate shared process state
//! (environment variables, current working directory).
//!
//! [`test_support::env_guard`](crate::test_support) already does this for
//! `aa-cli`'s own unit tests, but it is `#[cfg(test)]` and `pub(crate)` — reachable
//! only from code compiled as part of *this* crate's own test build. A file under
//! `aa-cli/tests/` compiles to its own separate binary that links `aa_cli` as an
//! ordinary, non-`cfg(test)` dependency, so it cannot name that module (AAASM-5989).
//! This one is deliberately an ordinary public item so an integration-test binary
//! can reach it; the shipped `aasm` binary links it but never calls it.
//!
//! `cargo nextest` isolates each test in its own process, so contention here is
//! zero under the documented test command — this exists for `cargo test`, where
//! every test in one file shares a process and races on any global mutation
//! neither serializes nor undoes.
//!
//! # Why reentrant
//!
//! A single test commonly layers two independent fixtures that each mutate
//! process-global state — e.g. one setting the working directory, a second (built
//! and held for its own lifetime, nested inside the first) setting environment
//! variables. Both need this guard; a plain non-reentrant [`Mutex`] would deadlock
//! the outer fixture against the inner one on the *same* thread. [`lock`] is
//! therefore reentrant per-thread: a nested call on the thread already holding the
//! guard succeeds immediately instead of blocking, while a call from a genuinely
//! different thread still waits for the real lock. Only the outermost [`EnvGuard`]
//! on a given thread holds the underlying [`MutexGuard`]; inner ones are cheap.

use std::cell::Cell;
use std::sync::{Mutex, MutexGuard};

static PROCESS_ENV_LOCK: Mutex<()> = Mutex::new(());

thread_local! {
    /// How many live [`EnvGuard`]s the current thread holds. Only the first
    /// (depth 0 → 1) actually takes [`PROCESS_ENV_LOCK`]; deeper ones just count.
    static DEPTH: Cell<u32> = const { Cell::new(0) };
}

/// Holds the process-wide environment/cwd lock (or, for a nested acquisition on
/// the same thread, just a share of the outermost one) until dropped.
pub struct EnvGuard {
    // `None` for a nested (nonzero-depth) acquisition — the outermost `EnvGuard`
    // on this thread owns the real guard, this one only tracks depth on drop.
    _real: Option<MutexGuard<'static, ()>>,
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        DEPTH.with(|d| d.set(d.get() - 1));
    }
}

/// Acquire the process-wide lock guarding environment variable and working
/// directory mutation shared across `aa-cli`'s `tests/` fixtures.
///
/// Recovers from a poisoned mutex so one panicking fixture does not cascade
/// into every later one in the same binary. Reentrant per-thread — see the
/// module docs — so nesting two guarded fixtures in one test is safe.
pub fn lock() -> EnvGuard {
    let depth = DEPTH.with(|d| d.get());
    let real = if depth == 0 {
        Some(PROCESS_ENV_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner()))
    } else {
        None
    };
    DEPTH.with(|d| d.set(depth + 1));
    EnvGuard { _real: real }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Falsifies the reentrancy claim directly: a non-reentrant `Mutex` would
    /// hang forever on the second `lock()` here, on the same thread as the
    /// first.
    #[test]
    fn reentrant_lock_on_one_thread_does_not_deadlock() {
        let _outer = lock();
        let _inner = lock();
    }

    /// Falsifies serialization directly (AAASM-5989's falsification
    /// requirement 2): two threads each hold the guard across a sleep while
    /// recording an enter/exit pair. If the guard actually excludes a
    /// concurrent holder, one thread's pair is always adjacent in the
    /// recorded order — never interleaved with the other's.
    #[test]
    fn two_threads_serialize_through_the_guard() {
        static ORDER: Mutex<Vec<&'static str>> = Mutex::new(Vec::new());
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));

        let spawn = |label: &'static str, barrier: std::sync::Arc<std::sync::Barrier>| {
            std::thread::spawn(move || {
                barrier.wait();
                let _guard = lock();
                ORDER.lock().unwrap().push(label);
                std::thread::sleep(std::time::Duration::from_millis(50));
                ORDER.lock().unwrap().push(label);
            })
        };
        let a = spawn("a", std::sync::Arc::clone(&barrier));
        let b = spawn("b", barrier);
        a.join().unwrap();
        b.join().unwrap();

        let order = ORDER.lock().unwrap().clone();
        assert!(
            order == ["a", "a", "b", "b"] || order == ["b", "b", "a", "a"],
            "guard did not serialize the two threads: {order:?}"
        );
    }
}
