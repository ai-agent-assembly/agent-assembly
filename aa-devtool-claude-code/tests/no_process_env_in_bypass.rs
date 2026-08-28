//! A source-scan negative control for AAASM-5993.
//!
//! # Why a source scan and not just the 2×2 behavioural matrix
//!
//! `claude_code_lifecycle.rs` proves `environment_bypasses` behaves correctly
//! for the inputs it is given. It cannot prove nobody *also* left a
//! `std::env` read sitting next to it — a second, unused read of the process
//! environment would pass every behavioural test while still being exactly
//! the AAASM-5993 defect for a caller that reads the wrong function. This
//! test scans `bypass.rs`'s own source for the pattern directly, so the
//! absence of the bug is a property of the file, not just of one function's
//! observed behaviour.
//!
//! The positive control matters as much as the scan itself: a scan that never
//! fires proves nothing. [`the_scanner_actually_flags_a_process_env_read`]
//! writes a file that *does* read the process environment and asserts the
//! same matching logic catches it, so a silently-broken scanner cannot pass
//! this test by doing nothing.

use std::path::Path;

/// Whether `source` contains a read of the process environment via
/// `std::env`.
///
/// A plain substring match rather than a parse: blunt, but precise enough for
/// one file, and [`the_scanner_actually_flags_a_process_env_read`] is what
/// keeps it honest.
fn reads_process_env(source: &str) -> bool {
    ["std::env::var", "std::env::vars", "env::var(", "env::vars("]
        .iter()
        .any(|pattern| source.contains(pattern))
}

/// `bypass.rs` must read a caller-stated [`CallerEnvironment`], never the
/// process environment of whatever happens to be running it — AAASM-5993's
/// whole point is that the process running it is a shared daemon, not the
/// caller.
///
/// This scans `bypass.rs` alone, never this test's own source, so the literal
/// patterns [`reads_process_env`] and the positive control below deliberately
/// contain cannot make this assertion fire on itself.
#[test]
fn bypass_rs_never_reads_the_process_environment() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/bypass.rs");
    let source = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path:?}: {e}"));
    assert!(
        !reads_process_env(&source),
        "{path:?} reads the process environment directly (AAASM-5993): a bypass check must read a \
         CallerEnvironment the caller supplied, never std::env — the daemon's own environment \
         describes the daemon, not the caller asking about it"
    );
}

/// Proves [`reads_process_env`] actually fires, so
/// [`bypass_rs_never_reads_the_process_environment`] passing means "no match
/// found" and not "the matcher is broken".
#[test]
fn the_scanner_actually_flags_a_process_env_read() {
    let dir = tempfile::tempdir().expect("tempdir");
    let file = dir.path().join("would_be_a_regression.rs");
    std::fs::write(
        &file,
        "fn f() -> Option<String> { std::env::var(\"ANTHROPIC_BASE_URL\").ok() }",
    )
    .expect("write fixture");
    let source = std::fs::read_to_string(&file).expect("read fixture");
    assert!(
        reads_process_env(&source),
        "the scanner's own matching logic no longer detects a process environment read; it would \
         pass bypass_rs_never_reads_the_process_environment by doing nothing"
    );
}
