//! Rust helper for invoking `tests/fixtures/sdk_driver.py` (AAASM-1078 / ST-2).
//!
//! Used by both the hermetic ST-2 selftest and (in ST-3) the real
//! parent→child registration scenario against a running gateway.

use std::path::PathBuf;
use std::process::{Command, Output};

/// Locate `tests/fixtures/sdk_driver.py` relative to the crate's manifest
/// directory. Cargo sets `CARGO_MANIFEST_DIR` for both `cargo test` and
/// `cargo run` invocations.
pub fn fixture_path() -> PathBuf {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    PathBuf::from(manifest_dir)
        .join("tests")
        .join("fixtures")
        .join("sdk_driver.py")
}

/// Run the Python driver with the given CLI args + extra env vars and
/// return its captured output. Resolves `python3` from `$PATH`; CI is
/// expected to provide it via `actions/setup-python`.
pub fn run(args: &[&str], envs: &[(&str, &str)]) -> std::io::Result<Output> {
    let script = fixture_path();
    let mut cmd = Command::new("python3");
    cmd.arg(&script);
    cmd.args(args);
    for (k, v) in envs {
        cmd.env(k, v);
    }
    cmd.output()
}
