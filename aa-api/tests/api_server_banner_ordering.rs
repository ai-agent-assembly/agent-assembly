//! Regression test for AAASM-4572.
//!
//! `aa-api-server` must not print its "serving full /api/v1/* REST surface"
//! banner when startup will abort on a malformed `AASM_API_KEY`. The banner
//! implies the port is bound and the server is up; a script, systemd
//! `ExecStartPost` probe, or container readiness scraper reading stdout/stderr
//! top-to-bottom would treat it as a successful start. Announcing "serving" and
//! then exiting non-zero must be mutually exclusive — never both.
//!
//! This drives the shipped binary end-to-end (not an internal helper) because
//! the bug was purely one of ordering in `main()`: the format validation must
//! run before the banner is emitted.

use std::process::Command;

/// A too-short (7-char hex) key that `ApiKey::parse` rejects for length.
const MALFORMED_KEY: &str = "aa_test123";

/// The exact substring the success banner prints — the thing that must NOT
/// appear on the abort path.
const SERVING_BANNER: &str = "serving full /api/v1/* REST surface";

#[test]
fn malformed_api_key_aborts_without_printing_serving_banner() {
    let output = Command::new(env!("CARGO_BIN_EXE_aa-api-server"))
        .env("AASM_API_KEY", MALFORMED_KEY)
        // Never actually reached (parse fails first), but keep the run hermetic.
        .env("AA_API_ADDR", "127.0.0.1:0")
        .output()
        .expect("spawn aa-api-server");

    assert!(
        !output.status.success(),
        "expected a non-zero exit for a malformed AASM_API_KEY, got {:?}",
        output.status
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains(SERVING_BANNER),
        "the '{SERVING_BANNER}' banner must NOT be printed when startup aborts on \
         a malformed key — the banner implies the server is up. stderr was:\n{stderr}"
    );
    assert!(
        stderr.contains("invalid AASM_API_KEY"),
        "expected a clear 'invalid AASM_API_KEY' error on the abort path. stderr was:\n{stderr}"
    );
}
