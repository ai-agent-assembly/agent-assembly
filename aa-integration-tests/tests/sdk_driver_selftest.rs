//! AAASM-1078 / ST-2 acceptance test.
//!
//! Asserts `python3 sdk_driver.py --selftest` exits 0 hermetically (no
//! gateway, no SDK install, no Rust harness state) and that stdout
//! contains the JSON contract the Rust assertions module (ST-3) will read.

mod common;

use common::sdk_driver;

#[test]
fn selftest_exits_zero_and_emits_agent_id_json() {
    let output = sdk_driver::run(&["--selftest"], &[]).expect("spawn python3 sdk_driver.py");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "sdk_driver.py --selftest must exit 0; got {:?}\nstdout:\n{stdout}\nstderr:\n{stderr}",
        output.status.code(),
    );

    let trimmed = stdout.trim();
    let json: serde_json::Value =
        serde_json::from_str(trimmed).unwrap_or_else(|e| panic!("stdout must be JSON: {e}\nstdout: {trimmed:?}"));
    assert!(
        json.get("parent_agent_id").and_then(|v| v.as_str()).is_some(),
        "JSON must include parent_agent_id (got {json:?})",
    );
    assert!(
        json.get("child_agent_id").and_then(|v| v.as_str()).is_some(),
        "JSON must include child_agent_id (got {json:?})",
    );
}
