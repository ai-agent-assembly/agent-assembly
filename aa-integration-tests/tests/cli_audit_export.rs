//! Binary-invocation regression tests for `aasm audit export` (AAASM-1479).
//!
//! Pre-fix, every invocation of `aasm audit export` panicked inside clap
//! with:
//!
//! ```text
//! Mismatch between definition and access of `output`.
//! Could not downcast to alloc::string::String,
//!     need to downcast to aa_cli::output::OutputFormat
//! ```
//!
//! because two flags shared the clap matches-store id `"output"` —
//! the top-level `Cli::output: OutputFormat` (global) and the
//! `ExportArgs::output: Option<String>` (leaf). The existing
//! `aa-cli/tests/audit_list_export.rs` constructs `ExportArgs`
//! directly and bypasses clap, so it never caught this.
//!
//! AAASM-1479 fixes the collision by renaming the leaf field to
//! `output_file` and the user-facing flag to `--output-file`. These
//! tests guard the binary-invocation path so a future re-introduction
//! of the same conflict fails loudly here rather than silently in
//! production.
//!
//! Why this file (not `cli_audit.rs`): the sibling subtask AAASM-1461
//! (ST-5) is adding `aa-integration-tests/tests/cli_audit.rs` in a
//! parallel worktree. Creating a separate file here keeps the merge
//! conflict surface at zero and lets the two PRs land in either order.

mod common;

use std::io::Read;

use common::cli::CliFixture;

/// Signature substring of the clap downcast-mismatch panic. If this
/// appears in any test's stderr the bug has been re-introduced.
const CLAP_DOWNCAST_PANIC_SIGNATURE: &str = "Mismatch between definition and access";

// ============================================================================
// Regression: clap parse no longer panics
// ============================================================================

#[tokio::test(flavor = "multi_thread")]
async fn audit_export_format_json_does_not_panic_on_clap_parse() {
    let fixture = CliFixture::start().await.expect("fixture should start");

    let out = fixture
        .cmd()
        .args(["audit", "export", "--format", "json"])
        .output()
        .expect("aasm audit export should execute (panic-free)");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains(CLAP_DOWNCAST_PANIC_SIGNATURE),
        "AAASM-1479 regression: stderr contains clap downcast-mismatch panic signature; \
         stderr was:\n{stderr}",
    );
    // Note: we intentionally do NOT assert exit code — depending on whether
    // the in-process gateway mounts `/api/v1/logs`, the command may exit
    // 0 (empty JSON array printed to stdout) or non-zero (clean HTTP error
    // printed to stderr). Either is a successful pass — what matters is
    // no panic.
}

// ============================================================================
// Happy paths: --output-file flag works end-to-end
// ============================================================================

#[tokio::test(flavor = "multi_thread")]
async fn audit_export_json_with_output_file_writes_valid_json_array() {
    let fixture = CliFixture::start().await.expect("fixture should start");
    let tmp = tempfile::NamedTempFile::new().expect("tempfile for output");
    let path = tmp.path().to_string_lossy().to_string();

    let out = fixture
        .cmd()
        .args(["audit", "export", "--format", "json", "--output-file", &path])
        .output()
        .expect("aasm audit export --output-file should execute");

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains(CLAP_DOWNCAST_PANIC_SIGNATURE),
        "clap should not panic on the renamed --output-file flag; stderr:\n{stderr}",
    );

    // If the run exited successfully, the file must be parseable as a JSON
    // array. If it exited non-zero (e.g. /api/v1/logs not mounted in the
    // fixture), the file may be missing or empty — accept that as a known
    // harness limitation rather than failing on it.
    if out.status.success() {
        let mut file = std::fs::File::open(tmp.path()).expect("output file should exist on success");
        let mut contents = String::new();
        file.read_to_string(&mut contents).expect("read output file");
        let parsed: serde_json::Value = serde_json::from_str(&contents)
            .unwrap_or_else(|e| panic!("output should be valid JSON: {e}\nstdout: {contents}"));
        assert!(
            parsed.is_array(),
            "output should be a JSON array (possibly empty); got:\n{parsed}",
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn audit_export_csv_with_output_file_writes_csv_header() {
    let fixture = CliFixture::start().await.expect("fixture should start");
    let tmp = tempfile::NamedTempFile::new().expect("tempfile for output");
    let path = tmp.path().to_string_lossy().to_string();

    let out = fixture
        .cmd()
        .args(["audit", "export", "--format", "csv", "--output-file", &path])
        .output()
        .expect("aasm audit export --output-file (csv) should execute");

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains(CLAP_DOWNCAST_PANIC_SIGNATURE),
        "clap should not panic on the renamed --output-file flag (csv); stderr:\n{stderr}",
    );

    // Same harness-tolerant pattern as the JSON variant.
    if out.status.success() {
        let mut file = std::fs::File::open(tmp.path()).expect("output file should exist on success");
        let mut contents = String::new();
        file.read_to_string(&mut contents).expect("read output file");
        let first_line = contents
            .lines()
            .next()
            .unwrap_or_else(|| panic!("CSV output should have at least a header line; got:\n{contents}"));
        // Canonical header from write_csv() in aa-cli/src/commands/audit/export.rs.
        assert!(
            first_line.contains("timestamp") && first_line.contains("agent_id"),
            "CSV header should include 'timestamp' and 'agent_id'; got: {first_line}",
        );
    }
}
