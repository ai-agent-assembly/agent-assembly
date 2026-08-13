//! A machine-readable ledger of whether a scenario *measured* anything
//! (AAASM-5465).
//!
//! # The problem this exists for
//!
//! A scenario that opts out prints `SKIP [...]` and returns `Ok(())`, which the
//! test runner counts as a pass — by design, and documented. But the summary
//! line a reviewer actually reads (`26 tests run: 26 passed`) is then identical
//! whether the optional real-tool scenario took its measurement or declined to.
//! The distinction survives only in `--no-capture` stdout, which nothing
//! asserts on, so "the lane was green" cannot be read as "the lane measured".
//!
//! This writes the distinction somewhere a workflow step can assert on:
//! `.ci/test-evidence-summary.sh` nets the declarations here against the
//! runner's own pass count and refuses to call a lane that declined everything
//! a passing lane.
//!
//! # Why the declaration is a *decline*, not a pass
//!
//! Only the opt-out paths record. A scenario that ran is counted by the test
//! runner itself (nextest's JUnit report), so nothing here has to be kept in
//! step with the number of scenarios in a file — a new test that forgets to
//! call `record` is counted as substantive, which is the safe direction. The
//! unsafe direction, a scenario that declined and said nothing, is the one the
//! guards in `conformance_support` and `spike_support` close by recording
//! *inside* the guard rather than at its call site.
//!
//! # Three outcomes, not two
//!
//! [`Measurement`] separates "this platform cannot run the scenario at all"
//! from "the platform is fine and the tool is not installed" from "it ran".
//! Collapsing the first two — which a single `Skipped` token did — hides the
//! only one of them a CI lane can fix: a lane that provisions the binary and
//! still reports [`Measurement::ToolAbsent`] is broken, while the same lane
//! reporting [`Measurement::UnsupportedPlatform`] is on the wrong runner.
//!
//! # Opt-in by design
//!
//! Recording happens only when `AA_CONFORMANCE_OUTCOME_DIR` names a directory,
//! so a local `cargo nextest run` behaves exactly as before and leaves nothing
//! behind. A lane that wants the ledger sets the variable. When it *is* set, a
//! write failure panics rather than degrading quietly — a ledger that silently
//! did not get written would restore the very invisibility it is here to fix.
//!
//! # Why this module has no dependencies
//!
//! It is `#[path]`-included by test binaries in three crates
//! (`aa-integration-tests`, `aa-cli`, `aa-devtool-claude-code`), and the whole
//! point of a single ledger is that every suite writes the *same* record. Rolling
//! the four-field object by hand rather than reaching for `serde_json` keeps the
//! set of crates that can include it equal to the set of crates that have a
//! `tests/` directory.

#![allow(dead_code)]

/// The environment variable naming the directory the ledger is written into.
pub const OUTCOME_DIR_ENV: &str = "AA_CONFORMANCE_OUTCOME_DIR";

/// What a scenario established about the product.
///
/// The four states are deliberately distinct: a scenario that could never run
/// here, one whose tool was missing, and one that ran and established nothing
/// are three different failures of evidence, and collapsing them is what lets an
/// unmeasured lane read as a measured one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Measurement {
    /// The scenario ran and its assertions were taken against observed
    /// behaviour.
    Measured,
    /// (a) The host platform cannot run this scenario at all — the integration
    /// under test is macOS-only, or the fixture needs a POSIX shell. No CI
    /// configuration on this runner can change the answer; a different runner
    /// can.
    UnsupportedPlatform,
    /// (b) The platform is capable and the tool under test is not installed.
    /// Honest on a developer laptop, and a *broken lane* on any CI job that
    /// provisions the binary itself.
    ToolAbsent,
    /// (c) inverted: every precondition held, so the scenario committed to
    /// measuring, and then produced no evidence. This is a failed measurement,
    /// not an opt-out.
    NotMeasured,
}

impl Measurement {
    /// The token written to the ledger and matched by the workflow.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Measured => "measured",
            Self::UnsupportedPlatform => "unsupported_platform",
            Self::ToolAbsent => "tool_absent",
            Self::NotMeasured => "not_measured",
        }
    }

    /// Whether this outcome means the scenario produced evidence.
    ///
    /// Used by the callers that decide whether to keep going; the CI summary
    /// asks the same question of the ledger files.
    pub fn is_evidence(self) -> bool {
        matches!(self, Self::Measured)
    }
}

/// Print the outcome and, when the ledger is enabled, record it as JSON.
///
/// `detail` is free text for a human reading the ledger; the summary script
/// asserts on `outcome` alone. One file per scenario, so scenarios running in
/// parallel processes never contend for the same path.
///
/// # Panics
///
/// When `AA_CONFORMANCE_OUTCOME_DIR` is set and the record cannot be written.
pub fn record(scenario: &str, measurement: Measurement, detail: &str) {
    println!("OUTCOME [{scenario}]: {} — {detail}", measurement.as_str());
    let Some(dir) = std::env::var_os(OUTCOME_DIR_ENV) else {
        return;
    };
    let dir = std::path::PathBuf::from(dir);
    std::fs::create_dir_all(&dir).unwrap_or_else(|e| panic!("{} could not be created: {e}", dir.display()));
    let rendered = format!(
        "{{\n  \"scenario\": \"{}\",\n  \"outcome\": \"{}\",\n  \"platform\": \"{}\",\n  \"detail\": \"{}\"\n}}\n",
        escape(scenario),
        measurement.as_str(),
        escape(std::env::consts::OS),
        escape(detail),
    );
    let path = dir.join(format!("{}.json", slug(scenario)));
    std::fs::write(&path, rendered).unwrap_or_else(|e| panic!("{} could not be written: {e}", path.display()));
}

/// A filename-safe form of a scenario name.
fn slug(scenario: &str) -> String {
    scenario
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect()
}

/// JSON string-escape the four fields this module writes.
///
/// Covers the two-character escapes plus the control range, which is the whole
/// of what a scenario name or a `detail` built from an error message can carry.
fn escape(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for c in raw.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}
