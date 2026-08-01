//! A machine-readable ledger of whether a scenario *measured* anything.
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
//! This writes the distinction somewhere a workflow step can assert on: the
//! real-tool lane, whose entire reason to exist is the one assertion a mock
//! cannot make, fails if its scenario recorded anything other than
//! [`Measurement::Measured`].
//!
//! # Opt-in by design
//!
//! Recording happens only when `AA_CONFORMANCE_OUTCOME_DIR` names a directory,
//! so a local `cargo nextest run` behaves exactly as before and leaves nothing
//! behind. A lane that wants the ledger sets the variable. When it *is* set, a
//! write failure panics rather than degrading quietly — a ledger that silently
//! did not get written would restore the very invisibility it is here to fix.

/// The environment variable naming the directory the ledger is written into.
pub const OUTCOME_DIR_ENV: &str = "AA_CONFORMANCE_OUTCOME_DIR";

/// What a scenario established about the product.
///
/// The three states are deliberately distinct: a scenario that never ran and a
/// scenario that ran and established nothing are different failures of
/// evidence, and collapsing them is what lets an unmeasured lane read as a
/// measured one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Measurement {
    /// The scenario ran and its assertions were taken against observed
    /// behaviour.
    Measured,
    /// A precondition the scenario is allowed to decline on was absent — the
    /// host is the wrong platform, or the tool under test is not installed.
    Skipped,
    /// Every precondition held, so the scenario committed to measuring, and
    /// then produced no evidence. This is a failed measurement, not an opt-out.
    NotMeasured,
}

impl Measurement {
    /// The token written to the ledger and matched by the workflow.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Measured => "measured",
            Self::Skipped => "skipped",
            Self::NotMeasured => "not_measured",
        }
    }
}

/// Print the outcome and, when the ledger is enabled, record it as JSON.
///
/// `detail` is free text for a human reading the ledger; the workflow asserts
/// on `outcome` alone. One file per scenario, so scenarios running in parallel
/// processes never contend for the same path.
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
    let body = serde_json::json!({
        "scenario": scenario,
        "outcome": measurement.as_str(),
        "detail": detail,
    });
    let path = dir.join(format!("{}.json", slug(scenario)));
    let rendered = serde_json::to_string_pretty(&body).expect("a three-field object always serialises");
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
