//! AAASM-5299 — an **unset** `$AA_POLICY` must keep synthesising the budget-only
//! bootstrap policy, leaving the scope-index cascade empty so
//! `cascade_loaded() == false`. This is the ADR-0024 unconfigured / Unknown
//! signal: a generated bootstrap policy must never be presented as an
//! operator-authored cascade.
//!
//! `$AA_POLICY` is process-wide, so this scenario lives in its own test binary
//! (one env-mutating `#[test]` per file) to avoid racing sibling tests under
//! either `cargo test` or nextest.

use aa_api::AppState;

#[test]
fn unset_source_leaves_cascade_empty() {
    std::env::remove_var("AA_POLICY");

    let state = AppState::local_in_memory().expect("in-memory state builds with no policy source");

    // No operator source: the bootstrap policy loads via the single-file loader
    // and the cascade stays empty, so the dashboard projections render the
    // Unknown / Unconfigured state rather than inferring permission.
    assert!(
        !state.policy_engine.cascade_loaded(),
        "an unset source must leave the cascade empty — cascade_loaded() must be false"
    );
}
