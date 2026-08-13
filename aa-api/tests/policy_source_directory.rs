//! AAASM-5299 — a `$AA_POLICY` **directory** source must populate the
//! scope-index cascade, so `AppState`'s engine reports `cascade_loaded() ==
//! true` and a cascade-derived read returns the operator's scoped documents.
//!
//! This is the ADR-0023 Option (a) acceptance evidence: before this wiring,
//! `AppState` always built the engine via `load_from_file` (primary slot only),
//! leaving the cascade empty in every shipped deployment.
//!
//! `$AA_POLICY` is process-wide, so this scenario lives in its own test binary
//! (one env-mutating `#[test]` per file) to avoid racing sibling tests under
//! either `cargo test` or nextest.

use aa_api::AppState;
use aa_gateway::policy::PolicyScope;

#[test]
fn directory_source_populates_the_cascade() {
    let dir = tempfile::tempdir().expect("temp policy dir");

    // A Global allow-all plus a narrower Team-scoped document. The Team doc is
    // what proves the *cascade* (scope index) was populated — `load_from_file`
    // could never insert it.
    std::fs::write(
        dir.path().join("000-global.yaml"),
        "apiVersion: agent-assembly.dev/v1alpha1\n\
         kind: GovernancePolicy\n\
         metadata:\n  name: local-global\n  version: \"0.1.0\"\n\
         spec:\n  tools: {}\n",
    )
    .expect("write global doc");
    std::fs::write(
        dir.path().join("100-team-alpha.yaml"),
        "apiVersion: agent-assembly.dev/v1alpha1\n\
         kind: GovernancePolicy\n\
         metadata:\n  name: local-team-alpha\n  version: \"0.1.0\"\n\
         spec:\n  scope: team:team-alpha\n  tools:\n    bash:\n      allow: false\n",
    )
    .expect("write team doc");

    std::env::set_var("AA_POLICY", dir.path());
    let state = AppState::local_in_memory().expect("in-memory state builds from a cascade directory");
    std::env::remove_var("AA_POLICY");

    // The scope index carries at least one scoped document: the unconfigured
    // signal is now `true` for cascade-derived projections.
    assert!(
        state.policy_engine.cascade_loaded(),
        "a directory source must populate the cascade — cascade_loaded() must be true"
    );

    // And a cascade-derived read returns the operator's real Team document,
    // not the empty result every shipped deployment saw before AAASM-5299.
    let team_policies = state
        .policy_engine
        .policies_for_scope(&PolicyScope::Team("team-alpha".to_string()));
    assert_eq!(
        team_policies.len(),
        1,
        "the Team-scoped document must be present in the loaded cascade"
    );
}
