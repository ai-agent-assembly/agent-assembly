//! AAASM-5299 — a `$AA_POLICY` **file** source must keep today's primary-slot
//! behaviour: the operator's single document loads via `load_from_file`, so the
//! scope-index cascade stays empty and `cascade_loaded() == false`.
//!
//! `$AA_POLICY` is process-wide, so this scenario lives in its own test binary
//! (one env-mutating `#[test]` per file) to avoid racing sibling tests under
//! either `cargo test` or nextest.

use aa_api::AppState;

#[test]
fn file_source_keeps_primary_slot_behaviour() {
    let dir = tempfile::tempdir().expect("temp policy dir");
    let file = dir.path().join("policy.yaml");
    std::fs::write(
        &file,
        "apiVersion: agent-assembly.dev/v1alpha1\n\
         kind: GovernancePolicy\n\
         metadata:\n  name: local-file-policy\n  version: \"0.1.0\"\n\
         spec:\n  tools: {}\n",
    )
    .expect("write policy file");

    std::env::set_var("AA_POLICY", &file);
    let state = AppState::local_in_memory().expect("in-memory state builds from a single file");
    std::env::remove_var("AA_POLICY");

    // A single-file source uses the primary slot only — the cascade is never
    // populated, matching the pre-AAASM-5299 behaviour.
    assert!(
        !state.policy_engine.cascade_loaded(),
        "a file source must leave the cascade empty — cascade_loaded() must be false"
    );
}
