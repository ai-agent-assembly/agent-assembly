// Fixture support file for AAASM-5876's registry-health negative control
// (case 10: a release-blocking journey's evidence points at a test marked
// `#[ignore]` — this must not validate as automated evidence, mirroring the
// AAASM-4479 principle that a deterministic skip cannot silently count as
// coverage).

#[test]
#[ignore]
fn a_deliberately_ignored_test_used_only_as_a_fixture() {
    unreachable!("never actually run — this file exists only to be referenced by a fixture");
}
