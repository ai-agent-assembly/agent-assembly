// Fixture support file for AAASM-5876's registry-health negative control
// (case 13: two functions where a shorter name is a prefix of a longer,
// #[ignore]d sibling — the ignore-detection window must not leak the
// unrelated sibling's marker onto the shorter, non-ignored function).

#[ignore = "flaky"]
#[test]
fn a_prefix_collision_target_extended() {
    unreachable!("never actually run — fixture only");
}

#[test]
fn a_prefix_collision_target() {
    unreachable!("never actually run — fixture only");
}
