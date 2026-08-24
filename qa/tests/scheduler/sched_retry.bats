#!/usr/bin/env bats
# AAASM-5891 AC-7 control #5: retry works after a transient stall.

load helpers.bash

setup() { setup_sched_home; }
teardown() { teardown_sched_home; }

@test "a retry-safe class retries once after a transient stall, then succeeds" {
    local counter="$AA_SCHED_HOME/transient-counter"
    run "$SCHED" run --class cargo_build --id transient-1 -- \
        "$FIXTURES/fake-transient-stall.sh" "$counter"
    [ "$status" -eq 0 ]
    grep -q '^attempt=2' "$AA_SCHED_HOME/jobs/transient-1/meta"
    grep -q '^outcome=finished' "$AA_SCHED_HOME/jobs/transient-1/status"
    [ "$(cat "$counter")" -eq 2 ]
}

@test "a non-retry-safe class does not retry after a stall" {
    run "$SCHED" run --class macos_security --id hung-once -- "$FIXTURES/fake-hung.sh"
    [ "$status" -eq 77 ]
    grep -q '^attempt=1' "$AA_SCHED_HOME/jobs/hung-once/meta"
    run ! grep -q '^outcome=retrying' "$AA_SCHED_HOME/jobs/hung-once/status"
}
