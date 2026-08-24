#!/usr/bin/env bats
# AAASM-5891 AC-7 control #9: processes NOT owned by this scheduler are
# never touched by reap/cleanup/the watchdog — paired with a positive
# control (an owned process IS killed), since "nothing was killed" alone
# would also pass for a scheduler that kills nothing at all.

load helpers.bash

setup() { setup_sched_home; }
teardown() { teardown_sched_home; }

@test "an out-of-band process survives reap and cleanup untouched" {
    "$FIXTURES/fake-hung.sh" &
    local foreign_pid=$!

    "$SCHED" reap
    "$SCHED" cleanup
    run kill -0 "$foreign_pid"
    [ "$status" -eq 0 ]

    kill -KILL "$foreign_pid" 2>/dev/null || true
    wait "$foreign_pid" 2>/dev/null || true
}

@test "positive control: an owned hung job IS killed by the watchdog" {
    run "$SCHED" run --class lint_fast --id owned-1 -- "$FIXTURES/fake-hung.sh"
    [ "$status" -eq 77 ]
    local pgid
    pgid=$(grep -m1 '^pgid=' "$AA_SCHED_HOME/jobs/owned-1/meta" | cut -d= -f2-)
    run ps -o pid= -g "$pgid"
    [ -z "$output" ]
}

@test "cleanup does not touch a foreign process even while an owned job is also running" {
    "$FIXTURES/fake-hung.sh" &
    local foreign_pid=$!

    sched_run_bg jp --class lint_fast --id owned-2 -- "$FIXTURES/fake-hung.sh"
    sched_wait "$jp" || true

    "$SCHED" cleanup
    run kill -0 "$foreign_pid"
    [ "$status" -eq 0 ]

    kill -KILL "$foreign_pid" 2>/dev/null || true
    wait "$foreign_pid" 2>/dev/null || true
}
