#!/usr/bin/env bats
# AAASM-5891 AC-7 control #10 (and AC-6): cleanup leaves no residue on
# both the succeeding and the failing path.

load helpers.bash

setup() { setup_sched_home; }
teardown() { teardown_sched_home; }

port_is_listening() {
    lsof -i ":$1" -sTCP:LISTEN >/dev/null 2>&1
}

@test "cleanup leaves no listener/process/temp-dir residue on the success path" {
    run "$SCHED" run --class lint_fast --id listener-ok --campaign cleanup-test -- \
        "$FIXTURES/fake-listener.sh" succeed
    [ "$status" -eq 0 ]

    local port temp_dir
    port=$(grep -m1 '^port=' "$AA_SCHED_HOME/jobs/listener-ok/meta" | cut -d= -f2-)
    temp_dir=$(grep -m1 '^temp_dir=' "$AA_SCHED_HOME/jobs/listener-ok/meta" | cut -d= -f2-)
    [ -n "$port" ]
    [ -n "$temp_dir" ]

    "$SCHED" cleanup --campaign cleanup-test

    run ! port_is_listening "$port"
    [ ! -d "$temp_dir" ]
    local pgid
    pgid=$(grep -m1 '^pgid=' "$AA_SCHED_HOME/jobs/listener-ok/meta" | cut -d= -f2-)
    run ps -o pid= -g "$pgid"
    [ -z "$output" ]
}

@test "cleanup leaves no listener/process/temp-dir residue on the failure (killed) path" {
    run "$SCHED" run --class lint_fast --id listener-hang --campaign cleanup-test2 -- \
        "$FIXTURES/fake-listener.sh" hang
    [ "$status" -eq 77 ]

    local port temp_dir
    port=$(grep -m1 '^port=' "$AA_SCHED_HOME/jobs/listener-hang/meta" | cut -d= -f2-)
    temp_dir=$(grep -m1 '^temp_dir=' "$AA_SCHED_HOME/jobs/listener-hang/meta" | cut -d= -f2-)
    [ -n "$port" ]
    [ -n "$temp_dir" ]

    # The watchdog's own kill path already ran cleanup_job_owned_state, but
    # an explicit `cleanup` call must be idempotent/harmless on top of it —
    # this is the path the coordinator actually calls at campaign end.
    "$SCHED" cleanup --campaign cleanup-test2

    run ! port_is_listening "$port"
    [ ! -d "$temp_dir" ]
}
