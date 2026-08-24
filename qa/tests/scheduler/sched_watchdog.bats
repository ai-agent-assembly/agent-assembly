#!/usr/bin/env bats
# AAASM-5891 AC-7 controls #3, #4: a hung owned subprocess is detected and
# terminated; a healthy slow/progressing subprocess is not falsely killed.

load helpers.bash

setup() { setup_sched_home; }
teardown() { teardown_sched_home; }

@test "a hung owned subprocess is detected and terminated (TERM)" {
    run "$SCHED" run --class lint_fast --id hung-1 -- "$FIXTURES/fake-hung.sh"
    [ "$status" -eq 77 ]
    grep -q '^outcome=stalled' "$AA_SCHED_HOME/jobs/hung-1/status"
    local pgid
    pgid=$(grep -m1 '^pgid=' "$AA_SCHED_HOME/jobs/hung-1/meta" | cut -d= -f2-)
    run ps -o pid= -g "$pgid"
    [ -z "$output" ]
}

@test "a hung owned subprocess that ignores TERM is escalated to KILL" {
    run "$SCHED" run --class lint_fast --id hung-2 -- "$FIXTURES/fake-hung-ignores-term.sh"
    [ "$status" -eq 77 ]
    local pgid
    pgid=$(grep -m1 '^pgid=' "$AA_SCHED_HOME/jobs/hung-2/meta" | cut -d= -f2-)
    run ps -o pid= -g "$pgid"
    [ -z "$output" ]
}

@test "a healthy slow/progressing subprocess is not falsely killed" {
    # fixtures.conf: lint_fast poll_s=1 stall_polls=2 -> a 2s no-progress
    # budget. Run the progressing fixture for 3x that (6s) — shorter than
    # the budget would prove nothing about false-positive risk.
    run "$SCHED" run --class lint_fast --id progressing-1 -- "$FIXTURES/fake-progressing.sh" 6
    [ "$status" -eq 0 ]
    grep -q '^outcome=finished' "$AA_SCHED_HOME/jobs/progressing-1/status"
    grep -q '^exit_code=0' "$AA_SCHED_HOME/jobs/progressing-1/status"
}
