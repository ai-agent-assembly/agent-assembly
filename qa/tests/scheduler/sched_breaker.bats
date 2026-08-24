#!/usr/bin/env bats
# AAASM-5891 AC-7 control #6: repeated stalls trip the resource-class
# circuit breaker.

load helpers.bash

setup() { setup_sched_home; }
teardown() { teardown_sched_home; }

@test "repeated stalls open the class breaker; a further run is refused" {
    # fixtures.conf: macos_security limit=1, breaker_threshold=2,
    # retry_safe=no — two independent stalling runs must trip it.
    run "$SCHED" run --class macos_security --id stall-a -- "$FIXTURES/fake-hung.sh"
    [ "$status" -eq 77 ]
    run "$SCHED" run --class macos_security --id stall-b -- "$FIXTURES/fake-hung.sh"
    [ "$status" -eq 77 ]

    run "$SCHED" breaker show macos_security
    [[ "$output" == *"state=open"* ]]

    # The breaker is already at its floor (default_limit=1), so a third
    # run must be refused outright with exit 75, never attempted.
    run "$SCHED" run --class macos_security --id stall-c -- "$FIXTURES/fake-progressing.sh" 1
    [ "$status" -eq 75 ]
    [ ! -d "$AA_SCHED_HOME/jobs/stall-c" ] || ! grep -q '^outcome=' "$AA_SCHED_HOME/jobs/stall-c/status" 2>/dev/null
}

@test "breaker reset closes the breaker and lets work resume" {
    run "$SCHED" run --class macos_security --id stall-a -- "$FIXTURES/fake-hung.sh"
    run "$SCHED" run --class macos_security --id stall-b -- "$FIXTURES/fake-hung.sh"
    run "$SCHED" breaker show macos_security
    [[ "$output" == *"state=open"* ]]

    "$SCHED" breaker reset macos_security
    run "$SCHED" breaker show macos_security
    [[ "$output" == *"state=closed"* ]]

    run "$SCHED" run --class macos_security --id after-reset -- "$FIXTURES/fake-progressing.sh" 1
    [ "$status" -eq 0 ]
}
