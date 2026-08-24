#!/usr/bin/env bats
# AAASM-5891 AC-7 control #7: unrelated workers continue while one
# resource class is blocked — a stalled/breaker-open class must never
# globalize into serializing the whole campaign.

load helpers.bash

setup() { setup_sched_home; }
teardown() { teardown_sched_home; }

@test "an open breaker on one class does not block unrelated classes" {
    # Trip macos_security's breaker (limit=1, threshold=2).
    "$SCHED" run --class macos_security --id trip-a -- "$FIXTURES/fake-hung.sh" || true
    "$SCHED" run --class macos_security --id trip-b -- "$FIXTURES/fake-hung.sh" || true
    run "$SCHED" breaker show macos_security
    [[ "$output" == *"state=open"* ]]

    # Unrelated classes must still complete normally and concurrently.
    local pids=()
    sched_run_bg p1 --class lint_fast --id lint-1 -- "$FIXTURES/fake-progressing.sh" 1
    sched_run_bg p2 --class readonly --id read-1 -- "$FIXTURES/fake-progressing.sh" 1
    pids=(p1 p2)
    local p all_ok=1
    for p in "${pids[@]}"; do
        sched_wait "${!p}" || all_ok=0
    done
    [ "$all_ok" -eq 1 ]
    grep -q '^outcome=finished' "$AA_SCHED_HOME/jobs/lint-1/status"
    grep -q '^outcome=finished' "$AA_SCHED_HOME/jobs/read-1/status"

    # Exactly the one class's breaker is open — not a blanket state.
    [ ! -f "$AA_SCHED_HOME/breakers/lint_fast" ] || ! grep -q '^state=open' "$AA_SCHED_HOME/breakers/lint_fast"
    [ ! -f "$AA_SCHED_HOME/breakers/readonly" ]
}
