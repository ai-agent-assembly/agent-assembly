#!/usr/bin/env bats
# AAASM-5891 AC-7 controls #1, #2: concurrency stays useful, heavy classes
# are bounded.

load helpers.bash

setup() { setup_sched_home; }
teardown() { teardown_sched_home; }

# Control #1: multiple read-only-class workers genuinely overlap. Asserts
# on the interval SET (max simultaneous), not on a pass/fail verdict — the
# whole point is proving actual concurrency, not merely "all finished".
@test "readonly workers really run concurrently" {
    local pids=() i
    for i in 1 2 3 4 5 6; do
        sched_run_bg "pid$i" --class readonly --id "readonly-$i" -- \
            "$FIXTURES/fake-progressing.sh" 2
        pids+=("pid$i")
    done
    local p rc_sum=0
    for p in "${pids[@]}"; do
        sched_wait "${!p}"
        rc_sum=$((rc_sum + $?))
    done
    [ "$rc_sum" -eq 0 ]

    # Compute max overlap from each job's own started_at/ended_at.
    local starts=() ends=()
    for i in 1 2 3 4 5 6; do
        starts+=("$(grep -m1 '^started_at=' "$AA_SCHED_HOME/jobs/readonly-$i/meta" | cut -d= -f2-)")
        ends+=("$(grep -m1 '^ended_at=' "$AA_SCHED_HOME/jobs/readonly-$i/status" | cut -d= -f2-)")
    done
    local max_overlap=0 a
    for a in "${starts[@]}"; do
        local overlap=0 b
        for i in "${!starts[@]}"; do
            b_start="${starts[$i]}"
            b_end="${ends[$i]}"
            if ((b_start <= a)) && ((b_end > a)); then
                overlap=$((overlap + 1))
            fi
        done
        ((overlap > max_overlap)) && max_overlap=$overlap
    done
    # readonly is unsupervised (poll_s=0) but still semaphore-free (limit
    # 10, six jobs) — real overlap must be observed, not merely permitted.
    [ "$max_overlap" -ge 4 ]
}

# Control #2: N simultaneous heavy-class requests never exceed the
# configured limit (1, per fixtures.conf's cargo_build row) — AND all of
# them eventually run rather than five silently being dropped.
@test "heavy cargo_build class never exceeds its configured limit" {
    export CARGO_TARGET_DIR
    CARGO_TARGET_DIR="$(mktemp -d)"
    local pids=() i
    for i in 1 2 3 4 5; do
        sched_run_bg "pid$i" --class cargo_build --id "build-$i" --worktree "$CARGO_TARGET_DIR" -- \
            "$FIXTURES/fake-progressing.sh" 1
        pids+=("pid$i")
    done
    local p all_ok=1
    for p in "${pids[@]}"; do
        sched_wait "${!p}" || all_ok=0
    done
    [ "$all_ok" -eq 1 ]

    for i in 1 2 3 4 5; do
        [ -f "$AA_SCHED_HOME/jobs/build-$i/status" ]
        grep -q '^outcome=finished' "$AA_SCHED_HOME/jobs/build-$i/status"
    done

    local starts=() ends=() max_overlap=0
    for i in 1 2 3 4 5; do
        starts+=("$(grep -m1 '^started_at=' "$AA_SCHED_HOME/jobs/build-$i/meta" | cut -d= -f2-)")
        ends+=("$(grep -m1 '^ended_at=' "$AA_SCHED_HOME/jobs/build-$i/status" | cut -d= -f2-)")
    done
    for a in "${starts[@]}"; do
        local overlap=0
        for i in "${!starts[@]}"; do
            if ((${starts[$i]} <= a)) && ((${ends[$i]} > a)); then
                overlap=$((overlap + 1))
            fi
        done
        ((overlap > max_overlap)) && max_overlap=$overlap
    done
    [ "$max_overlap" -eq 1 ]

    rm -rf "$CARGO_TARGET_DIR"
}
