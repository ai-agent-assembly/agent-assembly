#!/usr/bin/env bats
# AAASM-5891 AC-7 control #8: stale lease/process state is recovered.

load helpers.bash

setup() { setup_sched_home; }
teardown() { teardown_sched_home; }

@test "reap reclaims a slot held by a dead pid" {
    local pool_dir="$AA_SCHED_HOME/pools/global-test"
    mkdir -p "$pool_dir/slots/1"
    # A pid that is guaranteed dead: fork a short-lived process and wait
    # for it to actually exit before recording its (now-stale) identity.
    ( : ) &
    local dead_pid=$!
    wait "$dead_pid"
    {
        echo "pid=$dead_pid"
        echo "lstart=some-lstart-that-will-not-match-anyway"
        echo "job_id=stale-1"
    } >"$pool_dir/slots/1/holder"

    run "$SCHED" reap
    [ "$status" -eq 0 ]
    [ ! -d "$pool_dir/slots/1" ]
}

@test "reap reclaims a slot whose pid was recycled (lstart mismatch), never kills it" {
    local pool_dir="$AA_SCHED_HOME/pools/global-test2"
    mkdir -p "$pool_dir/slots/1"
    # Use this bats process's OWN pid+lstart as the "recycled" case: alive,
    # but the holder record deliberately claims a different lstart.
    {
        echo "pid=$$"
        echo "lstart=deliberately-wrong-lstart"
        echo "job_id=stale-2"
    } >"$pool_dir/slots/1/holder"

    run "$SCHED" reap
    [ "$status" -eq 0 ]
    [ ! -d "$pool_dir/slots/1" ]
    # The bats process itself (a real, unrelated, still-alive pid) must
    # still be alive — reap must never signal a pid on an lstart mismatch.
    run kill -0 "$$"
    [ "$status" -eq 0 ]
}

@test "reap does not touch a slot with a genuinely live, correctly-owned holder" {
    local pool_dir="$AA_SCHED_HOME/pools/global-test3"
    mkdir -p "$pool_dir/slots/1"
    "$FIXTURES/fake-hung.sh" &
    local live_pid=$!
    local lstart
    lstart=$(ps -o lstart= -p "$live_pid" | sed 's/^ *//;s/ *$//')
    {
        echo "pid=$live_pid"
        echo "lstart=$lstart"
        echo "job_id=live-1"
    } >"$pool_dir/slots/1/holder"

    run "$SCHED" reap
    [ "$status" -eq 0 ]
    [ -d "$pool_dir/slots/1" ]

    kill -KILL "$live_pid" 2>/dev/null || true
    wait "$live_pid" 2>/dev/null || true
}
