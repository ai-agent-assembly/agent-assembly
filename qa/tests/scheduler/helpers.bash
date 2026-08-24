#!/usr/bin/env bash
# Shared setup for qa/tests/scheduler/*.bats.

SCHED="$BATS_TEST_DIRNAME/../../scheduler/aa-sched"
FIXTURES="$BATS_TEST_DIRNAME/../fixtures/scheduler"

setup_sched_home() {
    # Hermetic per-test state: never the real $HOME/.aa-sched, or two test
    # files running in parallel (or a real campaign running concurrently on
    # this machine) would collide on the same pools/breakers.
    export AA_SCHED_HOME
    AA_SCHED_HOME="$(mktemp -d)"
    export AA_SCHED_CLASSES_CONF="$BATS_TEST_DIRNAME/fixtures.conf"
}

teardown_sched_home() {
    # Best-effort: kill anything the test left running before removing its
    # state, so a failed assertion never leaks a fixture process past the
    # test that started it.
    "$SCHED" cleanup >/dev/null 2>&1 || true
    rm -rf "$AA_SCHED_HOME"
}

# Runs `aa-sched run` in the background (bats' `run` blocks, which does not
# compose with wanting several jobs genuinely overlapping) and records its
# pid under $1's name for later `wait`.
sched_run_bg() {
    local outvar="$1"
    shift
    "$SCHED" run "$@" &
    printf -v "$outvar" '%s' "$!"
}

# Waits for a background `aa-sched run` (started via sched_run_bg) and
# returns its exit code the same way `wait` would.
sched_wait() {
    wait "$1"
}
