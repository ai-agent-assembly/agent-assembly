#!/usr/bin/env bats
# AAASM-5891 AC-7 control #11: a job blocked on a lock held by a process
# THIS SCHEDULER DID NOT START must not be killed and must not be retried
# — it has an identical mechanical stall signature to a genuinely wedged
# job, which is exactly the incident this Story exists to fix. Paired
# negative control: the identical flat job with no foreign holder present
# IS killed — the two cases must differ only in the holder's presence.

load helpers.bash

setup() { setup_sched_home; }
teardown() { teardown_sched_home; }

@test "a job blocked on a foreign lock holder is not killed and exits 76" {
    export CARGO_TARGET_DIR
    CARGO_TARGET_DIR="$(mktemp -d)"
    mkdir -p "$CARGO_TARGET_DIR/debug"

    "$FIXTURES/fake-lock-holder.sh" "$CARGO_TARGET_DIR/debug/.cargo-lock" 20 &
    local holder_pid=$!
    sleep 0.3 # let it actually open the fd before the job starts polling

    run "$SCHED" run --class cargo_build --id foreign-blocked -- "$FIXTURES/fake-hung.sh"
    [ "$status" -eq 76 ]
    grep -q '^status=WAITING_ON_FOREIGN_LOCK' "$AA_SCHED_HOME/jobs/foreign-blocked/status"

    # The foreign holder must still be alive — untouched.
    run kill -0 "$holder_pid"
    [ "$status" -eq 0 ]

    # The breaker for cargo_build must not have recorded a stall: this is
    # not the class's fault.
    if [ -f "$AA_SCHED_HOME/breakers/cargo_build" ]; then
        ! grep -q '^state=open' "$AA_SCHED_HOME/breakers/cargo_build"
    fi

    kill -KILL "$holder_pid" 2>/dev/null || true
    wait "$holder_pid" 2>/dev/null || true
    rm -rf "$CARGO_TARGET_DIR"
}

@test "negative control: the same flat job with no foreign holder present IS killed" {
    export CARGO_TARGET_DIR
    CARGO_TARGET_DIR="$(mktemp -d)"
    mkdir -p "$CARGO_TARGET_DIR/debug"
    # Deliberately no lock file, no holder — the only difference from the
    # test above.
    run "$SCHED" run --class cargo_build --id no-foreign-holder -- "$FIXTURES/fake-hung.sh"
    [ "$status" -eq 77 ]
    grep -q '^outcome=stalled' "$AA_SCHED_HOME/jobs/no-foreign-holder/status"
    rm -rf "$CARGO_TARGET_DIR"
}
