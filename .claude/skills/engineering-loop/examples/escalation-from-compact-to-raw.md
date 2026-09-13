# Example — escalating L0 → L1 → L2 → L3 to find the real root cause

Scenario: a Rust workspace change to a connection-pool crate. A targeted
`nextest` run reports a failure that looks trivial at L0 but is actually
caused by something the compact levels actively hide.

## L0 — PASS/FAIL + counts

```
$ cargo nextest run -p pool-core --test integration
------------
 Summary [   4.912s] 12 tests run: 11 passed, 1 failed
------------
FAILED [   4.912s] pool-core::integration acquire_under_load
```

One failure out of twelve. Not enough to act on yet — could be a real bug,
a flaky timing assumption, or an environment issue.

## L1 — file/line + diagnostic

```
$ cargo nextest run -p pool-core --test integration acquire_under_load --nocapture 2>&1 | tail -20
tests/integration.rs:203:9: assertion failed: pool.active_count() <= max_size
```

Now there's a location and a one-line diagnostic: the pool exceeded
`max_size` under load. That's surprising enough (this is exactly the
invariant the change touched) that L0/L1 alone aren't enough to trust —
stopping here risks either dismissing a real bug as "probably flaky" or
mis-fixing based on an incomplete picture.

## L2 — relevant traceback / context

```
$ RUST_BACKTRACE=1 cargo nextest run -p pool-core --test integration acquire_under_load --nocapture
thread 'acquire_under_load' panicked at tests/integration.rs:203:9:
assertion failed: pool.active_count() <= max_size
  left: 17
 right: 16
note: run with `RUST_BACKTRACE=full` for a verbose backtrace
stack backtrace:
   0: pool_core::Pool::acquire
             at src/pool.rs:88:13
   1: pool_core::Pool::acquire_or_wait
             at src/pool.rs:104:9
   2: integration::acquire_under_load
             at tests/integration.rs:198:5
```

This narrows it to `Pool::acquire` at `src/pool.rs:88` momentarily letting
the active count hit 17 against a configured max of 16 — one over. The
traceback shows *where* but not *why* the check at line 88 didn't hold
under concurrent load; a check-then-increment race is suspected but not
confirmed.

## L3 — complete raw output

The suspicion is a race between the bounds check and the increment across
threads, which a single-threaded reading of the code wouldn't reveal.
Rather than guess, pull the complete raw output including everything the
summarized run discarded — full stdout across all 8 concurrent workers
the test spawns, in original interleaved order:

```
$ cargo nextest run -p pool-core --test integration acquire_under_load \
    --no-capture --test-threads=1 > /tmp/raw-acquire-under-load.log 2>&1
$ cat /tmp/raw-acquire-under-load.log
```

The raw log shows worker 4 and worker 7 both reading
`active_count() == 15` in the same microsecond window, both concluding
"below max, proceed", and both incrementing — a classic
check-then-act race in `Pool::acquire` (src/pool.rs:88) because the read
and the increment are two separate atomic operations instead of one
compare-and-swap. This is only visible in the full interleaved raw
output; the L1/L2 summaries (correctly) collapsed the 8 workers' output
into "one assertion failed" and discarded the very interleaving that
explains it.

## Fix and verification

Replace the check-then-increment with a single `compare_exchange` loop in
`Pool::acquire`, then re-run the narrow check first (L0):

```
$ cargo nextest run -p pool-core --test integration acquire_under_load
------------
 Summary [   4.877s] 1 test run: 1 passed
------------
```

Then the Full Gate before considering the fix done — the full workspace
test suite plus `cargo clippy` — per the execution model's final stage,
since a concurrency fix in a shared pool crate has blast radius beyond the
one test that caught it.

## Why the escalation was necessary here

L0 said "1 failed" — true but useless for a race. L1 said "an assertion
failed at this line" — better, but a race's *location* isn't its *cause*.
L2's backtrace named the function but a single-threaded stack trace cannot
show a cross-thread interleaving. Only L3's complete, uncollapsed,
multi-worker raw output revealed the actual race. Stopping at any earlier
level and patching the symptom (e.g. loosening the assertion, or adding a
retry) would have shipped the underlying race unfixed.
