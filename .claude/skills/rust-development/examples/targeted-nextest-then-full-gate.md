# Example — targeted nextest iteration, then the full gate

Illustrative walkthrough of `rust-development` composing with
`engineering-loop`'s execution model. Crate names and timings below are
invented for illustration, not measured figures — see
`references/aa-evidence-classification.md` for where real measured
evidence does and doesn't apply.

## Scenario

A workspace has crates `ledger-core` (a library) and `ledger-api` (a
service binary), plus several other unrelated members. A change to
`ledger-core`'s balance-reconciliation logic causes one unit test to fail.

## Explore

Locate the failing area first — the touched function
(`ledger_core::reconcile::apply_adjustment`) and its existing test module
(`ledger-core/src/reconcile.rs`, `#[cfg(test)] mod tests`). Prefer
CodeGraph/RTK if available, native `grep`/`Read` otherwise, per
`agents/skills/engineering-loop/references/optional-tool-fallback.md`.

## Narrow

Run only the one crate's library tests — not the whole workspace, not
even the whole crate's every target:

```
cargo nextest run -p ledger-core --lib
```

Output (illustrative):

```
FAIL [   0.014s] ledger-core reconcile::tests::apply_adjustment_rounds_down
     ... assertion failed: expected 1000, got 1001 ...
2 tests run: 1 passed, 1 failed
```

This is deliberately scoped to `-p ledger-core --lib` rather than
`-p ledger-core` (which would also compile/discover `ledger-core`'s
integration-test binaries) or an unscoped `cargo nextest run` (which
would compile/discover every target across every workspace member) — see
`references/cargo-workflow.md` § Targeted test loops for why an unscoped
invocation costs materially more discovery time regardless of how fast
the failing test itself runs.

## Validate / Escalate (engineering-loop's L0→L3 ladder)

L0 (PASS/FAIL counts) already shows one failure. Escalate to L1/L2 (the
assertion output above, already visible in this case) to see the actual
mismatch: `apply_adjustment` is truncating instead of rounding. Read the
function, find the bug (an integer-division truncation where the
original spec calls for rounding), fix it, then re-run the same narrow
command:

```
cargo nextest run -p ledger-core --lib
```

```
2 tests run: 2 passed, 0 failed
```

The narrow check now passes. Per `engineering-loop`, this is evidence the
specific fix works — not yet sufficient to call the change done, because
it hasn't touched `ledger-api` (which depends on `ledger-core`), hasn't
run clippy, and hasn't proven the change links/builds under the repo's
real build profile.

## Full Gate

Before declaring the change done, run the repository's own authoritative
full gate — for this illustrative workspace, something like:

```
cargo build --workspace
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo nextest run --workspace
```

(Substitute whatever command the target repo's own CI actually runs —
this skill never invents a gate command a repo doesn't already have.)
Only once this full, unscoped pass is green — proving `ledger-api` still
builds and links against the corrected `ledger-core`, and that no other
workspace member regressed — is the change ready to hand off, matching
`engineering-loop`'s Full Gate stage: a narrow check that passed is
evidence the fix works, never proof the repo is releasable.
