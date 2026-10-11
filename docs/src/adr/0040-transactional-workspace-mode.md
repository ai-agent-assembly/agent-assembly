# ADR 0040: Transactional Workspace Mode

**Status**: Proposed
**Date**: 2026-10
**Ticket**: [AAASM-6162](https://lightning-dust-mite.atlassian.net/browse/AAASM-6162) (Epic [AAASM-6159](https://lightning-dust-mite.atlassian.net/browse/AAASM-6159), *Agent Execution Runtime 2.0*)

This ADR extends [ADR 0035](0035-agent-execution-isolation-and-pluggable-enforcement-backends.md)
without amending it, and reuses [ADR 0030](0030-developer-integration-boundaries-and-trust-model.md)
§3.1 / [ADR 0033](0033-canonical-governance-and-enforcement-architecture.md) §6
vocabulary rather than defining a competing one. AAASM-6166's receipt decision
(`aa-cli/src/commands/execution_receipt/mod.rs`) lives as an 0035 amendment; the two
are complementary — this ADR's Decision 6 below is where they meet.

## Context

Every execution-isolation backend this repository ships answers *where* a confined
process may write — a filesystem-write boundary, a network-egress boundary, a
credential boundary. None of them answer *when* a write becomes durable. A confined
process today writes straight to the operator's real working directory the moment it
is permitted to write at all: `allowed to write` and `the base tree is mutated now`
are the same event.

A materialized-workspace-transaction mechanism already exists for this
(`aa-workspace-tx`, backed by the backend-neutral contract in `aa_isolation::tx`): open
a transaction over a declared surface, materialize a staged copy, let a process write
to the copy, and fold the exact change set back onto the base only on an explicit
commit decision. What did not exist before this ticket was any way to reach that
mechanism from `aasm run` — no CLI flag, no wiring of the staged directory into a
launch's working directory, no transaction metadata on the execution receipt, and no
enforced statement of what a transaction does not cover.

## Decision 1: a materialized transaction over a declared surface, never a full-tree copy

`--workspace-tx` stages a copy of the base directory (or `--workdir`) minus any
`--workspace-tx-exclude` selectors, rather than copying every byte under the working
directory. This repository's own build directories have reached hundreds of gigabytes
across worktrees (see the host-level incident notes in `~/CLAUDE.md`); copying
"everything under the working directory" by default for every governed launch would
repeat that mistake for every single run.

Three alternatives were considered and rejected:

- **`git worktree`** — a fresh worktree has no untracked or ignored build state. A real
  coding-agent workflow's edit-build-test cycle routinely depends on exactly that state
  (a `node_modules`, a `target/`, a virtualenv already present), so this would fail the
  dogfood workflow this ticket exists to make pass.
- **overlayfs** — Linux-only, and unfalsifiable on the macOS host this feature was
  authored and range-build-checked on. A mechanism this repository cannot verify on its
  own authoring platform is a mechanism nobody caught a regression in until CI did.
- **VM disk snapshots** — the macOS VM backend (`aa-isolation-macos-vm`) has no
  snapshot primitive, and workspace writes from inside that guest bypass the guest's
  own disk entirely via a single virtiofs share back to the host. There is no guest-side
  disk state to snapshot in the first place.

## Decision 2: copy, never hard-link — plus a commit-time inode re-check

A hard-linked staged file shares an inode with the base file; a write through the
staged path would mutate the base before any commit decision ever ran, defeating the
entire point of staging. `aa-workspace-tx::materialize` copies content byte-for-byte and
never calls `std::fs::hard_link`. `commit()` additionally re-checks, for every
added/modified entry, that the staged path does not share an inode with the
corresponding base path — a second, independent line of defense against a
materialization bug, not merely a restated intent.

## Decision 3: the fail-closed commit order, all-or-nothing

Every commit runs the same sequence, and any failure refuses the whole commit with
nothing applied:

1. **Drift check, scoped to the change set.** The base is re-measured immediately
   before commit; if any path the change set touches differs from what was recorded
   when the transaction opened, the commit refuses (`CommitRefusal::BaseDrift`) —
   someone else wrote to the base concurrently.
2. **Protected-path gate.** If the change set touches a `--workspace-tx-protect`
   selector and `--workspace-tx-approve` was not presented, the commit refuses
   (`ProtectedPathNotApproved`).
3. **Applier-side boundary check.** Every changed path must be a normal relative path
   — no absolute path, no `..` component — or the commit refuses
   (`BoundaryEscape`).
4. **Inode re-check** (Decision 2).
5. **Two-phase, `fsync`'d apply.** A journal describing every planned operation is
   written and `fsync`'d *before* any base path is touched (Decision 4).

## Decision 4: crash/cancel disposition — documented, not merely mechanized

The journal from step 5 above is the crash-safety half of "two-phase": it is durable on
disk before the base tree is touched at all, so a process that dies mid-apply leaves a
`TransactionStatus::InterruptedApply` on disk, never a silently half-done base
tree. (As of AAASM-6291 nothing in `aasm` yet reads that status back or reports
it to the operator, and re-opening the transaction re-materializes the staged copy
without checking for a journal; "discoverable" means present on disk, not surfaced.) Three properties are load-bearing and stated here plainly:

- Nothing in `aa-workspace-tx` ever auto-applies a journal on a later run. An
  interrupted apply requires explicit operator inspection; this is a deliberate scope
  boundary, not a gap waiting to be closed.
- A refused or interrupted transaction's state directory is retained, not removed, so
  the refused change set stays inspectable. A committed or cleanly discarded
  transaction's state directory is removed.
- `commit()` requires `TransactionStatus::Closed`; attempting it from `Open` or from a
  terminal status refuses (`NotClosed`) rather than panicking, because the caller is a
  CLI command reading real process exit state, which it can observe incorrectly.

## Decision 5: opt-in, outcome-driven settle rule, four flags

`--workspace-tx` is opt-in. `aasm run` never establishes a transaction unless asked, and
turning it on does not change the default posture of any other launch (isolation,
policy, or otherwise).

The commit-or-discard decision is a single rule, stated once, with nothing to fall out
of sync with it: the confined process's own exit code decides. Exit `0` attempts a
commit (subject to Decision 3's checks); any other exit — or an unobservable exit —
discards. There is no separate `--workspace-tx-commit` mode, no interactive
review-before-commit step, and no way for the flag surface to disagree with the
mechanism about what "success" means.

Four flags:

| Flag | Meaning |
|---|---|
| `--workspace-tx` | Establish a transaction over the base directory (`--workdir`, or the shell's own working directory). |
| `--workspace-tx-exclude <PATH>` | Repeatable. A selector excluded from the declared surface. |
| `--workspace-tx-protect <PATH>` | Repeatable. A selector whose change requires approval to commit. |
| `--workspace-tx-approve` | Pre-authorizes a commit touching a protected selector. |

State lives at `${AASM_STATE_DIR:-~/.aasm}/workspace-tx/<id>`, a sibling of the
execution-receipt store's own state root, never nested under it and never sharing a
file with it — three fail-closed preconditions (base-root-is-a-directory,
state-root/base-root non-nesting, and an exact `/`-or-home-directory refusal) run
before anything is registered or copied, matching the ordering `aasm run`'s planner
already holds its `--workdir` check to.

## Decision 6: truthful reporting, additive only

The execution receipt's `WorkspaceBinding` (previously always `None`) is now populated
when `--workspace-tx` applied: base/result/diff digests, added/modified/deleted
counts, a refusal-kind token when refused, the surface-exclusion and protected-selector
counts, whether approval was presented, and a `not_transactional` list. Every field is
additive; the receipt schema identifier is unchanged.

Every `--workspace-tx` run also prints a `workspace_tx.*` block to stderr — the only
surface a transaction's truth reaches when no execution-isolation boundary ran, since
the unconfined `--isolation none` path (the default) writes no execution receipt at
all, with or without a transaction.

Both surfaces carry the same disclaimer, drawn from one constant
(`NOT_TRANSACTIONAL`) so the two cannot drift: a transaction says nothing about network
calls, database writes, processes started, or a path outside the declared surface. It
is about durability of the declared surface, not about confinement. `aasm receipt
verify`'s validation rules enforce this rather than merely asserting it — a receipt
whose `WorkspaceBinding` drops even one disclaimer token fails verification.

## Decision 7: the `workspace_transaction` capability domain stays `unmeasured`

`CapabilityDomain::WorkspaceTransaction` lowers to `unrepresentable` today
(`aa_isolation::lowering`) — no policy schema node exists for it, and no backend
enforces it. This ticket does not push an `EvidenceRecord` for that domain on a
`--workspace-tx` run. Two reasons: the policy layer cannot express the domain yet, so
there is nothing for a run to have satisfied or violated against policy; and the
commit-or-discard decision itself runs offline, after the confined process has already
exited — it is not an in-run control decision the runtime's evidence model is shaped to
describe. Recorded here as a decision, not left as an unexplained gap.

## Known properties, stated rather than hidden

- **Exclusions are one-directional.** `--workspace-tx-exclude` excludes a selector from
  the *copy-in* to the staged workspace — it is not excluded from the *apply-back*. A
  path the confined process creates inside an excluded selector is absent from the base
  manifest, present in the staged manifest, diffs as `Added`, and is applied to the base
  on commit. `surface_excluded_count` on the receipt therefore means "excluded from the
  copy-in", not "outside the transaction" — and an excluded path is **absent from the
  staged workspace, not shared with the base**: a build inside a transaction with
  `target/` excluded rebuilds from scratch.
- **Policy selectors are not rewritten.** A policy path selector naming the project
  directory explicitly is matched against real base paths; it is not rewritten onto the
  staged root, so it does not cover a transaction's staged copy.
- **Rename reads as delete+add.** No rename detection exists; a path moved by the
  confined process is recorded as one deletion and one addition.

## What this ADR does not decide

- A policy-schema node for `CapabilityDomain::WorkspaceTransaction`.
- Surface-size or entry-count ceilings, or a copy-time disk budget.
- `aasm workspace tx show/commit/discard/gc` — no subcommand exists yet to inspect,
  manually resolve, or garbage-collect a transaction's state directory.
- Interactive review-before-commit.
- An overlayfs, git-worktree, or VM-disk-snapshot backend for this same contract.
- Whether transactional mode ever becomes the default for `aasm run`.
- Multiple concurrent transactions over one base directory.
- Any SaaS-side verification of a transaction's receipt binding.

## Consequences

- **Disk cost proportional to the declared surface.** A transaction's staged copy
  costs roughly one additional copy of whatever the surface contains, for the duration
  of the launch.
- **A cold build inside a transaction**, whenever a build-output directory is excluded
  from the surface — the trade-off `target/`-style exclusions accept deliberately.
- **A concurrent editor turns into a refused commit, not a lost update.** Decision 3's
  drift check means a base path edited by something else while the transaction was
  open refuses the whole commit rather than silently overwriting the concurrent edit.
  This is by design: a refusal is recoverable (retry against a fresh transaction); a
  silently lost update is not.
