# Reference — classification of AI Agent Assembly's Rust evidence

`rust-development` reuses real, evidence-backed findings from
`ai-agent-assembly/agent-assembly`'s AAASM-5991/5992 Rust-performance
epic instead of re-deriving them from scratch. Source documents (read in
full for this classification, both under that repo's own
`docs/bench-5992/`): `rust-dev-performance-policy.md` (the durable policy
that repo maintains for itself) and `report.md` (the AAASM-5992 benchmark
spike — the primary evidence the policy itself defers to).

## The deference rule — read this before anything below

**The generic Rust skill defers to a narrower repository/product measured
policy when present.** `ai-agent-assembly/agent-assembly` keeps its own
Rust performance policy at `docs/bench-5992/rust-dev-performance-policy.md`
in its own repository — this skill never overrides it, and nothing below
becomes universal Horonom fact merely because it was measured well. Per
`governance/engineering/agent-skill-architecture.md` §7, the reverse
direction — Horonom governance or company-wide "fact" leaking into an
`ai-agent-assembly/*` repo, or that repo's own machine-specific numbers
being presented as a Horonom-wide invariant — is a FAIL-severity
governance-boundary defect, not a style nit. That's why this
classification exists: to let a Horonom repo benefit from AA's real
measurement work without silently annexing AA's machine and product as
if they were company truth.

If a Horonom repo's own Rust workspace ever accumulates its own
benchmark-backed policy, that repo's policy is narrower authority for
itself, exactly the same way AA's is for AA — this skill would then defer
to it too.

## (a) Reusable company-level Rust patterns — generalizable

These are mechanism-level facts about Cargo/rustc/nextest's own design,
not about AA's specific crate graph or machine, so they transfer to any
Rust repo:

- A shared `target-dir`'s `debug/.cargo-lock` is one exclusive lock for
  the *entire* debug-profile tree — concurrent debug builds against the
  same target-dir serialize regardless of which packages they touch.
  This is a property of Cargo's locking model, not of any one repo's code.
- Cargo's own incremental-compilation cache satisfies a warm single-file
  rebuild before `rustc` (or a wrapper like sccache) is ever invoked —
  sccache is only able to act under non-incremental builds
  (`CARGO_INCREMENTAL=0`, the typical CI regime); it is a no-op for a
  local incremental edit loop, not something that stacks on top of it.
- Test-target discovery/link cost scales with the *number* of freshly
  built test binaries invited into a discovery pass, not with a fixed
  per-workspace tax — narrowing the invocation (`--lib`, `--test <stem>`,
  `-p <crate>`) is a discovery-*count* fix and the only lever; no
  nextest flag skips or parallelizes the cost away.
- Full per-worktree/per-lane target-dir isolation trades shared-lock
  contention for disk growth; a shared target-dir trades disk growth for
  lock contention. Whichever a repo chooses, unbounded growth needs some
  ownership-scoped reclamation discipline (reclaim exactly the resource
  you own, refuse rather than guess on anything active or unproven) — the
  *pattern* generalizes even though AA's specific reclamation tool
  (below) does not.
- Report and reason about compile time, link time, discovery time, and
  actual test-execution time as separate quantities — collapsing a
  multi-phase command into one "it took N minutes" figure hides which
  phase is actually the cost, and which phase (if any) is a genuine stall
  versus expected overhead.
- `cargo check` cannot prove link/native/release-profile correctness
  (see `references/cargo-workflow.md`) — this is a fact about what
  `check` does, true on every Rust toolchain, not an AA-specific finding.

## (b) AI-Agent-Assembly-specific facts — do not universalize

These are real, well-measured numbers, but they describe one repo's crate
graph, one CI configuration, and one point in time. Never present them as
Horonom-wide targets or thresholds:

- Exact wall-clock numbers: 139s cold build, 6s warm rebuild, 584s test-binary
  compile (157s compile + ~427s discovery), 54s for a single `--lib` target,
  ~1h40m for an unscoped 34-target run, 29 GiB peak disk for one isolated
  benchmark lane.
- Exact CI job wall-clock ranges (Build 10m1s–12m49s, Clippy 7m19s–8m29s,
  Test 34m25s–41m58s, commit-range-build 4m46s–12m26s) and the ~15%
  cache-write error rate observed on Build/Clippy sccache runs.
- Per-job sccache verdicts specific to that repo's job shapes: adopted for
  `build`/`clippy lint`/`commit-range-build` (measured ~25% median
  wall-clock cut on a clean rebuild, n=3 reps on one small leaf crate);
  explicitly **rejected** for `test` (AAASM-6004 — both A/B arms fell
  inside the existing no-sccache baseline) and for `coverage`
  (AAASM-6006 — warm run was *slower*, hit rate dropped). A different
  repo's job shapes could land differently in either direction; the
  verdict is not portable, only the experimental method is.
- `Swatinem/rust-cache`'s `cache-targets: false` adopted for the `build`
  job only (AAASM-6005) — a finding about that repo's cache reliability
  on that job, not a blanket recommendation.
- "At most 2 uncontrolled heavy Cargo lanes" — the policy document itself
  states this has no new empirical lane-count derivation from this epic;
  it's a carried-forward default pending real per-lane disk-quota data,
  not a measured ceiling to adopt as-is elsewhere.
- `rust-target-lifecycle.sh`, its CLI surface, and its safety behaviors —
  a real implementation, but explicitly repo/machine-scoped by the
  report's own NO_NEW_REPO decision (§8: "this developer's worktree
  layout convention," no demonstrated cross-repo reuse). Reuse the
  *pattern* it embodies (ownership-scoped, refuse-rather-than-guess
  reclamation) described in (a) above — never assume a Horonom repo has
  this exact script, and never commit a reference to its literal path as
  if it were shared tooling.
- 30 workspace members, 898 resolved `Cargo.lock` packages, duplicate
  dependency-version counts — describes that one workspace's dependency
  graph at that commit.

## (c) Machine-specific — do not universalize

- The benchmark machine's 16 logical CPUs / 128 GiB RAM and its disk
  headroom over the campaign (417→373 GiB free) — a different developer
  machine or CI runner has different numbers, and "heavy-lane" guidance
  derived from this machine's disk math doesn't transfer as-is.
- The 2026-08-26 disk-exhaustion field incident (229 MiB free / 100%
  capacity under uncontrolled per-worktree isolation) — real evidence for
  *why* unbounded per-lane growth is dangerous, but the absolute
  threshold is this machine's, not a general "you will run out at N GiB"
  claim.
- Any local absolute filesystem path from either source document (this
  developer's home-directory worktree layout, the campaign's benchmark
  lane directories) — never carry a literal path like that into this
  skill's committed content; per
  `governance/engineering/agent-skill-architecture.md` §8, workspace
  roots are runtime-local defaults, never committed literally.
- macOS-vs-Linux linker asymmetry as measured on this machine's toolchain
  (Apple's post-Xcode-15 default linker vs. mold on Linux CI) — the
  underlying ecosystem facts (rust-lld's macOS support status, mold's
  Linux maturity) may shift with toolchain/ecosystem updates; the report
  itself flags this classification as not necessarily permanent.

## (d) Outdated / needs revalidation

- **The dyld/Gatekeeper/codesign first-launch-validation mechanism for
  nextest discovery cost is not independently confirmed in the primary
  evidence.** `rust-dev-performance-policy.md` states it as established
  fact ("macOS Gatekeeper/codesign first-launch validation on every
  freshly-linked test binary"). `report.md` §4.1 — the document the
  policy itself names as primary evidence, with any discrepancy treated
  as a bug in the policy — is explicit that this run "did not
  independently take a `sample`/stack-trace of its own, so it is an
  inference by analogy, not an independently re-proven mechanism," and
  that the observed process state is "also consistent with codesign IPC,
  filesystem I/O wait, or nextest's own internal synchronization." Treat
  the *mechanism* as plausible, not confirmed. What **is** directly
  measured and durable regardless of mechanism: the discovery-phase cost
  scales with the number of freshly-linked binaries invited into
  discovery, and narrowing scope is the only lever that reduces it — that
  claim belongs in bucket (a); the dyld/Gatekeeper causal story belongs
  here.
- **Warm-cache sccache hit rate** (steady-state, after multiple runs'
  worth of object-cache accumulation) — the report states this is
  unavailable and needs its own future measurement run; the only sccache
  numbers on record are cold/near-cold.
- **2/4/8-lane concurrency sweep** — deliberately not re-run this
  campaign; carried forward from an earlier epic's evidence. The report's
  own limitations section says a future challenge to that conclusion
  needs a fresh sweep, not a re-read of the existing writeup.
- **Cranelift/Wild linker rejection** — evaluated and rejected only
  because of the ecosystem's state at evaluation time (nightly-only,
  `panic=abort` forced on macOS, no incremental linking on Linux); both
  documents flag this as a snapshot judgment to revisit if the ecosystem
  changes, not a permanent verdict.
- **The ~15% sccache cache-write error rate** — recorded as real but with
  an undiagnosed cause; carrying it forward as "sccache has a ~15% error
  rate" without also carrying the "cause not diagnosed" caveat would
  overstate confidence.
