# Isolation/runtime campaign — final reconciliation (2026-09-03)

Durable record for any future session picking this campaign back up. The
working ledger (`scratchpad/ISOLATION-CAMPAIGN-LEDGER.md`) has the full
chronological detail; this file is the committed, permanent summary of where
it landed.

## Status: **ENGINEERING_COMPLETE**

Every ticket this campaign's later passes opened is closed with real,
CI-verified evidence, except one that is correctly tracked as an **upstream
limitation / watch item**, not open AASM engineering work. No
independently-actionable isolation/runtime engineering work remains
identified as of this reconciliation.

## What closed, with evidence

| Ticket | Disposition | Evidence |
|---|---|---|
| AAASM-6029 | Done — spike, recommendation: don't build a per-decision evidence channel now | [report](AAASM-6029-per-decision-prevention-evidence-spike.md), PR #2339 |
| AAASM-6041 / AAASM-5532 | Done — real, CI-enforced coverage | PR #2355 (`4fa74466b`) — detached/re-parented descendant scenario un-`#[ignore]`d, passing for real through the production launcher with genuine PID-1 re-parenting |
| AAASM-6040 | Done — doc correction + pinning test | PR #2356 (`0c58ca57b`) — `can_observe()`'s false "enforcing implies knowing" claim corrected |
| AAASM-5634 | Done — truthfulness fix | PR #2357 (`965b13700`) — `SSL_write_ex`/`SSL_read_ex` false attachment claim corrected |
| AAASM-6050 | Done — truthfulness fix | PR #2359 (`48521911548`) — `kprobe.rs` module doc under-claim corrected (found incidentally, fixed same pass per the campaign's defect-handling policy) |
| **AAASM-6039** | **Done — upstream limitation, watch item** (labels: `upstream-limitation`, `not-aasm-defect`, `watch-item`) | See below |

All merges used the AAASM-5858 owner-only admin-merge exception (verified org
owner, fresh identity check each time), merge commits only, never
squash/rebase. All CI runs referenced above were green before merge.

## AAASM-6039 in detail — why it is not open engineering work

The desired capability — a live per-decision Sandlock CLI event stream, so
AASM could show *which specific action* was denied rather than only that a
boundary is enforced — **does not exist in Sandlock today**, verified by
reading real upstream source and releases (read-only `gh api`, no writes made
to any repository AASM does not own, at any point):

- Sandlock v0.8.6 is genuinely the current release.
- `sandlock inspect`/`ps` expose effective policy/metadata only.
- RFC #72 (`sandlock learn`, shipped) generates a static aggregated policy
  profile from one observed run — not a live per-decision stream. Its own
  speculative `--debug-log` side-channel was never implemented.
- RFC #68 ("control-socket introspection", shipped `ps`/`inspect`/`kill`)
  explicitly scoped a `logs` verb — *"ring buffer of recent seccomp denials
  and MITM proxy decisions"* — exactly the shape AASM wants. **That verb was
  never implemented**, confirmed against the current `Command` enum on
  `multikernel/sandlock`'s `main` branch. No separate tracking issue exists
  for it.

This is a genuine upstream gap, not an AASM defect and not something AASM's
own code can produce — AAASM-6029 already established that the AASM-side
consuming path (`EvidenceKind::Decision`, `supports_prevention_claim`, the
whole promotion path) is fully built and needs only a producer.

**Standing policy**: no issue, PR, comment, or any other content is submitted
to any repository AASM does not own without explicit, case-by-case owner
approval. A complete, ready-to-submit issue package (referencing RFC #68's
already-scoped `logs` verb) is preserved in AAASM-6039's Jira comment history
for if/when that approval is given. It has not been submitted.

**Revisit only if:**
1. Sandlock ships a `logs` verb, `--events-fd`, or any other CLI per-decision
   event surface in a future release, or
2. AASM's own requirements change such that linking Sandlock as a library
   (reaching `policy_fn` directly) becomes an acceptable trade against its
   license/provenance cost (AAASM-6029's finding), or
3. The owner explicitly approves filing the prepared upstream request.

None of these conditions currently hold.

## Scope boundary — what this campaign did not touch, and why

The Epic 5526 Jira DAG has other open items. None were pulled into this
campaign:

- **AAASM-5533** (MCP transport mediation) and its siblings **5645/5649/5650**
  (all MCP-related) — different subsystem, explicitly deprioritized/deferred
  as a separate campaign per repeated owner instruction across this session.
- **AAASM-5648** (tenant isolation at the storage layer) — different
  subsystem (data/storage isolation, not execution isolation).
- **AAASM-5640** (eBPF loader daemon release-channel gap) — release/
  distribution engineering, not an isolation/runtime mechanism defect.
- **AAASM-5536/5630/5631** (doc-truthfulness CI gates, absolute-claim removal,
  DispatchTool credential-injection decision) — general Security Boundary
  epic meta-work, not execution-isolation mechanism work, and several require
  a product/security decision this pass's mandate did not authorize.

None of these were pulled in merely to keep the campaign active, per explicit
instruction not to manufacture work.

## Root-cause findings this campaign produced, for future reference

- **`aa-isolation-native/src/proc_scope.rs`'s `/proc` scoping** (AAASM-5804)
  deliberately grants `/proc/self` only for the top-level launched process,
  resolved once before `execve`, to keep other processes' `/proc/<pid>`
  entries out of the boundary. A forked descendant's own `/proc/self`
  therefore resolves to a directory no rule names — real, documented,
  intentional, not a bug. `getppid()` (a plain syscall, not
  filesystem-mediated) is the correct way to observe a descendant's identity
  under this design, not a `/proc` grant change.
- Two independent CI-caught instances this campaign of the same mistake
  class ("spawning a new process to check an ancestor's identity measures
  the new process's own parent, not the ancestor's") — first with `awk`
  (PR #2348, original scenario), then with `python3` spawned as a child
  (this campaign's first fix attempt, caught before merge). The fix in both
  cases is either a no-fork shell builtin or `exec`ing in place, never a
  fork+exec.
