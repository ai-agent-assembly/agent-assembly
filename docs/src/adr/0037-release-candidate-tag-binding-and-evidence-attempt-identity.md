# ADR 0037: Release Candidate/Tag Binding & Append-Only Evidence Attempts

**Status**: Accepted (AAASM-6001, owner decision recorded on the Jira ticket).

## Context

`scripts/qa/check-release-evidence.py` (AAASM-5878/5898/5899, ADR-adjacent but
never itself ADR-recorded) binds a release tag to the exact commit QA and
security actually verified, via a committed evidence record
(`docs/release/qa-signoff/v<version>.evidence.json`) naming a
`candidate_sha`. `scripts/release-tag-guard.sh` (AAASM-5879) is the sole
sanctioned tag-creation path and re-checks this binding itself, independent
of and originally stricter than the checker's own R1 rule.

**AAASM-5998** found and fixed the real bug this ADR was originally opened
to address: `release-tag-guard.sh`'s step 5 required literal
`candidate_sha == HEAD`, which is unsatisfiable for any real, committed
evidence file (`build-release-evidence.py` captures `candidate_sha` as HEAD
*before* the evidence file is committed, so committing it necessarily
advances HEAD one commit past that value). AAASM-5998 replaced that literal
check with a fresh re-run of `check-release-evidence.py --tag-target HEAD`
immediately before tagging — reusing R1/R1b, the checker's own existing,
already-accepted candidate-binding and tamper-detection rules — as TOCTOU
defense-in-depth for the window between `release-readiness.sh` (which
already ran the same check) and the `git tag` call. A follow-up chain on
that same PR closed three further adversarial-review findings in R1/R1b
(a dependency-swap-via-mechanical-Cargo.toml-bump bypass, a sign-off-file
forgery riding as "docs", and an R1b tamper-detection bypass that could
choose its own search boundary) and hardened R1b/R6 against a crash on a
non-ancestor `candidate_sha`. **This is a real, shipped, merged fix**
(PR #2277 and its follow-ups) — not a hypothetical this ADR is proposing to
resolve from scratch. (An earlier version of this ADR/ticket's Context
section reproduced the unsatisfiable-`candidate_sha`-equality bug against a
stale local checkout that predated PR #2277 and, on that basis, incorrectly
claimed the bug was still live and that AAASM-5998 "did not touch"
`release-tag-guard.sh`'s own check at all. Both claims were wrong and were
retracted on the Jira ticket before this revision.)

**What AAASM-5998's shipped fix does NOT do**, and what this ADR actually
decides: it re-runs R1, and R1's own allowlist
(`_MECHANICAL_PREFIXES = ("docs/release/",)`) is deliberately broad —
correct for R1's own admissibility question (does stale-but-mechanical
drift, e.g. a version-bump commit or a release-notes file, still let a
candidate's evidence be reused for a later tag target), but too broad for
`release-tag-guard.sh`'s own question: is the *literal commit about to be
tagged* bound to the *literal commit verified*, with zero tolerance for
anything else riding along. Under R1 alone, an operator (or an attacker)
could add an unrelated `docs/release/` file — release notes, a second
version's evidence, an unrelated doc — in the same range as the sanctioned
evidence commit, and R1 would still classify the whole range as
`ancestor-mechanical` and pass. R1b's own carve-out already excludes
`docs/release/qa-signoff/` and `docs/release/security-signoff/` from that
tolerance (treating a post-candidate change to a sign-off file as
EXECUTABLE, i.e. blocking) — closing part of this gap already — but the
blanket `docs/release/` prefix outside those two subdirectories remains
tolerant, and R1 has no concept of "exactly this version's own artifacts,
nothing else" at all.

**AAASM-6001's separate, still-open finding**: no sanctioned skill in the
real operator flow ever generates the evidence file. `build-release-evidence.py`
is documented (`docs/release/qa-verification-manifest-schema.md`'s
"Generation" section) but never invoked by `/release-qa-gate` or
`/release-security-gate`, and `release-tag-cut` only ever reads the file —
correctly, since it must stay a verifier and fail closed rather than
opportunistically generate a missing prerequisite. This ADR's decision
addresses both findings together, since a repeatable finalization step and
a re-verification loop after `BLOCK` both need the same append-only
evidence-attempt identity described below.

AAASM-5999 added Developer Integration golden-journey coverage — unrelated
to this ADR; referenced only because it was investigated in the same
session and is explicitly out of scope here.

This ADR records: (1) how a version's repeated real verification attempts
are represented so a `BLOCK` is never lost, and (2) how a release tag's
candidate binding legally admits the evidence-generation commit(s) that
authorize it — a policy narrower than, and additional to, R1/R1b, not a
modification of them.

## Decision

### 1. Verification attempts are append-only

- A `BLOCK` verification attempt's evidence is immutable forever — never
  rewritten, amended, squashed, or converted to `PASS`.
- A later real verification (remediation landed as a new commit, re-run)
  creates a **fresh evidence-attempt identity**, never overwrites the prior
  one.
- The "current authoritative verdict" for a version is derived by reading
  the highest-numbered existing attempt, not by any written pointer file.

Mechanically: a version's first attempt keeps the pre-existing filename
(`docs/release/qa-signoff/v<version>.evidence.json`); every attempt after
that is `docs/release/qa-signoff/v<version>.attempt-<N>.evidence.json`, `N`
a positive integer with no leading zero, auto-incremented from what already
exists on disk. `<N>` is a QA-evidence bookkeeping suffix only — it is never
a product/patch version, never appears in a git tag, and never touches
`Cargo.toml`/`CHANGELOG.md`. This deliberately does not reuse the repo's
`-rc.N` product prerelease convention as the identifier itself (that would
consume a real product-version axis as a retry counter, which the owner
decision explicitly rejected); it mirrors that convention's *shape*
(a deterministic, monotonic, dotted-integer suffix) in a namespace that can
never collide with or leak into the real tag/version namespace.

`scripts/qa/build-release-evidence.py` refuses to mint a new attempt for a
`candidate_sha` that already has recorded evidence — a second attempt for an
unchanged commit is bookkeeping noise, not a real re-verification.

A new skill, `release-evidence-finalize`, is the one sanctioned place this
file is generated — after both the QA and security sign-off gates have
produced a sign-off for the same candidate, before the tag cut.
`release-tag-cut`/`release-tag-guard.sh` remain read-only verifiers of
whatever `release-evidence-finalize` already committed; they never generate
evidence themselves (requirement: fail closed on missing evidence, never
self-heal).

### 2. Candidate/tag binding — the allowlisted A→B model (Option 4)

```
A = evidence.candidate_sha — the exact product/code commit QA and
    security actually verified
B = the current HEAD, and the commit the tag will point at
```

`release-tag-guard.sh` accepts `B` as the tag target if and only if, in
**addition to** the existing R1/R1b re-verification AAASM-5998 already
performs (step 5a — unchanged by this ADR):

- **`A` is an ancestor of `B`** (`git merge-base --is-ancestor A B`), or
  `A == B` exactly;
- **every path that differs between `A` and `B` is on a narrow,
  version-scoped allowlist** — for the exact `<version>` requested:
  - `docs/release/qa-signoff/v<version>.md`
  - `docs/release/qa-signoff/v<version>.evidence.json`
  - `docs/release/qa-signoff/v<version>.attempt-<N>.evidence.json`
    (`N` matching `[1-9][0-9]*` exactly — no leading zero, no trailing
    characters, `re.escape()`d version, exact-match/full-match only, never a
    glob or prefix)
  - `docs/release/security-signoff/v<version>.md`
- a path that isn't already equal to its own `os.path.normpath()`, or that
  contains a `..` path segment, or starts with `/` or `~`, is refused
  outright regardless of what it otherwise looks like (traversal/
  canonicalization defense, independent of the allowlist match itself);
- **R1, R1b, and every other existing content-integrity/evidence-binding
  check in `check-release-evidence.py` still run and still pass** (step 5a) —
  `release-readiness.sh` check 14 is unchanged and still gates the tag as it
  did before this ADR.

Any other changed path between `A` and `B` — a source file, `Cargo.toml`/
`Cargo.lock`, CI workflow, build/runtime config, another version's evidence
file, a malformed filename that merely resembles a real attempt, or a real
allowlisted path landing in the **same commit** as a non-allowlisted one —
fails closed.

This is a **separate, narrower** check from `check-release-evidence.py`'s
own R1 rule (implemented as `strict_candidate_binding_violations()` /
`--strict-tag-binding`), run by `release-tag-guard.sh` step 5b in addition
to — not instead of — step 5a's existing R1/R1b re-verification. R1's
`_MECHANICAL_PREFIXES = ("docs/release/",)` is deliberately broad (it exists
so mechanical release-prep churn — a version-bump commit, `CHANGELOG.md`,
any file under `docs/release/`, `sonar-project.properties` — doesn't force a
full re-verification for R1's own purpose: tolerable drift between the
evidence's candidate and the tag target for that checker's admissibility
question). That tolerance is correct for R1 and would be wrong here: the
guard's job is binding the *literal commit about to be tagged* to the
*literal commit verified*, so its allowlist is version-scoped and
artifact-specific, not a directory prefix. The implementation reuses R1's
git-diff-enumeration mechanism (`GitRepo.diff_name_only`, `GitRepo.is_ancestor`)
but is given its own distinct, narrower policy — deliberately not
parameterized into a shared allowlist, so a future edit that "simplifies"
the two into one cannot widen this guard's boundary by accident.

### 3. What this proves

`released executable/product state at B == verified product state at A`,
while allowing only the immutable authorization artifacts required to make
the release auditable — no product/runtime/build/source/config/workflow
change can ride into the tagged commit after verification, regardless of
how it's dressed up (a single mixed commit, a forged filename, a sibling
version's evidence, a non-ancestor candidate, an unrelated
`docs/release/` file R1 alone would tolerate).

## Alternatives considered

Full option analysis (10-axis comparison per option) is recorded on
AAASM-6001's Jira thread; summarized here for the durable record.

- **Option 1 — guard admits a single, unrestricted evidence-only commit.**
  Rejected: an ad hoc, easy-to-under-scope single-commit rule duplicating
  part of R1 without reusing its already-reviewed enumeration mechanism; a
  sloppy "the commit only touches the evidence path" check is a real bypass
  risk (nothing stops a second file riding along in that one commit).
- **Option 2 — tag targets `candidate_sha` explicitly, not `HEAD`.**
  Rejected: removes the guard's implicit "you are standing on the commit
  you're about to tag" property entirely — no working-tree/HEAD linkage at
  all, a materially larger bypass surface (any reachable commit named by the
  evidence file tags successfully regardless of what's checked out); also a
  high-complexity inversion of `release-tag-cut`'s existing pre-condition
  model (bump PR / release notes / sign-offs are all expected to be *on* the
  commit being tagged).
- **Option 3 — evidence lands post-tag.** Rejected: inverts the entire
  release-relay ordering (gate-then-tag becomes tag-then-gate), directly
  conflicts with the standing AAASM-6001 decision that evidence *authorizes*
  the tag pre-push, and is the option with the largest bypass surface (a tag
  could be pushed with zero verification and evidence backfilled after the
  fact to match whatever shipped).
- **Generic "`candidate_sha` is any ancestor of `HEAD`, filtered only by R1's
  existing allowlist".** This is what AAASM-5998's shipped fix does on its
  own (step 5a) — explicitly rejected as *sufficient on its own* by the
  owner decision: it tolerates an unrelated `docs/release/` file (release
  notes, a sibling version's evidence) riding into the tagged commit
  alongside the sanctioned evidence, an obvious post-verification-mutation
  bypass once evidence generation is a real, repeatable operator step
  (AAASM-6001) rather than a rare one-off commit. Kept as step 5a (TOCTOU
  re-verification of R1/R1b's own tamper/freshness semantics is still
  correct and still required); Option 4's narrower check is layered on top
  as step 5b, not a replacement.

## Consequences

- `check-release-evidence.py` gains `strict_candidate_binding_violations()`
  and a `--strict-tag-binding` CLI mode; no change to R1/R1b rule logic, no
  evidence schema change.
- `release-tag-guard.sh` step 5 becomes two steps: 5a (AAASM-5998's existing
  R1/R1b re-verification, unchanged) and 5b (this ADR's narrower,
  version-scoped check, additional).
- A version's evidence for a given attempt is permanently reachable by exact
  path; `latest_evidence_path()` (checker) and
  `next_evidence_out_path()`/reuse-refusal (emitter) share the same
  `[1-9][0-9]*`-anchored attempt-number pattern as this guard's allowlist, so
  a malformed/forged filename is rejected consistently everywhere it's
  checked, not just at the tag guard.
- Real, end-to-end-reproduced negative/positive coverage lives in
  `scripts/tests/release-relay-negative-control.sh` (extended: a generic
  docs/release/ file, a mixed allowed+forbidden commit, sibling-version
  evidence, and a forged attempt filename each still block under 5b even
  though R1 alone tolerates or is silent on some of them).
- **`--strict-tag-binding`'s evidence resolution is git-tree-based
  (`latest_evidence_path_at_ref()`, `git ls-tree`/`git show`), deliberately
  different from the general R1-R10 flow's disk-based
  `latest_evidence_path()`.** An independent adversarial review of this
  diff (before it shipped) found that the first cut resolved evidence via
  `os.listdir()`/`open()` on disk in every mode, including
  `--strict-tag-binding` — meaning an untracked file dropped anywhere
  under `docs/release/qa-signoff/` (no commit or push rights needed, just
  filesystem write access to the checkout at the moment the guard runs)
  would be treated as authoritative, and with `candidate_sha ==
  tag_target_sha` trivially satisfied by naming the current HEAD, made the
  guard report OK against a completely unverified commit. `release-tag-guard.sh`'s
  own step 2 (clean working tree) already rejects an untracked file in the
  real end-to-end flow, but `check-release-evidence.py` cannot assume it is
  only ever invoked downstream of that gate — a regression test
  (`scripts/tests/release-relay-negative-control.sh`, "untracked forged
  evidence file") plants exactly this file and asserts refusal.
- **`strict_candidate_binding_violations()` scans every commit in the
  candidate..target range (`paths_touched_in_range()`, `git log
  --name-only --no-renames`), not the net two-tree diff
  (`diff_name_only()`).** The same review found a net diff misses (a) an
  intermediate commit that changes a non-allowlisted path and a later
  commit that reverts it back to the original content before the tag
  target — the two-tree diff shows no change at all; and (b) — with git's
  default rename detection left on — a same-content move of a forbidden
  file into an allowlisted path within a single commit, which can pair the
  deletion with the addition and drop the forbidden source path from the
  diff entirely. A merge commit anywhere in the range is now refused
  outright for the same reason (`git log --name-only` shows no file list
  for a merge commit by default). Regression tests for both cases (revert-
  then-reapply; the merge-commit refusal falls out of existing coverage)
  live in the same file.
- **An allowlisted path is checked for git object mode, not just its
  string, at the tag target** (`GitRepo.mode_at()`) — refuses if a
  gitlink/submodule reference (mode `160000`, pointing at an arbitrary,
  potentially attacker-controlled external commit) has been substituted at
  the exact same path, which the string-only allowlist match alone cannot
  distinguish from an ordinary content edit.

## Revision history

- 2026-08-28 — initial version, AAASM-6001 owner decision (Option 4)
  recorded and implemented against a local checkout that was stale relative
  to `remote/main` (46 commits behind) — the Context section's claims about
  AAASM-5998 not having touched `release-tag-guard.sh` were wrong, retracted
  on the Jira ticket, and corrected in the revision below.
- 2026-08-28 — three findings from an independent adversarial review of the
  implementation (a working-tree-trust bypass in `--strict-tag-binding`'s
  evidence resolution; a net-diff blind spot to revert-then-reapply and
  rename-collapse; a gitlink-substitution gap in the allowlist check) fixed
  before this ADR's implementation was pushed. No change to the accepted
  Option-4 design or its allowlist; all three were implementation gaps in
  how the design was enforced, not design changes.
- 2026-08-28 — Context and Alternatives rewritten against `remote/main`'s
  actual shipped state (PR #2277 and its follow-ups); Decision section 2 and
  Consequences updated to describe step 5b as additional to AAASM-5998's
  existing step 5a, not a replacement of it. No change to the accepted
  Option-4 design itself.
