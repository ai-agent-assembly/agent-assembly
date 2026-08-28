---
name: release-evidence-finalize
description: Generate and commit the immutable release-evidence artifact for a version once both the QA and security sign-offs are final. Use after /release-qa-gate and /release-security-gate have both produced a sign-off for the exact candidate you want evidenced, and before /release-tag-cut. Each run mints a fresh, permanently-preserved evidence file (AAASM-6001) — it never overwrites a prior attempt's evidence, including a prior BLOCK. Does not tag, does not push, does not invent sign-offs it can't find.
---

# release-evidence-finalize

Thin finalization stage between the sign-off gates and the tag cut:

```
release-security-gate ─┐
                        ├─> release-evidence-finalize ─> release-tag-cut
release-qa-gate ────────┘        (this skill)          (verify/read/tag only)
```

**Why this exists as its own step** (AAASM-6001). `docs/release/qa-signoff/v<X>.evidence.json`
is documented (`docs/release/qa-verification-manifest-schema.md`) and
`scripts/qa/build-release-evidence.py` exists, but no skill in the real
operator flow ever invoked it — `/release-qa-gate` and `/release-security-gate`
produce the `.md` sign-offs; `release-tag-cut` reads the evidence file (via
`release-readiness.sh` check 14 / `release-tag-guard.sh`) without generating
it. `release-tag-cut` stays a verifier: it must fail closed if evidence is
missing, not opportunistically generate it. This skill is the one place
that generates it, so evidence generation (this skill) and evidence
verification (`release-tag-cut`) stay conceptually separate — a
re-verification loop after a BLOCK belongs here, not inside the tag-cut
skill.

## When to use

Both are true:

- `docs/release/security-signoff/v<X>.md` exists (stage 0,
  `/release-security-gate <X>`).
- `docs/release/qa-signoff/v<X>.md` exists (stage 0, `/release-qa-gate <X>`
  in `release` depth).

Either sign-off may itself be `Verdict: BLOCK` — evidencing a BLOCK
candidate (so the BLOCK becomes a permanent, auditable record) is exactly as
valid a reason to run this skill as evidencing a PASS one.

## When NOT to use

- **Only one sign-off exists.** Wait for the other — evidence must reconcile
  both inputs together (`build_evidence`'s own signature requires both
  paths); do not run this against a stand-in or a stale sign-off from a
  different candidate.
- **You want to re-evidence the exact same commit that already has
  evidence.** There is nothing to re-verify — `build-release-evidence.py`
  refuses (a second attempt for an unchanged candidate is bookkeeping
  noise, not a real re-verification). Re-run the sign-off gate(s) first if
  something needs to change, then run this skill against the new commit.
- **You are trying to fix a BLOCK by editing its evidence file.** Not
  possible by design (R1b) and not the intended recovery — remediate,
  re-run the sign-off gate(s) on the fixed commit, then run this skill
  again; it mints a new attempt automatically.

## How to use

```bash
python3 scripts/qa/build-release-evidence.py --repo-root . --version <X>
```

No `--out`/`--candidate-sha` needed for a normal run — `--candidate-sha`
defaults to `git rev-parse HEAD`, and `--out` auto-selects the next unused
evidence-attempt path for `<X>`:

- First attempt for `<X>` → `docs/release/qa-signoff/v<X>.evidence.json`
  (same path the schema doc already documents — a version's first attempt
  is unchanged).
- Every attempt after that → `docs/release/qa-signoff/v<X>.attempt-<N>.evidence.json`,
  `<N>` auto-incremented from whatever attempts already exist on disk.

The attempt number is a QA-evidence bookkeeping suffix only. It is never a
product version, never appears in a git tag, and never touches
`Cargo.toml`/`CHANGELOG.md` — per AAASM-6001's owner decision, ordinary
product patch versions are not consumed as retry counters.

**Do not pass `--out` in a normal run.** The default path is always a fresh,
never-yet-used attempt path for `<X>` — that is what makes a prior attempt's
evidence immutable in practice. `--out` exists as an override for tests and
one-off tooling; using it to point at an existing file will silently
overwrite it (the emitter does not protect an explicit `--out` the way the
default path is protected by construction) — never do that against a real
evidence file.

Commit the result:

```bash
git add docs/release/qa-signoff/v<X>.evidence.json  # or v<X>.attempt-<N>.evidence.json
git commit -m "📝 (release): Evidence for v<X> (verdict: <PASS|BLOCK>)"
```

> Committing the evidence file, as instructed above, advances `HEAD` one
> commit past the `candidate_sha` the evidence names. This is expected and
> sanctioned: `release-tag-guard.sh`'s strict candidate/tag binding check
> (`--strict-tag-binding`) accepts `HEAD` descending from `candidate_sha`
> through commits that touch *only* this version's own sign-off/evidence
> artifacts — exactly `docs/release/qa-signoff/v<X>.md`,
> `docs/release/qa-signoff/v<X>.evidence.json` (or `.attempt-<N>.evidence.json`),
> and `docs/release/security-signoff/v<X>.md` (ADR 0037, AAASM-6001 Option 4)
> — the exact shape a normal `git add`+`git commit` of the evidence file
> this skill just wrote produces. It does **not** accept any other change
> riding along in that commit (a source/config/build/workflow file, another
> version's evidence, a malformed attempt filename) — keep the evidence
> commit to exactly the evidence file, nothing else.

Report the verdict printed by the emitter (`wrote <path> (verdict: <V>)`).

- **PASS** — evidence is ready; `/release-tag-cut <X>` can now bind to it
  (via `scripts/qa/check-release-evidence.py`'s default resolution, which
  always picks the highest-numbered attempt that exists).
- **BLOCK** — this attempt's evidence is now permanently on record. Do not
  touch it. Remediate, get the sign-off(s) re-run against the fixed commit,
  then run this skill again — it mints attempt N+1 without you naming a
  number.

## Post-conditions

- Exactly one new evidence file exists, committed, at a path that has never
  existed before this run.
- Every prior evidence file for `<X>` (if any) is untouched — verify with
  `git log --oneline -- docs/release/qa-signoff/v<X>*.evidence.json` before
  and after; each prior path's history should gain zero new commits.
- `scripts/qa/check-release-evidence.py --version <X> --tag-target HEAD`
  (no `--evidence` override) resolves to the file this run just wrote.
