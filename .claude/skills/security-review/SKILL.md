---
name: security-review
description: Run the release-gate security review for an agent-assembly release, scaled by release type (patch / minor / major). Patch = dependency/advisory audit + release-diff review; minor = + changed-attack-surface review via the trust-boundary delta checklist; major = + full threat-model refresh + pen-test checklist. Emits a PASS/BLOCK sign-off artifact and BLOCKS on any unaddressed High/Critical finding. Use as the stage-0 pre-cut gate before /release-tag-cut.
---

# security-review

The **release-gate** security review. It runs *before* a release tag is cut,
scales the depth of review to the release type, and produces a committed
**sign-off artifact** that the release-readiness check enforces. A release with
an unaddressed High or Critical finding **cannot** proceed.

This SKILL.md is a lean overview; the per-tier checklist detail lives in
[REFERENCE.md](REFERENCE.md). The threat model it refreshes is
[`docs/src/security/release-threat-model.md`](../../../docs/src/security/release-threat-model.md);
the per-release delta form it fills is
[`docs/src/security/trust-boundary-review-checklist.md`](../../../docs/src/security/trust-boundary-review-checklist.md).

## Where this sits in the release relay

A full release is a relay (see
[`release-tag-cut/SKILL.md`](../release-tag-cut/SKILL.md)). This skill is
**stage 0 — the pre-cut gate**, run *before* `release-tag-cut`:

0. **`/security-review <version>`** (this skill) — review scaled by release type;
   write the sign-off artifact under `docs/release/security-signoff/`. A
   **BLOCK** verdict, or any unaddressed High/Critical, stops the release here.
1. **`/release-tag-cut <version>`** — bump + tag + push. Its pre-conditions now
   require a `Verdict: PASS` sign-off for `<version>` (enforced by
   `scripts/release-readiness.sh`).
2. **fan-out** (automatic, `release.yml`).
3. **`/release-validate-channels v<version>`** (read-only).
4. **`/homebrew-tap-merge <PR>`** (write, tap repo).

## When to use

- The operator is preparing to cut a release tag and needs the mandatory
  pre-cut security sign-off (every patch / minor / major).
- Re-running after addressing findings, to flip a prior **BLOCK** to **PASS**.

Triggering phrasing: *"Security-review beta.4"*, *"Run the release security gate
for 0.0.1-beta.4"*, *"Sign off the security review before we tag"*.

## When NOT to use

- **Not a release.** This is a release gate, not an ad-hoc audit. For a
  standalone code review, use `/security-review` from the built-in review path or
  open a security ticket.
- **SDK-only release** — the SDK repos run their own quality gates; this skill is
  agent-assembly-monorepo scoped.
- **The sign-off already PASSes for this exact version and nothing changed
  since** — do not regenerate; the artifact is the record.

## How to use

**Invocation**:

```text
/security-review <version>
```

where `<version>` is the target literal exactly as it will appear in the tag
(e.g. `0.0.1-beta.4`, NOT `v0.0.1-beta.4`).

**Release-type detection.** Derive patch / minor / major from `<version>` vs the
previous tag (operator may override):

- **patch** — within the same pre-release series, the trailing counter advances
  (e.g. `0.0.1-beta.3` → `0.0.1-beta.4`), or the SemVer patch advances.
- **minor** — the SemVer minor advances (`0.0.1` → `0.1.0`), or a pre-release
  channel is promoted (`…beta.N` → `…rc.1`).
- **major** — the SemVer major advances (`0.x` → `1.0.0`).

The tiers are **additive** — minor does everything patch does *plus more*; major
does everything minor does *plus more*.

## The tiers (additive)

| Tier | Scope (each tier ADDS to the one above) |
|---|---|
| **patch** | Dependency/advisory audit (`cargo deny check advisories`, open Dependabot + CodeQL alerts) **+** release-diff review (`git log <prev-tag>..HEAD`). |
| **minor** | *patch* **+** changed-attack-surface review: fill the [trust-boundary review checklist](../../../docs/src/security/trust-boundary-review-checklist.md) against the diff (new endpoints, loosened policy defaults, new egress/IPC surface). |
| **major** | *minor* **+** full [release threat-model](../../../docs/src/security/release-threat-model.md) refresh (advance the version field + revision table) **+** the pen-test checklist (REFERENCE.md). |

Per-tier step detail, the exact commands, and the pen-test checklist are in
[REFERENCE.md](REFERENCE.md).

## Verdict rule (BLOCK on unaddressed High/Critical)

Classify every finding `Critical / High / Medium / Low / Info`. Then:

- **BLOCK** if **any** Critical or High finding is unaddressed (not fixed, not
  accepted-with-owner-justification recorded in the artifact).
- **PASS** only when no Critical/High remains unaddressed and the tier's required
  sections are all completed.

A **BLOCK** verdict stops the release: `release-readiness.sh` fails the readiness
run unless the artifact for `<version>` contains `Verdict: PASS`.

## The sign-off artifact (output)

The review writes one Markdown file:

```text
docs/release/security-signoff/v<version>.md
```

It is produced from the template at
[`docs/release/security-signoff/TEMPLATE.md`](../../../docs/release/security-signoff/TEMPLATE.md)
and MUST contain, at minimum:

- **Reviewer** and **Date**.
- **Release type** (patch / minor / major) and **previous tag**.
- The **findings table** (severity · finding · status).
- The completed **trust-boundary review checklist** (minor+).
- A single **`Verdict: PASS`** or **`Verdict: BLOCK`** line — the exact token
  `Verdict: PASS` is what `release-readiness.sh` greps for.

Commit it (`📝 (release): Security sign-off for v<version>`) so the release has an
auditable, blocking record.

## Pre-conditions

1. Target `<version>` provided; previous tag resolvable (`git describe --tags`
   or operator-supplied).
2. `cargo deny` available (or note its absence in the artifact as an Info item +
   fall back to `deny.toml` review).
3. Run from the `agent-assembly/` checkout (or a worktree) with `remote` fetched.

## What this skill does NOT do

- It does **not** cut the tag (that is `/release-tag-cut`).
- It does **not** fix findings — it classifies and gates; fixes are separate
  commits/PRs reviewed on their own.
- It does **not** touch repos other than `ai-agent-assembly/agent-assembly`.

## Detailed references

- **Per-tier checklist + commands + pen-test list** → [REFERENCE.md](REFERENCE.md)
- **Release relay** → [`release-tag-cut/SKILL.md`](../release-tag-cut/SKILL.md)
- **Gate enforcement** → `scripts/release-readiness.sh` (the sign-off check) and
  [`docs/release/RUNBOOK.md`](../../../docs/release/RUNBOOK.md).
