# Verification report — AAASM-3566

**Story:** 🔒 (security): Release-gated security-review process + threat model &
trust-boundary docs
**Branch:** `v0.0.1/AAASM-3566/release_security_gate`
**Date:** 2026-06-23
**Verifier:** Claude Code

## Subtasks delivered

| Subtask | Deliverable | State |
|---|---|---|
| AAASM-3572 | `docs/src/security/release-threat-model.md` (versioned, 6-layer map, revision table) + SUMMARY + cross-links | Done |
| AAASM-3573 | `docs/src/security/trust-boundary-review-checklist.md` (per-boundary delta form, guarded NO row) + SUMMARY + cross-links | Done |
| AAASM-3574 | `.claude/skills/security-review/SKILL.md` + `REFERENCE.md` (additive patch/minor/major tiers, BLOCK rule) | Done |
| AAASM-3575 | `scripts/release-readiness.sh` check 11 + `docs/release/security-signoff/TEMPLATE.md` + RUNBOOK §1.5 + `release-tag-cut/SKILL.md` wiring | Done |
| AAASM-3577 | This report | Done |

## Acceptance criteria

### AC1 — Every release records a security-review sign-off artifact

- `docs/release/security-signoff/TEMPLATE.md` exists; operators copy it to
  `v<version>.md`.
- RUNBOOK §1.5 and `release-tag-cut/SKILL.md` (relay stage 0 + pre-conditions)
  reference the artifact.
- `release-readiness.sh` check 11 enforces its presence + `Verdict: PASS`.

**Result: PASS.**

### AC2 — Threat model is versioned and refreshed at each major

- `release-threat-model.md` carries `Threat-model version: 1`, a
  "Last full refresh" line, a **Revision table** (one row per major), and a
  "When this is refreshed" policy stating *full rewrite + version bump at each
  major; a major whose version did not advance is itself a finding*.

**Result: PASS.**

### AC3 — Gate scales by release type and blocks on unaddressed High/Critical

- `/security-review` SKILL defines **additive** patch → minor → major tiers and a
  verdict rule that BLOCKs on any unaddressed Critical/High.
- `release-readiness.sh` check 11 fails on a missing or non-PASS sign-off.

**Gate paths exercised against the real `scripts/release-readiness.sh`:**

| Path | Setup | Observed |
|---|---|---|
| Negative | no `v<version>.md` | `✗ Security-review sign-off missing … ` — readiness fails at check 11 |
| Positive | `v<version>.md` with `Verdict: PASS` | `✓ Security-review sign-off present and Verdict: PASS` |
| Block | `v<version>.md` with `Verdict: BLOCK` | `✗ Security-review sign-off verdict is not PASS …` — readiness fails |

(Temporary test artifacts were removed; the working tree is clean — no
`v<version>.md` for any real release is committed by this PR.)

**Result: PASS.**

## Validation performed

- `bash -n scripts/release-readiness.sh` — clean.
- `shellcheck -S warning scripts/release-readiness.sh` — clean.
- All relative Markdown links in the new docs + skill cross-links resolve
  (release-threat-model, trust-boundary-review-checklist, SUMMARY entries,
  security-review SKILL/REFERENCE → RUNBOOK / script / docs / template).
- `mdbook` / `cargo doc` not run locally (macOS toolchain); covered by CI on the
  PR.

## Conclusion

All three Story acceptance criteria are satisfied and the release-readiness gate
demonstrably blocks (not merely documents) on a missing/non-PASS security
sign-off. **AAASM-3566 verified.**
