# ADR 0027: The Accessibility Floor Overrides the Visual Specification

**Status**: Accepted
**Date**: 2026-07
**Ticket**: [AAASM-5134](https://lightning-dust-mite.atlassian.net/browse/AAASM-5134)

ADR [0025](0025-design-v2-authoritative-visual-spec.md) makes `design/v2/hi-fi/` the
authoritative visual specification. This ADR records the one thing that outranks it:
where a value in the spec fails a **WCAG 2.1 AA** floor, the accessibility floor wins,
the *spec* is corrected at source, and the correction is recorded here. It complements
ADR 0025 rather than replacing it, and it is deliberately more general than the single
defect that prompted it — the whole point is that the next surface built from the mock
cannot reintroduce the same failure.

It also differs in mechanism from ADR [0017](0017-dashboard-design-parity-ratified-evolutions.md).
0017 records cases where the *shipped implementation* is authoritative over the mock and
annotates the mock with a supersession note. Here the mock is **edited**: an inaccessible
value is not a design decision to be ratified around, it is a defect in the specification.

---

## Context

The AAASM-5134 rail-palette migration repointed the dashboard's left nav rail at the
hi-fi tokens. An adversarial review of PR #1722 measured the resulting foreground
colours against the rail ground and found two below the AA floor:

| Token (v2) | Value | vs `#0e0e0e` rail | Size | AA 4.5:1 |
|---|---|---|---|---|
| `--rail-fg` | `#c8c5b8` | 11.15:1 | 14px | pass |
| `--rail-fg-dim` | `#8a8880` | 5.44:1 | 11px | pass |
| **`--rail-fg-muted`** (group headings) | `#6a6a60` | **3.53:1** | 11px | **fail** |
| **`--rail-num`** (route numbers) | `#6a6a60` | **3.53:1** | 11px | **fail** |

Contrast is computed with the WCAG 2.1 relative-luminance formula over sRGB. Neither
value qualifies for the 3:1 large-text exception: both render at `0.6875rem` (11px),
far below the 18.66px/24px thresholds.

The forcing constraint is that the rail is **persistent chrome on every screen**, and
the group headings are navigational structure, not decoration — they are the only thing
distinguishing one route cluster from the next.

Two facts made this a decision rather than a bug fix:

1. `#6a6a60` is not an implementation slip. It is what the authoritative spec specifies
   (`design/v2/hi-fi/styles.css`), so "match the mock" and "meet AA" gave opposite
   answers, and nothing recorded said which wins.
2. No ADR in this repo mentions WCAG, contrast, or accessibility at all. The precedence
   question had never been answered, so each surface was free to answer it differently.

The rail is intentionally dark in **both** themes (`dashboard/src/styles.css:219-224`),
and v2 darkens it further to `#0a0907` in dark mode — so a correction has to clear the
floor against both grounds, not just the lighter one.

## Decision

1. **A WCAG 2.1 AA floor overrides the authoritative visual specification wherever the
   two conflict.** For text this is 4.5:1 (normal) / 3:1 (large, ≥18.66px or ≥14px bold).
   No surface may knowingly ship a value below the floor on the grounds that the mock
   specifies it.

2. **The correction is made in the specification, not only downstream.** The offending
   token is edited in `design/v2/hi-fi/` with an inline `ACCESSIBILITY CORRECTION`
   comment naming this ADR and the measured ratios. Fixing only the implementation would
   leave the spec still specifying a value we refuse to ship, and the next surface built
   from it would reintroduce the failure. `design/v1/` is historical and is left alone.

3. **The correction is the smallest step that clears the floor.** Design intent survives
   as far as it can: stay on the same hue ramp and move only until the threshold is met,
   rather than substituting a new colour. For `--rail-fg-muted` that is
   **`#6a6a60` → `#7b7b71`**, measuring **4.52:1** against `#0e0e0e` and **4.66:1**
   against v2's `#0a0907` dark-mode rail — the first value on the ramp above 4.5:1
   (`#7a7a70` reaches only 4.45:1).

4. **Each corrected value is pinned by a test** that recomputes the ratio from the
   shipped token, so a later palette edit cannot silently drop back below the floor.

## Accepted risks

- **`--rail-num` (route numbers) is knowingly left at 3.53:1**, scoped to AAASM-5134.
  The assumption making this acceptable is that the numbers are ordinal decoration
  beside an already-compliant text label — losing them costs sequence, not meaning or
  navigation. It is *not* deferred because it is unimportant: the number sits inside the
  nav row, so it also renders on the `--rail-item-hover` fill (`#1f1f1f`), where even the
  corrected grey reaches only 3.86:1. Clearing AA there requires a hover-state decision
  (lighten the token, darken the hover fill, or restate the number on hover) with its own
  visual consequences, and guessing at it inside an unrelated PR is how design debt gets
  laundered. Tracked on AAASM-5134.
- The corrected value clears the floor by a small margin (4.52:1 against a 4.5:1
  requirement). This is safe because the computation is deterministic — a fixed formula
  over fixed sRGB values, not a rendering-dependent measurement — which is exactly why
  decision 4 pins it with an exact recomputation rather than an eyeball check.

## Explicitly forbidden designs

- **Do not "restore" a corrected token to its mock value** on parity grounds. A parity
  audit that flags `#7b7b71` as drift from `#6a6a60` is reading a superseded value; this
  ADR is the record that says so.
- **Do not meet the floor by enlarging text to reach the 3:1 large-text exception**
  unless the size change is independently desirable. Shrinking the accessible surface to
  fit an inaccessible colour inverts the priority this ADR establishes.
- **Do not fix only `dashboard/src/` and leave `design/v2/` specifying the failing
  value.** That is the state this ADR exists to prevent.
- **Do not treat an aria-hidden decorative glyph as text** requiring 4.5:1 — the rail's
  `★` marker and status dots are `aria-hidden` and carry no information the adjacent
  label does not.

## Consequences

- **Future contributors / agents**: "the mock says so" is no longer a sufficient
  justification for a contrast failure. The precedence question has one answer.
- **Design**: `design/v2/hi-fi/` is now a corrected artefact rather than a verbatim
  handoff. Every deviation carries an inline comment naming this ADR, so the diff from
  the original handoff stays legible.
- **ADR 0025**: unaffected in substance — v2 remains authoritative. Its authority is now
  qualified by this floor. 0025 is still `Proposed`; this ADR does not depend on its
  ratification, because the floor holds whichever directory is authoritative.
- **Cost**: a per-surface contrast pass is now implied work whenever a palette is
  repointed. That is real effort and is the intended trade.

## Validation requirements

- `dashboard/src/components/AppShell.contrast.test.ts` parses the shipped
  `--shell-nav-*` tokens out of `AppShell.css`, recomputes WCAG relative luminance
  against the rail ground, and asserts the group-heading ratio is ≥ 4.5:1 in both
  themes. It runs in the **unit** suite (`pnpm test`), deliberately not in the
  Playwright e2e suite, which no CI job currently executes.
- The test asserts the *ratio*, not the hex, so a future palette change is free to move
  the colour as long as it stays compliant.

## Reconsideration triggers

- WCAG 2.2 / 3.0 adoption, or an organisational decision to target AAA (7:1), which
  would re-open every value in the table above.
- A new design handoff (`design/v3/`) — the corrections recorded here must be carried
  forward into it, or they are silently lost.
- The rail ceasing to be dark in both themes, which would change every ground colour the
  ratios above are computed against.
- Resolution of the `--rail-num` hover-state question, which retires this ADR's one
  accepted risk.

## Traceability

| Reference | Relation |
| --- | --- |
| [AAASM-5134](https://lightning-dust-mite.atlassian.net/browse/AAASM-5134) | Rail hi-fi palette migration — the ticket whose review surfaced the failure |
| [AAASM-5149](https://lightning-dust-mite.atlassian.net/browse/AAASM-5149) | Shell-truthfulness ticket sharing PR #1722 |
| [PR #1722](https://github.com/ai-agent-assembly/agent-assembly/pull/1722) | Implements the correction in `dashboard/` and `design/v2/` |
| [ADR 0025](0025-design-v2-authoritative-visual-spec.md) | Establishes `design/v2/` as authoritative; qualified by this ADR |
| [ADR 0017](0017-dashboard-design-parity-ratified-evolutions.md) | Prior mock-vs-shipped precedence record; different mechanism (annotate, not edit) |
