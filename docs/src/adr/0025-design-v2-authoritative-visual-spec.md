# ADR 0025: `design/v2/` Is the Authoritative Visual Specification

**Status**: Proposed — **requires product/design sign-off** (the owner of the hi-fi
handoff) before it is treated as binding on future audits
**Date**: 2026-07
**Ticket**: [AAASM-5082](https://lightning-dust-mite.atlassian.net/browse/AAASM-5082)

`design/README.md` has stated for some time that *"`design/v1/` remains as the
pre-theme reference. Use **v2** as the current visual spec."* — yet ADR 0017,
Epic [AAASM-5020](https://lightning-dust-mite.atlassian.net/browse/AAASM-5020),
Epic [AAASM-5077](https://lightning-dust-mite.atlassian.net/browse/AAASM-5077) and
every per-surface audit to date cite `design/v1/hi-fi/*.jsx`. This ADR closes that
gap: it records v2 as authoritative, records the file-level verification that **no
prior verdict is invalidated by the switch**, and fixes the evidence standard for
future visual work.

It exists because the alternative — silently re-anchoring — would invite exactly the
re-litigation it is meant to prevent. Anyone who notices that the closed audits cite a
directory the README calls superseded will reasonably ask whether the audits are still
valid. This ADR answers that question once, with evidence, so nobody re-runs them.

---

## Context

`design/v2/hi-fi/` is the Claude Design handoff that introduced the **light/dark theme
system** shipped under AAASM-2595: `styles.css` gained the
`:root` + `:root[data-theme="dark"]` token pair, and `design/v2/screenshots/` holds the
light/dark reference captures.

The dashboard's own theming is token-driven and already assumes the v2 model —
`OverviewPage.tsx:34-36` documents that a ring colour "is passed as a theme-token
string (e.g. `var(--ok)`) so the ring inverts with the active theme — never a"
hard-coded hex. So the *product* is on v2 while the *governance record* is on v1.

The risk of a re-anchor is that it reads as an invalidation: if v1 is superseded, are
the ADR 0017 ratifications — every one of which cites a `design/v1/hi-fi/*.jsx` file —
still binding? They are, and the reason is a verifiable property of the two
directories, not an assurance.

---

## Verification performed

Both directories hold the **same 25 files** — identical names, no additions, no
removals:

```
agent-detail  alerts  audit-log  capability  costs  data-audit  data-extra  data
fleet  identity  index.html  live-ops  onboarding  overview  policy-editor  policy
scrub  shell  states  styles.css  teams  topology  trace  tweaks-panel  tweaks
```

Every file was diffed line-by-line. Because the AAASM-5077 programme appended
`SUPERSESSION NOTE` banner comments to the **v1** files only (and not to v2), those
banner blocks were stripped before comparison — otherwise every annotated file would
show a spurious 16-to-18-line delta that is a product of this repo's own annotation
work, not of the v1→v2 handoff.

**Result — 17 of the 25 files are byte-identical**: `alerts`, `audit-log`, `costs`,
`data`, `data-audit`, `data-extra`, `fleet`, `identity`, `index.html`, `onboarding`,
`overview`, `policy`, `policy-editor`, `scrub`, `teams`, `trace`, `tweaks-panel`.

The eight that differ:

| File | Changed lines | Nature of the change |
|---|---|---|
| `agent-detail.jsx` | 2 | `background: '#fbfaf6'` → `var(--paper)` |
| `capability.jsx` | 2 | legend swatch `background: '#fbfaf6'` → `var(--paper)` |
| `states.jsx` | 2 | `background: '#0e0e0e'` → `var(--code-bg)` |
| `tweaks.jsx` | 24 | adds a `theme: 'light'` tweak, a `light`/`dark` radio, and the `data-theme` setter; exposes `window.setTweak` |
| `topology.jsx` | 43 | 8 hard-coded hexes → tokens, **plus** a `TOPO_EC_DARK` edge palette selected at render time (SVG strokes cannot read CSS vars) |
| `live-ops.jsx` | 70 | canvas fill/stroke hexes replaced by a `COL` palette object chosen on `data-theme` (canvas cannot read CSS vars) |
| `shell.jsx` | 43 | adds the topbar **theme-toggle button** (sun/moon SVG + `MutationObserver` sync) |
| `styles.css` | 215 | the `:root` / `:root[data-theme="dark"]` token system, `--rail-*` and `--code-*` tokens, a transition rule on major surfaces, and `.theme-toggle` styling. Overwhelmingly hard-coded values replaced by token references — see the four exceptions below. |

Counts are `diff … | grep -c '^[<>]'` (POSIX). A Myers/`difflib` word-level count gives
slightly different figures for `styles.css` (217 / 221) because it splits some
reflowed hunks differently; the discrepancy is in the counting method, not the content.

### The structural-equivalence claim, and its one honest caveat

**Claim: v2 is v1 plus theme tokenisation. No page's layout, component tree,
information architecture, state model, data shape, or affordance set differs.**

Verified on far more than the three surfaces this audit committed to check — all 25
files were diffed. The overwhelming majority of changed lines fall into one of three
buckets:

1. a hard-coded colour literal replaced by a token reference;
2. a JS-side palette object introduced *because* the target is `<canvas>` or an SVG
   stroke attribute, which cannot resolve a CSS custom property
   (`live-ops.jsx`, `topology.jsx`);
3. the theme control mechanism itself (`tweaks.jsx`, `shell.jsx`, `.theme-toggle`).

**"Overwhelming majority", not "every line".** An earlier draft of this ADR claimed
*every* changed line fell into those buckets and that *every* removed line was a
literal replaced by a token. Review refuted both, and the exceptions are named here
rather than smoothed over — an evidence document that overstates its evidence is worth
less than one that doesn't:

- **`.modal` border: `var(--line-3)` → `var(--line-2)`** (v1 `styles.css:573` → v2
  `:656`). **Token→token**, not literal→token — and it changes the rendered colour in
  light mode, from near-black `#1a1a1a` to the `#c4bfb0` beige hairline.
- **`.modal` box-shadow: `rgba(0,0,0,0.18)` → `rgba(0,0,0,0.40)`**. Literal→**different
  literal**, in none of the three buckets. A deeper modal shadow.
- **`.rule-num` color: `var(--paper-2)` → `var(--paper)`** — token→token, same class of
  change as the `.modal` border.
- **`.layer-counter` gains a new `color: var(--ink)` declaration** (v1 `styles.css:1306`
  block) alongside its `background` switching to `color-mix(…)` — a **new property**,
  not a substitution.
- **A `transition` rule is added to ~20 pre-existing selectors** (v2
  `styles.css:117-121`: `body, .main, .topbar, .page, … .rail-item, .rail-foot,
  .rail-brand`). This is a **motion** addition, and it fires on interactions that have
  nothing to do with theming — `.rail-item:hover` now cross-fades where v1 switched
  instantly.

None of the five alters layout, component structure, or what a surface says; four are
sub-pixel-to-hairline colour shifts and the fifth is easing. **They do not disturb the
carry-over conclusion**, which is about structure — but the absolutes did not survive
contact with the diff, so they are gone.

**The one genuine structural difference**, stated plainly rather than hidden: v2's
`shell.jsx` renders a topbar button that v1 does not, and v2's tweaks panel has a
control v1's does not. This ADR does not pretend otherwise. It claims only that the
addition is **the theme switch itself**, is confined to the app chrome, and touches
**no governance surface** — not one of the ten audited pages gains, loses, or reshapes
anything. No ADR 0017 item, and no per-surface audit verdict, is about the topbar's
button inventory. An independent re-diff of all 25 files during review, plus a
programmatic layout-property scan, confirmed this as the *only* structural difference
and confirmed the carry-over conclusion.

### Therefore: every prior verdict stands

Because the difference is confined to colour tokenisation plus the theme control, an
audit that reached a verdict about `design/v1/hi-fi/<surface>.jsx` would reach the
**identical** verdict against `design/v2/hi-fi/<surface>.jsx`. Concretely:

- **ADR 0017's 20 RATIFY items remain ratified**, unchanged, with their v1 file
  citations still correct — v1 is not deleted and remains readable.
- **AAASM-5077's FE-buildable and backend-blocked inventories remain valid.** (Subject
  only to the separate correction recorded in ADR 0017's own "Correction" addendum,
  which is about a mis-recorded fact, not about v1-vs-v2.)
- **AAASM-5020's design-fidelity work remains valid.**

**Nobody should re-run a closed audit on the grounds that it cited v1.** That is the
single most important sentence in this record.

---

## Decision

1. **`design/v2/hi-fi/` is the current authoritative visual specification.** New
   design-parity work, new audits, and new implementation cite v2.
2. **`design/v1/hi-fi/` is a historical pre-theme reference.** It is **not deleted** —
   ADR 0017's item citations point into it, and its `SUPERSESSION NOTE` banners are
   part of the AAASM-5077 record. It is read-only history.
3. **Prior structural reconciliation carries over unchanged**, on the evidence above.
   A future contributor who wants to reopen a closed verdict needs a reason other than
   the v1→v2 re-anchor.
4. **All future light/dark screenshots and visual-regression evidence are captured
   against the v2 prototype**, not v1. A screenshot taken against v1 is evidence about
   the pre-theme prototype and does not satisfy a visual-fidelity acceptance criterion.

   **This is a forward requirement on capture, not a claim that a baseline already
   exists.** `design/v2/screenshots/` holds **9** files — 1 light (`theme-light.png`)
   and 8 dark — against **43** in `design/v1/screenshots/`. There is therefore **no
   per-surface light/dark v2 baseline today**, and any acceptance criterion that
   assumes one is unsatisfiable as written. Building that baseline is a companion
   action this ADR names but does not schedule; until it exists, per-surface visual
   evidence is captured fresh from the v2 prototype rather than diffed against a
   stored reference.
5. **Where a *new* deviation from v2 is found, it is recorded under ADR 0017's existing
   addendum convention** (as the AAASM-5099 addendum already does), not as a new
   parity programme.

## Consequences

- **Positive.** The governance record and the README stop disagreeing about which
  directory is the spec. Future audits have one place to look, and one theme-complete
  reference to screenshot against.
- **Positive.** The equivalence is now evidenced rather than assumed, so the re-anchor
  costs nothing in re-work.
- **Neutral / accepted.** v1 stays in-tree. Two hi-fi directories will keep confusing
  newcomers; `design/README.md` is updated to state the relationship explicitly, and
  the v1 supersession banners already point at ADR 0017.
- **Neutral.** If a genuine structural divergence between v1 and v2 is discovered
  later that this diff missed, it is recorded as a correction to this ADR — the same
  way ADR 0017's correction addendum was added — rather than by quietly editing the
  equivalence claim above.

## Reconsideration triggers

- A `design/v3/` handoff, which would repeat this exercise.
- Any change to `design/v2/hi-fi/` that is **not** theme-related, which would break the
  "v2 = v1 + tokenisation" invariant this ADR's carry-over argument depends on.

## Decision required from

**Product / design (the hi-fi handoff owner)** — confirm items 1–5 above, and in
particular item 4: that v2 is the required evidence base for visual-regression
acceptance from here on.

**Merging this ADR authorises no implementation and changes no product behaviour.**
It is a documentation and evidence-standard decision.

## Traceability

- Raised under Epic
  [AAASM-5082](https://lightning-dust-mite.atlassian.net/browse/AAASM-5082).
- Re-anchors the reference used by ADR 0017 and by Epics
  [AAASM-5020](https://lightning-dust-mite.atlassian.net/browse/AAASM-5020) /
  [AAASM-5077](https://lightning-dust-mite.atlassian.net/browse/AAASM-5077).
- The theme system itself shipped under
  [AAASM-2595](https://lightning-dust-mite.atlassian.net/browse/AAASM-2595).
- Companion doc: `design/README.md`.
