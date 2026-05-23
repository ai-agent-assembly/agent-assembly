# Design-fidelity verification — AAASM-1592 (E18 S-K — Dashboard Settings → Retention Policy admin UI)

> Design-fidelity sub-ticket: [AAASM-1871](https://lightning-dust-mite.atlassian.net/browse/AAASM-1871) — `[6/6]` under [AAASM-1592](https://lightning-dust-mite.atlassian.net/browse/AAASM-1592). Final sub-ticket of the story.
>
> Companion to the functional AC verification in
> [`AAASM-1592-functional.md`](AAASM-1592-functional.md) (AAASM-1869). This one
> cross-checks the *rendered visual design* of the page against the
> [design tokens](../dashboard/src/pages/Settings/Settings.css) shipped under
> AAASM-1866 and the ASCII layout reference in AAASM-1592's story description.
>
> Evidence captured by the new Playwright spec
> [`dashboard/tests/e2e/retention-policy-design-fidelity.spec.ts`](../dashboard/tests/e2e/retention-policy-design-fidelity.spec.ts).
> Run via `pnpm --dir dashboard exec playwright test tests/e2e/retention-policy-design-fidelity.spec.ts`.
>
> Screenshots land in `dashboard/docs/verification/aaasm-1871/` (6 captures —
> shell-default, settings-nav, validation-error, archive-mode, last-run-loaded,
> success-banner).
>
> Viewport: 1280×720 (Playwright default Desktop Chrome).

## Summary

```
Running 8 tests using 8 workers
  ✓ page shell — heading, three controls, three action buttons, last-run section (475ms)
  ✓ Settings sidebar — Storage section + Retention Policy nav link in active state (454ms)
  ✓ Save Changes button uses --color-primary + white foreground (333ms)
  ✓ validation error state — warm_days input gets danger-bordered + error text visible (472ms)
  ✓ archive mode — Archive URL field appears with placeholder + danger-bordered when empty (439ms)
  ✓ last-run stats panel — 5-cell grid with all five labels rendered (459ms)
  ✓ stat grid uses tabular-nums + responsive auto-fit columns (404ms)
  ✓ success banner uses --color-bg-success after a successful Save (475ms)
  8 passed (1.4s)
```

## Per-element verdict

| Surface | Verdict |
|---|---|
| Page heading "Retention Policy" — `<h1>` | ✅ Matches |
| Three numeric / select controls visible — hot_days / warm_days / cold_action | ✅ Matches |
| Three action buttons in single row — Save Changes / Run Now (Dry Run) / Run Now | ✅ Matches |
| Settings sidebar — Storage section header + active nav link state | ✅ Matches |
| Save Changes button — `--color-primary` (#2563eb) bg + white fg | ✅ Matches (rgb(37,99,235) / rgb(255,255,255)) |
| Validation error state — warm_days input border becomes `--color-danger` (#c54242) when invalid | ✅ Matches (rgb(197,66,66)) |
| Validation error text visible in `.retention-policy__field-error` | ✅ Matches |
| Archive URL field — placeholder `s3://...` and `--color-danger` border when empty | ✅ Matches |
| Last-run panel — 5-cell grid with all five labels (Hot rows / Compressed / Archived / Dropped / Freed) | ✅ Matches |
| Last-run panel — `freed_bytes` humanised (e.g. `127.0 MB`) | ✅ Matches |
| Stat grid — `display: grid` + ≥ 2 columns (responsive `auto-fit minmax(160px, 1fr)`) | ✅ Matches |
| Stat values — `font-variant-numeric: tabular-nums` | ✅ Matches |
| Success banner — `--color-bg-success` (#e7f6ec) background after Save | ✅ Matches (rgb(231,246,236)) |

## Accepted divergences from the story's ASCII layout

These are intentional design decisions, NOT regressions:

- Story shows three buttons stacked vertically (one per row); impl uses an inline row (`.retention-policy__actions` flex layout). Same controls, more compact, matches how operators typically expect inline form actions.
- Story shows "Drop / Archive to S3" as a dropdown with the literal "▼ Drop" arrow glyph; impl uses a native `<select>` (browser renders its own arrow). Same control, native chrome — and accessibility wins from native control rendering.
- Story shows the "Last retention run" panel as a fixed 5-row vertical block; impl uses a 5-cell `repeat(auto-fit, minmax(160px, 1fr))` grid with the same 5 labels. Same data, responsive across viewport widths.
- Story shows section dividers as ASCII rules (`─`); impl uses CSS `border-top: 1px solid var(--color-border)` on the `.retention-policy__last-run` block. Same visual function, design-token-friendly.

## Screenshot evidence

`dashboard/docs/verification/aaasm-1871/`:

| File | State captured |
|---|---|
| `01-shell-default.png` | Initial loaded state — Drop cold action, no last run |
| `02-settings-nav.png` | Settings sidebar with Storage section header + active link |
| `03-validation-error.png` | warm_days = 30 (≤ hot_days) — error visible, Save disabled |
| `04-archive-mode.png` | cold_action = archive — URL field visible, danger-bordered |
| `05-last-run-loaded.png` | Last-run panel populated with 5 stat cells |
| `06-success-banner.png` | After successful PUT — `--color-bg-success` banner |

## Verdict

✅ **The rendered visual design matches every element in AAASM-1592's layout reference.** Token usage is consistent with the established dashboard design system (`--color-primary`, `--color-danger`, `--color-bg-success` etc. from `Settings.css`). No design regressions; accepted divergences documented above.

This is the final sub-ticket of AAASM-1592. Once this verification PR merges, the parent Story can be closed.
