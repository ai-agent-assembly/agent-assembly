# Dashboard E2E tests

Playwright-driven end-to-end and visual regression tests for the dashboard.

## Running

The Playwright config (`dashboard/playwright.config.ts`) auto-starts `vite preview` on `http://localhost:4173` before the tests run, so build once and the tests can start:

```sh
pnpm build
pnpm test:e2e
```

To run a single spec file:

```sh
pnpm exec playwright test responsive-viewport-visual
```

## Visual regression — `responsive-viewport-visual.spec.ts`

This spec implements AAASM-1324: the AppShell layout cannot silently regress at the two canonical desktop widths (1280×800, 1920×1080) for the `/approvals`, `/agents` (Fleet), and `/policies` pages. Six snapshots total.

### Where baselines live

`dashboard/tests/e2e/responsive-viewport-visual.spec.ts-snapshots/`. Filenames follow Playwright's per-spec layout: `<route>-<viewport>-<project>-<platform>.png`.

Baselines are **platform-specific** — Playwright appends `-chromium-darwin` on macOS, `-chromium-linux` on Linux. When CI runs on a different platform than your dev box, the spec will fail until that platform's baseline is committed. Regenerate on each target platform you care about.

### Regenerating baselines (when a deliberate visual change lands)

After your code change, run:

```sh
pnpm exec playwright test responsive-viewport-visual --update-snapshots
```

That overwrites the `.png` files in the snapshots dir with the new render. Inspect the diff, confirm the change is what you intended, then commit the updated baselines.

### Masking non-deterministic regions

The spec already masks the AppShell topbar status region (which can show stream-connect timestamps) and any element flagged `data-visreg-mask`. If you add new dynamic content to a page covered by the spec, tag the volatile node:

```tsx
<span data-visreg-mask>{formattedTimestamp}</span>
```

Without the tag, the snapshot will flake on every run.

### Diff tolerance

The spec uses `maxDiffPixelRatio: 0.01` to absorb 1–2 px sub-pixel AA differences between local and CI hardware. Any real layout regression will dwarf this budget and fail the assertion.

## Theme regression — `theme-visual.spec.ts`

AAASM-2597 (follow-up to the AAASM-2595 light/dark theme). Guards the `data-theme` token system end-to-end against the real rendered app — only the network is stubbed.

Two halves:

- **Visual** — `toHaveScreenshot()` baselines for six representative pages (Fleet, Policies, Identity, Settings, Violations heatmap, Live Ops) in **both** themes, so a regression (light-on-light text, broken surface re-theme, unreadable contrast) shows up as a pixel diff. 12 snapshots in `theme-visual.spec.ts-snapshots/`, same `-chromium-<platform>` naming + masking + `maxDiffPixelRatio: 0.01` rules as above.
- **Behavioural** — the topbar toggle flips `data-theme` on `<html>` and re-themes the surface; the choice persists across reload (localStorage `aa-dashboard-theme`); the OS `prefers-color-scheme` drives the theme on first load (no stored choice); and the nav rail + code/terminal palette (`--term-*`) stay dark in **both** modes (the AAASM-2595 design intent).

Regenerate the baselines after a deliberate theme change:

```sh
pnpm exec playwright test theme-visual --update-snapshots
```

### CI lane

The dashboard has **no Playwright CI job** — every visual/e2e spec here (this one, `responsive-viewport-visual`, and all the `*-design-fidelity` specs) runs locally only. CI covers the dashboard via `dashboard-typecheck`, `dashboard-build`, and `dashboard-test` (vitest). This spec is therefore a **local visual gate**; run it before landing theme changes. That keeps the platform-specific (`-darwin`) baselines stable instead of churning against Linux runners.
