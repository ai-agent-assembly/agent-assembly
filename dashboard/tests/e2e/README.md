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

The **snapshot** specs — this one and `responsive-viewport-visual` — remain a **local visual gate**. Their baselines are platform-specific (`-chromium-darwin`) and no `-chromium-linux` baselines exist, so running them on a Linux runner would churn rather than verify. Run them before landing theme changes.

Everything else now runs in CI. See [Authentication](#authentication) and [CI gate](#ci-gate) below.

## Authentication

Seed the token into **`sessionStorage`**, never `localStorage`:

```ts
await page.addInitScript(() => sessionStorage.setItem('aa_token', 'e2e-test-token'))
```

`dashboard/src/auth/tokenStorage.ts` has read from `sessionStorage` only since AAASM-4322. A spec that seeds `localStorage` does not authenticate — it times out before the app mounts, with no hint that auth was the cause. That mistake silently killed 31 files for 19 days (AAASM-5191).

Note that the **theme** (`aa-dashboard-theme`) does legitimately live in `localStorage`. Only `aa_token` moved.

**Do not seed both stores "to be safe."** `localStorage` is a state production cannot reach — AAASM-4322 removed the token from it as XSS-exfiltration hardening — so a spec seeding both would keep passing if that hardening were ever reverted, and the gate would certify the vulnerability. `pnpm e2e:check-seeds` enforces this and runs as its own step in `dashboard-e2e`.

## CI gate

The `dashboard-e2e` job in `.github/workflows/ci.yml` runs this suite on any change matching the `dashboard` path filter, and is part of the `ci-success` aggregate — a red e2e run is a **merge blocker**, not an advisory signal.

It runs `dashboard/playwright.ci.config.ts`: the normal config plus a quarantine list. **Specs are gated by default** — a file must be named in that list to be excluded — so anything you add here is covered without doing anything.

If your spec is quarantined, it is because it was already failing when the gate was introduced (AAASM-5195), is a known race (AAASM-5198), or needs something the job does not provision (`hitl-approval` boots a real `aa-api` via `cargo`). Nothing is `.skip`-ed or deleted: `pnpm test:e2e` still runs the whole suite locally, quarantined specs included. Fix a spec, confirm it passes, delete its line, and lower `QUARANTINE_CEILING` by one — the list only shrinks, and that ceiling is what enforces it rather than merely asserting it.

**What the gate does not prove:** 43 of the 44 gated specs stub every network call with `page.route`, so it compares the frontend against its own mocks — it is not an API-contract check and cannot see backend drift. See ADR-0028 for the full list of non-claims.

Failures publish the HTML report, failure screenshots, retry traces and JUnit XML as build artifacts, so a CI-only failure can be diagnosed without reproducing it locally.
